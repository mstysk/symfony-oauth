<?php

declare(strict_types=1);

namespace App\OAuth\Extension;

use App\OAuth\Entity\AuthCode as AuthCodeEntity;
use App\OAuth\Repository\AuthCodeRepository;
use DateInterval;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;
use Symfony\Component\Uid\Uuid;

/**
 * AuthorizationCodeGrant + MCP-spec invariants:
 *   - PKCE (S256) is required for ALL clients (including confidential),
 *     overriding league's per-client default.
 *   - RFC 8707 `resource` is read at /authorize (optional, validated and
 *     bound to the auth code) and required at /token; if a resource
 *     was bound at /authorize, the /token request MUST match it
 *     (audience-confused-deputy defense per §2.2).
 *   - The validated resource is propagated into the access token's
 *     `aud` claim via McpAccessTokenEntity::setAudiences().
 */
final class ResourceIndicatorGrant extends AuthCodeGrant
{
    private ?string $pendingResource = null;
    private ?string $pendingCodeResource = null;

    public function __construct(
        AuthCodeRepositoryInterface $authCodeRepository,
        RefreshTokenRepositoryInterface $refreshTokenRepository,
        DateInterval $authCodeTTL,
        private readonly AllowedResources $allowedResources,
        private readonly LoggerInterface $logger = new NullLogger(),
    ) {
        parent::__construct($authCodeRepository, $refreshTokenRepository, $authCodeTTL);
    }

    protected function createAuthorizationRequest(): AuthorizationRequestInterface
    {
        return new AuthorizationRequest();
    }

    public function validateAuthorizationRequest(ServerRequestInterface $request): AuthorizationRequestInterface
    {
        $codeChallenge = $this->getQueryStringParameter('code_challenge', $request);
        if ($codeChallenge === null) {
            throw OAuthServerException::invalidRequest('code_challenge', 'PKCE is required');
        }

        $method = $this->getQueryStringParameter('code_challenge_method', $request);
        if ($method !== 'S256') {
            throw OAuthServerException::invalidRequest(
                'code_challenge_method',
                'Code challenge method must be S256',
            );
        }

        $authRequest = parent::validateAuthorizationRequest($request);

        // RFC 8707: `resource` is optional at /authorize. If supplied, it
        // must be in the allowlist and use a safe scheme. We bind it onto
        // the auth code at completion time (issueAuthCode) so the matching
        // check at /token has something to compare to.
        $resource = $this->getQueryStringParameter('resource', $request);
        if ($resource !== null) {
            // redirect_uri has been validated by parent — invalid_target
            // here is RFC 6749 §4.1.2.1 class-(b), which means we 302 back
            // to the client with error=invalid_target instead of JSON.
            $redirectWithState = $this->makeRedirectUri(
                $authRequest->getRedirectUri() ?? $this->getClientRedirectUri($authRequest->getClient()),
                $authRequest->getState() !== null ? ['state' => $authRequest->getState()] : [],
            );

            if (!self::isAcceptableResourceScheme($resource)) {
                throw $this->invalidTarget('resource scheme must be https (or http://localhost)', $redirectWithState);
            }
            if (!$this->allowedResources->contains($resource)) {
                throw $this->invalidTarget('resource not allowed', $redirectWithState);
            }
            if ($authRequest instanceof AuthorizationRequest) {
                $authRequest->setResource($resource);
            }
        }

        return $authRequest;
    }

    public function completeAuthorizationRequest(AuthorizationRequestInterface $authorizationRequest): ResponseTypeInterface
    {
        if ($authorizationRequest instanceof AuthorizationRequest) {
            $this->pendingCodeResource = $authorizationRequest->getResource();
        }

        try {
            return parent::completeAuthorizationRequest($authorizationRequest);
        } finally {
            $this->pendingCodeResource = null;
        }
    }

    /**
     * Override to bind the resource onto the AuthCode entity before
     * persistNewAuthCode flushes — replicates parent's loop with the
     * single extra setResource() call.
     *
     * @param non-empty-string $userIdentifier
     * @param \League\OAuth2\Server\Entities\ScopeEntityInterface[] $scopes
     */
    protected function issueAuthCode(
        DateInterval $authCodeTTL,
        ClientEntityInterface $client,
        string $userIdentifier,
        ?string $redirectUri,
        array $scopes = [],
    ): AuthCodeEntityInterface {
        $authCode = $this->authCodeRepository->getNewAuthCode();
        $authCode->setExpiryDateTime((new \DateTimeImmutable())->add($authCodeTTL));
        $authCode->setClient($client);
        $authCode->setUserIdentifier($userIdentifier);
        if ($redirectUri !== null) {
            $authCode->setRedirectUri($redirectUri);
        }
        foreach ($scopes as $scope) {
            $authCode->addScope($scope);
        }

        if ($this->pendingCodeResource !== null && $authCode instanceof AuthCodeEntity) {
            $authCode->setResource($this->pendingCodeResource);
        }

        $maxAttempts = self::MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS;
        while ($maxAttempts-- > 0) {
            $authCode->setIdentifier($this->generateUniqueIdentifier());
            try {
                $this->authCodeRepository->persistNewAuthCode($authCode);

                return $authCode;
            } catch (\League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException $e) {
                if ($maxAttempts === 0) {
                    throw $e;
                }
            }
        }

        return $authCode;
    }

    public function respondToAccessTokenRequest(
        ServerRequestInterface $request,
        ResponseTypeInterface $responseType,
        DateInterval $accessTokenTTL,
    ): ResponseTypeInterface {
        $resource = $this->getRequestParameter('resource', $request);

        if ($resource === null) {
            throw $this->invalidTarget('resource is required');
        }

        if (!self::isAcceptableResourceScheme($resource)) {
            throw $this->invalidTarget('resource scheme must be https (or http://localhost)');
        }

        if (!$this->allowedResources->contains($resource)) {
            throw $this->invalidTarget('resource not allowed');
        }

        // RFC 8707 §2.2 — if /authorize bound a resource onto the auth code,
        // the /token request must specify the same resource.
        $this->assertBoundResourceMatches($request, $resource);

        $this->pendingResource = $resource;

        try {
            return parent::respondToAccessTokenRequest($request, $responseType, $accessTokenTTL);
        } finally {
            $this->pendingResource = null;
        }
    }

    /**
     * Override to inject `aud = [resource]` into the access token entity
     * before persistence (so the JWT and the DB row both carry it).
     *
     * @param non-empty-string|null $userIdentifier
     * @param \League\OAuth2\Server\Entities\ScopeEntityInterface[] $scopes
     */
    protected function issueAccessToken(
        DateInterval $accessTokenTTL,
        ClientEntityInterface $client,
        string|null $userIdentifier,
        array $scopes = [],
    ): AccessTokenEntityInterface {
        $accessToken = $this->accessTokenRepository->getNewToken($client, $scopes, $userIdentifier);
        $accessToken->setExpiryDateTime((new \DateTimeImmutable())->add($accessTokenTTL));
        $accessToken->setPrivateKey($this->privateKey);

        if ($this->pendingResource !== null && $accessToken instanceof McpAccessTokenEntity) {
            $accessToken->setAudiences([$this->pendingResource]);
        }

        $maxAttempts = self::MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS;
        while ($maxAttempts-- > 0) {
            $accessToken->setIdentifier($this->generateUniqueIdentifier());
            try {
                $this->accessTokenRepository->persistNewAccessToken($accessToken);

                return $accessToken;
            } catch (\League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException $e) {
                if ($maxAttempts === 0) {
                    throw $e;
                }
            }
        }

        return $accessToken;
    }

    /**
     * Override to start a fresh refresh-token family on initial issuance
     * (the auth-code → token leg). Subsequent rotations are handled by
     * FamilyAwareRefreshTokenGrant, which inherits the family_id from the
     * old refresh token.
     */
    protected function issueRefreshToken(AccessTokenEntityInterface $accessToken): ?RefreshTokenEntityInterface
    {
        if (!$this->supportsGrantType($accessToken->getClient(), 'refresh_token')) {
            return null;
        }

        $refreshToken = $this->refreshTokenRepository->getNewRefreshToken();
        if ($refreshToken === null) {
            return null;
        }

        $refreshToken->setExpiryDateTime((new \DateTimeImmutable())->add($this->refreshTokenTTL));
        $refreshToken->setAccessToken($accessToken);

        if ($refreshToken instanceof SimpleRefreshTokenEntity && $refreshToken->getFamilyId() === null) {
            $refreshToken->setFamilyId(Uuid::v7());
        }

        $maxAttempts = self::MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS;
        while ($maxAttempts-- > 0) {
            $refreshToken->setIdentifier($this->generateUniqueIdentifier());
            try {
                $this->refreshTokenRepository->persistNewRefreshToken($refreshToken);

                return $refreshToken;
            } catch (\League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException $e) {
                if ($maxAttempts === 0) {
                    throw $e;
                }
            }
        }

        return $refreshToken;
    }

    /**
     * Decrypt the auth code from the request body, look up the AuthCode
     * row, and assert any bound resource matches the /token request.
     */
    private function assertBoundResourceMatches(ServerRequestInterface $request, string $requestResource): void
    {
        if (!$this->authCodeRepository instanceof AuthCodeRepository) {
            return; // can't enforce without our concrete repo
        }

        $encryptedCode = $this->getRequestParameter('code', $request);
        if ($encryptedCode === null) {
            return; // parent will reject with invalid_request
        }

        try {
            $payload = json_decode($this->decrypt($encryptedCode));
        } catch (\Throwable $e) {
            // parent's validateAuthorizationCode will surface this to the
            // client as invalid_grant. Log so the production triage path
            // can distinguish a bad-input attempt from a misconfiguration
            // (e.g. encryption-key rotation that broke decrypt).
            $this->logger->warning('Failed to decrypt authorization code while checking bound resource', [
                'exception' => $e::class,
                'message' => $e->getMessage(),
            ]);

            return;
        }

        if (!\is_object($payload) || !isset($payload->auth_code_id)) {
            return;
        }

        $boundResource = $this->authCodeRepository->getBoundResource((string) $payload->auth_code_id);
        if ($boundResource === null) {
            return; // /authorize did not bind a resource — /token-side check is sufficient
        }

        if ($boundResource !== $requestResource) {
            throw $this->invalidTarget(sprintf(
                'resource %s does not match the value bound to the authorization code',
                $requestResource,
            ));
        }
    }

    public static function isAcceptableResourceScheme(string $resource): bool
    {
        $parts = parse_url($resource);
        if ($parts === false || !isset($parts['scheme'], $parts['host'])) {
            return false;
        }

        $scheme = strtolower($parts['scheme']);
        $host = strtolower($parts['host']);

        // parse_url returns IPv6 hosts wrapped in square brackets ('[::1]').
        // Strip them before comparing against the localhost allowlist.
        if (str_starts_with($host, '[') && str_ends_with($host, ']')) {
            $host = substr($host, 1, -1);
        }

        if ($scheme === 'https') {
            return true;
        }

        return $scheme === 'http' && \in_array($host, ['localhost', '127.0.0.1', '::1'], true);
    }

    private function invalidTarget(string $hint, ?string $redirectUri = null): OAuthServerException
    {
        return new OAuthServerException(
            'The requested resource is invalid, missing, unknown, or malformed',
            8,
            'invalid_target',
            400,
            $hint,
            $redirectUri,
        );
    }
}
