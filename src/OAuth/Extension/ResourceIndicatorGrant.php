<?php

declare(strict_types=1);

namespace App\OAuth\Extension;

use DateInterval;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Grant\AuthCodeGrant;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\RequestAccessTokenEvent;
use League\OAuth2\Server\RequestEvent;
use League\OAuth2\Server\RequestRefreshTokenEvent;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * AuthorizationCodeGrant + MCP-spec invariants:
 *   - PKCE (S256) is required for ALL clients (including confidential),
 *     overriding league's per-client default.
 *   - RFC 8707 `resource` parameter is required at the token endpoint;
 *     value must match an entry in MCP_ALLOWED_RESOURCES (exact-match).
 *   - The validated resource is propagated into the access token's
 *     `aud` claim via McpAccessTokenEntity::setAudiences().
 */
final class ResourceIndicatorGrant extends AuthCodeGrant
{
    private ?string $pendingResource = null;

    public function __construct(
        AuthCodeRepositoryInterface $authCodeRepository,
        RefreshTokenRepositoryInterface $refreshTokenRepository,
        DateInterval $authCodeTTL,
        private readonly AllowedResources $allowedResources,
    ) {
        parent::__construct($authCodeRepository, $refreshTokenRepository, $authCodeTTL);
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

        return parent::validateAuthorizationRequest($request);
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

    private static function isAcceptableResourceScheme(string $resource): bool
    {
        $parts = parse_url($resource);
        if ($parts === false || !isset($parts['scheme'], $parts['host'])) {
            return false;
        }

        $scheme = strtolower($parts['scheme']);
        $host = strtolower($parts['host']);

        if ($scheme === 'https') {
            return true;
        }

        // http is only acceptable for localhost development.
        return $scheme === 'http' && \in_array($host, ['localhost', '127.0.0.1', '::1'], true);
    }

    private function invalidTarget(string $hint): OAuthServerException
    {
        // RFC 8707 §3 — error code "invalid_target", HTTP 400.
        // league/oauth2-server has no factory for this so we build it directly.
        return new OAuthServerException(
            'The requested resource is invalid, missing, unknown, or malformed',
            8,
            'invalid_target',
            400,
            $hint,
        );
    }
}
