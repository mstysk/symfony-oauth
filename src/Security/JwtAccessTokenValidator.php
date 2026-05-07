<?php

declare(strict_types=1);

namespace App\Security;

use App\OAuth\Extension\AllowedResources;
use App\OAuth\Extension\KidDeriver;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;

/**
 * Validates a Bearer JWT issued by this AS for use against /mcp.
 *
 * Order is deliberate — cheap structural checks first, DB hit last so an
 * obviously-malformed token costs us no Doctrine query:
 *   1. parse + signature  (RS256 against public.key)
 *   2. exp / nbf          (LooseValidAt — no clock-skew tolerance, fine for PoC)
 *   3. iss exact-match    (RFC 7519 §4.1.1 — Phase 1's OAUTH_ISSUER)
 *   4. aud allow-list     (RFC 8707 — must be in MCP_ALLOWED_RESOURCES)
 *   5. kid header         (KidDeriver — proves the signing key matches the JWKS)
 *   6. revocation check   (RFC 9700 §4.14 — refresh-token reuse cascades here)
 *
 * On any failure throws InvalidJwtException with a typed `reason`.
 */
final class JwtAccessTokenValidator
{
    public function __construct(
        private readonly string $publicKeyPath,
        private readonly string $issuer,
        private readonly KidDeriver $kidDeriver,
        private readonly AllowedResources $allowedResources,
        private readonly AccessTokenRepositoryInterface $accessTokens,
    ) {
    }

    public function validate(string $rawJwt): ValidatedToken
    {
        $verificationKey = InMemory::file($this->publicKeyPath);
        $config = Configuration::forAsymmetricSigner(new Sha256(), $verificationKey, $verificationKey);

        try {
            $token = $config->parser()->parse($rawJwt);
        } catch (\Throwable $e) {
            throw new InvalidJwtException(InvalidJwtReason::Malformed, 'Malformed JWT: ' . $e->getMessage(), $e);
        }

        if (!$token instanceof UnencryptedToken) {
            throw new InvalidJwtException(InvalidJwtReason::Malformed, 'Encrypted tokens are not supported.');
        }

        if (!$config->validator()->validate($token, new SignedWith($config->signer(), $config->verificationKey()))) {
            throw new InvalidJwtException(InvalidJwtReason::SignatureMismatch, 'JWT signature does not match the public key.');
        }

        try {
            $config->validator()->assert($token, new LooseValidAt(SystemClock::fromUTC()));
        } catch (\Throwable $e) {
            throw new InvalidJwtException(InvalidJwtReason::Expired, 'JWT is expired or not yet valid.', $e);
        }

        $iss = $token->claims()->get('iss');
        if ($iss !== $this->issuer) {
            throw new InvalidJwtException(
                InvalidJwtReason::IssuerMismatch,
                sprintf('JWT issuer "%s" does not match expected "%s".', is_string($iss) ? $iss : '(non-string)', $this->issuer),
            );
        }

        $aud = $token->claims()->get('aud');
        $auds = $this->normalizeAudiences($aud);
        $allowed = $this->allowedResources->all();
        $matched = array_values(array_intersect($auds, $allowed));
        if ($matched === []) {
            throw new InvalidJwtException(
                InvalidJwtReason::AudienceMismatch,
                'JWT audience is not in the MCP allowed-resources list.',
            );
        }

        $kid = $token->headers()->get('kid');
        $expectedKid = $this->kidDeriver->derive();
        if ($kid !== $expectedKid) {
            throw new InvalidJwtException(
                InvalidJwtReason::KidMismatch,
                sprintf('JWT kid "%s" does not match expected "%s".', is_string($kid) ? $kid : '(missing)', $expectedKid),
            );
        }

        $jti = $token->claims()->get('jti');
        if (!is_string($jti) || $jti === '') {
            throw new InvalidJwtException(InvalidJwtReason::Malformed, 'JWT is missing a string jti claim.');
        }
        if ($this->accessTokens->isAccessTokenRevoked($jti)) {
            throw new InvalidJwtException(InvalidJwtReason::Revoked, 'JWT has been revoked.');
        }

        $sub = $token->claims()->get('sub');
        $clientId = $token->claims()->get('client_id');
        $scopeClaim = $token->claims()->get('scope');
        $scopes = is_string($scopeClaim) && $scopeClaim !== ''
            ? array_values(array_filter(explode(' ', $scopeClaim), static fn (string $s): bool => $s !== ''))
            : [];

        return new ValidatedToken(
            jti: $jti,
            sub: is_string($sub) ? $sub : null,
            clientId: is_string($clientId) ? $clientId : null,
            scopes: $scopes,
            audiences: $auds,
        );
    }

    /** @return list<string> */
    private function normalizeAudiences(mixed $claim): array
    {
        if (is_string($claim)) {
            return [$claim];
        }
        if (is_array($claim)) {
            return array_values(array_filter($claim, 'is_string'));
        }

        return [];
    }
}
