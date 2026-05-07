<?php

declare(strict_types=1);

namespace App\Security;

/**
 * Result of JwtAccessTokenValidator::validate(). Carries the claims the
 * MCP controller needs after the security firewall accepts the request:
 *  - jti: the access-token identifier (used as the security username),
 *  - sub: the resource-owner identifier (Symfony user identifier),
 *  - clientId: the OAuth client_id that was issued the token,
 *  - scopes: space-separated `scope` claim split into a list,
 *  - audiences: the JWT `aud` claim normalized to a string list.
 */
final class ValidatedToken
{
    /**
     * @param list<string> $scopes
     * @param list<string> $audiences
     */
    public function __construct(
        public readonly string $jti,
        public readonly ?string $sub,
        public readonly ?string $clientId,
        public readonly array $scopes,
        public readonly array $audiences,
    ) {
    }

    public function hasScope(string $scope): bool
    {
        return in_array($scope, $this->scopes, true);
    }
}
