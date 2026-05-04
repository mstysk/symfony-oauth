<?php

declare(strict_types=1);

namespace App\OAuth\Extension;

final class ServerMetadataBuilder
{
    public function __construct(private readonly string $issuer)
    {
    }

    /** @return array<string, mixed> */
    public function build(): array
    {
        $base = rtrim($this->issuer, '/');

        return [
            'issuer' => $this->issuer,
            'authorization_endpoint' => $base . '/oauth/authorize',
            'token_endpoint' => $base . '/oauth/token',
            'registration_endpoint' => $base . '/oauth/register',
            'jwks_uri' => $base . '/.well-known/jwks.json',
            'response_types_supported' => ['code'],
            'grant_types_supported' => ['authorization_code', 'refresh_token'],
            'code_challenge_methods_supported' => ['S256'],
            'token_endpoint_auth_methods_supported' => ['client_secret_basic', 'none'],
            'scopes_supported' => ['mcp'],
        ];
    }
}
