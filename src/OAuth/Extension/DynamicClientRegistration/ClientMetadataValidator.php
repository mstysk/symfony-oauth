<?php

declare(strict_types=1);

namespace App\OAuth\Extension\DynamicClientRegistration;

use League\OAuth2\Server\Exception\OAuthServerException;

/**
 * RFC 7591 §3.2.2 — validate client metadata at the registration endpoint.
 * On any violation, throws OAuthServerException with the appropriate error
 * code (invalid_redirect_uri or invalid_client_metadata).
 *
 * Phase 1 supports only authorization_code + refresh_token grants and
 * restricts redirect_uris to a host allowlist (localhost / 127.0.0.1).
 */
final class ClientMetadataValidator
{
    private const SUPPORTED_GRANT_TYPES = ['authorization_code', 'refresh_token'];

    /** @param string[] $allowedHosts */
    public function __construct(private readonly array $allowedHosts)
    {
    }

    /**
     * @param array<string, mixed> $metadata
     *
     * @throws OAuthServerException
     */
    public function validate(array $metadata): void
    {
        if (!isset($metadata['redirect_uris']) || !\is_array($metadata['redirect_uris']) || $metadata['redirect_uris'] === []) {
            throw $this->invalidClientMetadata('redirect_uris', 'redirect_uris is required and must be a non-empty array');
        }

        foreach ($metadata['redirect_uris'] as $uri) {
            if (!\is_string($uri)) {
                throw $this->invalidRedirectUri('redirect_uri entries must be strings');
            }
            $this->validateRedirectUri($uri);
        }

        $grantTypes = $metadata['grant_types'] ?? ['authorization_code'];
        if (!\is_array($grantTypes)) {
            throw $this->invalidClientMetadata('grant_types', 'grant_types must be an array');
        }

        foreach ($grantTypes as $grant) {
            if (!\in_array($grant, self::SUPPORTED_GRANT_TYPES, true)) {
                throw $this->invalidClientMetadata(
                    'grant_types',
                    sprintf('grant_type "%s" is not supported', \is_string($grant) ? $grant : '?'),
                );
            }
        }
    }

    private function validateRedirectUri(string $uri): void
    {
        $parts = parse_url($uri);
        if ($parts === false || !isset($parts['scheme'], $parts['host'])) {
            throw $this->invalidRedirectUri('redirect_uri must be a valid absolute URI: ' . $uri);
        }

        $scheme = strtolower($parts['scheme']);
        if (!\in_array($scheme, ['http', 'https'], true)) {
            throw $this->invalidRedirectUri('redirect_uri scheme must be http or https: ' . $uri);
        }

        $host = strtolower($parts['host']);
        if (!\in_array($host, $this->allowedHosts, true)) {
            throw $this->invalidRedirectUri(sprintf(
                'redirect_uri host "%s" is not in the allowlist',
                $host,
            ));
        }
    }

    private function invalidRedirectUri(string $hint): OAuthServerException
    {
        // RFC 7591 §3.2.2 — "invalid_redirect_uri".
        return new OAuthServerException(
            'One or more redirect_uri values are invalid',
            9,
            'invalid_redirect_uri',
            400,
            $hint,
        );
    }

    private function invalidClientMetadata(string $field, string $hint): OAuthServerException
    {
        // RFC 7591 §3.2.2 — "invalid_client_metadata".
        return new OAuthServerException(
            sprintf('Client metadata field "%s" is invalid', $field),
            10,
            'invalid_client_metadata',
            400,
            $hint,
        );
    }
}
