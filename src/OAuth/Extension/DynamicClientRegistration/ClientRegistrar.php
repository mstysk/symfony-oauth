<?php

declare(strict_types=1);

namespace App\OAuth\Extension\DynamicClientRegistration;

use App\OAuth\Entity\Client;
use App\OAuth\Extension\RedirectUriNormalizer;
use App\OAuth\Repository\ClientRepository;
use Symfony\Component\Uid\Uuid;

/**
 * RFC 7591 §3.2.1 — process a validated DCR payload and persist the client.
 *
 * - validates via ClientMetadataValidator
 * - normalizes redirect_uris for storage (the response keeps the originals)
 * - issues a UUID v7 client_id and, when token_endpoint_auth_method != "none",
 *   a client_secret returned in plaintext exactly once
 */
final class ClientRegistrar
{
    public function __construct(
        private readonly ClientMetadataValidator $validator,
        private readonly ClientRepository $clientRepository,
    ) {
    }

    /**
     * @param array<string, mixed> $metadata
     *
     * @return array<string, mixed>
     */
    public function register(array $metadata): array
    {
        $this->validator->validate($metadata);

        /** @var string[] $originalUris */
        $originalUris = $metadata['redirect_uris'];
        $normalizedUris = array_values(array_map(
            static fn (string $uri): string => RedirectUriNormalizer::normalize($uri),
            $originalUris,
        ));

        $authMethod = (string) ($metadata['token_endpoint_auth_method'] ?? 'client_secret_basic');
        $isPublic = $authMethod === 'none';

        $clientSecret = null;
        $secretHash = null;
        if (!$isPublic) {
            $clientSecret = bin2hex(random_bytes(32));
            $secretHash = password_hash($clientSecret, PASSWORD_BCRYPT);
        }

        $clientId = Uuid::v7();

        $client = new Client(
            id: $clientId,
            name: (string) ($metadata['client_name'] ?? 'unnamed'),
            secretHash: $secretHash,
            redirectUris: $normalizedUris,
            grantTypes: $metadata['grant_types'] ?? ['authorization_code'],
            scopes: ['mcp'],
            dcrMetadata: $metadata,
        );

        $this->clientRepository->save($client);

        $response = [
            'client_id' => $clientId->toRfc4122(),
            'client_name' => $client->getName(),
            'redirect_uris' => $originalUris,
            'grant_types' => $client->getGrantTypes(),
            'token_endpoint_auth_method' => $authMethod,
        ];
        if ($clientSecret !== null) {
            $response['client_secret'] = $clientSecret;
        }

        return $response;
    }
}
