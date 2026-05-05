<?php

declare(strict_types=1);

namespace App\Tests\OAuth\Entity;

use App\OAuth\Entity\Client;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class ClientTest extends TestCase
{
    public function test_constructed_client_exposes_identifier_and_redirect_uris(): void
    {
        $id = Uuid::v7();
        $client = new Client(
            id: $id,
            name: 'demo',
            secretHash: null,
            redirectUris: ['http://localhost:8000/cb'],
            grantTypes: ['authorization_code', 'refresh_token'],
            scopes: ['mcp'],
            dcrMetadata: ['client_name' => 'demo'],
        );

        self::assertSame($id->toRfc4122(), $client->getIdentifier());
        self::assertSame(['http://localhost:8000/cb'], $client->getRedirectUri());
        self::assertFalse($client->isConfidential());
        self::assertSame('demo', $client->getName());
    }

    public function test_confidential_client_has_secret(): void
    {
        $client = new Client(
            id: Uuid::v7(),
            name: 'srv',
            secretHash: password_hash('s3cret', PASSWORD_BCRYPT),
            redirectUris: ['https://example.com/cb'],
            grantTypes: ['authorization_code', 'refresh_token'],
            scopes: ['mcp'],
            dcrMetadata: [],
        );

        self::assertTrue($client->isConfidential());
        self::assertTrue(password_verify('s3cret', $client->getSecretHash()));
    }
}
