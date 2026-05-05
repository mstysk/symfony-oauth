<?php

declare(strict_types=1);

namespace App\Tests\Controller\WellKnown;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

final class AuthorizationServerMetadataControllerTest extends WebTestCase
{
    public function test_returns_rfc_8414_metadata_json(): void
    {
        $client = self::createClient();
        $client->request('GET', '/.well-known/oauth-authorization-server');

        self::assertSame(200, $client->getResponse()->getStatusCode());
        self::assertSame(
            'application/json',
            explode(';', (string) $client->getResponse()->headers->get('Content-Type'))[0],
        );

        $payload = json_decode((string) $client->getResponse()->getContent(), associative: true);
        self::assertIsArray($payload);
        self::assertSame('http://localhost:8000', $payload['issuer']);
        self::assertSame('http://localhost:8000/oauth/authorize', $payload['authorization_endpoint']);
        self::assertSame(['S256'], $payload['code_challenge_methods_supported']);
    }
}
