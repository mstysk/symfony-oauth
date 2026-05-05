<?php

declare(strict_types=1);

namespace App\Tests\Controller\WellKnown;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

final class ProtectedResourceMetadataControllerTest extends WebTestCase
{
    public function test_authorization_server_byte_equals_as_metadata_issuer(): void
    {
        $client = self::createClient();

        $client->request('GET', '/.well-known/oauth-authorization-server');
        self::assertSame(200, $client->getResponse()->getStatusCode());
        $as = json_decode((string) $client->getResponse()->getContent(), associative: true);

        $client->request('GET', '/.well-known/oauth-protected-resource');
        self::assertSame(200, $client->getResponse()->getStatusCode());
        $prm = json_decode((string) $client->getResponse()->getContent(), associative: true);

        self::assertSame([$as['issuer']], $prm['authorization_servers']);
        self::assertSame(['mcp'], $prm['scopes_supported']);
        self::assertSame(['header'], $prm['bearer_methods_supported']);
        self::assertSame('http://localhost:8000/mcp', $prm['resource']);
    }
}
