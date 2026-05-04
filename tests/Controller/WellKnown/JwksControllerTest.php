<?php

declare(strict_types=1);

namespace App\Tests\Controller\WellKnown;

use App\OAuth\Extension\KidDeriver;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

final class JwksControllerTest extends WebTestCase
{
    public function test_returns_jwks_with_rs256_key_and_matching_kid(): void
    {
        $client = self::createClient();
        $client->request('GET', '/.well-known/jwks.json');

        self::assertSame(200, $client->getResponse()->getStatusCode());

        $payload = json_decode((string) $client->getResponse()->getContent(), associative: true);
        self::assertCount(1, $payload['keys']);

        $key = $payload['keys'][0];
        self::assertSame('RSA', $key['kty']);
        self::assertSame('sig', $key['use']);
        self::assertSame('RS256', $key['alg']);
        self::assertNotEmpty($key['kid']);
        self::assertNotEmpty($key['n']);
        self::assertNotEmpty($key['e']);

        // kid agrees with what KidDeriver produces from the same public key.
        $kidDeriver = self::getContainer()->get(KidDeriver::class);
        self::assertSame($kidDeriver->derive(), $key['kid']);
    }
}
