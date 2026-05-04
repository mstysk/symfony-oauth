<?php

declare(strict_types=1);

namespace App\Tests\OAuth\Extension\DynamicClientRegistration;

use App\OAuth\Entity\Client;
use App\OAuth\Extension\DynamicClientRegistration\ClientRegistrar;
use App\Tests\OAuth\Support\DoctrineKernelTestCase;
use Symfony\Component\Uid\Uuid;

final class ClientRegistrarTest extends DoctrineKernelTestCase
{
    public function test_registers_public_client_and_keeps_original_redirect_uris_in_response(): void
    {
        /** @var ClientRegistrar $registrar */
        $registrar = self::getContainer()->get(ClientRegistrar::class);

        // Mixed-case host on input — response keeps it verbatim, DB row stores
        // the normalized lowercase form.
        $input = [
            'client_name' => 'demo',
            'redirect_uris' => ['HTTP://Localhost:9000/Cb'],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'token_endpoint_auth_method' => 'none',
        ];

        $response = $registrar->register($input);

        self::assertSame(['HTTP://Localhost:9000/Cb'], $response['redirect_uris']);
        self::assertArrayNotHasKey('client_secret', $response);
        self::assertNotEmpty($response['client_id']);

        $row = $this->em->getRepository(Client::class)->findOneBy([
            'clientIdentifier' => $response['client_id'],
        ]);
        self::assertInstanceOf(Client::class, $row);
        self::assertFalse($row->isConfidential());
        self::assertSame(['http://localhost:9000/Cb'], $row->getRedirectUri());

        // client_id is a parseable UUID (v7).
        self::assertTrue(Uuid::isValid($response['client_id']));
    }

    public function test_registers_confidential_client_returns_secret_once(): void
    {
        /** @var ClientRegistrar $registrar */
        $registrar = self::getContainer()->get(ClientRegistrar::class);

        $response = $registrar->register([
            'client_name' => 'srv',
            'redirect_uris' => ['https://localhost/cb'],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'token_endpoint_auth_method' => 'client_secret_basic',
        ]);

        self::assertNotEmpty($response['client_secret']);

        $row = $this->em->getRepository(Client::class)->findOneBy([
            'clientIdentifier' => $response['client_id'],
        ]);
        self::assertInstanceOf(Client::class, $row);
        self::assertTrue($row->isConfidential());
        self::assertTrue(password_verify($response['client_secret'], (string) $row->getSecretHash()));
    }
}
