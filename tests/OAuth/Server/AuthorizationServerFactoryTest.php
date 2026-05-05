<?php

declare(strict_types=1);

namespace App\Tests\OAuth\Server;

use App\OAuth\Server\AuthorizationServerFactory;
use App\Tests\OAuth\Support\DoctrineKernelTestCase;
use League\OAuth2\Server\AuthorizationServer;

final class AuthorizationServerFactoryTest extends DoctrineKernelTestCase
{
    public function test_creates_a_usable_authorization_server(): void
    {
        /** @var AuthorizationServerFactory $factory */
        $factory = self::getContainer()->get(AuthorizationServerFactory::class);

        $server = $factory->create();

        self::assertInstanceOf(AuthorizationServer::class, $server);
    }

    public function test_factory_can_be_called_repeatedly(): void
    {
        /** @var AuthorizationServerFactory $factory */
        $factory = self::getContainer()->get(AuthorizationServerFactory::class);

        $first = $factory->create();
        $second = $factory->create();

        self::assertNotSame($first, $second, 'Each create() returns a fresh AuthorizationServer instance');
    }
}
