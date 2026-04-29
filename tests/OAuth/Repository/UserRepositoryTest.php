<?php

declare(strict_types=1);

namespace App\Tests\OAuth\Repository;

use App\OAuth\Repository\UserRepository;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Core\User\UserProviderInterface;

final class UserRepositoryTest extends TestCase
{
    public function test_returns_user_entity_when_password_matches(): void
    {
        $hash = password_hash('pw', PASSWORD_BCRYPT);
        $provider = $this->createStub(UserProviderInterface::class);
        $provider->method('loadUserByIdentifier')->willReturnCallback(
            fn (string $id) => $id === 'alice'
                ? new InMemoryUser('alice', $hash)
                : throw new UserNotFoundException(),
        );

        $repo = new UserRepository($provider);

        $entity = $repo->getUserEntityByUserCredentials(
            'alice',
            'pw',
            'authorization_code',
            $this->createStub(ClientEntityInterface::class),
        );

        self::assertNotNull($entity);
        self::assertSame('alice', $entity->getIdentifier());
    }

    public function test_returns_null_for_unknown_user(): void
    {
        $provider = $this->createStub(UserProviderInterface::class);
        $provider->method('loadUserByIdentifier')->willThrowException(new UserNotFoundException());

        $repo = new UserRepository($provider);

        self::assertNull($repo->getUserEntityByUserCredentials(
            'ghost',
            'pw',
            'authorization_code',
            $this->createStub(ClientEntityInterface::class),
        ));
    }
}
