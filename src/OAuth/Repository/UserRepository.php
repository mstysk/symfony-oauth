<?php

declare(strict_types=1);

namespace App\OAuth\Repository;

use App\OAuth\Entity\User;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

final class UserRepository implements UserRepositoryInterface
{
    public function __construct(private readonly UserProviderInterface $provider)
    {
    }

    public function getUserEntityByUserCredentials(
        string $username,
        string $password,
        string $grantType,
        ClientEntityInterface $clientEntity,
    ): ?UserEntityInterface {
        try {
            $user = $this->provider->loadUserByIdentifier($username);
        } catch (UserNotFoundException) {
            return null;
        }

        if ($user instanceof PasswordAuthenticatedUserInterface
            && password_verify($password, (string) $user->getPassword())
        ) {
            return new User($user->getUserIdentifier());
        }

        return null;
    }
}
