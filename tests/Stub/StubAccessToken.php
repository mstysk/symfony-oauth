<?php

declare(strict_types=1);

namespace App\Tests\Stub;

use League\OAuth2\Server\CryptKeyInterface;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;

/**
 * Minimal AccessTokenEntityInterface stub for tests that only need the
 * identifier (e.g. RefreshTokenRepository persistNewRefreshToken).
 */
final class StubAccessToken implements AccessTokenEntityInterface
{
    public function __construct(private readonly string $identifier)
    {
    }

    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    public function setIdentifier(string $identifier): void
    {
    }

    public function getExpiryDateTime(): \DateTimeImmutable
    {
        return new \DateTimeImmutable('+1 hour');
    }

    public function setExpiryDateTime(\DateTimeImmutable $dateTime): void
    {
    }

    public function setUserIdentifier(string $identifier): void
    {
    }

    public function getUserIdentifier(): ?string
    {
        return null;
    }

    public function getClient(): ClientEntityInterface
    {
        throw new \LogicException('not implemented');
    }

    public function setClient(ClientEntityInterface $client): void
    {
    }

    public function addScope(ScopeEntityInterface $scope): void
    {
    }

    /** @return ScopeEntityInterface[] */
    public function getScopes(): array
    {
        return [];
    }

    public function setPrivateKey(CryptKeyInterface $privateKey): void
    {
    }

    public function toString(): string
    {
        return '';
    }
}
