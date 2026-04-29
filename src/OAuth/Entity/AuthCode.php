<?php

declare(strict_types=1);

namespace App\OAuth\Entity;

use Doctrine\ORM\Mapping as ORM;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;

#[ORM\Entity]
#[ORM\Table(name: 'oauth_auth_codes')]
class AuthCode implements AuthCodeEntityInterface
{
    #[ORM\Id]
    #[ORM\Column(type: 'string', length: 191)]
    private string $identifier;

    #[ORM\Column(type: 'string', length: 191)]
    private string $clientId;

    #[ORM\Column(type: 'string', length: 191, nullable: true)]
    private ?string $userId = null;

    #[ORM\Column(type: 'datetime_immutable')]
    private \DateTimeImmutable $expiryDateTime;

    /** @var string[] */
    #[ORM\Column(type: 'json')]
    private array $scopeIds = [];

    #[ORM\Column(type: 'string', length: 2048, nullable: true)]
    private ?string $redirectUri = null;

    #[ORM\Column(type: 'string', length: 255, nullable: true)]
    private ?string $codeChallenge = null;

    #[ORM\Column(type: 'string', length: 16, nullable: true)]
    private ?string $codeChallengeMethod = null;

    #[ORM\Column(type: 'string', length: 2048, nullable: true)]
    private ?string $resource = null;

    #[ORM\Column(type: 'boolean')]
    private bool $revoked = false;

    /** Runtime references (not persisted directly). */
    private ?ClientEntityInterface $client = null;
    /** @var ScopeEntityInterface[] */
    private array $scopes = [];

    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    public function setIdentifier(string $identifier): void
    {
        $this->identifier = $identifier;
    }

    public function getClient(): ClientEntityInterface
    {
        if ($this->client === null) {
            throw new \LogicException('Client must be hydrated via setClient() before access.');
        }
        return $this->client;
    }

    public function setClient(ClientEntityInterface $client): void
    {
        $this->client = $client;
        $this->clientId = $client->getIdentifier();
    }

    public function getClientId(): string
    {
        return $this->clientId;
    }

    /** @return ScopeEntityInterface[] */
    public function getScopes(): array
    {
        return $this->scopes;
    }

    public function addScope(ScopeEntityInterface $scope): void
    {
        $this->scopes[] = $scope;
        $this->scopeIds[] = $scope->getIdentifier();
        $this->scopeIds = array_values(array_unique($this->scopeIds));
    }

    /** @return string[] */
    public function getScopeIds(): array
    {
        return $this->scopeIds;
    }

    public function getExpiryDateTime(): \DateTimeImmutable
    {
        return $this->expiryDateTime;
    }

    public function setExpiryDateTime(\DateTimeImmutable $dateTime): void
    {
        $this->expiryDateTime = $dateTime;
    }

    public function getUserIdentifier(): ?string
    {
        return $this->userId;
    }

    public function setUserIdentifier(string $identifier): void
    {
        $this->userId = $identifier;
    }

    public function getRedirectUri(): ?string
    {
        return $this->redirectUri;
    }

    public function setRedirectUri(string $uri): void
    {
        $this->redirectUri = $uri;
    }

    public function getCodeChallenge(): ?string
    {
        return $this->codeChallenge;
    }

    public function setCodeChallenge(?string $codeChallenge): void
    {
        $this->codeChallenge = $codeChallenge;
    }

    public function getCodeChallengeMethod(): ?string
    {
        return $this->codeChallengeMethod;
    }

    public function setCodeChallengeMethod(?string $method): void
    {
        $this->codeChallengeMethod = $method;
    }

    public function getResource(): ?string
    {
        return $this->resource;
    }

    public function setResource(?string $resource): void
    {
        $this->resource = $resource;
    }

    public function isRevoked(): bool
    {
        return $this->revoked;
    }

    public function revoke(): void
    {
        $this->revoked = true;
    }
}
