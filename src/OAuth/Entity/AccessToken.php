<?php

declare(strict_types=1);

namespace App\OAuth\Entity;

use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
#[ORM\Table(name: 'oauth_access_tokens')]
class AccessToken
{
    #[ORM\Id]
    #[ORM\Column(type: 'string', length: 191)]
    private string $identifier;

    #[ORM\Column(type: 'string', length: 191)]
    private string $clientId;

    #[ORM\Column(type: 'string', length: 191, nullable: true)]
    private ?string $userId;

    #[ORM\Column(type: 'datetime_immutable')]
    private \DateTimeImmutable $expiresAt;

    /** @var string[] */
    #[ORM\Column(type: 'json')]
    private array $scopes;

    /** @var string[] */
    #[ORM\Column(type: 'json')]
    private array $audience;

    #[ORM\Column(type: 'boolean')]
    private bool $revoked = false;

    /**
     * @param string[] $scopes
     * @param string[] $audience
     */
    public function __construct(
        string $identifier,
        string $clientId,
        ?string $userId,
        \DateTimeImmutable $expiresAt,
        array $scopes,
        array $audience,
    ) {
        $this->identifier = $identifier;
        $this->clientId = $clientId;
        $this->userId = $userId;
        $this->expiresAt = $expiresAt;
        $this->scopes = $scopes;
        $this->audience = $audience;
    }

    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    public function getClientId(): string
    {
        return $this->clientId;
    }

    public function getUserId(): ?string
    {
        return $this->userId;
    }

    public function getExpiresAt(): \DateTimeImmutable
    {
        return $this->expiresAt;
    }

    /** @return string[] */
    public function getScopes(): array
    {
        return $this->scopes;
    }

    /** @return string[] */
    public function getAudience(): array
    {
        return $this->audience;
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
