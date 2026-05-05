<?php

declare(strict_types=1);

namespace App\OAuth\Entity;

use Doctrine\ORM\Mapping as ORM;
use Symfony\Component\Uid\Uuid;

#[ORM\Entity]
#[ORM\Table(name: 'oauth_refresh_tokens')]
class RefreshToken
{
    #[ORM\Id]
    #[ORM\Column(type: 'string', length: 191)]
    private string $identifier;

    #[ORM\Column(type: 'string', length: 191)]
    private string $accessTokenId;

    #[ORM\Column(type: 'uuid')]
    private Uuid $familyId;

    #[ORM\Column(type: 'datetime_immutable')]
    private \DateTimeImmutable $expiresAt;

    #[ORM\Column(type: 'boolean')]
    private bool $revoked = false;

    public function __construct(
        string $identifier,
        string $accessTokenId,
        Uuid $familyId,
        \DateTimeImmutable $expiresAt,
    ) {
        $this->identifier = $identifier;
        $this->accessTokenId = $accessTokenId;
        $this->familyId = $familyId;
        $this->expiresAt = $expiresAt;
    }

    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    public function getAccessTokenId(): string
    {
        return $this->accessTokenId;
    }

    public function getFamilyId(): Uuid
    {
        return $this->familyId;
    }

    public function getExpiresAt(): \DateTimeImmutable
    {
        return $this->expiresAt;
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
