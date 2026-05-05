<?php

declare(strict_types=1);

namespace App\OAuth\Entity;

use Doctrine\ORM\Mapping as ORM;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use Symfony\Component\Uid\Uuid;

#[ORM\Entity]
#[ORM\Table(name: 'oauth_clients')]
class Client implements ClientEntityInterface
{
    #[ORM\Id]
    #[ORM\Column(type: 'uuid')]
    private Uuid $id;

    #[ORM\Column(type: 'string', length: 191, unique: true)]
    private string $clientIdentifier;

    #[ORM\Column(type: 'string', length: 191)]
    private string $clientName;

    #[ORM\Column(type: 'string', length: 255, nullable: true)]
    private ?string $secretHash;

    #[ORM\Column(type: 'boolean')]
    private bool $confidential;

    /** @var string[] */
    #[ORM\Column(type: 'json')]
    private array $redirectUris;

    /** @var string[] */
    #[ORM\Column(type: 'json')]
    private array $grantTypes;

    /** @var string[] */
    #[ORM\Column(type: 'json')]
    private array $scopesAllowed;

    /** @var array<string, mixed> */
    #[ORM\Column(type: 'json')]
    private array $dcrMetadata;

    #[ORM\Column(type: 'datetime_immutable')]
    private \DateTimeImmutable $createdAt;

    /**
     * @param string[] $redirectUris  normalized
     * @param string[] $grantTypes
     * @param string[] $scopes
     * @param array<string, mixed> $dcrMetadata
     */
    public function __construct(
        Uuid $id,
        string $name,
        ?string $secretHash,
        array $redirectUris,
        array $grantTypes,
        array $scopes,
        array $dcrMetadata,
        ?\DateTimeImmutable $createdAt = null,
    ) {
        $this->id = $id;
        $this->clientIdentifier = $id->toRfc4122();
        $this->clientName = $name;
        $this->secretHash = $secretHash;
        $this->confidential = $secretHash !== null;
        $this->redirectUris = $redirectUris;
        $this->grantTypes = $grantTypes;
        $this->scopesAllowed = $scopes;
        $this->dcrMetadata = $dcrMetadata;
        $this->createdAt = $createdAt ?? new \DateTimeImmutable();
    }

    // --- ClientEntityInterface ---
    public function getIdentifier(): string
    {
        return $this->clientIdentifier;
    }

    public function getName(): string
    {
        return $this->clientName;
    }

    /** @return string[] */
    public function getRedirectUri(): array
    {
        return $this->redirectUris;
    }

    public function isConfidential(): bool
    {
        return $this->confidential;
    }

    // --- App-side accessors ---
    public function getId(): Uuid
    {
        return $this->id;
    }

    public function getSecretHash(): ?string
    {
        return $this->secretHash;
    }

    /** @return string[] */
    public function getGrantTypes(): array
    {
        return $this->grantTypes;
    }

    /** @return string[] */
    public function getScopesAllowed(): array
    {
        return $this->scopesAllowed;
    }

    /** @return array<string, mixed> */
    public function getDcrMetadata(): array
    {
        return $this->dcrMetadata;
    }

    public function getCreatedAt(): \DateTimeImmutable
    {
        return $this->createdAt;
    }
}
