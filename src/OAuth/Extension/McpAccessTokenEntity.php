<?php

declare(strict_types=1);

namespace App\OAuth\Extension;

use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use League\OAuth2\Server\CryptKeyInterface;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;

final class McpAccessTokenEntity implements AccessTokenEntityInterface
{
    private string $identifier = '';
    private \DateTimeImmutable $expiryDateTime;
    private CryptKeyInterface $privateKey;
    private ClientEntityInterface $client;
    private ?string $userIdentifier = null;
    /** @var ScopeEntityInterface[] */
    private array $scopes = [];
    /** @var string[] */
    private array $audiences = [];
    private ?string $rendered = null;

    public function __construct(
        private readonly string $issuer,
        private readonly KidDeriver $kidDeriver,
        private readonly string $publicKeyPath,
    ) {
    }

    public function setPrivateKey(CryptKeyInterface $privateKey): void
    {
        $this->privateKey = $privateKey;
    }

    public function setClient(ClientEntityInterface $client): void
    {
        $this->client = $client;
    }

    public function getClient(): ClientEntityInterface
    {
        return $this->client;
    }

    public function setUserIdentifier(string $identifier): void
    {
        $this->userIdentifier = $identifier;
    }

    public function getUserIdentifier(): ?string
    {
        return $this->userIdentifier;
    }

    public function addScope(ScopeEntityInterface $scope): void
    {
        $this->scopes[] = $scope;
    }

    /** @return ScopeEntityInterface[] */
    public function getScopes(): array
    {
        return $this->scopes;
    }

    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    public function setIdentifier(string $identifier): void
    {
        $this->identifier = $identifier;
    }

    public function getExpiryDateTime(): \DateTimeImmutable
    {
        return $this->expiryDateTime;
    }

    public function setExpiryDateTime(\DateTimeImmutable $dateTime): void
    {
        $this->expiryDateTime = $dateTime;
    }

    /** @param string[] $audiences */
    public function setAudiences(array $audiences): void
    {
        $this->audiences = $audiences;
    }

    /** @return string[] */
    public function getAudiences(): array
    {
        return $this->audiences;
    }

    public function toString(): string
    {
        if ($this->rendered !== null) {
            return $this->rendered;
        }

        $signingKey = InMemory::file(
            $this->privateKey->getKeyPath(),
            $this->privateKey->getPassPhrase() ?? '',
        );
        $verificationKey = InMemory::file($this->publicKeyPath);

        $config = Configuration::forAsymmetricSigner(new Sha256(), $signingKey, $verificationKey);

        $now = new \DateTimeImmutable();
        $builder = $config->builder()
            ->withHeader('kid', $this->kidDeriver->derive())
            ->issuedBy($this->issuer)
            ->identifiedBy($this->identifier)
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($now)
            ->expiresAt($this->expiryDateTime)
            ->withClaim('client_id', $this->client->getIdentifier())
            ->withClaim('scope', implode(' ', array_map(
                static fn (ScopeEntityInterface $s): string => $s->getIdentifier(),
                $this->scopes,
            )));

        if ($this->userIdentifier !== null) {
            $builder = $builder->relatedTo($this->userIdentifier);
        }
        if ($this->audiences !== []) {
            $builder = $builder->permittedFor(...$this->audiences);
        }

        return $this->rendered = $builder
            ->getToken($config->signer(), $config->signingKey())
            ->toString();
    }

    public function __toString(): string
    {
        return $this->toString();
    }
}
