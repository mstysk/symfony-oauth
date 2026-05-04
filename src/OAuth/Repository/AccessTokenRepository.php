<?php

declare(strict_types=1);

namespace App\OAuth\Repository;

use App\OAuth\Entity\AccessToken;
use App\OAuth\Extension\KidDeriver;
use App\OAuth\Extension\McpAccessTokenEntity;
use Doctrine\ORM\EntityManagerInterface;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;

final class AccessTokenRepository implements AccessTokenRepositoryInterface
{
    public function __construct(
        private readonly EntityManagerInterface $em,
        private readonly string $issuer,
        private readonly KidDeriver $kidDeriver,
        private readonly string $publicKeyPath,
    ) {
    }

    /**
     * @param ScopeEntityInterface[] $scopes
     */
    public function getNewToken(
        ClientEntityInterface $clientEntity,
        array $scopes,
        ?string $userIdentifier = null,
    ): AccessTokenEntityInterface {
        $token = new McpAccessTokenEntity($this->issuer, $this->kidDeriver, $this->publicKeyPath);
        $token->setClient($clientEntity);
        foreach ($scopes as $scope) {
            $token->addScope($scope);
        }
        if ($userIdentifier !== null) {
            $token->setUserIdentifier((string) $userIdentifier);
        }

        return $token;
    }

    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity): void
    {
        $row = new AccessToken(
            identifier: $accessTokenEntity->getIdentifier(),
            clientId: $accessTokenEntity->getClient()->getIdentifier(),
            userId: $accessTokenEntity->getUserIdentifier() === null
                ? null
                : (string) $accessTokenEntity->getUserIdentifier(),
            expiresAt: $accessTokenEntity->getExpiryDateTime(),
            scopes: array_map(
                static fn (ScopeEntityInterface $s): string => $s->getIdentifier(),
                $accessTokenEntity->getScopes(),
            ),
            audience: method_exists($accessTokenEntity, 'getAudiences')
                ? $accessTokenEntity->getAudiences()
                : [],
        );

        $this->em->persist($row);
        $this->em->flush();
    }

    public function revokeAccessToken(string $tokenId): void
    {
        $row = $this->em->find(AccessToken::class, $tokenId);
        if ($row instanceof AccessToken) {
            $row->revoke();
            $this->em->flush();
        }
    }

    public function isAccessTokenRevoked(string $tokenId): bool
    {
        $row = $this->em->find(AccessToken::class, $tokenId);
        return $row === null || $row->isRevoked();
    }
}
