<?php

declare(strict_types=1);

namespace App\OAuth\Repository;

use App\OAuth\Entity\AccessToken;
use Doctrine\ORM\EntityManagerInterface;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;

final class AccessTokenRepository implements AccessTokenRepositoryInterface
{
    public function __construct(private readonly EntityManagerInterface $em)
    {
    }

    /**
     * @param ScopeEntityInterface[] $scopes
     */
    public function getNewToken(
        ClientEntityInterface $clientEntity,
        array $scopes,
        ?string $userIdentifier = null,
    ): AccessTokenEntityInterface {
        // Phase B placeholder — replaced in Task C4 with McpAccessTokenEntity.
        throw new \LogicException('AccessTokenRepository::getNewToken() is implemented in Phase C (Task C4).');
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
