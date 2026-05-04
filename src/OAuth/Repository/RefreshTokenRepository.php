<?php

declare(strict_types=1);

namespace App\OAuth\Repository;

use App\OAuth\Entity\RefreshToken;
use App\OAuth\Extension\SimpleRefreshTokenEntity;
use Doctrine\ORM\EntityManagerInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use Symfony\Component\Uid\Uuid;

final class RefreshTokenRepository implements RefreshTokenRepositoryInterface
{
    public function __construct(private readonly EntityManagerInterface $em)
    {
    }

    public function getNewRefreshToken(): ?RefreshTokenEntityInterface
    {
        return new SimpleRefreshTokenEntity();
    }

    public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity): void
    {
        if (!$refreshTokenEntity instanceof SimpleRefreshTokenEntity) {
            throw new \LogicException(sprintf(
                'Unexpected refresh token entity %s; expected %s.',
                $refreshTokenEntity::class,
                SimpleRefreshTokenEntity::class,
            ));
        }

        $row = new RefreshToken(
            identifier: $refreshTokenEntity->getIdentifier(),
            accessTokenId: $refreshTokenEntity->getAccessToken()->getIdentifier(),
            familyId: $refreshTokenEntity->getFamilyId() ?? Uuid::v7(),
            expiresAt: $refreshTokenEntity->getExpiryDateTime(),
        );

        $this->em->persist($row);
        $this->em->flush();
    }

    public function revokeRefreshToken(string $tokenId): void
    {
        $row = $this->em->find(RefreshToken::class, $tokenId);
        if (!$row instanceof RefreshToken) {
            return;
        }

        if ($row->isRevoked()) {
            // RFC 9700 §4.14 — re-use detected. Revoke the entire family.
            $this->revokeFamily($row->getFamilyId());

            return;
        }

        $row->revoke();
        $this->em->flush();
    }

    public function isRefreshTokenRevoked(string $tokenId): bool
    {
        $row = $this->em->find(RefreshToken::class, $tokenId);

        return $row === null || $row->isRevoked();
    }

    private function revokeFamily(Uuid $familyId): void
    {
        $rows = $this->em->getRepository(RefreshToken::class)->findBy([
            'familyId' => $familyId,
        ]);
        $changed = false;
        foreach ($rows as $row) {
            if (!$row->isRevoked()) {
                $row->revoke();
                $changed = true;
            }
        }
        if ($changed) {
            $this->em->flush();
        }
    }
}
