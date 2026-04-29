<?php

declare(strict_types=1);

namespace App\OAuth\Repository;

use App\OAuth\Entity\RefreshToken;
use Doctrine\ORM\EntityManagerInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;

final class RefreshTokenRepository implements RefreshTokenRepositoryInterface
{
    public function __construct(private readonly EntityManagerInterface $em)
    {
    }

    public function getNewRefreshToken(): ?RefreshTokenEntityInterface
    {
        // Phase B placeholder — replaced in Task C6 with the family-aware
        // RefreshToken entity. Tests construct RefreshToken rows directly
        // until then.
        throw new \LogicException('RefreshTokenRepository::getNewRefreshToken() is implemented in Phase C (Task C6).');
    }

    public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity): void
    {
        // Wired up in Task C6 alongside getNewRefreshToken().
        throw new \LogicException('RefreshTokenRepository::persistNewRefreshToken() is implemented in Phase C (Task C6).');
    }

    public function revokeRefreshToken(string $tokenId): void
    {
        $row = $this->em->find(RefreshToken::class, $tokenId);
        if ($row instanceof RefreshToken) {
            $row->revoke();
            $this->em->flush();
        }
    }

    public function isRefreshTokenRevoked(string $tokenId): bool
    {
        $row = $this->em->find(RefreshToken::class, $tokenId);
        return $row === null || $row->isRevoked();
    }
}
