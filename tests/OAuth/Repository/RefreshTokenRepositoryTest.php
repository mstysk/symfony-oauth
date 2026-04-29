<?php

declare(strict_types=1);

namespace App\Tests\OAuth\Repository;

use App\OAuth\Entity\RefreshToken;
use App\OAuth\Repository\RefreshTokenRepository;
use App\Tests\OAuth\Support\DoctrineKernelTestCase;
use Symfony\Component\Uid\Uuid;

final class RefreshTokenRepositoryTest extends DoctrineKernelTestCase
{
    public function test_persist_and_revoke_round_trip(): void
    {
        /** @var RefreshTokenRepository $repo */
        $repo = self::getContainer()->get(RefreshTokenRepository::class);

        $row = new RefreshToken(
            identifier: 'rt-1',
            accessTokenId: 'jti-1',
            familyId: Uuid::v7(),
            expiresAt: new \DateTimeImmutable('+30 days'),
        );
        $this->em->persist($row);
        $this->em->flush();

        self::assertFalse($repo->isRefreshTokenRevoked('rt-1'));
        $repo->revokeRefreshToken('rt-1');
        self::assertTrue($repo->isRefreshTokenRevoked('rt-1'));
    }
}
