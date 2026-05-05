<?php

declare(strict_types=1);

namespace App\Tests\OAuth\Repository;

use App\OAuth\Entity\RefreshToken;
use App\OAuth\Extension\SimpleRefreshTokenEntity;
use App\OAuth\Repository\RefreshTokenRepository;
use App\Tests\OAuth\Support\DoctrineKernelTestCase;
use App\Tests\Stub\StubAccessToken;
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

    public function test_get_new_refresh_token_returns_simple_entity(): void
    {
        /** @var RefreshTokenRepository $repo */
        $repo = self::getContainer()->get(RefreshTokenRepository::class);

        $entity = $repo->getNewRefreshToken();

        self::assertInstanceOf(SimpleRefreshTokenEntity::class, $entity);
    }

    public function test_persist_new_refresh_token_writes_row_with_family_id(): void
    {
        /** @var RefreshTokenRepository $repo */
        $repo = self::getContainer()->get(RefreshTokenRepository::class);

        $entity = $repo->getNewRefreshToken();
        \assert($entity instanceof SimpleRefreshTokenEntity);
        $entity->setIdentifier('rt-new');
        $entity->setExpiryDateTime(new \DateTimeImmutable('+30 days'));
        $entity->setAccessToken(new StubAccessToken('jti-1'));
        $familyId = Uuid::v7();
        $entity->setFamilyId($familyId);

        $repo->persistNewRefreshToken($entity);

        $row = $this->em->find(RefreshToken::class, 'rt-new');
        self::assertNotNull($row);
        self::assertSame($familyId->toRfc4122(), $row->getFamilyId()->toRfc4122());
        self::assertSame('jti-1', $row->getAccessTokenId());
    }

    public function test_persist_throws_when_family_id_not_set(): void
    {
        // The repository now refuses to silently fall back to a fresh
        // family_id (would break RFC 9700 §4.14 reuse detection). Grants
        // are responsible for stamping it on; failure to do so is a bug.
        /** @var RefreshTokenRepository $repo */
        $repo = self::getContainer()->get(RefreshTokenRepository::class);

        $entity = $repo->getNewRefreshToken();
        \assert($entity instanceof SimpleRefreshTokenEntity);
        $entity->setIdentifier('rt-bad');
        $entity->setExpiryDateTime(new \DateTimeImmutable('+30 days'));
        $entity->setAccessToken(new StubAccessToken('jti-1'));

        $this->expectException(\LogicException::class);
        $this->expectExceptionMessage('family_id');
        $repo->persistNewRefreshToken($entity);
    }

    public function test_reuse_detection_revokes_entire_family_via_is_revoked_check(): void
    {
        // RFC 9700 §4.14: presenting an already-revoked refresh token is
        // the reuse signal. League's RefreshTokenGrant calls
        // isRefreshTokenRevoked() during validation, so that's where we
        // hook the family-wide revocation.
        /** @var RefreshTokenRepository $repo */
        $repo = self::getContainer()->get(RefreshTokenRepository::class);

        $familyId = Uuid::v7();
        $this->em->persist(new RefreshToken('rt-old', 'jti-1', $familyId, new \DateTimeImmutable('+30 days')));
        $this->em->persist(new RefreshToken('rt-new', 'jti-2', $familyId, new \DateTimeImmutable('+30 days')));
        $this->em->flush();

        // Legitimate revoke of rt-old — rt-new (the rotated successor)
        // stays alive.
        $repo->revokeRefreshToken('rt-old');
        $this->em->clear();
        $rtNew = $this->em->find(RefreshToken::class, 'rt-new');
        self::assertFalse($rtNew->isRevoked());

        // Attacker presents rt-old (already revoked) — isRefreshTokenRevoked
        // detects the reuse and revokes every member of the family.
        self::assertTrue($repo->isRefreshTokenRevoked('rt-old'));

        $this->em->clear();
        self::assertTrue($this->em->find(RefreshToken::class, 'rt-old')->isRevoked());
        self::assertTrue($this->em->find(RefreshToken::class, 'rt-new')->isRevoked());
    }
}
