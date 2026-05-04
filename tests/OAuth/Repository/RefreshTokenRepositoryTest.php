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

    public function test_persist_new_refresh_token_generates_family_id_when_unset(): void
    {
        /** @var RefreshTokenRepository $repo */
        $repo = self::getContainer()->get(RefreshTokenRepository::class);

        $entity = $repo->getNewRefreshToken();
        \assert($entity instanceof SimpleRefreshTokenEntity);
        $entity->setIdentifier('rt-fresh');
        $entity->setExpiryDateTime(new \DateTimeImmutable('+30 days'));
        $entity->setAccessToken(new StubAccessToken('jti-1'));

        $repo->persistNewRefreshToken($entity);

        $row = $this->em->find(RefreshToken::class, 'rt-fresh');
        self::assertNotNull($row);
        // family_id was generated; it is a non-empty UUID.
        self::assertNotEmpty($row->getFamilyId()->toRfc4122());
    }

    public function test_reuse_detection_revokes_entire_family(): void
    {
        /** @var RefreshTokenRepository $repo */
        $repo = self::getContainer()->get(RefreshTokenRepository::class);

        $familyId = Uuid::v7();
        $this->em->persist(new RefreshToken('rt-old', 'jti-1', $familyId, new \DateTimeImmutable('+30 days')));
        $this->em->persist(new RefreshToken('rt-new', 'jti-2', $familyId, new \DateTimeImmutable('+30 days')));
        $this->em->flush();

        // First revoke: just rt-old.
        $repo->revokeRefreshToken('rt-old');
        self::assertTrue($repo->isRefreshTokenRevoked('rt-old'));
        self::assertFalse($repo->isRefreshTokenRevoked('rt-new'));

        // Second call on the same already-revoked token = reuse → revoke whole family.
        $repo->revokeRefreshToken('rt-old');
        self::assertTrue($repo->isRefreshTokenRevoked('rt-old'));
        self::assertTrue($repo->isRefreshTokenRevoked('rt-new'));
    }
}
