<?php

declare(strict_types=1);

namespace App\Tests\OAuth\Repository;

use App\OAuth\Entity\AccessToken;
use App\OAuth\Entity\Client;
use App\OAuth\Entity\Scope;
use App\OAuth\Extension\McpAccessTokenEntity;
use App\OAuth\Repository\AccessTokenRepository;
use App\Tests\OAuth\Support\DoctrineKernelTestCase;
use Symfony\Component\Uid\Uuid;

final class AccessTokenRepositoryTest extends DoctrineKernelTestCase
{
    public function test_persist_and_revoke_round_trip(): void
    {
        $clientId = Uuid::v7();
        $this->em->persist(new Client(
            id: $clientId,
            name: 'c',
            secretHash: null,
            redirectUris: ['http://localhost:8000/cb'],
            grantTypes: ['authorization_code'],
            scopes: ['mcp'],
            dcrMetadata: [],
        ));
        $this->em->flush();

        /** @var AccessTokenRepository $repo */
        $repo = self::getContainer()->get(AccessTokenRepository::class);

        $row = new AccessToken(
            identifier: 'jti-1',
            clientId: $clientId->toRfc4122(),
            userId: 'alice',
            expiresAt: new \DateTimeImmutable('+1 hour'),
            scopes: ['mcp'],
            audience: ['http://localhost:8000/mcp'],
        );
        $this->em->persist($row);
        $this->em->flush();

        self::assertFalse($repo->isAccessTokenRevoked('jti-1'));
        $repo->revokeAccessToken('jti-1');
        self::assertTrue($repo->isAccessTokenRevoked('jti-1'));
    }

    public function test_get_new_token_returns_mcp_access_token_entity(): void
    {
        /** @var AccessTokenRepository $repo */
        $repo = self::getContainer()->get(AccessTokenRepository::class);

        $client = new Client(
            id: Uuid::v7(),
            name: 'c',
            secretHash: null,
            redirectUris: ['http://localhost:8000/cb'],
            grantTypes: ['authorization_code'],
            scopes: ['mcp'],
            dcrMetadata: [],
        );

        $token = $repo->getNewToken($client, [new Scope('mcp')], 'alice');

        self::assertInstanceOf(McpAccessTokenEntity::class, $token);
        self::assertSame($client, $token->getClient());
        self::assertSame('alice', $token->getUserIdentifier());
        self::assertCount(1, $token->getScopes());
    }
}
