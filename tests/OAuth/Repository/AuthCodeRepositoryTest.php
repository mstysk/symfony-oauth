<?php

declare(strict_types=1);

namespace App\Tests\OAuth\Repository;

use App\OAuth\Entity\AuthCode;
use App\OAuth\Entity\Client;
use App\OAuth\Entity\Scope;
use App\OAuth\Repository\AuthCodeRepository;
use App\Tests\OAuth\Support\DoctrineKernelTestCase;
use Symfony\Component\Uid\Uuid;

final class AuthCodeRepositoryTest extends DoctrineKernelTestCase
{
    public function test_persist_and_revoke(): void
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

        /** @var AuthCodeRepository $repo */
        $repo = self::getContainer()->get(AuthCodeRepository::class);

        $code = $repo->getNewAuthCode();
        $code->setIdentifier('code-123');
        $code->setUserIdentifier('alice');
        $code->setExpiryDateTime(new \DateTimeImmutable('+10 min'));
        $code->setClient($this->em->getRepository(Client::class)->findOneBy([
            'clientIdentifier' => $clientId->toRfc4122(),
        ]));
        $code->setRedirectUri('http://localhost:8000/cb');
        $code->addScope(new Scope('mcp'));
        $code->setCodeChallenge('abc');
        $code->setCodeChallengeMethod('S256');
        $code->setResource('http://localhost:8000/mcp');

        $repo->persistNewAuthCode($code);

        self::assertFalse($repo->isAuthCodeRevoked('code-123'));
        $repo->revokeAuthCode('code-123');
        self::assertTrue($repo->isAuthCodeRevoked('code-123'));
    }
}
