<?php

declare(strict_types=1);

namespace App\Tests\OAuth\Repository;

use App\OAuth\Entity\Client;
use App\OAuth\Repository\ClientRepository;
use App\Tests\OAuth\Support\DoctrineKernelTestCase;
use Symfony\Component\Uid\Uuid;

final class ClientRepositoryTest extends DoctrineKernelTestCase
{
    public function test_validates_public_client_without_secret(): void
    {
        $repo = self::getContainer()->get(ClientRepository::class);

        $id = Uuid::v7();
        $this->em->persist(new Client(
            id: $id,
            name: 'pub',
            secretHash: null,
            redirectUris: ['http://localhost:8000/cb'],
            grantTypes: ['authorization_code', 'refresh_token'],
            scopes: ['mcp'],
            dcrMetadata: [],
        ));
        $this->em->flush();

        $client = $repo->getClientEntity($id->toRfc4122());
        self::assertNotNull($client);
        self::assertFalse($client->isConfidential());

        self::assertTrue($repo->validateClient($id->toRfc4122(), null, 'authorization_code'));
        self::assertFalse($repo->validateClient($id->toRfc4122(), null, 'client_credentials'));
    }

    public function test_validates_confidential_client_with_secret(): void
    {
        $repo = self::getContainer()->get(ClientRepository::class);

        $id = Uuid::v7();
        $this->em->persist(new Client(
            id: $id,
            name: 'srv',
            secretHash: password_hash('s3cret', PASSWORD_BCRYPT),
            redirectUris: ['https://example.com/cb'],
            grantTypes: ['authorization_code', 'refresh_token'],
            scopes: ['mcp'],
            dcrMetadata: [],
        ));
        $this->em->flush();

        self::assertTrue($repo->validateClient($id->toRfc4122(), 's3cret', 'authorization_code'));
        self::assertFalse($repo->validateClient($id->toRfc4122(), 'wrong', 'authorization_code'));
    }
}
