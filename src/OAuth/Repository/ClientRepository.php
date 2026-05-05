<?php

declare(strict_types=1);

namespace App\OAuth\Repository;

use App\OAuth\Entity\Client;
use Doctrine\ORM\EntityManagerInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;

final class ClientRepository implements ClientRepositoryInterface
{
    public function __construct(private readonly EntityManagerInterface $em)
    {
    }

    public function getClientEntity(string $clientIdentifier): ?ClientEntityInterface
    {
        return $this->em->getRepository(Client::class)
            ->findOneBy(['clientIdentifier' => $clientIdentifier]);
    }

    public function validateClient(
        string $clientIdentifier,
        ?string $clientSecret,
        ?string $grantType,
    ): bool {
        $client = $this->getClientEntity($clientIdentifier);
        if (!$client instanceof Client) {
            return false;
        }

        if ($grantType !== null && !\in_array($grantType, $client->getGrantTypes(), true)) {
            return false;
        }

        if ($client->isConfidential()) {
            if ($clientSecret === null) {
                return false;
            }
            return password_verify($clientSecret, (string) $client->getSecretHash());
        }

        return $clientSecret === null;
    }

    public function save(Client $client): void
    {
        $this->em->persist($client);
        $this->em->flush();
    }
}
