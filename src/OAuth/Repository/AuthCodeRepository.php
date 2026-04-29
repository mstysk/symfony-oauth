<?php

declare(strict_types=1);

namespace App\OAuth\Repository;

use App\OAuth\Entity\AuthCode;
use Doctrine\ORM\EntityManagerInterface;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;

final class AuthCodeRepository implements AuthCodeRepositoryInterface
{
    public function __construct(private readonly EntityManagerInterface $em)
    {
    }

    public function getNewAuthCode(): AuthCodeEntityInterface
    {
        return new AuthCode();
    }

    public function persistNewAuthCode(AuthCodeEntityInterface $authCodeEntity): void
    {
        if (!$authCodeEntity instanceof AuthCode) {
            throw new \LogicException('Unexpected auth code entity');
        }
        $this->em->persist($authCodeEntity);
        $this->em->flush();
    }

    public function revokeAuthCode(string $codeId): void
    {
        $code = $this->em->find(AuthCode::class, $codeId);
        if ($code instanceof AuthCode) {
            $code->revoke();
            $this->em->flush();
        }
    }

    public function isAuthCodeRevoked(string $codeId): bool
    {
        $code = $this->em->find(AuthCode::class, $codeId);
        return $code === null || $code->isRevoked();
    }
}
