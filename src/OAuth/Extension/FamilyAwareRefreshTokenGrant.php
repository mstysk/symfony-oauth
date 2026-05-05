<?php

declare(strict_types=1);

namespace App\OAuth\Extension;

use App\OAuth\Entity\RefreshToken as RefreshTokenRow;
use Doctrine\ORM\EntityManagerInterface;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Grant\RefreshTokenGrant;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use Psr\Http\Message\ServerRequestInterface;

/**
 * RefreshTokenGrant + family_id propagation for RFC 9700 §4.14 reuse
 * detection. league's stock grant has no concept of token families;
 * each rotation would otherwise produce a brand-new family because
 * SimpleRefreshTokenEntity ships with familyId === null and nothing
 * carries the previous token's family forward.
 */
final class FamilyAwareRefreshTokenGrant extends RefreshTokenGrant
{
    private ?\Symfony\Component\Uid\Uuid $pendingFamilyId = null;

    public function __construct(
        RefreshTokenRepositoryInterface $refreshTokenRepository,
        private readonly EntityManagerInterface $em,
    ) {
        parent::__construct($refreshTokenRepository);
    }

    /**
     * Capture the OLD refresh token's family_id before delegating to
     * parent. Stash it so issueRefreshToken can stamp it onto the new
     * SimpleRefreshTokenEntity, preserving the rotation chain.
     *
     * @return array<string, mixed>
     */
    protected function validateOldRefreshToken(ServerRequestInterface $request, string $clientId): array
    {
        $payload = parent::validateOldRefreshToken($request, $clientId);

        if (isset($payload['refresh_token_id']) && \is_string($payload['refresh_token_id'])) {
            $row = $this->em->find(RefreshTokenRow::class, $payload['refresh_token_id']);
            if ($row instanceof RefreshTokenRow) {
                $this->pendingFamilyId = $row->getFamilyId();
            }
        }

        return $payload;
    }

    /**
     * Override to set the captured family_id on the new refresh token
     * before persistence. Re-implements AbstractGrant::issueRefreshToken
     * with the single extra setFamilyId() call.
     */
    protected function issueRefreshToken(AccessTokenEntityInterface $accessToken): ?RefreshTokenEntityInterface
    {
        if (!$this->supportsGrantType($accessToken->getClient(), 'refresh_token')) {
            return null;
        }

        $refreshToken = $this->refreshTokenRepository->getNewRefreshToken();
        if ($refreshToken === null) {
            return null;
        }

        $refreshToken->setExpiryDateTime((new \DateTimeImmutable())->add($this->refreshTokenTTL));
        $refreshToken->setAccessToken($accessToken);

        if ($refreshToken instanceof SimpleRefreshTokenEntity && $this->pendingFamilyId !== null) {
            $refreshToken->setFamilyId($this->pendingFamilyId);
        }

        $maxAttempts = self::MAX_RANDOM_TOKEN_GENERATION_ATTEMPTS;
        while ($maxAttempts-- > 0) {
            $refreshToken->setIdentifier($this->generateUniqueIdentifier());
            try {
                $this->refreshTokenRepository->persistNewRefreshToken($refreshToken);

                $this->pendingFamilyId = null;

                return $refreshToken;
            } catch (\League\OAuth2\Server\Exception\UniqueTokenIdentifierConstraintViolationException $e) {
                if ($maxAttempts === 0) {
                    throw $e;
                }
            }
        }

        return $refreshToken;
    }
}
