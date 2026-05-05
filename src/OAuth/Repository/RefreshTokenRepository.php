<?php

declare(strict_types=1);

namespace App\OAuth\Repository;

use App\OAuth\Entity\RefreshToken;
use App\OAuth\Extension\SimpleRefreshTokenEntity;
use Doctrine\ORM\EntityManagerInterface;
use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use Symfony\Component\Uid\Uuid;

final class RefreshTokenRepository implements RefreshTokenRepositoryInterface
{
    public function __construct(private readonly EntityManagerInterface $em)
    {
    }

    public function getNewRefreshToken(): ?RefreshTokenEntityInterface
    {
        return new SimpleRefreshTokenEntity();
    }

    public function persistNewRefreshToken(RefreshTokenEntityInterface $refreshTokenEntity): void
    {
        if (!$refreshTokenEntity instanceof SimpleRefreshTokenEntity) {
            throw new \LogicException(sprintf(
                'Unexpected refresh token entity %s; expected %s.',
                $refreshTokenEntity::class,
                SimpleRefreshTokenEntity::class,
            ));
        }

        // family_id MUST be set explicitly by the grant
        // (ResourceIndicatorGrant for first-issuance, FamilyAwareRefreshTokenGrant
        // for rotation). If a future grant forgets to call setFamilyId(), we
        // surface the bug instead of silently starting a fresh chain — that
        // would break RFC 9700 §4.14 reuse detection without anyone noticing.
        $familyId = $refreshTokenEntity->getFamilyId();
        if ($familyId === null) {
            throw new \LogicException(sprintf(
                '%s expected family_id to be set by the grant before persistNewRefreshToken; ' .
                'see ResourceIndicatorGrant::issueRefreshToken / FamilyAwareRefreshTokenGrant::issueRefreshToken.',
                SimpleRefreshTokenEntity::class,
            ));
        }

        $row = new RefreshToken(
            identifier: $refreshTokenEntity->getIdentifier(),
            accessTokenId: $refreshTokenEntity->getAccessToken()->getIdentifier(),
            familyId: $familyId,
            expiresAt: $refreshTokenEntity->getExpiryDateTime(),
        );

        $this->em->persist($row);
        $this->em->flush();
    }

    public function revokeRefreshToken(string $tokenId): void
    {
        $row = $this->em->find(RefreshToken::class, $tokenId);
        if (!$row instanceof RefreshToken) {
            return;
        }

        if ($row->isRevoked()) {
            // RFC 9700 §4.14 — re-use detected. Revoke the entire family.
            $this->revokeFamily($row->getFamilyId());

            return;
        }

        $row->revoke();
        $this->em->flush();
    }

    public function isRefreshTokenRevoked(string $tokenId): bool
    {
        // NOTE: side-effect-on-query. League calls this method during
        // refresh-token validation, which is the only safe hook to fire
        // family revocation when a revoked token is replayed. Renaming
        // to is_revoked_or_revoke_family() would be more honest but
        // would also require a custom interface; leave as-is.
        //
        // TODO (post-PoC): wrap the find/revoke pair in SELECT ... FOR
        // UPDATE so two parallel rotations on the same row can't both
        // see "not revoked" and produce a duplicate family branch.
        // RFC 9700 §4.14 acknowledges races; this is a hardening item.
        $row = $this->em->find(RefreshToken::class, $tokenId);
        if ($row === null) {
            return true;
        }

        if ($row->isRevoked()) {
            // RFC 9700 §4.14 — a revoked refresh token presented for
            // exchange is the canonical reuse signal. Revoke the whole
            // family so any sibling token (legitimately rotated to, or
            // a parallel attacker's rotation) is killed too.
            $this->revokeFamily($row->getFamilyId());

            return true;
        }

        return false;
    }

    private function revokeFamily(Uuid $familyId): void
    {
        $rows = $this->em->getRepository(RefreshToken::class)->findBy([
            'familyId' => $familyId,
        ]);
        $changed = false;
        foreach ($rows as $row) {
            if (!$row->isRevoked()) {
                $row->revoke();
                $changed = true;
            }
        }
        if ($changed) {
            $this->em->flush();
        }
    }
}
