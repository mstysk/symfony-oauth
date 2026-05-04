<?php

declare(strict_types=1);

namespace App\OAuth\Extension;

use League\OAuth2\Server\Entities\RefreshTokenEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\RefreshTokenTrait;
use Symfony\Component\Uid\Uuid;

/**
 * Pure value object — RefreshTokenEntityInterface impl that the
 * RefreshTokenRepository hands out from getNewRefreshToken().
 *
 * Carries an optional family_id so the grant can preserve the family
 * across rotations. If the grant doesn't set one, the repository
 * generates a fresh UUID v7 at persistence time.
 */
final class SimpleRefreshTokenEntity implements RefreshTokenEntityInterface
{
    use EntityTrait;
    use RefreshTokenTrait;

    private ?Uuid $familyId = null;

    public function getFamilyId(): ?Uuid
    {
        return $this->familyId;
    }

    public function setFamilyId(Uuid $familyId): void
    {
        $this->familyId = $familyId;
    }
}
