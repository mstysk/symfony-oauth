<?php

declare(strict_types=1);

namespace App\OAuth\Repository;

use App\OAuth\Entity\Scope;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;

final class ScopeRepository implements ScopeRepositoryInterface
{
    /** @param array<string, string> $scopes identifier => description */
    public function __construct(private readonly array $scopes)
    {
    }

    public function getScopeEntityByIdentifier(string $identifier): ?ScopeEntityInterface
    {
        return isset($this->scopes[$identifier]) ? new Scope($identifier) : null;
    }

    /**
     * @param ScopeEntityInterface[] $scopes
     * @return ScopeEntityInterface[]
     */
    public function finalizeScopes(
        array $scopes,
        string $grantType,
        ClientEntityInterface $clientEntity,
        ?string $userIdentifier = null,
        ?string $authCodeId = null,
    ): array {
        return $scopes;
    }
}
