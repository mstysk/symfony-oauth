<?php

declare(strict_types=1);

namespace App\Tests\Stub;

use League\OAuth2\Server\Entities\ClientEntityInterface;

final class StubClient implements ClientEntityInterface
{
    public function __construct(
        private readonly string $identifier,
        private readonly string $name = 'stub',
        private readonly bool $confidential = false,
        /** @var string[] */
        private readonly array $redirectUris = [],
    ) {
    }

    public function getIdentifier(): string
    {
        return $this->identifier;
    }

    public function getName(): string
    {
        return $this->name;
    }

    /** @return string[] */
    public function getRedirectUri(): array
    {
        return $this->redirectUris;
    }

    public function isConfidential(): bool
    {
        return $this->confidential;
    }
}
