<?php

declare(strict_types=1);

namespace App\OAuth\Extension;

final class ProtectedResourceMetadataBuilder
{
    public function __construct(
        private readonly string $issuer,
        private readonly AllowedResources $allowedResources,
    ) {
    }

    /** @return array<string, mixed> */
    public function build(): array
    {
        $resources = $this->allowedResources->all();
        $primaryResource = $resources[0] ?? '';

        return [
            'resource' => $primaryResource,
            // byte-equal copy of the issuer; must match ServerMetadataBuilder::build()['issuer'].
            'authorization_servers' => [$this->issuer],
            'scopes_supported' => ['mcp'],
            'bearer_methods_supported' => ['header'],
        ];
    }
}
