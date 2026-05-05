<?php

declare(strict_types=1);

namespace App\OAuth\Extension;

final class AllowedResources
{
    /** @var string[] */
    private readonly array $resources;

    /** @param string[] $values */
    public function __construct(array $values)
    {
        $this->resources = array_values(array_filter(
            array_map('trim', $values),
            static fn (string $v): bool => $v !== '',
        ));
    }

    /** @return string[] */
    public function all(): array
    {
        return $this->resources;
    }

    public function contains(string $resource): bool
    {
        return \in_array($resource, $this->resources, true);
    }
}
