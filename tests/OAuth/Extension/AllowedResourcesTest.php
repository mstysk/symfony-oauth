<?php

declare(strict_types=1);

namespace App\Tests\OAuth\Extension;

use App\OAuth\Extension\AllowedResources;
use PHPUnit\Framework\TestCase;

final class AllowedResourcesTest extends TestCase
{
    public function test_trims_and_filters_empty(): void
    {
        $r = new AllowedResources(['  http://localhost:8000/mcp  ', '', '   ', 'https://api.example/mcp']);

        self::assertSame(
            ['http://localhost:8000/mcp', 'https://api.example/mcp'],
            $r->all(),
        );
    }

    public function test_contains_strict_match(): void
    {
        $r = new AllowedResources(['http://localhost:8000/mcp']);

        self::assertTrue($r->contains('http://localhost:8000/mcp'));
        self::assertFalse($r->contains('http://localhost:8000/mcp/'));
        self::assertFalse($r->contains('http://localhost:8000/MCP'));
    }
}
