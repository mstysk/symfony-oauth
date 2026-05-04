<?php

declare(strict_types=1);

namespace App\Tests\OAuth\Extension;

use App\OAuth\Extension\AllowedResources;
use App\OAuth\Extension\ProtectedResourceMetadataBuilder;
use PHPUnit\Framework\TestCase;

final class ProtectedResourceMetadataBuilderTest extends TestCase
{
    public function test_builds_required_fields(): void
    {
        $builder = new ProtectedResourceMetadataBuilder(
            issuer: 'http://localhost:8000',
            allowedResources: new AllowedResources(['http://localhost:8000/mcp']),
        );

        $meta = $builder->build();

        self::assertSame('http://localhost:8000/mcp', $meta['resource']);
        // byte-equal with the issuer string passed in (no normalization).
        self::assertSame(['http://localhost:8000'], $meta['authorization_servers']);
        self::assertSame(['mcp'], $meta['scopes_supported']);
        // Strict equality — must not include 'query' or 'body'.
        self::assertSame(['header'], $meta['bearer_methods_supported']);
    }

    public function test_issuer_byte_equal_with_trailing_slash(): void
    {
        $builder = new ProtectedResourceMetadataBuilder(
            issuer: 'http://localhost:8000/',
            allowedResources: new AllowedResources(['http://localhost:8000/mcp']),
        );

        self::assertSame(['http://localhost:8000/'], $builder->build()['authorization_servers']);
    }
}
