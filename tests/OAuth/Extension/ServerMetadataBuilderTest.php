<?php

declare(strict_types=1);

namespace App\Tests\OAuth\Extension;

use App\OAuth\Extension\ServerMetadataBuilder;
use PHPUnit\Framework\TestCase;

final class ServerMetadataBuilderTest extends TestCase
{
    public function test_builds_required_fields(): void
    {
        $builder = new ServerMetadataBuilder('http://localhost:8000');
        $meta = $builder->build();

        self::assertSame('http://localhost:8000', $meta['issuer']);
        self::assertSame('http://localhost:8000/oauth/authorize', $meta['authorization_endpoint']);
        self::assertSame('http://localhost:8000/oauth/token', $meta['token_endpoint']);
        self::assertSame('http://localhost:8000/oauth/register', $meta['registration_endpoint']);
        self::assertSame('http://localhost:8000/.well-known/jwks.json', $meta['jwks_uri']);
        self::assertSame(['code'], $meta['response_types_supported']);
        self::assertContains('authorization_code', $meta['grant_types_supported']);
        self::assertContains('refresh_token', $meta['grant_types_supported']);
        self::assertSame(['S256'], $meta['code_challenge_methods_supported']);
        self::assertContains('client_secret_basic', $meta['token_endpoint_auth_methods_supported']);
        self::assertContains('none', $meta['token_endpoint_auth_methods_supported']);
        self::assertSame(['mcp'], $meta['scopes_supported']);
    }

    public function test_issuer_is_used_verbatim_for_eq_with_prm(): void
    {
        $builder = new ServerMetadataBuilder('http://localhost:8000/');
        $meta = $builder->build();

        // Trailing slash preserved as-is so PRM/AS metadata can byte-eq compare.
        self::assertSame('http://localhost:8000/', $meta['issuer']);
        // But endpoints are mounted on the trimmed base.
        self::assertSame('http://localhost:8000/oauth/authorize', $meta['authorization_endpoint']);
    }
}
