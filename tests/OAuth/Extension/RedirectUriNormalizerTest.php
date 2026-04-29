<?php

declare(strict_types=1);

namespace App\Tests\OAuth\Extension;

use App\OAuth\Extension\RedirectUriNormalizer;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class RedirectUriNormalizerTest extends TestCase
{
    #[DataProvider('cases')]
    public function test_normalize(string $input, string $expected): void
    {
        self::assertSame($expected, RedirectUriNormalizer::normalize($input));
    }

    public static function cases(): iterable
    {
        // Host is lowercased; scheme is lowercased.
        yield ['HTTP://Localhost:8000/cb', 'http://localhost:8000/cb'];
        yield ['https://EXAMPLE.com/Path', 'https://example.com/Path'];
        // Trailing slash is preserved as-is (strict comparison).
        yield ['https://example.com/cb/', 'https://example.com/cb/'];
        yield ['https://example.com/cb',  'https://example.com/cb'];
        // Query is kept (RFC 6749 forbids fragments, which we strip).
        yield ['https://example.com/cb?x=1', 'https://example.com/cb?x=1'];
    }

    public function test_throws_on_invalid_uri(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        RedirectUriNormalizer::normalize('not a url');
    }
}
