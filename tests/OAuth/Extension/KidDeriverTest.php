<?php

declare(strict_types=1);

namespace App\Tests\OAuth\Extension;

use App\OAuth\Extension\KidDeriver;
use PHPUnit\Framework\TestCase;

final class KidDeriverTest extends TestCase
{
    public function test_kid_is_first_16_hex_chars_of_sha256_of_public_key_pem(): void
    {
        $publicKeyPath = __DIR__ . '/../../fixtures/public.key';
        $pem = file_get_contents($publicKeyPath);
        self::assertNotFalse($pem, 'Test fixture missing — see tests/fixtures/README.md');

        $kid = (new KidDeriver($publicKeyPath))->derive();

        self::assertSame(16, \strlen($kid));
        self::assertSame(substr(hash('sha256', $pem), 0, 16), $kid);
    }

    public function test_throws_when_key_unreadable(): void
    {
        $deriver = new KidDeriver('/no/such/file.key');

        $this->expectException(\RuntimeException::class);
        $deriver->derive();
    }
}
