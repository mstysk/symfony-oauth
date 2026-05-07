<?php

declare(strict_types=1);

namespace App\OAuth\Extension;

final class KidDeriver
{
    private ?string $kid = null;

    public function __construct(private readonly string $publicKeyPath)
    {
    }

    public function derive(): string
    {
        return $this->kid ??= $this->compute();
    }

    private function compute(): string
    {
        $pem = @file_get_contents($this->publicKeyPath);
        if ($pem === false) {
            throw new \RuntimeException('Cannot read public key at ' . $this->publicKeyPath);
        }

        return substr(hash('sha256', $pem), 0, 16);
    }
}
