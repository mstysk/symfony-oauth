<?php

declare(strict_types=1);

namespace App\OAuth\Extension;

final class RedirectUriNormalizer
{
    public static function normalize(string $uri): string
    {
        $parts = parse_url($uri);
        if ($parts === false || !isset($parts['scheme'], $parts['host'])) {
            throw new \InvalidArgumentException('Invalid redirect_uri: ' . $uri);
        }

        $scheme = strtolower($parts['scheme']);
        $host = strtolower($parts['host']);
        $port = isset($parts['port']) ? ':' . $parts['port'] : '';
        $path = $parts['path'] ?? '';
        $query = isset($parts['query']) ? '?' . $parts['query'] : '';
        // Fragments are stripped (RFC 6749 §3.1.2 forbids them in redirect URIs).

        return $scheme . '://' . $host . $port . $path . $query;
    }
}
