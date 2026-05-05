<?php

declare(strict_types=1);

namespace App\Controller\WellKnown;

use App\OAuth\Extension\KidDeriver;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Attribute\Route;

final class JwksController
{
    public function __construct(
        private readonly KidDeriver $kidDeriver,
        private readonly string $publicKeyPath,
    ) {
    }

    #[Route(
        path: '/.well-known/jwks.json',
        name: 'app_well_known_jwks',
        methods: ['GET'],
    )]
    public function __invoke(): JsonResponse
    {
        $pem = file_get_contents($this->publicKeyPath);
        if ($pem === false) {
            throw new \RuntimeException('Cannot read public key at ' . $this->publicKeyPath);
        }

        $resource = openssl_pkey_get_public($pem);
        if ($resource === false) {
            throw new \RuntimeException('Public key at ' . $this->publicKeyPath . ' is not a valid PEM');
        }

        $details = openssl_pkey_get_details($resource);
        if ($details === false || !isset($details['rsa']['n'], $details['rsa']['e'])) {
            throw new \RuntimeException('Cannot extract RSA modulus/exponent from public key');
        }

        $base64url = static fn (string $bytes): string => rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');

        return new JsonResponse([
            'keys' => [[
                'kty' => 'RSA',
                'use' => 'sig',
                'alg' => 'RS256',
                'kid' => $this->kidDeriver->derive(),
                'n' => $base64url($details['rsa']['n']),
                'e' => $base64url($details['rsa']['e']),
            ]],
        ]);
    }
}
