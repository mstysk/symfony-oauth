<?php

declare(strict_types=1);

namespace App\OAuth\Server;

use App\OAuth\Extension\ResourceIndicatorGrant;
use App\OAuth\Repository\AccessTokenRepository;
use App\OAuth\Repository\ClientRepository;
use App\OAuth\Repository\RefreshTokenRepository;
use App\OAuth\Repository\ScopeRepository;
use Defuse\Crypto\Key;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Grant\RefreshTokenGrant;

/**
 * Wires the league AuthorizationServer with our repos and the
 * grants we support. Phase D6 (TokenController) and the
 * authorize/consent flow both pull a single AS instance from here.
 */
final class AuthorizationServerFactory
{
    public function __construct(
        private readonly ClientRepository $clientRepository,
        private readonly AccessTokenRepository $accessTokenRepository,
        private readonly ScopeRepository $scopeRepository,
        private readonly RefreshTokenRepository $refreshTokenRepository,
        private readonly ResourceIndicatorGrant $resourceIndicatorGrant,
        private readonly string $privateKeyPath,
        private readonly string $encryptionKey,
        private readonly string $accessTokenTtl,
        private readonly string $refreshTokenTtl,
    ) {
    }

    public function create(): AuthorizationServer
    {
        $privateKey = new CryptKey($this->privateKeyPath, null, false);
        $encryptionKey = str_starts_with($this->encryptionKey, 'def00000')
            ? Key::loadFromAsciiSafeString($this->encryptionKey)
            : $this->encryptionKey;

        $server = new AuthorizationServer(
            clientRepository: $this->clientRepository,
            accessTokenRepository: $this->accessTokenRepository,
            scopeRepository: $this->scopeRepository,
            privateKey: $privateKey,
            encryptionKey: $encryptionKey,
        );

        $accessTokenTtl = new \DateInterval($this->accessTokenTtl);
        $refreshTokenTtl = new \DateInterval($this->refreshTokenTtl);

        // PKCE is required by ResourceIndicatorGrant::validateAuthorizationRequest
        // for all clients (stricter than league's default which only requires
        // it for public clients), so no enableCodeExchangeProof() call is needed.
        $this->resourceIndicatorGrant->setRefreshTokenTTL($refreshTokenTtl);
        $server->enableGrantType($this->resourceIndicatorGrant, $accessTokenTtl);

        // Refresh token grant — exchanges a still-valid refresh_token for a
        // new access_token (+ rotated refresh_token). Without this, every
        // /oauth/token request with grant_type=refresh_token would fall
        // through league's grant loop and be rejected as unsupported.
        $refreshTokenGrant = new RefreshTokenGrant($this->refreshTokenRepository);
        $refreshTokenGrant->setRefreshTokenTTL($refreshTokenTtl);
        $server->enableGrantType($refreshTokenGrant, $accessTokenTtl);

        return $server;
    }
}
