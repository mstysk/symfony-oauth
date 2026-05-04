<?php

declare(strict_types=1);

namespace App\OAuth\Server;

use App\OAuth\Extension\ResourceIndicatorGrant;
use App\OAuth\Repository\AccessTokenRepository;
use App\OAuth\Repository\ClientRepository;
use App\OAuth\Repository\ScopeRepository;
use Defuse\Crypto\Key;
use League\OAuth2\Server\AuthorizationServer;
use League\OAuth2\Server\CryptKey;

/**
 * Wires the league AuthorizationServer with our repos and the
 * ResourceIndicatorGrant. Phase D6 (TokenController) and the
 * authorize/consent flow both pull a single AS instance from here.
 */
final class AuthorizationServerFactory
{
    public function __construct(
        private readonly ClientRepository $clientRepository,
        private readonly AccessTokenRepository $accessTokenRepository,
        private readonly ScopeRepository $scopeRepository,
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

        // PKCE is required by ResourceIndicatorGrant::validateAuthorizationRequest
        // for all clients (stricter than league's default which only requires
        // it for public clients), so no enableCodeExchangeProof() call is needed.
        $this->resourceIndicatorGrant->setRefreshTokenTTL(new \DateInterval($this->refreshTokenTtl));

        $server->enableGrantType(
            $this->resourceIndicatorGrant,
            new \DateInterval($this->accessTokenTtl),
        );

        return $server;
    }
}
