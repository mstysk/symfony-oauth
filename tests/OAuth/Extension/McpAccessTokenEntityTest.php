<?php

declare(strict_types=1);

namespace App\Tests\OAuth\Extension;

use App\OAuth\Entity\Scope;
use App\OAuth\Extension\KidDeriver;
use App\OAuth\Extension\McpAccessTokenEntity;
use App\Tests\Stub\StubClient;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use League\OAuth2\Server\CryptKey;
use PHPUnit\Framework\TestCase;

final class McpAccessTokenEntityTest extends TestCase
{
    public function test_jwt_contains_aud_array_iss_and_kid(): void
    {
        $privatePath = __DIR__ . '/../../fixtures/private.key';
        $publicPath  = __DIR__ . '/../../fixtures/public.key';

        $token = new McpAccessTokenEntity(
            issuer: 'http://localhost:8000',
            kidDeriver: new KidDeriver($publicPath),
            publicKeyPath: $publicPath,
        );
        $token->setIdentifier('jti-1');
        $token->setExpiryDateTime(new \DateTimeImmutable('+1 hour'));
        $token->setUserIdentifier('alice');
        $token->setClient(new StubClient('client-1'));
        $token->addScope(new Scope('mcp'));
        $token->setAudiences(['http://localhost:8000/mcp']);
        $token->setPrivateKey(new CryptKey($privatePath, null, false));

        $jwt = $token->toString();

        $parsed = (new Parser(new JoseEncoder()))->parse($jwt);
        self::assertInstanceOf(UnencryptedToken::class, $parsed);

        self::assertSame('jti-1', $parsed->claims()->get('jti'));
        self::assertSame('http://localhost:8000', $parsed->claims()->get('iss'));
        self::assertSame(['http://localhost:8000/mcp'], $parsed->claims()->get('aud'));
        self::assertSame('alice', $parsed->claims()->get('sub'));
        self::assertSame('client-1', $parsed->claims()->get('client_id'));
        self::assertSame('mcp', $parsed->claims()->get('scope'));

        $expectedKid = (new KidDeriver($publicPath))->derive();
        self::assertSame($expectedKid, $parsed->headers()->get('kid'));

        // __toString magic returns the same value as toString().
        self::assertSame($jwt, (string) $token);
    }
}
