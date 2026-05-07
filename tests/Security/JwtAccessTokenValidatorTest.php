<?php

declare(strict_types=1);

namespace App\Tests\Security;

use App\OAuth\Extension\AllowedResources;
use App\OAuth\Extension\KidDeriver;
use App\Security\InvalidJwtException;
use App\Security\InvalidJwtReason;
use App\Security\JwtAccessTokenValidator;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use PHPUnit\Framework\TestCase;

final class JwtAccessTokenValidatorTest extends TestCase
{
    private const ISSUER = 'http://localhost:8000';
    private const ALLOWED = 'http://localhost:8000/mcp';

    private string $privatePath;
    private string $publicPath;
    private string $expectedKid;
    private StubAccessTokenRepository $accessTokens;

    protected function setUp(): void
    {
        $this->privatePath = __DIR__ . '/../fixtures/private.key';
        $this->publicPath = __DIR__ . '/../fixtures/public.key';
        $this->expectedKid = (new KidDeriver($this->publicPath))->derive();
        $this->accessTokens = new StubAccessTokenRepository();
    }

    public function test_valid_jwt_returns_validated_token(): void
    {
        $jwt = $this->mintToken();

        $token = $this->validator()->validate($jwt);

        self::assertSame('jti-1', $token->jti);
        self::assertSame('alice', $token->sub);
        self::assertSame('client-1', $token->clientId);
        self::assertSame(['mcp'], $token->scopes);
        self::assertSame([self::ALLOWED], $token->audiences);
        self::assertTrue($token->hasScope('mcp'));
    }

    public function test_jwt_with_tampered_signature_is_rejected(): void
    {
        $jwt = $this->mintToken();
        // Flip the last byte of the signature segment.
        $segments = explode('.', $jwt);
        $segments[2] = strtr(substr($segments[2], 0, -1) . 'A', '+/', '-_');
        $tampered = implode('.', $segments);

        try {
            $this->validator()->validate($tampered);
            self::fail('Expected InvalidJwtException');
        } catch (InvalidJwtException $e) {
            self::assertSame(InvalidJwtReason::SignatureMismatch, $e->reason);
        }
    }

    public function test_jwt_signed_with_alien_key_is_rejected(): void
    {
        // Generate a fresh RSA keypair at runtime and use it to sign.
        $alien = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => \OPENSSL_KEYTYPE_RSA,
        ]);
        self::assertNotFalse($alien);
        openssl_pkey_export($alien, $alienPrivate);
        $alienPath = tempnam(sys_get_temp_dir(), 'jwt-alien-');
        self::assertNotFalse($alienPath);
        file_put_contents($alienPath, $alienPrivate);

        try {
            $jwt = $this->mintToken(privateKeyOverride: $alienPath);

            try {
                $this->validator()->validate($jwt);
                self::fail('Expected InvalidJwtException');
            } catch (InvalidJwtException $e) {
                self::assertSame(InvalidJwtReason::SignatureMismatch, $e->reason);
            }
        } finally {
            @unlink($alienPath);
        }
    }

    public function test_jwt_from_wrong_issuer_is_rejected(): void
    {
        $jwt = $this->mintToken(issuer: 'http://attacker.example/');

        try {
            $this->validator()->validate($jwt);
            self::fail('Expected InvalidJwtException');
        } catch (InvalidJwtException $e) {
            self::assertSame(InvalidJwtReason::IssuerMismatch, $e->reason);
        }
    }

    public function test_jwt_with_unknown_audience_is_rejected(): void
    {
        $jwt = $this->mintToken(audience: 'http://attacker.example/mcp');

        try {
            $this->validator()->validate($jwt);
            self::fail('Expected InvalidJwtException');
        } catch (InvalidJwtException $e) {
            self::assertSame(InvalidJwtReason::AudienceMismatch, $e->reason);
        }
    }

    public function test_jwt_with_kid_mismatch_is_rejected(): void
    {
        $jwt = $this->mintToken(kid: 'deadbeefdeadbeef');

        try {
            $this->validator()->validate($jwt);
            self::fail('Expected InvalidJwtException');
        } catch (InvalidJwtException $e) {
            self::assertSame(InvalidJwtReason::KidMismatch, $e->reason);
        }
    }

    public function test_expired_jwt_is_rejected(): void
    {
        $jwt = $this->mintToken(
            issuedAt: new \DateTimeImmutable('-2 hour'),
            expiresAt: new \DateTimeImmutable('-1 hour'),
        );

        try {
            $this->validator()->validate($jwt);
            self::fail('Expected InvalidJwtException');
        } catch (InvalidJwtException $e) {
            self::assertSame(InvalidJwtReason::Expired, $e->reason);
        }
    }

    public function test_revoked_jwt_is_rejected(): void
    {
        $this->accessTokens->revoked['jti-revoked'] = true;
        $jwt = $this->mintToken(jti: 'jti-revoked');

        try {
            $this->validator()->validate($jwt);
            self::fail('Expected InvalidJwtException');
        } catch (InvalidJwtException $e) {
            self::assertSame(InvalidJwtReason::Revoked, $e->reason);
        }
    }

    public function test_malformed_jwt_is_rejected(): void
    {
        try {
            $this->validator()->validate('not.a.jwt');
            self::fail('Expected InvalidJwtException');
        } catch (InvalidJwtException $e) {
            self::assertSame(InvalidJwtReason::Malformed, $e->reason);
        }
    }

    private function validator(): JwtAccessTokenValidator
    {
        return new JwtAccessTokenValidator(
            publicKeyPath: $this->publicPath,
            issuer: self::ISSUER,
            kidDeriver: new KidDeriver($this->publicPath),
            allowedResources: new AllowedResources([self::ALLOWED]),
            accessTokens: $this->accessTokens,
        );
    }

    private function mintToken(
        ?string $privateKeyOverride = null,
        string $issuer = self::ISSUER,
        string $audience = self::ALLOWED,
        ?string $kid = null,
        ?\DateTimeImmutable $issuedAt = null,
        ?\DateTimeImmutable $expiresAt = null,
        string $jti = 'jti-1',
    ): string {
        $privatePath = $privateKeyOverride ?? $this->privatePath;
        $publicPath = $this->publicPath;
        $config = Configuration::forAsymmetricSigner(
            new Sha256(),
            InMemory::file($privatePath),
            InMemory::file($publicPath),
        );
        $issuedAt ??= new \DateTimeImmutable('-1 minute');
        $expiresAt ??= new \DateTimeImmutable('+1 hour');

        $token = $config->builder()
            ->withHeader('kid', $kid ?? $this->expectedKid)
            ->issuedBy($issuer)
            ->permittedFor($audience)
            ->identifiedBy($jti)
            ->issuedAt($issuedAt)
            ->canOnlyBeUsedAfter($issuedAt)
            ->expiresAt($expiresAt)
            ->withClaim('client_id', 'client-1')
            ->withClaim('scope', 'mcp')
            ->relatedTo('alice')
            ->getToken($config->signer(), $config->signingKey());

        return $token->toString();
    }
}

final class StubAccessTokenRepository implements AccessTokenRepositoryInterface
{
    /** @var array<string, true> */
    public array $revoked = [];

    public function getNewToken(
        ClientEntityInterface $clientEntity,
        array $scopes,
        string|null $userIdentifier = null,
    ): AccessTokenEntityInterface {
        throw new \LogicException('not used in validator tests');
    }

    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity): void
    {
    }

    public function revokeAccessToken(string $tokenId): void
    {
        $this->revoked[$tokenId] = true;
    }

    public function isAccessTokenRevoked(string $tokenId): bool
    {
        return isset($this->revoked[$tokenId]);
    }
}
