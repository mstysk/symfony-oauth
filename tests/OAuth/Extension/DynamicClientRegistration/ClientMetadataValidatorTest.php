<?php

declare(strict_types=1);

namespace App\Tests\OAuth\Extension\DynamicClientRegistration;

use App\OAuth\Extension\DynamicClientRegistration\ClientMetadataValidator;
use League\OAuth2\Server\Exception\OAuthServerException;
use PHPUnit\Framework\TestCase;

final class ClientMetadataValidatorTest extends TestCase
{
    public function test_accepts_valid_localhost_redirect_uri(): void
    {
        $validator = new ClientMetadataValidator(['localhost', '127.0.0.1']);

        $validator->validate([
            'redirect_uris' => ['http://localhost:9000/cb'],
            'grant_types' => ['authorization_code', 'refresh_token'],
        ]);

        $this->expectNotToPerformAssertions();
    }

    public function test_rejects_redirect_uri_with_disallowed_host(): void
    {
        $validator = new ClientMetadataValidator(['localhost', '127.0.0.1']);

        try {
            $validator->validate([
                'redirect_uris' => ['https://attacker.example.com/cb'],
                'grant_types' => ['authorization_code'],
            ]);
            self::fail('Expected OAuthServerException');
        } catch (OAuthServerException $e) {
            self::assertSame('invalid_redirect_uri', $e->getPayload()['error']);
        }
    }

    public function test_rejects_redirect_uri_with_bad_scheme(): void
    {
        $validator = new ClientMetadataValidator(['localhost']);

        try {
            $validator->validate([
                'redirect_uris' => ['file:///etc/passwd'],
                'grant_types' => ['authorization_code'],
            ]);
            self::fail('Expected OAuthServerException');
        } catch (OAuthServerException $e) {
            self::assertSame('invalid_redirect_uri', $e->getPayload()['error']);
        }
    }

    public function test_rejects_unsupported_grant_type(): void
    {
        $validator = new ClientMetadataValidator(['localhost']);

        try {
            $validator->validate([
                'redirect_uris' => ['http://localhost/cb'],
                'grant_types' => ['authorization_code', 'client_credentials'],
            ]);
            self::fail('Expected OAuthServerException');
        } catch (OAuthServerException $e) {
            self::assertSame('invalid_client_metadata', $e->getPayload()['error']);
        }
    }

    public function test_rejects_when_redirect_uris_missing(): void
    {
        $validator = new ClientMetadataValidator(['localhost']);

        try {
            $validator->validate(['grant_types' => ['authorization_code']]);
            self::fail('Expected OAuthServerException');
        } catch (OAuthServerException $e) {
            self::assertSame('invalid_client_metadata', $e->getPayload()['error']);
        }
    }
}
