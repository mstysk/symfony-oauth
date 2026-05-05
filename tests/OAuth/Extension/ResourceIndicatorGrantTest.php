<?php

declare(strict_types=1);

namespace App\Tests\OAuth\Extension;

use App\OAuth\Extension\AllowedResources;
use App\OAuth\Extension\ResourceIndicatorGrant;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;
use League\OAuth2\Server\Repositories\RefreshTokenRepositoryInterface;
use League\OAuth2\Server\ResponseTypes\ResponseTypeInterface;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ServerRequestInterface;

final class ResourceIndicatorGrantTest extends TestCase
{
    public function test_authorize_without_code_challenge_throws_invalid_request(): void
    {
        $grant = $this->makeGrant();
        $request = $this->makeRequest(query: [
            'client_id' => 'c1',
            // no code_challenge
        ]);

        try {
            $grant->validateAuthorizationRequest($request);
            self::fail('Expected OAuthServerException');
        } catch (OAuthServerException $e) {
            self::assertSame('invalid_request', $e->getPayload()['error']);
            self::assertStringContainsString('PKCE', $e->getPayload()['hint']);
        }
    }

    public function test_authorize_with_non_s256_method_throws_invalid_request(): void
    {
        $grant = $this->makeGrant();
        $request = $this->makeRequest(query: [
            'client_id' => 'c1',
            'code_challenge' => str_repeat('a', 43),
            'code_challenge_method' => 'plain',
        ]);

        try {
            $grant->validateAuthorizationRequest($request);
            self::fail('Expected OAuthServerException');
        } catch (OAuthServerException $e) {
            self::assertSame('invalid_request', $e->getPayload()['error']);
            self::assertStringContainsString('S256', $e->getPayload()['hint']);
        }
    }

    public function test_token_request_without_resource_throws_invalid_target(): void
    {
        $grant = $this->makeGrant();
        $request = $this->makeRequest(body: [
            'grant_type' => 'authorization_code',
            'code' => 'x',
        ]);

        $this->expectInvalidTarget(fn () => $grant->respondToAccessTokenRequest(
            $request,
            $this->createStub(ResponseTypeInterface::class),
            new \DateInterval('PT1H'),
        ));
    }

    #[DataProvider('acceptable_scheme_cases')]
    public function test_acceptable_resource_scheme(string $resource, bool $expected): void
    {
        self::assertSame($expected, ResourceIndicatorGrant::isAcceptableResourceScheme($resource));
    }

    public static function acceptable_scheme_cases(): iterable
    {
        // https — always OK.
        yield 'https any host' => ['https://api.example/mcp', true];
        // http — only localhost variants.
        yield 'http localhost' => ['http://localhost:8000/mcp', true];
        yield 'http 127.0.0.1' => ['http://127.0.0.1:8000/mcp', true];
        // IPv6 localhost — parse_url returns "[::1]"; the helper must
        // strip the brackets before comparing to the allowlist.
        yield 'http [::1]' => ['http://[::1]:8000/mcp', true];
        // http on non-localhost — rejected.
        yield 'http example' => ['http://example.com/mcp', false];
        // bad shape.
        yield 'no scheme' => ['/relative', false];
        yield 'garbage' => ['not a url', false];
    }

    public function test_token_request_with_disallowed_scheme_throws_invalid_target(): void
    {
        $grant = $this->makeGrant();
        $request = $this->makeRequest(body: [
            'resource' => 'http://example.com/mcp',  // http but not localhost
        ]);

        $this->expectInvalidTarget(fn () => $grant->respondToAccessTokenRequest(
            $request,
            $this->createStub(ResponseTypeInterface::class),
            new \DateInterval('PT1H'),
        ));
    }

    public function test_token_request_with_unlisted_resource_throws_invalid_target(): void
    {
        $grant = $this->makeGrant(allowed: ['http://localhost:8000/mcp']);
        $request = $this->makeRequest(body: [
            'resource' => 'http://localhost:8000/other',
        ]);

        $this->expectInvalidTarget(fn () => $grant->respondToAccessTokenRequest(
            $request,
            $this->createStub(ResponseTypeInterface::class),
            new \DateInterval('PT1H'),
        ));
    }

    /** @param string[] $allowed */
    private function makeGrant(array $allowed = ['http://localhost:8000/mcp']): ResourceIndicatorGrant
    {
        return new ResourceIndicatorGrant(
            authCodeRepository: $this->createStub(AuthCodeRepositoryInterface::class),
            refreshTokenRepository: $this->createStub(RefreshTokenRepositoryInterface::class),
            authCodeTTL: new \DateInterval('PT10M'),
            allowedResources: new AllowedResources($allowed),
        );
    }

    /**
     * @param array<string, string> $query
     * @param array<string, string> $body
     */
    private function makeRequest(array $query = [], array $body = []): ServerRequestInterface
    {
        $request = $this->createStub(ServerRequestInterface::class);
        $request->method('getQueryParams')->willReturn($query);
        $request->method('getParsedBody')->willReturn($body);

        return $request;
    }

    private function expectInvalidTarget(callable $fn): void
    {
        try {
            $fn();
            self::fail('Expected OAuthServerException with error=invalid_target');
        } catch (OAuthServerException $e) {
            self::assertSame('invalid_target', $e->getPayload()['error']);
            self::assertSame(400, $e->getHttpStatusCode());
        }
    }
}
