<?php

declare(strict_types=1);

namespace App\Tests\Controller\Mcp;

use App\OAuth\Entity\AccessToken;
use App\OAuth\Extension\KidDeriver;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Tools\SchemaTool;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * Functional tests for /mcp Bearer JWT auth + scope enforcement.
 *
 * Each test mints its own JWT with McpAccessTokenEntity (the real path
 * tokens take in production), so the only thing being short-circuited is
 * the `/oauth/authorize → /oauth/token` flow — which has its own
 * coverage in TokenControllerTest. That keeps each negative case to a
 * single assertion's worth of work and lets us cover the seven distinct
 * validator-rejection paths without seven full OAuth flows.
 */
final class McpAuthenticationTest extends WebTestCase
{
    private const ISSUER = 'http://localhost:8000';
    private const AUDIENCE = 'http://localhost:8000/mcp';

    private KernelBrowser $client;
    private EntityManagerInterface $em;
    private string $privateKeyPath;
    private string $publicKeyPath;
    private string $expectedKid;

    protected function setUp(): void
    {
        $this->client = self::createClient();
        $this->em = self::getContainer()->get(EntityManagerInterface::class);

        $tool = new SchemaTool($this->em);
        $metas = $this->em->getMetadataFactory()->getAllMetadata();
        $tool->dropDatabase();
        if ($metas !== []) {
            $tool->createSchema($metas);
        }

        // Read the same key paths the validator's binding sees. In CI the
        // path comes from .env.test as %kernel.project_dir%/tests/fixtures/...;
        // in local Docker the compose environment sets /app/config/jwt/...
        // and dotenv won't override (overrideExistingVars: false). Resolve
        // the placeholder ourselves so this test matches the validator either
        // way without forking the env at the bootstrap layer.
        $projectDir = \dirname(__DIR__, 3);
        $this->privateKeyPath = $this->resolveKeyPath((string) ($_SERVER['OAUTH_PRIVATE_KEY_PATH'] ?? ''), $projectDir);
        $this->publicKeyPath = $this->resolveKeyPath((string) ($_SERVER['OAUTH_PUBLIC_KEY_PATH'] ?? ''), $projectDir);
        $this->expectedKid = (new KidDeriver($this->publicKeyPath))->derive();
    }

    public function test_request_without_bearer_returns_401_with_www_authenticate_header(): void
    {
        $this->postJsonRpc(['jsonrpc' => '2.0', 'id' => 1, 'method' => 'tools/list']);

        $response = $this->client->getResponse();
        self::assertSame(401, $response->getStatusCode());
        // The generated host is environment-dependent (KernelBrowser
        // defaults to "localhost"; production runs on localhost:8000).
        // Pin only the path portion of resource_metadata.
        $challenge = (string) $response->headers->get('WWW-Authenticate');
        self::assertStringContainsString('Bearer realm="symfony-oauth"', $challenge);
        self::assertMatchesRegularExpression(
            '~resource_metadata="https?://[^/]+/\.well-known/oauth-protected-resource"~',
            $challenge,
        );
    }

    public function test_request_with_invalid_signature_returns_401(): void
    {
        $jwt = $this->mintJwt();
        $segments = explode('.', $jwt);
        $segments[2] = rtrim(strtr(base64_encode(random_bytes(256)), '+/', '-_'), '=');
        $tampered = implode('.', $segments);

        $this->postJsonRpc(['jsonrpc' => '2.0', 'id' => 1, 'method' => 'tools/list'], $tampered);

        self::assertSame(401, $this->client->getResponse()->getStatusCode());
    }

    public function test_request_with_wrong_audience_returns_401(): void
    {
        $jwt = $this->mintJwt(audiences: ['http://attacker.example/mcp']);

        $this->postJsonRpc(['jsonrpc' => '2.0', 'id' => 1, 'method' => 'tools/list'], $jwt);

        self::assertSame(401, $this->client->getResponse()->getStatusCode());
    }

    public function test_request_with_wrong_issuer_returns_401(): void
    {
        $jwt = $this->mintJwt(issuer: 'http://attacker.example/');

        $this->postJsonRpc(['jsonrpc' => '2.0', 'id' => 1, 'method' => 'tools/list'], $jwt);

        self::assertSame(401, $this->client->getResponse()->getStatusCode());
    }

    public function test_request_with_kid_mismatch_returns_401(): void
    {
        $jwt = $this->mintJwt(kid: 'deadbeefdeadbeef');

        $this->postJsonRpc(['jsonrpc' => '2.0', 'id' => 1, 'method' => 'tools/list'], $jwt);

        self::assertSame(401, $this->client->getResponse()->getStatusCode());
    }

    public function test_request_with_revoked_token_returns_401(): void
    {
        $this->seedAccessToken('jti-revoked', revoked: true);
        $jwt = $this->mintJwt(jti: 'jti-revoked');

        $this->postJsonRpc(['jsonrpc' => '2.0', 'id' => 1, 'method' => 'tools/list'], $jwt);

        self::assertSame(401, $this->client->getResponse()->getStatusCode());
    }

    public function test_tools_call_without_mcp_scope_returns_403_insufficient_scope(): void
    {
        $this->seedAccessToken('jti-noscope');
        $jwt = $this->mintJwt(jti: 'jti-noscope', scopes: []);

        $this->postJsonRpc([
            'jsonrpc' => '2.0',
            'id' => 1,
            'method' => 'tools/call',
            'params' => ['name' => 'echo', 'arguments' => ['message' => 'hi']],
        ], $jwt);

        $response = $this->client->getResponse();
        self::assertSame(403, $response->getStatusCode());
        $body = $this->jsonBody();
        self::assertSame(-32000, $body['error']['code']);
        self::assertSame('insufficient_scope', $body['error']['message']);

        $challenge = (string) $response->headers->get('WWW-Authenticate');
        self::assertStringContainsString('error="insufficient_scope"', $challenge);
        self::assertStringContainsString('scope="mcp"', $challenge);
    }

    public function test_initialize_returns_server_info_and_capabilities(): void
    {
        $this->seedAccessToken('jti-init');
        // Even with no `mcp` scope, initialize is allowed (per MCP spec).
        $jwt = $this->mintJwt(jti: 'jti-init', scopes: []);

        $this->postJsonRpc(['jsonrpc' => '2.0', 'id' => 1, 'method' => 'initialize'], $jwt);

        self::assertResponseIsSuccessful();
        $body = $this->jsonBody();
        self::assertSame('2025-03-26', $body['result']['protocolVersion']);
        self::assertSame('symfony-oauth', $body['result']['serverInfo']['name']);
    }

    public function test_tools_list_returns_echo_tool(): void
    {
        $this->seedAccessToken('jti-list');
        $jwt = $this->mintJwt(jti: 'jti-list');

        $this->postJsonRpc(['jsonrpc' => '2.0', 'id' => 1, 'method' => 'tools/list'], $jwt);

        self::assertResponseIsSuccessful();
        $body = $this->jsonBody();
        self::assertCount(1, $body['result']['tools']);
        self::assertSame('echo', $body['result']['tools'][0]['name']);
    }

    public function test_tools_call_echo_returns_message_in_content(): void
    {
        $this->seedAccessToken('jti-call');
        $jwt = $this->mintJwt(jti: 'jti-call');

        $this->postJsonRpc([
            'jsonrpc' => '2.0',
            'id' => 1,
            'method' => 'tools/call',
            'params' => ['name' => 'echo', 'arguments' => ['message' => 'hello mcp']],
        ], $jwt);

        self::assertResponseIsSuccessful();
        $body = $this->jsonBody();
        self::assertSame([['type' => 'text', 'text' => 'hello mcp']], $body['result']['content']);
        self::assertFalse($body['result']['isError']);
    }

    /** @param array<string, mixed> $payload */
    private function postJsonRpc(array $payload, ?string $bearer = null): void
    {
        $server = ['CONTENT_TYPE' => 'application/json'];
        if ($bearer !== null) {
            $server['HTTP_AUTHORIZATION'] = 'Bearer ' . $bearer;
        }
        $this->client->request(
            method: 'POST',
            uri: '/mcp',
            server: $server,
            content: json_encode($payload, \JSON_THROW_ON_ERROR),
        );
    }

    /** @return array<string, mixed> */
    private function jsonBody(): array
    {
        $decoded = json_decode((string) $this->client->getResponse()->getContent(), associative: true);
        self::assertIsArray($decoded);

        return $decoded;
    }

    /**
     * Mints a Bearer JWT directly via lcobucci/jwt — same shape that
     * McpAccessTokenEntity emits in production, but with named overrides
     * for the adversarial test cases (wrong kid header, wrong issuer, etc.).
     *
     * @param list<string> $audiences
     * @param list<string> $scopes
     */
    private function mintJwt(
        string $jti = 'jti-test-1',
        string $issuer = self::ISSUER,
        ?string $kid = null,
        array $audiences = [self::AUDIENCE],
        array $scopes = ['mcp'],
        ?\DateTimeImmutable $expiresAt = null,
    ): string {
        $config = Configuration::forAsymmetricSigner(
            new Sha256(),
            InMemory::file($this->privateKeyPath),
            InMemory::file($this->publicKeyPath),
        );
        $now = new \DateTimeImmutable();
        $builder = $config->builder()
            ->withHeader('kid', $kid ?? $this->expectedKid)
            ->issuedBy($issuer)
            ->permittedFor(...$audiences)
            ->identifiedBy($jti)
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($now)
            ->expiresAt($expiresAt ?? $now->modify('+1 hour'))
            ->withClaim('client_id', 'client-1')
            ->withClaim('scope', implode(' ', $scopes))
            ->relatedTo('alice');

        return $builder->getToken($config->signer(), $config->signingKey())->toString();
    }

    private function resolveKeyPath(string $value, string $projectDir): string
    {
        return str_replace('%kernel.project_dir%', $projectDir, $value);
    }

    private function seedAccessToken(string $jti, bool $revoked = false): void
    {
        $row = new AccessToken(
            identifier: $jti,
            clientId: 'client-1',
            userId: 'alice',
            expiresAt: new \DateTimeImmutable('+1 hour'),
            scopes: ['mcp'],
            audience: [self::AUDIENCE],
        );
        if ($revoked) {
            $row->revoke();
        }
        $this->em->persist($row);
        $this->em->flush();
    }
}

