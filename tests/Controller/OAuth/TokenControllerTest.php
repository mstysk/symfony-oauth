<?php

declare(strict_types=1);

namespace App\Tests\Controller\OAuth;

use App\OAuth\Entity\Client;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Tools\SchemaTool;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\Security\Core\User\InMemoryUserProvider;
use Symfony\Component\Uid\Uuid;
use Symfony\Contracts\Cache\CacheInterface;

final class TokenControllerTest extends WebTestCase
{
    private const CODE_VERIFIER = 'verifier-verifier-verifier-verifier-verifier-x';
    private KernelBrowser $client;
    private EntityManagerInterface $em;
    private string $clientId;

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

        $cache = self::getContainer()->get('cache.app');
        \assert($cache instanceof CacheInterface);
        $cache->clear();

        $this->clientId = $this->seedClient();
    }

    public function test_full_authorization_code_flow_with_resource_indicator(): void
    {
        $this->loginAsAlice();
        $code = $this->runAuthorizeAndConsent();

        $this->client->request('POST', '/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $this->clientId,
            'redirect_uri' => 'http://localhost:8000/cb',
            'code_verifier' => self::CODE_VERIFIER,
            'code' => $code,
            'resource' => 'http://localhost:8000/mcp',
        ]);

        self::assertSame(200, $this->client->getResponse()->getStatusCode(), (string) $this->client->getResponse()->getContent());

        $body = json_decode((string) $this->client->getResponse()->getContent(), associative: true);
        self::assertArrayHasKey('access_token', $body);
        self::assertSame('Bearer', $body['token_type']);
        self::assertArrayHasKey('refresh_token', $body);

        // The JWT carries aud === [resource] per RFC 8707.
        $jwt = (new Parser(new JoseEncoder()))->parse($body['access_token']);
        self::assertSame(['http://localhost:8000/mcp'], $jwt->claims()->get('aud'));
        self::assertSame('http://localhost:8000', $jwt->claims()->get('iss'));
    }

    public function test_token_request_without_resource_returns_invalid_target(): void
    {
        $this->loginAsAlice();
        $code = $this->runAuthorizeAndConsent();

        $this->client->request('POST', '/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $this->clientId,
            'redirect_uri' => 'http://localhost:8000/cb',
            'code_verifier' => self::CODE_VERIFIER,
            'code' => $code,
            // resource missing
        ]);

        self::assertSame(400, $this->client->getResponse()->getStatusCode());
        $body = json_decode((string) $this->client->getResponse()->getContent(), associative: true);
        self::assertSame('invalid_target', $body['error']);
    }

    public function test_token_request_with_unlisted_resource_returns_invalid_target(): void
    {
        $this->loginAsAlice();
        $code = $this->runAuthorizeAndConsent();

        $this->client->request('POST', '/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $this->clientId,
            'redirect_uri' => 'http://localhost:8000/cb',
            'code_verifier' => self::CODE_VERIFIER,
            'code' => $code,
            'resource' => 'http://localhost:8000/other',
        ]);

        self::assertSame(400, $this->client->getResponse()->getStatusCode());
        $body = json_decode((string) $this->client->getResponse()->getContent(), associative: true);
        self::assertSame('invalid_target', $body['error']);
    }

    public function test_token_resource_mismatch_with_bound_value_returns_invalid_target(): void
    {
        // /authorize binds resource=http://localhost:8000/mcp; /token then
        // sends a different (but allowlisted) resource — must reject.
        $this->loginAsAlice();
        $code = $this->runAuthorizeAndConsent(boundResource: 'http://localhost:8000/mcp');

        $this->client->request('POST', '/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $this->clientId,
            'redirect_uri' => 'http://localhost:8000/cb',
            'code_verifier' => self::CODE_VERIFIER,
            'code' => $code,
            // Different from the one bound at /authorize. Even if it were
            // allowlisted, the audience must match what the user authorized.
            'resource' => 'http://localhost:8000/different',
        ]);

        self::assertSame(400, $this->client->getResponse()->getStatusCode());
        $body = json_decode((string) $this->client->getResponse()->getContent(), associative: true);
        self::assertSame('invalid_target', $body['error']);
    }

    public function test_refresh_token_grant_issues_a_new_access_token(): void
    {
        $this->loginAsAlice();
        $code = $this->runAuthorizeAndConsent();

        // 1) Exchange the auth code for the initial token pair.
        $this->client->request('POST', '/oauth/token', [
            'grant_type' => 'authorization_code',
            'client_id' => $this->clientId,
            'redirect_uri' => 'http://localhost:8000/cb',
            'code_verifier' => self::CODE_VERIFIER,
            'code' => $code,
            'resource' => 'http://localhost:8000/mcp',
        ]);
        self::assertSame(200, $this->client->getResponse()->getStatusCode());
        $first = json_decode((string) $this->client->getResponse()->getContent(), associative: true);
        self::assertArrayHasKey('refresh_token', $first);

        // 2) Use the refresh_token to issue a fresh access_token.
        $this->client->request('POST', '/oauth/token', [
            'grant_type' => 'refresh_token',
            'client_id' => $this->clientId,
            'refresh_token' => $first['refresh_token'],
        ]);

        self::assertSame(
            200,
            $this->client->getResponse()->getStatusCode(),
            'refresh_token grant should be enabled — got: ' . (string) $this->client->getResponse()->getContent(),
        );

        $second = json_decode((string) $this->client->getResponse()->getContent(), associative: true);
        self::assertArrayHasKey('access_token', $second);
        self::assertNotSame($first['access_token'], $second['access_token']);
        self::assertArrayHasKey('refresh_token', $second);
    }

    private function seedClient(): string
    {
        $id = Uuid::v7();
        $this->em->persist(new Client(
            id: $id,
            name: 'demo',
            secretHash: null,
            redirectUris: ['http://localhost:8000/cb'],
            grantTypes: ['authorization_code', 'refresh_token'],
            scopes: ['mcp'],
            dcrMetadata: [],
        ));
        $this->em->flush();

        return $id->toRfc4122();
    }

    private function loginAsAlice(): void
    {
        /** @var InMemoryUserProvider $provider */
        $provider = self::getContainer()->get('security.user.provider.concrete.in_memory');
        $user = $provider->loadUserByIdentifier('alice');
        $this->client->loginUser($user);
    }

    /**
     * Runs GET /oauth/authorize → POST /oauth/consent (allow), returns the
     * authorization code from the redirect. When `boundResource` is set, it
     * is sent as the RFC 8707 `resource` parameter at /authorize so the
     * AuthCode row is bound to it.
     */
    private function runAuthorizeAndConsent(?string $boundResource = null): string
    {
        $codeChallenge = rtrim(strtr(base64_encode(hash('sha256', self::CODE_VERIFIER, true)), '+/', '-_'), '=');

        $authorizeUrl = sprintf(
            '/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code&code_challenge=%s&code_challenge_method=S256&state=xyz',
            $this->clientId,
            'http://localhost:8000/cb',
            $codeChallenge,
        );
        if ($boundResource !== null) {
            $authorizeUrl .= '&resource=' . urlencode($boundResource);
        }

        $crawler = $this->client->request('GET', $authorizeUrl);
        if ($this->client->getResponse()->getStatusCode() !== 200) {
            self::fail('Authorize step failed: ' . $this->client->getResponse()->getStatusCode());
        }

        $token = (string) $crawler->filter('input[name="_token"]')->attr('value');
        $requestId = (string) $crawler->filter('input[name="request_id"]')->attr('value');

        $this->client->request('POST', '/oauth/consent', [
            '_token' => $token,
            'request_id' => $requestId,
            'decision' => 'allow',
        ]);
        if ($this->client->getResponse()->getStatusCode() !== 302) {
            self::fail('Consent allow failed: ' . $this->client->getResponse()->getStatusCode() . ' ' . (string) $this->client->getResponse()->getContent());
        }

        $location = (string) $this->client->getResponse()->headers->get('Location');
        $query = [];
        parse_str(parse_url($location, PHP_URL_QUERY) ?? '', $query);
        if (!isset($query['code']) || !\is_string($query['code'])) {
            self::fail("No code in redirect: $location");
        }

        return $query['code'];
    }
}
