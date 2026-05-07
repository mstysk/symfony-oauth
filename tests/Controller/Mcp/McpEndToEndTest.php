<?php

declare(strict_types=1);

namespace App\Tests\Controller\Mcp;

use App\OAuth\Entity\Client;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Tools\SchemaTool;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\Security\Core\User\InMemoryUserProvider;
use Symfony\Component\Uid\Uuid;

/**
 * E2E smoke test: drives the full Phase 1 + Phase 2 path —
 *   /oauth/authorize → /oauth/consent → /oauth/token → /mcp tools/call echo
 * — to prove the access token issued by the AS authenticates against
 * the RS, and the JWT's iss/aud/scope/kid all line up between the two
 * halves of the same Symfony process.
 *
 * One test method only; per-claim coverage lives in McpAuthenticationTest
 * (functional, mint-and-call) and JwtAccessTokenValidatorTest (unit).
 */
final class McpEndToEndTest extends WebTestCase
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

        $this->clientId = $this->seedClient();
    }

    public function test_full_flow_from_authorize_through_mcp_tools_call(): void
    {
        $this->loginAsAlice();
        $code = $this->runAuthorizeAndConsent('http://localhost:8000/mcp');

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
        self::assertIsArray($body);
        self::assertIsString($body['access_token']);
        $accessToken = $body['access_token'];

        // Now call /mcp with the freshly-minted Bearer token.
        $this->client->request(
            method: 'POST',
            uri: '/mcp',
            server: [
                'CONTENT_TYPE' => 'application/json',
                'HTTP_AUTHORIZATION' => 'Bearer ' . $accessToken,
            ],
            content: json_encode([
                'jsonrpc' => '2.0',
                'id' => 42,
                'method' => 'tools/call',
                'params' => ['name' => 'echo', 'arguments' => ['message' => 'hello phase 2']],
            ], \JSON_THROW_ON_ERROR),
        );

        self::assertResponseIsSuccessful();
        $rpc = json_decode((string) $this->client->getResponse()->getContent(), associative: true);
        self::assertIsArray($rpc);
        self::assertSame('2.0', $rpc['jsonrpc']);
        self::assertSame(42, $rpc['id']);
        self::assertSame(
            [['type' => 'text', 'text' => 'hello phase 2']],
            $rpc['result']['content'],
        );
        self::assertFalse($rpc['result']['isError']);
    }

    private function seedClient(): string
    {
        $id = Uuid::v7();
        $this->em->persist(new Client(
            id: $id,
            name: 'mcp-e2e',
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

    private function runAuthorizeAndConsent(string $boundResource): string
    {
        $codeChallenge = rtrim(strtr(base64_encode(hash('sha256', self::CODE_VERIFIER, true)), '+/', '-_'), '=');

        $authorizeUrl = sprintf(
            '/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code&code_challenge=%s&code_challenge_method=S256&state=xyz&resource=%s&scope=mcp',
            $this->clientId,
            'http://localhost:8000/cb',
            $codeChallenge,
            urlencode($boundResource),
        );

        $crawler = $this->client->request('GET', $authorizeUrl);
        self::assertSame(200, $this->client->getResponse()->getStatusCode());

        $token = (string) $crawler->filter('input[name="_token"]')->attr('value');
        $requestId = (string) $crawler->filter('input[name="request_id"]')->attr('value');

        $this->client->request('POST', '/oauth/consent', [
            '_token' => $token,
            'request_id' => $requestId,
            'decision' => 'allow',
        ]);
        self::assertSame(
            302,
            $this->client->getResponse()->getStatusCode(),
            'Consent allow failed: ' . (string) $this->client->getResponse()->getContent(),
        );

        $location = (string) $this->client->getResponse()->headers->get('Location');
        $query = [];
        parse_str(parse_url($location, \PHP_URL_QUERY) ?? '', $query);
        self::assertArrayHasKey('code', $query);
        self::assertIsString($query['code']);

        return $query['code'];
    }
}
