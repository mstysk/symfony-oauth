<?php

declare(strict_types=1);

namespace App\Tests\Controller\OAuth;

use App\Controller\OAuth\AuthorizationController;
use App\OAuth\Entity\Client;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Tools\SchemaTool;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Component\Security\Core\User\InMemoryUserProvider;
use Symfony\Component\Uid\Uuid;
use Symfony\Contracts\Cache\CacheInterface;

final class ConsentControllerTest extends WebTestCase
{
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

    public function test_missing_csrf_returns_400(): void
    {
        $this->loginAsAlice();
        $this->primePendingRequest();

        $this->client->request('POST', '/oauth/consent', ['decision' => 'allow']);

        self::assertSame(400, $this->client->getResponse()->getStatusCode());
        $payload = json_decode((string) $this->client->getResponse()->getContent(), associative: true);
        self::assertSame('invalid_request', $payload['error']);
    }

    public function test_no_pending_request_returns_400(): void
    {
        $this->loginAsAlice();
        $token = $this->primePendingRequestAndExtractCsrf();

        // Drop the pending request manually to simulate "no pending".
        $session = $this->client->getRequest()->getSession();
        $session->remove(AuthorizationController::PENDING_REQUEST_KEY);
        $session->save();

        $this->client->request('POST', '/oauth/consent', [
            '_token' => $token,
            'decision' => 'allow',
        ]);

        self::assertSame(400, $this->client->getResponse()->getStatusCode());
        $payload = json_decode((string) $this->client->getResponse()->getContent(), associative: true);
        self::assertSame('invalid_request', $payload['error']);
    }

    public function test_allow_redirects_to_redirect_uri_with_code(): void
    {
        $this->loginAsAlice();
        $token = $this->primePendingRequestAndExtractCsrf();

        $this->client->request('POST', '/oauth/consent', [
            '_token' => $token,
            'decision' => 'allow',
        ]);

        self::assertSame(302, $this->client->getResponse()->getStatusCode());
        $location = (string) $this->client->getResponse()->headers->get('Location');
        self::assertStringStartsWith('http://localhost:8000/cb', $location);
        self::assertMatchesRegularExpression('/[?&]code=/', $location);
        self::assertMatchesRegularExpression('/[?&]state=xyz/', $location);
    }

    public function test_deny_redirects_with_access_denied_error(): void
    {
        $this->loginAsAlice();
        $token = $this->primePendingRequestAndExtractCsrf();

        $this->client->request('POST', '/oauth/consent', [
            '_token' => $token,
            'decision' => 'deny',
        ]);

        self::assertSame(302, $this->client->getResponse()->getStatusCode());
        $location = (string) $this->client->getResponse()->headers->get('Location');
        self::assertStringContainsString('error=access_denied', $location);
    }

    public function test_replay_after_consume_returns_400(): void
    {
        $this->loginAsAlice();
        $token = $this->primePendingRequestAndExtractCsrf();

        $this->client->request('POST', '/oauth/consent', [
            '_token' => $token,
            'decision' => 'allow',
        ]);
        self::assertSame(302, $this->client->getResponse()->getStatusCode());

        $this->client->request('POST', '/oauth/consent', [
            '_token' => $token,
            'decision' => 'allow',
        ]);
        self::assertSame(400, $this->client->getResponse()->getStatusCode());
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

    private function primePendingRequest(): void
    {
        $this->primePendingRequestAndExtractCsrf();
    }

    /**
     * GET /oauth/authorize to stash the pending request, then return the
     * CSRF token from the rendered consent form (kept under the same
     * session as the subsequent POST).
     */
    private function primePendingRequestAndExtractCsrf(): string
    {
        $crawler = $this->client->request('GET', sprintf(
            '/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code&code_challenge=%s&code_challenge_method=S256&state=xyz',
            $this->clientId,
            'http://localhost:8000/cb',
            str_repeat('a', 43),
        ));
        if ($this->client->getResponse()->getStatusCode() !== 200) {
            self::fail('Authorize step failed: ' . $this->client->getResponse()->getStatusCode());
        }

        $token = (string) $crawler->filter('input[name="_token"]')->attr('value');
        if ($token === '') {
            self::fail('CSRF token not found in consent form');
        }

        return $token;
    }
}
