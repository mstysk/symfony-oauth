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

final class AuthorizationControllerTest extends WebTestCase
{
    private KernelBrowser $client;
    private EntityManagerInterface $em;

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
    }

    public function test_unauthenticated_request_redirects_to_login(): void
    {
        $this->client->request('GET', '/oauth/authorize?client_id=anything');

        self::assertSame(302, $this->client->getResponse()->getStatusCode());
        self::assertStringContainsString('/login', (string) $this->client->getResponse()->headers->get('Location'));
    }

    public function test_authenticated_request_without_code_challenge_returns_400(): void
    {
        $clientId = $this->seedClient();
        $this->loginAsAlice();

        $this->client->request('GET', sprintf(
            '/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code',
            $clientId,
            'http://localhost:8000/cb',
        ));

        $status = $this->client->getResponse()->getStatusCode();
        if ($status === 302) {
            self::fail('Request redirected to ' . $this->client->getResponse()->headers->get('Location'));
        }

        self::assertSame(400, $status);
        $payload = json_decode((string) $this->client->getResponse()->getContent(), associative: true);
        self::assertSame('invalid_request', $payload['error']);
    }

    public function test_authorize_with_resource_outside_allowlist_redirects_with_invalid_target(): void
    {
        $clientId = $this->seedClient();
        $this->loginAsAlice();

        $this->client->request('GET', sprintf(
            '/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code&code_challenge=%s&code_challenge_method=S256&state=xyz&resource=%s',
            $clientId,
            'http://localhost:8000/cb',
            str_repeat('a', 43),
            urlencode('http://localhost:8000/other'),
        ));

        self::assertSame(302, $this->client->getResponse()->getStatusCode());
        $location = (string) $this->client->getResponse()->headers->get('Location');
        self::assertStringStartsWith('http://localhost:8000/cb', $location);
        self::assertStringContainsString('error=invalid_target', $location);
        self::assertStringContainsString('state=xyz', $location);
    }

    public function test_authorize_binds_resource_to_authorization_request(): void
    {
        $clientId = $this->seedClient();
        $this->loginAsAlice();

        $this->client->request('GET', sprintf(
            '/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code&code_challenge=%s&code_challenge_method=S256&state=xyz&resource=%s',
            $clientId,
            'http://localhost:8000/cb',
            str_repeat('a', 43),
            urlencode('http://localhost:8000/mcp'),
        ));

        self::assertSame(200, $this->client->getResponse()->getStatusCode());

        $session = $this->client->getRequest()->getSession();
        $authRequest = $this->extractPendingRequest($session);
        self::assertInstanceOf(\App\OAuth\Extension\AuthorizationRequest::class, $authRequest);
        self::assertSame('http://localhost:8000/mcp', $authRequest->getResource());
    }

    public function test_invalid_scope_redirects_to_redirect_uri_with_error(): void
    {
        // RFC 6749 §4.1.2.1: errors after redirect_uri has been validated
        // (here: unknown scope) MUST 302 back to redirect_uri with
        // error=...&state=..., not return JSON on the AS origin.
        $clientId = $this->seedClient();
        $this->loginAsAlice();

        $this->client->request('GET', sprintf(
            '/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code&code_challenge=%s&code_challenge_method=S256&state=xyz&scope=unknown',
            $clientId,
            'http://localhost:8000/cb',
            str_repeat('a', 43),
        ));

        self::assertSame(302, $this->client->getResponse()->getStatusCode());
        $location = (string) $this->client->getResponse()->headers->get('Location');
        self::assertStringStartsWith('http://localhost:8000/cb', $location);
        self::assertStringContainsString('error=invalid_scope', $location);
        self::assertStringContainsString('state=xyz', $location);
    }

    public function test_valid_request_renders_consent_form_and_stashes_pending(): void
    {
        $clientId = $this->seedClient();
        $this->loginAsAlice();

        $crawler = $this->client->request('GET', sprintf(
            '/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code&code_challenge=%s&code_challenge_method=S256&state=xyz',
            $clientId,
            'http://localhost:8000/cb',
            str_repeat('a', 43),
        ));

        self::assertSame(200, $this->client->getResponse()->getStatusCode());
        self::assertGreaterThan(0, $crawler->filter('button[name="decision"]')->count());

        // Form carries the request_id minted at /authorize.
        $requestIdInput = $crawler->filter('input[name="request_id"]');
        self::assertCount(1, $requestIdInput);
        $requestId = (string) $requestIdInput->attr('value');
        self::assertNotEmpty($requestId);

        // Pending request stashed in session under the per-request key.
        $session = $this->client->getRequest()->getSession();
        self::assertNotNull($session->get(AuthorizationController::SESSION_KEY_PREFIX . $requestId));
    }

    public function test_second_authorize_does_not_overwrite_first(): void
    {
        // Confused-deputy defense: a second /authorize that arrives in
        // the same session must not blow away the pending entry the user
        // is currently looking at.
        $clientId = $this->seedClient();
        $this->loginAsAlice();

        $crawler1 = $this->client->request('GET', sprintf(
            '/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code&code_challenge=%s&code_challenge_method=S256&state=first',
            $clientId,
            'http://localhost:8000/cb',
            str_repeat('a', 43),
        ));
        $firstId = (string) $crawler1->filter('input[name="request_id"]')->attr('value');

        $crawler2 = $this->client->request('GET', sprintf(
            '/oauth/authorize?client_id=%s&redirect_uri=%s&response_type=code&code_challenge=%s&code_challenge_method=S256&state=second',
            $clientId,
            'http://localhost:8000/cb',
            str_repeat('b', 43),
        ));
        $secondId = (string) $crawler2->filter('input[name="request_id"]')->attr('value');

        self::assertNotSame($firstId, $secondId, 'Each /authorize must mint a fresh request_id');

        $session = $this->client->getRequest()->getSession();
        self::assertNotNull($session->get(AuthorizationController::SESSION_KEY_PREFIX . $firstId));
        self::assertNotNull($session->get(AuthorizationController::SESSION_KEY_PREFIX . $secondId));
    }

    /**
     * Test helper: pulls whichever pending AuthorizationRequest is in
     * session (assumes there's exactly one).
     */
    private function extractPendingRequest(\Symfony\Component\HttpFoundation\Session\SessionInterface $session): mixed
    {
        foreach ($session->all() as $key => $value) {
            if (str_starts_with((string) $key, AuthorizationController::SESSION_KEY_PREFIX)) {
                return $value;
            }
        }

        return null;
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
}
