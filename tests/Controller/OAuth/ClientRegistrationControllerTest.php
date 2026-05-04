<?php

declare(strict_types=1);

namespace App\Tests\Controller\OAuth;

use App\OAuth\Entity\Client;
use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Tools\SchemaTool;
use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;
use Symfony\Contracts\Cache\CacheInterface;

final class ClientRegistrationControllerTest extends WebTestCase
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

        // Reset rate-limiter buckets so tests don't bleed into each other
        // (the limiter persists state in cache.app across kernel reboots).
        $cache = self::getContainer()->get('cache.app');
        \assert($cache instanceof CacheInterface);
        $cache->clear();
    }

    public function test_successful_registration_returns_201_with_original_redirect_uris(): void
    {
        $body = [
            'client_name' => 'demo',
            'redirect_uris' => ['HTTP://Localhost:9000/Cb'],
            'grant_types' => ['authorization_code', 'refresh_token'],
            'token_endpoint_auth_method' => 'none',
        ];

        $this->client->request(
            'POST',
            '/oauth/register',
            server: ['CONTENT_TYPE' => 'application/json'],
            content: json_encode($body, JSON_THROW_ON_ERROR),
        );

        self::assertSame(201, $this->client->getResponse()->getStatusCode());

        $payload = json_decode((string) $this->client->getResponse()->getContent(), associative: true);
        self::assertSame(['HTTP://Localhost:9000/Cb'], $payload['redirect_uris']);
        self::assertNotEmpty($payload['client_id']);
        self::assertArrayNotHasKey('client_secret', $payload);
    }

    public function test_invalid_redirect_uri_host_returns_400(): void
    {
        $this->client->request(
            'POST',
            '/oauth/register',
            server: ['CONTENT_TYPE' => 'application/json'],
            content: json_encode([
                'redirect_uris' => ['https://attacker.example.com/cb'],
                'grant_types' => ['authorization_code'],
            ], JSON_THROW_ON_ERROR),
        );

        self::assertSame(400, $this->client->getResponse()->getStatusCode());
        $payload = json_decode((string) $this->client->getResponse()->getContent(), associative: true);
        self::assertSame('invalid_redirect_uri', $payload['error']);
    }

    public function test_rate_limit_kicks_in_after_burst(): void
    {
        $body = json_encode([
            'redirect_uris' => ['http://localhost/cb'],
            'grant_types' => ['authorization_code'],
            'token_endpoint_auth_method' => 'none',
        ], JSON_THROW_ON_ERROR);

        $statuses = [];
        for ($i = 0; $i < 7; $i++) {
            $this->client->request(
                'POST',
                '/oauth/register',
                server: [
                    'CONTENT_TYPE' => 'application/json',
                    'REMOTE_ADDR' => '203.0.113.42',
                ],
                content: $body,
            );
            $statuses[] = $this->client->getResponse()->getStatusCode();
        }

        $last = end($statuses);
        self::assertSame(429, $last, 'Last burst attempt should be rate-limited; got ' . implode(',', $statuses));
        self::assertNotEmpty($this->client->getResponse()->headers->get('Retry-After'));
    }

    /** Sanity check that the registered Client makes it to the database. */
    public function test_registered_client_persists_to_db(): void
    {
        $this->client->request(
            'POST',
            '/oauth/register',
            server: ['CONTENT_TYPE' => 'application/json'],
            content: json_encode([
                'client_name' => 'persist-me',
                'redirect_uris' => ['http://localhost/cb'],
                'grant_types' => ['authorization_code'],
                'token_endpoint_auth_method' => 'none',
            ], JSON_THROW_ON_ERROR),
        );

        $payload = json_decode((string) $this->client->getResponse()->getContent(), associative: true);
        $row = $this->em->getRepository(Client::class)->findOneBy([
            'clientIdentifier' => $payload['client_id'],
        ]);

        self::assertInstanceOf(Client::class, $row);
        self::assertSame('persist-me', $row->getName());
    }
}
