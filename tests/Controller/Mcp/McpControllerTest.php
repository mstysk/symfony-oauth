<?php

declare(strict_types=1);

namespace App\Tests\Controller\Mcp;

use Symfony\Bundle\FrameworkBundle\KernelBrowser;
use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

/**
 * Smoke tests for /mcp wiring through the Symfony framework. Auth is not
 * yet enforced (commit 11 adds the firewall + Bearer authenticator); these
 * cases will be merged into McpAuthenticationTest in commit 14, which
 * exercises the full security path.
 */
final class McpControllerTest extends WebTestCase
{
    private KernelBrowser $client;

    protected function setUp(): void
    {
        $this->client = self::createClient();
    }

    public function test_tools_list_returns_echo_tool_via_framework(): void
    {
        $this->postJson(['jsonrpc' => '2.0', 'id' => 1, 'method' => 'tools/list']);

        self::assertResponseIsSuccessful();
        $body = $this->jsonBody();
        self::assertSame('2.0', $body['jsonrpc']);
        self::assertSame(1, $body['id']);
        self::assertCount(1, $body['result']['tools']);
        self::assertSame('echo', $body['result']['tools'][0]['name']);
    }

    public function test_invalid_jsonrpc_version_returns_invalid_request_error(): void
    {
        $this->postJson(['jsonrpc' => '1.0', 'id' => 1, 'method' => 'tools/list']);

        $body = $this->jsonBody();
        self::assertSame(-32600, $body['error']['code']);
    }

    public function test_malformed_json_returns_parse_error(): void
    {
        $this->client->request(
            method: 'POST',
            uri: '/mcp',
            server: ['CONTENT_TYPE' => 'application/json'],
            content: '{not json',
        );

        $body = $this->jsonBody();
        self::assertSame(-32700, $body['error']['code']);
    }

    public function test_notification_with_no_id_returns_202(): void
    {
        $this->postJson(['jsonrpc' => '2.0', 'method' => 'tools/list']);

        self::assertSame(202, $this->client->getResponse()->getStatusCode());
        self::assertSame('', (string) $this->client->getResponse()->getContent());
    }

    /** @param array<string, mixed> $payload */
    private function postJson(array $payload): void
    {
        $this->client->request(
            method: 'POST',
            uri: '/mcp',
            server: ['CONTENT_TYPE' => 'application/json'],
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
}
