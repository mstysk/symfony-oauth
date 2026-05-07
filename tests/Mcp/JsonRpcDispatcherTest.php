<?php

declare(strict_types=1);

namespace App\Tests\Mcp;

use App\Mcp\JsonRpcDispatcher;
use App\Mcp\JsonRpcException;
use App\Mcp\Tool\EchoTool;
use PHPUnit\Framework\TestCase;

final class JsonRpcDispatcherTest extends TestCase
{
    private function dispatcher(): JsonRpcDispatcher
    {
        return new JsonRpcDispatcher([new EchoTool()]);
    }

    public function test_initialize_returns_protocol_version_and_server_info(): void
    {
        $result = $this->dispatcher()->dispatch('initialize', []);

        self::assertSame('2025-03-26', $result['protocolVersion']);
        self::assertSame(['tools' => ['listChanged' => false]], $result['capabilities']);
        self::assertSame(['name' => 'symfony-oauth', 'version' => '0.2.0'], $result['serverInfo']);
    }

    public function test_tools_list_returns_registered_tools(): void
    {
        $result = $this->dispatcher()->dispatch('tools/list', []);

        self::assertCount(1, $result['tools']);
        $first = $result['tools'][0];
        self::assertSame('echo', $first['name']);
        self::assertSame('Echoes the provided message back.', $first['description']);
        self::assertArrayHasKey('inputSchema', $first);
    }

    public function test_tools_call_with_valid_arguments_returns_content_block(): void
    {
        $result = $this->dispatcher()->dispatch('tools/call', [
            'name' => 'echo',
            'arguments' => ['message' => 'hi'],
        ]);

        self::assertSame([['type' => 'text', 'text' => 'hi']], $result['content']);
        self::assertFalse($result['isError']);
    }

    public function test_unknown_method_returns_method_not_found(): void
    {
        $this->expectException(JsonRpcException::class);
        $this->expectExceptionCode(0);

        try {
            $this->dispatcher()->dispatch('does/not/exist', []);
        } catch (JsonRpcException $e) {
            self::assertSame(JsonRpcException::METHOD_NOT_FOUND, $e->jsonRpcCode);
            throw $e;
        }
    }

    public function test_tools_call_with_unknown_tool_name_returns_invalid_params(): void
    {
        try {
            $this->dispatcher()->dispatch('tools/call', ['name' => 'no-such-tool']);
            self::fail('Expected JsonRpcException');
        } catch (JsonRpcException $e) {
            self::assertSame(JsonRpcException::INVALID_PARAMS, $e->jsonRpcCode);
            self::assertStringContainsString('no-such-tool', $e->getMessage());
        }
    }

    public function test_tools_call_with_missing_name_returns_invalid_params(): void
    {
        try {
            $this->dispatcher()->dispatch('tools/call', []);
            self::fail('Expected JsonRpcException');
        } catch (JsonRpcException $e) {
            self::assertSame(JsonRpcException::INVALID_PARAMS, $e->jsonRpcCode);
        }
    }

    public function test_tools_call_with_invalid_tool_argument_returns_invalid_params(): void
    {
        try {
            $this->dispatcher()->dispatch('tools/call', [
                'name' => 'echo',
                'arguments' => [], // missing required 'message'
            ]);
            self::fail('Expected JsonRpcException');
        } catch (JsonRpcException $e) {
            self::assertSame(JsonRpcException::INVALID_PARAMS, $e->jsonRpcCode);
            // The dispatcher wraps the tool's InvalidArgumentException so the
            // tool author gets to phrase the user-facing message.
            self::assertStringContainsString('arguments.message', $e->getMessage());
        }
    }
}
