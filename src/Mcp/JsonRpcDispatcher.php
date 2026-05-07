<?php

declare(strict_types=1);

namespace App\Mcp;

use App\Mcp\Tool\ToolInterface;
use Symfony\Component\DependencyInjection\Attribute\AutowireIterator;

/**
 * Routes a single JSON-RPC method to the matching MCP handler. Pure: takes
 * the parsed envelope's method+params, returns the `result` payload (or
 * throws JsonRpcException). Has no Symfony / HTTP dependency.
 */
final class JsonRpcDispatcher
{
    /** @var array<string, ToolInterface> */
    private array $toolsByName = [];

    /** @param iterable<ToolInterface> $tools */
    public function __construct(
        #[AutowireIterator('app.mcp_tool')]
        iterable $tools,
    ) {
        foreach ($tools as $tool) {
            $this->toolsByName[$tool->name()] = $tool;
        }
    }

    /**
     * @param  array<string, mixed> $params
     * @return array<string, mixed>
     *
     * @throws JsonRpcException
     */
    public function dispatch(string $method, array $params): array
    {
        return match ($method) {
            'initialize' => $this->initialize(),
            'tools/list' => $this->toolsList(),
            'tools/call' => $this->toolsCall($params),
            default => throw JsonRpcException::methodNotFound($method),
        };
    }

    /** @return array<string, mixed> */
    private function initialize(): array
    {
        return [
            // MCP spec rev currently in widespread use by Inspector / Claude Desktop.
            'protocolVersion' => '2025-03-26',
            'capabilities' => [
                'tools' => ['listChanged' => false],
            ],
            'serverInfo' => [
                'name' => 'symfony-oauth',
                'version' => '0.2.0',
            ],
        ];
    }

    /** @return array<string, mixed> */
    private function toolsList(): array
    {
        $tools = [];
        foreach ($this->toolsByName as $tool) {
            $tools[] = [
                'name' => $tool->name(),
                'description' => $tool->description(),
                'inputSchema' => $tool->inputSchema(),
            ];
        }

        return ['tools' => $tools];
    }

    /**
     * @param  array<string, mixed> $params
     * @return array<string, mixed>
     */
    private function toolsCall(array $params): array
    {
        $name = $params['name'] ?? null;
        if (!is_string($name)) {
            throw JsonRpcException::invalidParams('tools/call: params.name must be a string');
        }
        if (!isset($this->toolsByName[$name])) {
            throw JsonRpcException::invalidParams("tools/call: unknown tool '{$name}'");
        }

        $arguments = $params['arguments'] ?? [];
        if (!is_array($arguments)) {
            throw JsonRpcException::invalidParams('tools/call: params.arguments must be an object');
        }

        try {
            /** @var array<string, mixed> $arguments */
            $content = $this->toolsByName[$name]->call($arguments);
        } catch (\InvalidArgumentException $e) {
            throw JsonRpcException::invalidParams($e->getMessage(), $e);
        }

        return [
            'content' => $content,
            'isError' => false,
        ];
    }
}
