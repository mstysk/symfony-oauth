<?php

declare(strict_types=1);

namespace App\Mcp\Tool;

/**
 * One MCP tool exposed at /mcp via tools/list and tools/call.
 *
 * Implementations are auto-tagged `app.mcp_tool` (see config/services.yaml)
 * and injected as `iterable` into the JSON-RPC dispatcher. To add a tool,
 * write a new final class implementing this interface — no registry edit.
 */
interface ToolInterface
{
    public function name(): string;

    public function description(): string;

    /**
     * JSON Schema describing the `arguments` payload of tools/call.
     *
     * @return array<string, mixed>
     */
    public function inputSchema(): array;

    /**
     * Execute the tool. Throws \InvalidArgumentException on bad input —
     * the dispatcher translates that to JSON-RPC error -32602.
     *
     * @param  array<string, mixed> $arguments
     * @return list<array<string, mixed>> MCP `content` blocks (e.g. `[{type: 'text', text: '...'}]`)
     */
    public function call(array $arguments): array;
}
