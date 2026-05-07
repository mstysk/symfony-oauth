<?php

declare(strict_types=1);

namespace App\Mcp\Tool;

final class EchoTool implements ToolInterface
{
    public function name(): string
    {
        return 'echo';
    }

    public function description(): string
    {
        return 'Echoes the provided message back.';
    }

    public function inputSchema(): array
    {
        return [
            'type' => 'object',
            'properties' => [
                'message' => ['type' => 'string'],
            ],
            'required' => ['message'],
        ];
    }

    public function call(array $arguments): array
    {
        $message = $arguments['message'] ?? null;
        if (!is_string($message)) {
            throw new \InvalidArgumentException('echo: arguments.message must be a string');
        }

        return [
            ['type' => 'text', 'text' => $message],
        ];
    }
}
