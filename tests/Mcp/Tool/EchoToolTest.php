<?php

declare(strict_types=1);

namespace App\Tests\Mcp\Tool;

use App\Mcp\Tool\EchoTool;
use PHPUnit\Framework\TestCase;

final class EchoToolTest extends TestCase
{
    public function test_metadata_describes_a_message_string_input(): void
    {
        $tool = new EchoTool();

        self::assertSame('echo', $tool->name());
        self::assertSame('Echoes the provided message back.', $tool->description());
        self::assertSame(
            [
                'type' => 'object',
                'properties' => ['message' => ['type' => 'string']],
                'required' => ['message'],
            ],
            $tool->inputSchema(),
        );
    }

    public function test_call_returns_message_in_text_content_block(): void
    {
        $tool = new EchoTool();

        self::assertSame(
            [['type' => 'text', 'text' => 'hello']],
            $tool->call(['message' => 'hello']),
        );
    }

    public function test_call_with_missing_message_throws_invalid_argument(): void
    {
        $tool = new EchoTool();

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('echo: arguments.message must be a string');

        $tool->call([]);
    }

    public function test_call_with_non_string_message_throws_invalid_argument(): void
    {
        $tool = new EchoTool();

        $this->expectException(\InvalidArgumentException::class);

        $tool->call(['message' => ['not', 'a', 'string']]);
    }
}
