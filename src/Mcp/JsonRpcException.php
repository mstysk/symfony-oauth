<?php

declare(strict_types=1);

namespace App\Mcp;

/**
 * Carries a JSON-RPC 2.0 error code so the controller can translate any
 * dispatcher failure into the right `error.code` in the response.
 *
 * Codes per https://www.jsonrpc.org/specification#error_object.
 */
final class JsonRpcException extends \RuntimeException
{
    public const PARSE_ERROR = -32700;
    public const INVALID_REQUEST = -32600;
    public const METHOD_NOT_FOUND = -32601;
    public const INVALID_PARAMS = -32602;
    public const INTERNAL_ERROR = -32603;

    public function __construct(
        public readonly int $jsonRpcCode,
        string $message,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }

    public static function parseError(string $message): self
    {
        return new self(self::PARSE_ERROR, $message);
    }

    public static function invalidRequest(string $message): self
    {
        return new self(self::INVALID_REQUEST, $message);
    }

    public static function methodNotFound(string $method): self
    {
        return new self(self::METHOD_NOT_FOUND, "Method not found: {$method}");
    }

    public static function invalidParams(string $message, ?\Throwable $previous = null): self
    {
        return new self(self::INVALID_PARAMS, $message, $previous);
    }
}
