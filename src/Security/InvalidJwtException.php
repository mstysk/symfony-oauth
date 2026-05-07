<?php

declare(strict_types=1);

namespace App\Security;

/**
 * Thrown by JwtAccessTokenValidator when a Bearer JWT fails any check
 * required to call /mcp. The `reason` is preserved separately from the
 * message so tests can assert which check caught the invalid token, and
 * the BearerJwtAuthenticator can map specific reasons to log levels or
 * different error envelopes if that ever matters.
 */
final class InvalidJwtException extends \RuntimeException
{
    public function __construct(
        public readonly InvalidJwtReason $reason,
        string $message,
        ?\Throwable $previous = null,
    ) {
        parent::__construct($message, 0, $previous);
    }
}
