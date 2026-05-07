<?php

declare(strict_types=1);

namespace App\Controller\Mcp;

use App\Mcp\JsonRpcDispatcher;
use App\Mcp\JsonRpcException;
use App\Security\BearerJwtAuthenticator;
use App\Security\ValidatedToken;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

/**
 * MCP Resource Server entry point. Accepts a single JSON-RPC 2.0 message
 * over POST and returns a single JSON-RPC response (or 202 No Content for
 * a notification). No SSE, no session resumability — Phase 2 is the
 * minimum surface a Bearer-JWT-authenticated MCP client needs to call
 * tools/list and tools/call.
 *
 * Auth (Bearer JWT) is enforced by the security firewall on ^/mcp; this
 * controller only runs for an authenticated request.
 */
final class McpController
{
    public function __construct(private readonly JsonRpcDispatcher $dispatcher)
    {
    }

    #[Route('/mcp', name: 'app_mcp', methods: ['POST'])]
    public function __invoke(Request $request): Response
    {
        try {
            $payload = json_decode($request->getContent(), associative: true, flags: \JSON_THROW_ON_ERROR);
        } catch (\JsonException $e) {
            return $this->errorResponse(null, JsonRpcException::PARSE_ERROR, 'Parse error: ' . $e->getMessage());
        }

        if (!is_array($payload)) {
            return $this->errorResponse(null, JsonRpcException::INVALID_REQUEST, 'Request must be a JSON object.');
        }

        // JSON-RPC 2.0: a notification has no `id` member at all (vs. id=null
        // which is still a request). Track that distinction explicitly so
        // dispatcher errors on notifications produce 202, not an error body.
        $isNotification = !array_key_exists('id', $payload);
        /** @var int|string|null $id */
        $id = $payload['id'] ?? null;

        if (($payload['jsonrpc'] ?? null) !== '2.0') {
            return $isNotification
                ? new Response('', Response::HTTP_ACCEPTED)
                : $this->errorResponse($id, JsonRpcException::INVALID_REQUEST, 'jsonrpc must be "2.0".');
        }

        $method = $payload['method'] ?? null;
        if (!is_string($method)) {
            return $isNotification
                ? new Response('', Response::HTTP_ACCEPTED)
                : $this->errorResponse($id, JsonRpcException::INVALID_REQUEST, 'method must be a string.');
        }

        $params = $payload['params'] ?? [];
        if (!is_array($params)) {
            return $isNotification
                ? new Response('', Response::HTTP_ACCEPTED)
                : $this->errorResponse($id, JsonRpcException::INVALID_REQUEST, 'params must be an object if present.');
        }

        // RFC 6750 §3.1 — `initialize` is the only method allowed without
        // the `mcp` scope (per MCP discovery semantics: a client should be
        // able to negotiate protocol version before exposing tool calls).
        // Everything else requires the scope; missing it is 403, not 401,
        // since the token IS valid — it just isn't authorized for /mcp's
        // tool surface. The WWW-Authenticate scope-challenge header is
        // attached by McpAuthenticationListener.
        if ($method !== 'initialize') {
            $validated = $request->attributes->get(BearerJwtAuthenticator::VALIDATED_TOKEN_ATTRIBUTE);
            if (!$validated instanceof ValidatedToken || !$validated->hasScope('mcp')) {
                return $isNotification
                    ? new Response('', Response::HTTP_ACCEPTED)
                    : new JsonResponse([
                        'jsonrpc' => '2.0',
                        'id' => $id,
                        'error' => ['code' => -32000, 'message' => 'insufficient_scope'],
                    ], Response::HTTP_FORBIDDEN);
            }
        }

        try {
            /** @var array<string, mixed> $params */
            $result = $this->dispatcher->dispatch($method, $params);
        } catch (JsonRpcException $e) {
            return $isNotification
                ? new Response('', Response::HTTP_ACCEPTED)
                : $this->errorResponse($id, $e->jsonRpcCode, $e->getMessage());
        }

        if ($isNotification) {
            return new Response('', Response::HTTP_ACCEPTED);
        }

        return new JsonResponse([
            'jsonrpc' => '2.0',
            'id' => $id,
            'result' => $result,
        ]);
    }

    private function errorResponse(int|string|null $id, int $code, string $message): JsonResponse
    {
        // Per JSON-RPC 2.0 §5: HTTP transports return 200 even on a JSON-RPC
        // error so the client reads error.code from the body. (HTTP 4xx/5xx
        // is reserved for transport-level failures like auth or server crash.)
        return new JsonResponse([
            'jsonrpc' => '2.0',
            'id' => $id,
            'error' => ['code' => $code, 'message' => $message],
        ]);
    }
}
