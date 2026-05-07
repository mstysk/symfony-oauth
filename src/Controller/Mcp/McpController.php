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
            return $this->errorResponse(false, null, JsonRpcException::PARSE_ERROR, 'Parse error: ' . $e->getMessage());
        }

        if (!is_array($payload)) {
            return $this->errorResponse(false, null, JsonRpcException::INVALID_REQUEST, 'Request must be a JSON object.');
        }

        // JSON-RPC 2.0: a notification has no `id` member at all (vs. id=null
        // which is still a request). errorResponse() honors that — a notification
        // gets 202 with no body even when its envelope is malformed.
        $isNotification = !array_key_exists('id', $payload);
        // JSON-RPC 2.0 §4: id is "a String, Number, or NULL" — Number
        // includes float, so don't narrow to int|string|null.
        /** @var int|float|string|null $id */
        $id = $payload['id'] ?? null;

        if (($payload['jsonrpc'] ?? null) !== '2.0') {
            return $this->errorResponse($isNotification, $id, JsonRpcException::INVALID_REQUEST, 'jsonrpc must be "2.0".');
        }

        $method = $payload['method'] ?? null;
        if (!is_string($method)) {
            return $this->errorResponse($isNotification, $id, JsonRpcException::INVALID_REQUEST, 'method must be a string.');
        }

        $params = $payload['params'] ?? [];
        if (!is_array($params)) {
            return $this->errorResponse($isNotification, $id, JsonRpcException::INVALID_REQUEST, 'params must be an object if present.');
        }

        // RFC 6750 §3.1 — `initialize` is the only method allowed without
        // the `mcp` scope (per MCP discovery semantics: a client should be
        // able to negotiate protocol version before exposing tool calls).
        // Missing scope on any other method is 403 (the token is valid, it
        // just isn't authorized for /mcp's tool surface).
        //
        // Note: a notification (no `id`) without scope returns 202 with no
        // body — JSON-RPC notifications never receive a response, so the
        // 403 + WWW-Authenticate challenge is unreachable for that path.
        // Notification clients without scope will silently no-op.
        if ($method !== 'initialize') {
            $validated = $request->attributes->get(BearerJwtAuthenticator::VALIDATED_TOKEN_ATTRIBUTE);
            if (!$validated instanceof ValidatedToken || !$validated->hasScope('mcp')) {
                return $this->errorResponse(
                    $isNotification,
                    $id,
                    JsonRpcException::INSUFFICIENT_SCOPE,
                    'insufficient_scope',
                    Response::HTTP_FORBIDDEN,
                );
            }
        }

        try {
            /** @var array<string, mixed> $params */
            $result = $this->dispatcher->dispatch($method, $params);
        } catch (JsonRpcException $e) {
            return $this->errorResponse($isNotification, $id, $e->jsonRpcCode, $e->getMessage());
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

    private function errorResponse(
        bool $isNotification,
        int|float|string|null $id,
        int $code,
        string $message,
        int $httpStatus = Response::HTTP_OK,
    ): Response {
        if ($isNotification) {
            return new Response('', Response::HTTP_ACCEPTED);
        }

        // Per JSON-RPC 2.0 §5: HTTP transports return 200 even on a JSON-RPC
        // error so the client reads error.code from the body. /mcp deviates
        // for 403 (insufficient_scope) so RFC 6750 §3.1 clients can react
        // to the status code; the body still carries the JSON-RPC error.
        return new JsonResponse([
            'jsonrpc' => '2.0',
            'id' => $id,
            'error' => ['code' => $code, 'message' => $message],
        ], $httpStatus);
    }
}
