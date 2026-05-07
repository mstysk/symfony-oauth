<?php

declare(strict_types=1);

namespace App\EventListener;

use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

/**
 * Adds the RFC 6750 §3 + RFC 9728 §5.1 WWW-Authenticate header to 401/403
 * responses from /mcp. The header tells MCP Inspector / Claude Desktop:
 *   - this is a Bearer-token resource (so the client knows to acquire one),
 *   - and where to discover the AS that issued it
 *     (resource_metadata pointing at /.well-known/oauth-protected-resource).
 *
 * Done in a listener instead of inline in the controller / authenticator
 * because the 401 path comes from Symfony's security layer (start() →
 * Response('', 401)), not from the controller, and the listener is the
 * only single hook that sees both kinds of response.
 */
#[AsEventListener(event: ResponseEvent::class)]
final class McpAuthenticationListener
{
    public function __construct(private readonly UrlGeneratorInterface $urlGenerator)
    {
    }

    public function __invoke(ResponseEvent $event): void
    {
        $request = $event->getRequest();
        $path = $request->getPathInfo();
        if ($path !== '/mcp' && !str_starts_with($path, '/mcp/')) {
            return;
        }

        $response = $event->getResponse();
        $status = $response->getStatusCode();
        if ($status !== Response::HTTP_UNAUTHORIZED && $status !== Response::HTTP_FORBIDDEN) {
            return;
        }

        $resourceMetadata = $this->urlGenerator->generate(
            'app_well_known_oauth_protected_resource',
            [],
            UrlGeneratorInterface::ABSOLUTE_URL,
        );

        // RFC 6750 §3.1: a 403 with insufficient_scope SHOULD include
        // `error="insufficient_scope"` plus `scope="..."` listing the
        // required scope, so the client can request a fresh token bearing it.
        $challenge = $status === Response::HTTP_FORBIDDEN
            ? sprintf(
                'Bearer realm="symfony-oauth", error="insufficient_scope", scope="mcp", resource_metadata="%s"',
                $resourceMetadata,
            )
            : sprintf(
                'Bearer realm="symfony-oauth", resource_metadata="%s"',
                $resourceMetadata,
            );

        $response->headers->set('WWW-Authenticate', $challenge);
    }
}
