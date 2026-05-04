<?php

declare(strict_types=1);

namespace App\Controller\OAuth;

use App\OAuth\Extension\DynamicClientRegistration\ClientRegistrar;
use League\OAuth2\Server\Exception\OAuthServerException;
use Symfony\Component\DependencyInjection\Attribute\Target;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\RateLimiter\RateLimiterFactoryInterface;
use Symfony\Component\Routing\Attribute\Route;

final class ClientRegistrationController
{
    public function __construct(
        private readonly ClientRegistrar $registrar,
        #[Target('dcr')]
        private readonly RateLimiterFactoryInterface $dcrLimiter,
    ) {
    }

    #[Route(
        path: '/oauth/register',
        name: 'app_oauth_register',
        methods: ['POST'],
    )]
    public function __invoke(Request $request): JsonResponse
    {
        $limit = $this->dcrLimiter->create($request->getClientIp() ?? 'anon')->consume(1);
        if (!$limit->isAccepted()) {
            $retryAfter = max(0, $limit->getRetryAfter()->getTimestamp() - time());

            return new JsonResponse(
                ['error' => 'too_many_requests'],
                429,
                ['Retry-After' => (string) $retryAfter],
            );
        }

        $payload = $this->decodeJson($request);
        if ($payload === null) {
            return new JsonResponse(
                ['error' => 'invalid_client_metadata', 'error_description' => 'Body must be a JSON object'],
                400,
            );
        }

        try {
            $response = $this->registrar->register($payload);
        } catch (OAuthServerException $e) {
            return new JsonResponse($e->getPayload(), $e->getHttpStatusCode());
        }

        return new JsonResponse($response, 201);
    }

    /** @return array<string, mixed>|null */
    private function decodeJson(Request $request): ?array
    {
        $content = $request->getContent();
        if ($content === '') {
            return null;
        }

        $decoded = json_decode($content, associative: true);

        return \is_array($decoded) ? $decoded : null;
    }
}
