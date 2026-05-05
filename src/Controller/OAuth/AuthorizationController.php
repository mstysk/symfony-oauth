<?php

declare(strict_types=1);

namespace App\Controller\OAuth;

use App\OAuth\Server\AuthorizationServerFactory;
use Symfony\Bridge\PsrHttpMessage\HttpMessageFactoryInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Uid\Uuid;

final class AuthorizationController extends AbstractController
{
    /**
     * Session-key prefix for pending AuthorizationRequest entries. Each
     * /authorize call mints a unique request_id and stashes the request
     * under "oauth.pending.<request_id>", which is also embedded as a
     * hidden field in the consent form. The POST-side (ConsentController)
     * pulls the entry by exactly that id, so a second /authorize that
     * arrives in the same session under a different client_id does NOT
     * overwrite the entry the user is currently looking at.
     */
    public const SESSION_KEY_PREFIX = 'oauth.pending.';
    public const REQUEST_ID_PARAM = 'request_id';

    public function __construct(
        private readonly AuthorizationServerFactory $serverFactory,
        private readonly HttpMessageFactoryInterface $psrFactory,
    ) {
    }

    #[Route(
        path: '/oauth/authorize',
        name: 'app_oauth_authorize',
        methods: ['GET'],
    )]
    public function __invoke(Request $request): Response
    {
        $psrRequest = $this->psrFactory->createRequest($request);
        $server = $this->serverFactory->create();

        $authRequest = $server->validateAuthorizationRequest($psrRequest);

        $requestId = Uuid::v7()->toRfc4122();
        $request->getSession()->set(self::SESSION_KEY_PREFIX . $requestId, $authRequest);

        return $this->render('oauth/consent.html.twig', [
            'request_id' => $requestId,
            'client_name' => $authRequest->getClient()->getName(),
            'scopes' => array_map(
                static fn ($scope) => $scope->getIdentifier(),
                $authRequest->getScopes(),
            ),
        ]);
    }
}
