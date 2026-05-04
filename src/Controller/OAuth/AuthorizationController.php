<?php

declare(strict_types=1);

namespace App\Controller\OAuth;

use App\OAuth\Server\AuthorizationServerFactory;
use League\OAuth2\Server\Exception\OAuthServerException;
use Symfony\Bridge\PsrHttpMessage\HttpMessageFactoryInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

final class AuthorizationController extends AbstractController
{
    public const PENDING_REQUEST_KEY = 'oauth.pending_authorization_request';

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

        try {
            $authRequest = $server->validateAuthorizationRequest($psrRequest);
        } catch (OAuthServerException $e) {
            return new JsonResponse($e->getPayload(), $e->getHttpStatusCode());
        }

        $request->getSession()->set(self::PENDING_REQUEST_KEY, $authRequest);

        return $this->render('oauth/consent.html.twig', [
            'client_name' => $authRequest->getClient()->getName(),
            'scopes' => array_map(
                static fn ($scope) => $scope->getIdentifier(),
                $authRequest->getScopes(),
            ),
        ]);
    }
}
