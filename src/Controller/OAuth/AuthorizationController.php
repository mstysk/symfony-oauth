<?php

declare(strict_types=1);

namespace App\Controller\OAuth;

use App\OAuth\Server\AuthorizationServerFactory;
use Symfony\Bridge\PsrHttpMessage\HttpMessageFactoryInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
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

        // Let OAuthServerException bubble — OAuthExceptionListener calls
        // $e->generateHttpResponse() which renders the right shape per
        // RFC 6749 §4.1.2.1: 302 to redirect_uri for class-(b) errors
        // (invalid_scope, server_error, invalid_request after redirect_uri
        // has been validated), and JSON for class-(a) errors thrown before
        // a usable redirect_uri is available (missing/invalid client_id,
        // unregistered redirect_uri, missing PKCE).
        $authRequest = $server->validateAuthorizationRequest($psrRequest);

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
