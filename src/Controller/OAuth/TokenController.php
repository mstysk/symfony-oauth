<?php

declare(strict_types=1);

namespace App\Controller\OAuth;

use App\OAuth\Server\AuthorizationServerFactory;
use League\OAuth2\Server\Exception\OAuthServerException;
use Nyholm\Psr7\Response as Psr7Response;
use Symfony\Bridge\PsrHttpMessage\HttpFoundationFactoryInterface;
use Symfony\Bridge\PsrHttpMessage\HttpMessageFactoryInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

final class TokenController
{
    public function __construct(
        private readonly AuthorizationServerFactory $serverFactory,
        private readonly HttpMessageFactoryInterface $psrFactory,
        private readonly HttpFoundationFactoryInterface $foundationFactory,
    ) {
    }

    #[Route(
        path: '/oauth/token',
        name: 'app_oauth_token',
        methods: ['POST'],
    )]
    public function __invoke(Request $request): Response
    {
        $psrRequest = $this->psrFactory->createRequest($request);

        try {
            $psrResponse = $this->serverFactory->create()->respondToAccessTokenRequest(
                $psrRequest,
                new Psr7Response(),
            );
        } catch (OAuthServerException $e) {
            $psrResponse = $e->generateHttpResponse(new Psr7Response());
        }

        return $this->foundationFactory->createResponse($psrResponse);
    }
}
