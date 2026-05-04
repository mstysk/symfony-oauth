<?php

declare(strict_types=1);

namespace App\Controller\WellKnown;

use App\OAuth\Extension\ServerMetadataBuilder;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Attribute\Route;

final class AuthorizationServerMetadataController
{
    public function __construct(private readonly ServerMetadataBuilder $builder)
    {
    }

    #[Route(
        path: '/.well-known/oauth-authorization-server',
        name: 'app_well_known_oauth_authorization_server',
        methods: ['GET'],
    )]
    public function __invoke(): JsonResponse
    {
        return new JsonResponse($this->builder->build());
    }
}
