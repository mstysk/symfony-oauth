<?php

declare(strict_types=1);

namespace App\Controller\WellKnown;

use App\OAuth\Extension\ProtectedResourceMetadataBuilder;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Attribute\Route;

final class ProtectedResourceMetadataController
{
    public function __construct(private readonly ProtectedResourceMetadataBuilder $builder)
    {
    }

    #[Route(
        path: '/.well-known/oauth-protected-resource',
        name: 'app_well_known_oauth_protected_resource',
        methods: ['GET'],
    )]
    public function __invoke(): JsonResponse
    {
        return new JsonResponse($this->builder->build());
    }
}
