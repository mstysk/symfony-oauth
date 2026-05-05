<?php

declare(strict_types=1);

namespace App\OAuth\Extension;

use League\OAuth2\Server\RequestTypes\AuthorizationRequest as LeagueAuthorizationRequest;

/**
 * Extends league's AuthorizationRequest with the RFC 8707 `resource`
 * indicator so that ResourceIndicatorGrant can bind the validated
 * resource onto the auth code at completion time.
 *
 * Returned by ResourceIndicatorGrant::createAuthorizationRequest(); the
 * AuthorizationController stashes this in session for the consent step
 * and ConsentController hands it back to completeAuthorizationRequest().
 */
final class AuthorizationRequest extends LeagueAuthorizationRequest
{
    private ?string $resource = null;

    public function getResource(): ?string
    {
        return $this->resource;
    }

    public function setResource(?string $resource): void
    {
        $this->resource = $resource;
    }
}
