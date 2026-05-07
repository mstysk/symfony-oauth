<?php

declare(strict_types=1);

namespace App\Security;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Http\Authenticator\AbstractAuthenticator;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

/**
 * Authenticates a request to /mcp via the Bearer JWT in the Authorization
 * header. Delegates the actual checks (signature, exp, iss, aud, kid,
 * revocation) to JwtAccessTokenValidator and stashes the resulting
 * ValidatedToken on the request so McpController can read scopes /
 * audiences for per-method authorization.
 *
 * The 401 entry-point body is intentionally empty — RFC 6750 §3 puts
 * Bearer challenge information in the WWW-Authenticate header, which
 * McpAuthenticationListener attaches in the response phase.
 */
final class BearerJwtAuthenticator extends AbstractAuthenticator implements AuthenticationEntryPointInterface
{
    public const VALIDATED_TOKEN_ATTRIBUTE = 'mcp_validated_token';

    public function __construct(private readonly JwtAccessTokenValidator $validator)
    {
    }

    public function supports(Request $request): bool
    {
        // RFC 7235 §2.1: auth-scheme is case-insensitive.
        return stripos((string) $request->headers->get('Authorization', ''), 'bearer ') === 0;
    }

    public function authenticate(Request $request): Passport
    {
        $auth = (string) $request->headers->get('Authorization', '');
        // The scheme keyword is always 7 chars ('Bearer '/'bearer '/'BEARER '),
        // so the slice is independent of the casing supports() accepted.
        $rawJwt = substr($auth, 7);

        try {
            $validated = $this->validator->validate($rawJwt);
        } catch (InvalidJwtException $e) {
            throw new CustomUserMessageAuthenticationException($e->getMessage(), [], 0, $e);
        }

        // Pass the parsed claims through to the controller. We can't use
        // a custom security token because Symfony's stateless firewall
        // re-creates a generic PostAuthenticationToken; the request is
        // the only object with a guaranteed lifetime through to controller.
        $request->attributes->set(self::VALIDATED_TOKEN_ATTRIBUTE, $validated);

        return new SelfValidatingPassport(
            new UserBadge(
                $validated->jti,
                static fn (string $id): InMemoryUser => new InMemoryUser($id, null, ['ROLE_USER']),
            ),
        );
    }

    public function onAuthenticationSuccess(
        Request $request,
        \Symfony\Component\Security\Core\Authentication\Token\TokenInterface $token,
        string $firewallName,
    ): ?Response {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): Response
    {
        return new Response('', Response::HTTP_UNAUTHORIZED);
    }

    public function start(Request $request, ?AuthenticationException $authException = null): Response
    {
        return new Response('', Response::HTTP_UNAUTHORIZED);
    }
}
