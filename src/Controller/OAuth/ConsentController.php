<?php

declare(strict_types=1);

namespace App\Controller\OAuth;

use App\OAuth\Entity\User as OAuthUser;
use App\OAuth\Server\AuthorizationServerFactory;
use League\OAuth2\Server\Exception\OAuthServerException;
use League\OAuth2\Server\RequestTypes\AuthorizationRequestInterface;
use Nyholm\Psr7\Response as Psr7Response;
use Symfony\Bridge\PsrHttpMessage\HttpFoundationFactoryInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Security\Http\Attribute\IsGranted;

final class ConsentController extends AbstractController
{
    public function __construct(
        private readonly AuthorizationServerFactory $serverFactory,
        private readonly CsrfTokenManagerInterface $csrfTokenManager,
        private readonly HttpFoundationFactoryInterface $foundationFactory,
    ) {
    }

    #[Route(
        path: '/oauth/consent',
        name: 'app_oauth_consent',
        methods: ['POST'],
    )]
    #[IsGranted('ROLE_USER')]
    public function __invoke(Request $request): Response
    {
        // All pre-completeAuthorizationRequest failures throw
        // OAuthServerException; OAuthExceptionListener renders the
        // RFC-shaped JSON 400. Keeping the response shape consistent
        // with the rest of the AS.
        $csrf = (string) $request->request->get('_token', '');
        if (!$this->csrfTokenManager->isTokenValid(new CsrfToken('consent', $csrf))) {
            throw OAuthServerException::invalidRequest('_token', 'CSRF token mismatch');
        }

        // Look up the pending request by the request_id embedded in the
        // form. This binds the POST to the specific /authorize that
        // rendered it, so a second /authorize that arrives in the same
        // session under a different client cannot silently swap which
        // request the user "consents" to.
        $requestId = (string) $request->request->get(AuthorizationController::REQUEST_ID_PARAM, '');
        if ($requestId === '' || !preg_match('/^[a-f0-9-]{36}$/i', $requestId)) {
            throw OAuthServerException::invalidRequest('request_id', 'Missing or malformed request_id');
        }

        $session = $request->getSession();
        $sessionKey = AuthorizationController::SESSION_KEY_PREFIX . $requestId;
        $authRequest = $session->get($sessionKey);
        $session->remove($sessionKey);

        if (!$authRequest instanceof AuthorizationRequestInterface) {
            throw OAuthServerException::invalidRequest('request_id', 'No pending authorization request');
        }

        $user = $this->getUser();
        if ($user === null) {
            throw new AccessDeniedException('Authenticated user required for consent');
        }
        // league requires a user on the AuthorizationRequest even when the
        // user denies — without it AuthCodeGrant::completeAuthorizationRequest
        // throws a LogicException.
        $authRequest->setUser(new OAuthUser($user->getUserIdentifier()));

        $decision = (string) $request->request->get('decision', 'deny');
        $authRequest->setAuthorizationApproved($decision === 'allow');

        // completeAuthorizationRequest may throw OAuthServerException —
        // OAuthExceptionListener handles it (302 to redirect_uri for
        // accessDenied, JSON for the rest).
        $psrResponse = $this->serverFactory->create()->completeAuthorizationRequest(
            $authRequest,
            new Psr7Response(),
        );

        return $this->foundationFactory->createResponse($psrResponse);
    }
}
