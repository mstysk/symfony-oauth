<?php

declare(strict_types=1);

namespace App\EventListener;

use League\OAuth2\Server\Exception\OAuthServerException;
use Nyholm\Psr7\Response as Psr7Response;
use Symfony\Bridge\PsrHttpMessage\HttpFoundationFactoryInterface;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;

/**
 * Single point where OAuthServerException is rendered. Lets controllers
 * just throw — the listener calls generateHttpResponse() so:
 *   - exceptions with a redirectUri (e.g. accessDenied during consent)
 *     become 302 redirects to the client,
 *   - others become RFC-shaped JSON with the right status.
 */
#[AsEventListener(event: ExceptionEvent::class)]
final class OAuthExceptionListener
{
    public function __construct(
        private readonly HttpFoundationFactoryInterface $foundationFactory,
    ) {
    }

    public function __invoke(ExceptionEvent $event): void
    {
        $exception = $event->getThrowable();
        if (!$exception instanceof OAuthServerException) {
            return;
        }

        $psrResponse = $exception->generateHttpResponse(new Psr7Response());
        $event->setResponse($this->foundationFactory->createResponse($psrResponse));
    }
}
