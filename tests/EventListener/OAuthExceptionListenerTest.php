<?php

declare(strict_types=1);

namespace App\Tests\EventListener;

use App\EventListener\OAuthExceptionListener;
use League\OAuth2\Server\Exception\OAuthServerException;
use PHPUnit\Framework\TestCase;
use Symfony\Bridge\PsrHttpMessage\Factory\HttpFoundationFactory;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\ExceptionEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;

final class OAuthExceptionListenerTest extends TestCase
{
    public function test_invalid_request_becomes_400_json(): void
    {
        $event = $this->dispatch(OAuthServerException::invalidRequest('client_id'));

        $response = $event->getResponse();
        self::assertNotNull($response);
        self::assertSame(400, $response->getStatusCode());
        $payload = json_decode((string) $response->getContent(), associative: true);
        self::assertSame('invalid_request', $payload['error']);
    }

    public function test_invalid_grant_becomes_400_json(): void
    {
        $event = $this->dispatch(OAuthServerException::invalidGrant('expired'));

        $response = $event->getResponse();
        self::assertNotNull($response);
        self::assertSame(400, $response->getStatusCode());
        self::assertSame(
            'invalid_grant',
            json_decode((string) $response->getContent(), associative: true)['error'],
        );
    }

    public function test_access_denied_with_redirect_becomes_302(): void
    {
        $event = $this->dispatch(OAuthServerException::accessDenied(
            'denied',
            'http://localhost:8000/cb?state=xyz',
        ));

        $response = $event->getResponse();
        self::assertNotNull($response);
        self::assertSame(302, $response->getStatusCode());
        self::assertStringContainsString(
            'error=access_denied',
            (string) $response->headers->get('Location'),
        );
    }

    public function test_non_oauth_exception_is_not_handled(): void
    {
        $event = $this->dispatch(new \RuntimeException('something else'));

        self::assertNull($event->getResponse());
    }

    private function dispatch(\Throwable $exception): ExceptionEvent
    {
        $listener = new OAuthExceptionListener(new HttpFoundationFactory());
        $event = new ExceptionEvent(
            $this->createStub(HttpKernelInterface::class),
            new Request(),
            HttpKernelInterface::MAIN_REQUEST,
            $exception,
        );
        $listener->__invoke($event);

        return $event;
    }
}
