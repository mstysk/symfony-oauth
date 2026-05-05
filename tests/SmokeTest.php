<?php

declare(strict_types=1);

namespace App\Tests;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

final class SmokeTest extends WebTestCase
{
    public function test_kernel_boots_in_test_env(): void
    {
        $client = self::createClient();
        $client->request('GET', '/this-route-does-not-exist');

        self::assertSame(404, $client->getResponse()->getStatusCode());
    }
}
