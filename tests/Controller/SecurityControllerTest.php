<?php

declare(strict_types=1);

namespace App\Tests\Controller;

use Symfony\Bundle\FrameworkBundle\Test\WebTestCase;

final class SecurityControllerTest extends WebTestCase
{
    public function test_get_login_renders_form(): void
    {
        $client = self::createClient();
        $crawler = $client->request('GET', '/login');

        self::assertSame(200, $client->getResponse()->getStatusCode());
        self::assertCount(1, $crawler->filter('input[name="_username"]'));
        self::assertCount(1, $crawler->filter('input[name="_password"]'));
        self::assertCount(1, $crawler->filter('input[name="_csrf_token"]'));
    }

    public function test_post_with_valid_credentials_redirects(): void
    {
        $client = self::createClient();
        $crawler = $client->request('GET', '/login');
        $form = $crawler->selectButton('Sign in')->form([
            '_username' => 'alice',
            '_password' => 'password',
        ]);
        $client->submit($form);

        self::assertSame(302, $client->getResponse()->getStatusCode());
    }

    public function test_post_with_invalid_credentials_redirects_back_to_login(): void
    {
        $client = self::createClient();
        $crawler = $client->request('GET', '/login');
        $form = $crawler->selectButton('Sign in')->form([
            '_username' => 'alice',
            '_password' => 'wrong',
        ]);
        $client->submit($form);

        // Symfony's form_login default failure handler redirects back to
        // login_path; the error is then read on the next GET via
        // AuthenticationUtils::getLastAuthenticationError.
        self::assertSame(302, $client->getResponse()->getStatusCode());
        self::assertStringContainsString('/login', (string) $client->getResponse()->headers->get('Location'));
    }
}
