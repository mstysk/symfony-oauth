<?php

declare(strict_types=1);

namespace App\Tests\OAuth\Repository;

use App\OAuth\Entity\Scope;
use App\OAuth\Repository\ScopeRepository;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use PHPUnit\Framework\TestCase;

final class ScopeRepositoryTest extends TestCase
{
    public function test_returns_known_scope(): void
    {
        $repo = new ScopeRepository(['mcp' => 'MCP access']);

        $scope = $repo->getScopeEntityByIdentifier('mcp');

        self::assertInstanceOf(Scope::class, $scope);
        self::assertSame('mcp', $scope->getIdentifier());
    }

    public function test_returns_null_for_unknown_scope(): void
    {
        $repo = new ScopeRepository(['mcp' => 'MCP access']);
        self::assertNull($repo->getScopeEntityByIdentifier('admin'));
    }

    public function test_finalize_scopes_returns_input_unchanged_for_known_scopes(): void
    {
        $repo = new ScopeRepository(['mcp' => 'MCP access']);
        $client = $this->createStub(ClientEntityInterface::class);

        $scopes = [new Scope('mcp')];
        self::assertSame($scopes, $repo->finalizeScopes($scopes, 'authorization_code', $client));
    }
}
