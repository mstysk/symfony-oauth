# OAuth 2.1 Authorization Server (Phase 1) Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement an OAuth 2.1 Authorization Server in this Symfony 8 app that satisfies MCP-spec requirements (RFC 8414/8707/7591/9728) end-to-end, so an MCP client like Claude Desktop can run Discovery → DCR → authorize → token exchange against it. The MCP Resource Server (`/mcp`) is **out of scope** for this plan and must return 404.

**Architecture:** Single Symfony app, single Docker service. `league/oauth2-server` provides PKCE + Authorization Code + Refresh Token grants; MCP-specific extensions (Resource Indicators, Dynamic Client Registration, Authorization Server Metadata, Protected Resource Metadata, family revocation, kid + iss + aud-as-array in JWT) are isolated under `src/OAuth/Extension/` so upstream improvements can replace them later. Persistence is SQLite via Doctrine ORM. Users come from Symfony Security `InMemoryUserProvider`.

**Tech Stack:** PHP 8.4, Symfony 8.0 (FrameworkBundle, SecurityBundle, TwigBundle, DoctrineBundle, DoctrineMigrationsBundle, RateLimiter), `league/oauth2-server` ≥ 9.3, `lcobucci/jwt`, `defuse/php-encryption`, SQLite, PHPUnit (`symfony/test-pack`).

**Spec source of truth:** `docs/plans/2026-04-29-oauth-mcp-poc-design.md`. Whenever this plan and the spec disagree, the spec wins — open the spec, read the relevant section, then update this plan before continuing.

---

## How to use this plan

- All commands run from the repo root: `/Users/masato.yoshioka/github/mstysk/symfony-oauth`.
- Wrap commands in `docker compose exec app …` once Phase A finishes (Docker becomes the runtime). Until then, the host PHP is fine.
- Each task has: a short goal, file list, numbered 2-5-minute steps (test → run-fail → implement → run-pass → commit), and the exact commit message body. Do not skip the "run-fail" step — it confirms the test actually exercises the new code.
- One Task = one commit. Use `feat:` for new behavior, `chore:` for scaffolding, `test:` for test-only commits, `docs:` for prose. Keep subjects ≤ 70 chars.
- All commits append the standard co-author trailer (`Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>`).
- If a step fails for an unrelated reason, **stop and ask** — do not "try a different approach" silently.
- Reference: design doc §1 (invariants), §3 (sequences), §4 (data model + Docker), §5 (test cases).

---

## Phase A — Bootstrap (no OAuth code yet)

### Task A1: Track existing skeleton in git

**Why:** Right now everything in the repo is untracked except for the empty `“root”` commit. Working from a clean tree makes per-task diffs reviewable.

**Files:** all existing scaffolding (`.editorconfig`, `.env`, `.env.dev`, `.gitignore`, `bin/`, `composer.json`, `composer.lock`, `config/`, `public/`, `src/`, `symfony.lock`).

**Step 1: Verify state**

Run: `git status`
Expected: a long "Untracked files" list including `composer.json`, `src/Kernel.php`, etc. The only existing tracked content is `CLAUDE.md` and `docs/plans/`.

**Step 2: Add and commit**

```bash
git add .editorconfig .env .env.dev .gitignore bin config public src symfony.lock composer.json composer.lock
git status                            # confirm nothing else got staged
git commit -m "$(cat <<'EOF'
chore: track Symfony 8.0 skeleton scaffolding

Initial commit of the symfony/skeleton output before any OAuth code.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

**Step 3: Verify**

Run: `git log --oneline`
Expected: three commits — root, design docs, scaffolding.

---

### Task A2: Add Docker (`Dockerfile`, `compose.yaml`, `.dockerignore`)

**Why:** All later tasks run inside the container. We set this up before installing dependencies so `composer install` runs in a controlled environment.

**Files:**
- Create: `Dockerfile`
- Create: `compose.yaml`
- Create: `.dockerignore`

**Step 1: Write `Dockerfile`**

```dockerfile
FROM php:8.4-cli

RUN apt-get update && apt-get install -y --no-install-recommends \
        git unzip libicu-dev libsqlite3-dev libzip-dev \
    && docker-php-ext-install intl pdo_sqlite zip \
    && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

WORKDIR /app
EXPOSE 8000
CMD ["php", "-S", "0.0.0.0:8000", "-t", "public"]
```

**Step 2: Write `compose.yaml`**

```yaml
services:
  app:
    build: .
    ports:
      - "8000:8000"
    environment:
      SYMFONY_DISABLE_DOTENV: "1"
      APP_ENV: ${APP_ENV:-dev}
      APP_SECRET: ${APP_SECRET:-insecure-dev-only}
      DATABASE_URL: ${DATABASE_URL:-sqlite:////app/var/data/oauth.db}
      OAUTH_PRIVATE_KEY_PATH: ${OAUTH_PRIVATE_KEY_PATH:-/app/config/jwt/private.key}
      OAUTH_PUBLIC_KEY_PATH: ${OAUTH_PUBLIC_KEY_PATH:-/app/config/jwt/public.key}
      OAUTH_ENCRYPTION_KEY: ${OAUTH_ENCRYPTION_KEY}
      OAUTH_ACCESS_TOKEN_TTL: ${OAUTH_ACCESS_TOKEN_TTL:-PT1H}
      OAUTH_REFRESH_TOKEN_TTL: ${OAUTH_REFRESH_TOKEN_TTL:-P30D}
      OAUTH_AUTH_CODE_TTL: ${OAUTH_AUTH_CODE_TTL:-PT10M}
      MCP_ALLOWED_RESOURCES: ${MCP_ALLOWED_RESOURCES:-http://localhost:8000/mcp}
      OAUTH_ISSUER: ${OAUTH_ISSUER:-http://localhost:8000}
    volumes:
      - .:/app
      - var-data:/app/var
      - vendor:/app/vendor
volumes:
  var-data:
  vendor:
```

**Step 3: Write `.dockerignore`**

```
.git
docs/
var/
vendor/
```

**Step 4: Build and smoke-test**

Run: `docker compose build`
Expected: build succeeds.

Run: `docker compose up -d`
Expected: container starts, port 8000 listens.

Run: `curl -i http://localhost:8000/`
Expected: 404 (no controllers yet) or 500 (no `vendor/` yet) — either is fine, we just want to confirm the dev server boots.

Run: `docker compose down`

**Step 5: Commit**

```bash
git add Dockerfile compose.yaml .dockerignore
git commit -m "$(cat <<'EOF'
chore: add Docker dev environment (php:8.4-cli + compose)

Single 'app' service with bind-mounted source, named volumes for
var/ and vendor/ (macOS perf), SYMFONY_DISABLE_DOTENV=1 so all env
flows through Compose interpolation.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task A3: `.gitignore` for keys and DB

**Files:**
- Modify: `.gitignore`
- Create: `config/jwt/.gitkeep`
- Create: `var/data/.gitkeep`

**Step 1: Append to `.gitignore`**

```
/config/jwt/*.key
/var/data/*.db
/var/data/*.db-journal
```

**Step 2: Create placeholders**

```bash
mkdir -p config/jwt var/data
touch config/jwt/.gitkeep var/data/.gitkeep
```

**Step 3: Commit**

```bash
git add .gitignore config/jwt/.gitkeep var/data/.gitkeep
git commit -m "$(cat <<'EOF'
chore: ignore JWT keys and SQLite DB files

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task A4: Install runtime dependencies

**Why:** Pull in everything we need so Phase B can write entities directly.

**Files:**
- Modify: `composer.json`
- Modify: `composer.lock`
- Modify: `symfony.lock`
- Modify: `config/bundles.php` (Flex auto-edits)
- Create: various `config/packages/*.yaml` (Flex recipes)

**Step 1: Start the container** (everything below runs through it)

Run: `docker compose up -d`

**Step 2: Install Symfony recipe-managed bundles**

Run:

```bash
docker compose exec app composer require \
  symfony/security-bundle:8.0.* \
  symfony/twig-bundle:8.0.* \
  symfony/form:8.0.* \
  symfony/validator:8.0.* \
  symfony/rate-limiter:8.0.* \
  symfony/uid \
  doctrine/orm:^3 \
  doctrine/doctrine-bundle:^2 \
  doctrine/doctrine-migrations-bundle:^3
```

Expected: Flex prompts for each recipe; accept all defaults (`y`).

**Note:** `symfony/uid` does **not** track Symfony's main version stream — leave it unconstrained and let Composer resolve the latest compatible release.

**Step 3: Install OAuth + JWT libraries**

Run:

```bash
docker compose exec app composer require \
  league/oauth2-server:^9 \
  lcobucci/jwt:^5 \
  defuse/php-encryption:^2 \
  ramsey/uuid:^4
```

**Step 4: Install dev/test dependencies**

Run:

```bash
docker compose exec app composer require --dev \
  symfony/test-pack:^1 \
  symfony/maker-bundle:^1
```

**Step 5: Verify the bundle list**

Run: `docker compose exec app php bin/console debug:dotenv 2>&1 | head -20`
Expected: dotenv table or "Dotenv is disabled" — either is fine; the goal is the container boots without container-compilation errors.

Run: `docker compose exec app php bin/console debug:container --types 2>&1 | head -5`
Expected: a list of autowireable services (proves the container compiled).

Run: `cat config/bundles.php`
Expected: includes `FrameworkBundle`, `SecurityBundle`, `TwigBundle`, `DoctrineBundle`, `DoctrineMigrationsBundle`, `MakerBundle`, `MonologBundle` (or similar).

**Step 6: Commit**

```bash
git add composer.json composer.lock symfony.lock config/ src/ public/
git status                          # nothing else should be added
git commit -m "$(cat <<'EOF'
chore: install Symfony bundles + league/oauth2-server stack

- security-bundle, twig-bundle, form, validator, rate-limiter, uid
- doctrine/orm, doctrine-bundle, doctrine-migrations-bundle
- league/oauth2-server, lcobucci/jwt, defuse/php-encryption
- dev: symfony/test-pack, maker-bundle

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task A5: Generate signing keys + encryption key (host-side, manual)

**Why:** Keys must exist before any OAuth code touches them. They are gitignored, generated once per machine.

**Files:** `config/jwt/private.key`, `config/jwt/public.key` (gitignored).

**Step 1: Generate RSA keypair on host**

Run from repo root:

```bash
openssl genrsa -out config/jwt/private.key 4096
openssl rsa -in config/jwt/private.key -pubout -out config/jwt/public.key
chmod 600 config/jwt/private.key
ls -la config/jwt/
```

Expected: `private.key` 600, `public.key` 644, both ~3 KB.

**Step 2: Generate `OAUTH_ENCRYPTION_KEY`**

Run:

```bash
docker compose exec app vendor/bin/generate-defuse-key
```

Expected: a string starting with `def00000…`.

**Step 3: Add to `.env`**

Open `.env` and paste the key:

```dotenv
###> oauth ###
OAUTH_ENCRYPTION_KEY=def00000…paste-actual-output-here…
###< oauth ###
```

`league/oauth2-server` v9 accepts both the `defuse/php-encryption` format (recommended, what `vendor/bin/generate-defuse-key` produces) and a raw random string. We use the defuse format for parity with future production setups.

**Step 4: Restart the stack so the env reaches PHP**

Run:

```bash
docker compose down
docker compose up -d
docker compose exec app sh -c 'echo "$OAUTH_ENCRYPTION_KEY" | head -c 16'
```

Expected: prints `def00000` followed by 8 chars.

**Step 5: Commit**

Only `.env` changed (the keys themselves are gitignored).

```bash
git add .env
git diff --cached                  # confirm only OAUTH_ENCRYPTION_KEY moved
git commit -m "$(cat <<'EOF'
chore: register OAUTH_ENCRYPTION_KEY in .env

Generated via vendor/bin/generate-defuse-key. RSA signing keys live
under config/jwt/ and remain gitignored — see README for openssl
genrsa instructions.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task A6: README quick-start

**Files:** Create `README.md` (the repo has none).

**Step 1: Write `README.md`**

```markdown
# symfony-oauth — OAuth 2.1 AS for MCP

PoC of an OAuth 2.1 Authorization Server (and, in Phase 2, a co-located
MCP Resource Server) written in PHP/Symfony 8. Spec lives at
`docs/plans/2026-04-29-oauth-mcp-poc-design.md`.

## Quick start

```bash
# 1. Generate RSA signing keys (one-time, host-side)
openssl genrsa -out config/jwt/private.key 4096
openssl rsa -in config/jwt/private.key -pubout -out config/jwt/public.key
chmod 600 config/jwt/private.key

# 2. Generate the defuse/php-encryption key, paste into .env
docker compose run --rm app vendor/bin/generate-defuse-key
# -> set OAUTH_ENCRYPTION_KEY in .env

# 3. Boot
docker compose up

# 4. Apply migrations
docker compose exec app php bin/console doctrine:migrations:migrate -n

# 5. Open http://localhost:8000/.well-known/oauth-authorization-server
```

## Tests

```bash
docker compose exec app vendor/bin/phpunit
```
```

**Step 2: Commit**

```bash
git add README.md
git commit -m "$(cat <<'EOF'
docs: add README quick-start

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task A7: PHPUnit baseline + first sanity test

**Why:** Confirm `WebTestCase` boots before writing any feature tests. If this is broken, every later test will be too.

**Files:**
- Create: `tests/SmokeTest.php`
- Create / modify: `.env.test`
- Inspect: `phpunit.xml.dist` (Flex created it during A4)

**Step 1: Inspect Flex-created `phpunit.xml.dist`**

Run: `cat phpunit.xml.dist`

Confirm `<env name="APP_ENV" value="test" />` is present. If not, add inside `<php>`.

**Step 2: Point the test environment at its own SQLite file via `.env.test`**

`.env.test` is loaded automatically when `APP_ENV=test`, *and only by the host process*. Inside Docker we set `SYMFONY_DISABLE_DOTENV=1`, so for tests we either run them on the host with `APP_ENV=test`, or we add `APP_ENV=test` + `DATABASE_URL=...` to a one-shot `docker compose exec app` env. The cleanest path is to write `.env.test` and run PHPUnit with the host PHP — but we want the container, so we ALSO export the DSN at the test command level.

Create `.env.test`:

```dotenv
KERNEL_CLASS='App\Kernel'
APP_SECRET='insecure-test-only'
SYMFONY_DEPRECATIONS_HELPER='disabled'
DATABASE_URL='sqlite:///%kernel.project_dir%/var/data/test.db'
OAUTH_ISSUER='http://localhost:8000'
OAUTH_PRIVATE_KEY_PATH='%kernel.project_dir%/tests/fixtures/private.key'
OAUTH_PUBLIC_KEY_PATH='%kernel.project_dir%/tests/fixtures/public.key'
OAUTH_ENCRYPTION_KEY='def00000…paste-test-only-key…'
OAUTH_ACCESS_TOKEN_TTL='PT1H'
OAUTH_REFRESH_TOKEN_TTL='P30D'
OAUTH_AUTH_CODE_TTL='PT10M'
MCP_ALLOWED_RESOURCES='http://localhost:8000/mcp'
```

**Do NOT override `doctrine.yaml` per-environment** — that path causes connection collisions. Always source the DSN from `.env.test`.

**Step 3: Adjust the PHPUnit command for Docker**

When running in the container, PHPUnit needs to read `.env.test` even with `SYMFONY_DISABLE_DOTENV=1`. The cleanest workaround: unset that variable for the test command.

```bash
docker compose exec -e SYMFONY_DISABLE_DOTENV=0 -e APP_ENV=test app vendor/bin/phpunit
```

Document this in `README.md` under "Tests".

**Step 4: Write the smoke test**

Create `tests/SmokeTest.php`:

```php
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
```

**Step 5: Run and verify pass**

Run:

```bash
docker compose exec -e SYMFONY_DISABLE_DOTENV=0 -e APP_ENV=test app vendor/bin/phpunit tests/SmokeTest.php
```

Expected: 1 test, 1 assertion, OK.

**Step 6: Commit**

```bash
git add tests/SmokeTest.php .env.test phpunit.xml.dist README.md
git commit -m "$(cat <<'EOF'
test: add WebTestCase smoke test + .env.test for separate test DB

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task A7.5: Generate test-only RSA keypair fixtures

**Why:** Tasks C3a (KidDeriver) and C3b (McpAccessTokenEntity) read `tests/fixtures/public.key` / `private.key`. Without these committed, the tests `markTestSkipped` and ship green by accident. We commit a **test-only** keypair so the suite is deterministic and hermetic. These keys are never used for issuing real tokens.

**Files:**
- Create: `tests/fixtures/private.key` (committed)
- Create: `tests/fixtures/public.key` (committed)
- Create: `tests/fixtures/README.md` (explains the keys are test-only)

**Step 1: Generate**

```bash
mkdir -p tests/fixtures
openssl genrsa -out tests/fixtures/private.key 2048
openssl rsa -in tests/fixtures/private.key -pubout -out tests/fixtures/public.key
chmod 600 tests/fixtures/private.key
```

2048 bits is fine for tests — fast, and the `.gitignore` rule `/config/jwt/*.key` does not match `tests/fixtures/*.key`.

**Step 2: Document**

Create `tests/fixtures/README.md`:

```markdown
# Test fixtures — RSA keypair

`private.key` and `public.key` are committed RSA keys used **only** by
the unit/functional test suite. They MUST NOT be used to sign real
tokens; production keys live under `config/jwt/` and are gitignored.

If you regenerate these, run any test once afterwards and update any
hard-coded `kid` expectations.
```

**Step 3: Verify the gitignore does not match**

Run: `git check-ignore -v tests/fixtures/private.key`
Expected: no output (= file is NOT ignored).

**Step 4: Commit**

```bash
git add tests/fixtures/private.key tests/fixtures/public.key tests/fixtures/README.md
git commit -m "$(cat <<'EOF'
test: add committed test-only RSA keypair fixtures

Used by KidDeriverTest and McpAccessTokenEntityTest. NOT for production.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task A8: Register the Doctrine UUID type

**Why:** Phase B entities use `#[ORM\Column(type: 'uuid')]`, which is **not** a built-in Doctrine DBAL type — it needs explicit registration via `Symfony\Bridge\Doctrine\Types\UuidType`. Without this, `doctrine:migrations:diff` and any test that boots the schema will fail with `Unknown column type "uuid" requested.`

**Files:**
- Modify: `config/packages/doctrine.yaml`

**Step 1: Add the type mapping**

Open `config/packages/doctrine.yaml` and locate the `dbal:` block. Add a `types:` key under it:

```yaml
doctrine:
    dbal:
        url: '%env(resolve:DATABASE_URL)%'
        types:
            uuid: Symfony\Bridge\Doctrine\Types\UuidType
        # ... rest unchanged
```

**Step 2: Verify**

Run: `docker compose exec app php bin/console doctrine:mapping:info 2>&1 | head -5`
Expected: prints "No mapped entities" (we have none yet) — but does NOT print an "Unknown column type" error. Any "uuid" type errors here mean the registration didn't take.

**Step 3: Commit**

```bash
git add config/packages/doctrine.yaml
git commit -m "$(cat <<'EOF'
chore: register Doctrine UUID type for entity mapping

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

## Phase B — Doctrine entities and OAuth state

Each entity lives in `src/OAuth/Entity/` and wears two hats: a Doctrine ORM entity and a `league/oauth2-server` `*EntityInterface` implementation.

**Important — do NOT use league's `EntityTrait` / `TokenEntityTrait` / `ClientTrait` / `AuthCodeTrait` here.** Those traits declare `protected` properties (`$identifier`, `$client`, `$expiryDateTime`, `$userIdentifier`, `$scopes`, `$redirectUri`, etc.) that Doctrine's attribute driver will try to map and then crash because they have no `#[ORM\Column]`. Implement the interface methods manually — there are only 3-7 per interface, and they are trivial getters/setters. The `Scope` and `User` entities (B1, B5) are pure value objects (no Doctrine mapping) so the trait there is fine; from B3 onward, no traits.

Repositories live in `src/OAuth/Repository/`. They are Symfony services (autowired) and implement `league`'s `*RepositoryInterface`. They internally use Doctrine `EntityManagerInterface`.

### Task B1: `Scope` entity + repository

**Files:**
- Create: `src/OAuth/Entity/Scope.php`
- Create: `src/OAuth/Repository/ScopeRepository.php`
- Create: `tests/OAuth/Repository/ScopeRepositoryTest.php`

**Step 1: Write the failing test**

```php
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
        $client = $this->createMock(ClientEntityInterface::class);

        $scopes = [new Scope('mcp')];
        self::assertSame($scopes, $repo->finalizeScopes($scopes, 'authorization_code', $client));
    }
}
```

**Step 2: Run, expect failure**

Run: `docker compose exec app vendor/bin/phpunit tests/OAuth/Repository/ScopeRepositoryTest.php`
Expected: errors — classes don't exist.

**Step 3: Implement**

Create `src/OAuth/Entity/Scope.php`:

```php
<?php

declare(strict_types=1);

namespace App\OAuth\Entity;

use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\ScopeTrait;

final class Scope implements ScopeEntityInterface
{
    use EntityTrait;
    use ScopeTrait;

    public function __construct(string $identifier)
    {
        $this->identifier = $identifier;
    }
}
```

Create `src/OAuth/Repository/ScopeRepository.php`:

```php
<?php

declare(strict_types=1);

namespace App\OAuth\Repository;

use App\OAuth\Entity\Scope;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;
use League\OAuth2\Server\Repositories\ScopeRepositoryInterface;

final class ScopeRepository implements ScopeRepositoryInterface
{
    /** @param array<string, string> $scopes identifier => description */
    public function __construct(private readonly array $scopes)
    {
    }

    public function getScopeEntityByIdentifier(string $identifier): ?ScopeEntityInterface
    {
        return isset($this->scopes[$identifier]) ? new Scope($identifier) : null;
    }

    /**
     * @param ScopeEntityInterface[] $scopes
     * @return ScopeEntityInterface[]
     */
    public function finalizeScopes(
        array $scopes,
        string $grantType,
        ClientEntityInterface $clientEntity,
        ?string $userIdentifier = null,
        ?string $authCodeId = null,
    ): array {
        return $scopes;
    }
}
```

**Step 4: Run, expect pass**

Run: `docker compose exec app vendor/bin/phpunit tests/OAuth/Repository/ScopeRepositoryTest.php`
Expected: 3 tests, OK.

**Step 5: Commit**

```bash
git add src/OAuth/Entity/Scope.php src/OAuth/Repository/ScopeRepository.php tests/OAuth/Repository/ScopeRepositoryTest.php
git commit -m "$(cat <<'EOF'
feat: add Scope entity and array-backed ScopeRepository

Phase 1 has only one scope ('mcp'); the repo accepts a config array
so we don't need a Doctrine entity for scopes yet.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task B2: `RedirectUriNormalizer` (used by Client repository and DCR)

**Why:** Multiple components need consistent URI normalization. Build it standalone, test it standalone.

**Files:**
- Create: `src/OAuth/Extension/RedirectUriNormalizer.php`
- Create: `tests/OAuth/Extension/RedirectUriNormalizerTest.php`

**Step 1: Write the failing test**

```php
<?php

declare(strict_types=1);

namespace App\Tests\OAuth\Extension;

use App\OAuth\Extension\RedirectUriNormalizer;
use PHPUnit\Framework\TestCase;

final class RedirectUriNormalizerTest extends TestCase
{
    /** @dataProvider cases */
    public function test_normalize(string $input, string $expected): void
    {
        self::assertSame($expected, RedirectUriNormalizer::normalize($input));
    }

    public static function cases(): iterable
    {
        // Host is lowercased; scheme is lowercased.
        yield ['HTTP://Localhost:8000/cb', 'http://localhost:8000/cb'];
        yield ['https://EXAMPLE.com/Path', 'https://example.com/Path'];
        // Trailing slash is preserved as-is (strict comparison).
        yield ['https://example.com/cb/', 'https://example.com/cb/'];
        yield ['https://example.com/cb',  'https://example.com/cb'];
        // Query and fragment are kept (RFC 6749 forbids fragments, but we just normalize).
        yield ['https://example.com/cb?x=1', 'https://example.com/cb?x=1'];
    }

    public function test_throws_on_invalid_uri(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        RedirectUriNormalizer::normalize('not a url');
    }
}
```

**Step 2: Run, expect failure**

Run: `docker compose exec app vendor/bin/phpunit tests/OAuth/Extension/RedirectUriNormalizerTest.php`

**Step 3: Implement**

```php
<?php

declare(strict_types=1);

namespace App\OAuth\Extension;

final class RedirectUriNormalizer
{
    public static function normalize(string $uri): string
    {
        $parts = parse_url($uri);
        if ($parts === false || !isset($parts['scheme'], $parts['host'])) {
            throw new \InvalidArgumentException('Invalid redirect_uri: ' . $uri);
        }

        $scheme = strtolower($parts['scheme']);
        $host = strtolower($parts['host']);
        $port = isset($parts['port']) ? ':' . $parts['port'] : '';
        $path = $parts['path'] ?? '';
        $query = isset($parts['query']) ? '?' . $parts['query'] : '';
        // Fragments are stripped (RFC 6749 §3.1.2 forbids them in redirect URIs).

        return $scheme . '://' . $host . $port . $path . $query;
    }
}
```

**Step 4: Run, expect pass**

**Step 5: Commit**

```bash
git add src/OAuth/Extension/RedirectUriNormalizer.php tests/OAuth/Extension/RedirectUriNormalizerTest.php
git commit -m "$(cat <<'EOF'
feat: add RedirectUriNormalizer (lowercase scheme/host, strip fragment)

Used by ClientRepository and DCR for exact-match comparison
(spec §3 invariant: redirect_uri is compared verbatim post-normalize).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task B3: `Client` Doctrine entity (implements `ClientEntityInterface`)

**Files:**
- Create: `src/OAuth/Entity/Client.php`
- Create: `tests/OAuth/Entity/ClientTest.php`

**Step 1: Write the failing test**

```php
<?php

declare(strict_types=1);

namespace App\Tests\OAuth\Entity;

use App\OAuth\Entity\Client;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;

final class ClientTest extends TestCase
{
    public function test_constructed_client_exposes_identifier_and_redirect_uris(): void
    {
        $id = Uuid::v7();
        $client = new Client(
            id: $id,
            name: 'demo',
            secretHash: null,
            redirectUris: ['http://localhost:8000/cb'],
            grantTypes: ['authorization_code', 'refresh_token'],
            scopes: ['mcp'],
            dcrMetadata: ['client_name' => 'demo'],
        );

        self::assertSame($id->toRfc4122(), $client->getIdentifier());
        self::assertSame(['http://localhost:8000/cb'], $client->getRedirectUri());
        self::assertFalse($client->isConfidential());
        self::assertSame('demo', $client->getName());
    }

    public function test_confidential_client_has_secret(): void
    {
        $client = new Client(
            id: Uuid::v7(),
            name: 'srv',
            secretHash: password_hash('s3cret', PASSWORD_BCRYPT),
            redirectUris: ['https://example.com/cb'],
            grantTypes: ['authorization_code', 'refresh_token'],
            scopes: ['mcp'],
            dcrMetadata: [],
        );

        self::assertTrue($client->isConfidential());
        self::assertTrue(password_verify('s3cret', $client->getSecretHash()));
    }
}
```

**Step 2: Run, expect failure**

**Step 3: Implement** `src/OAuth/Entity/Client.php`

No traits. Implement `ClientEntityInterface` directly. The interface methods are: `getIdentifier`, `getName`, `getRedirectUri` (returns string|string[]), `isConfidential`. Everything else is for our own use.

```php
<?php

declare(strict_types=1);

namespace App\OAuth\Entity;

use Doctrine\ORM\Mapping as ORM;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use Symfony\Component\Uid\Uuid;

#[ORM\Entity]
#[ORM\Table(name: 'oauth_clients')]
class Client implements ClientEntityInterface
{
    #[ORM\Id]
    #[ORM\Column(type: 'uuid')]
    private Uuid $id;

    #[ORM\Column(type: 'string', length: 191, unique: true)]
    private string $clientIdentifier;

    #[ORM\Column(type: 'string', length: 191)]
    private string $clientName;

    #[ORM\Column(type: 'string', length: 255, nullable: true)]
    private ?string $secretHash;

    #[ORM\Column(type: 'boolean')]
    private bool $confidential;

    /** @var string[] */
    #[ORM\Column(type: 'json')]
    private array $redirectUris;

    /** @var string[] */
    #[ORM\Column(type: 'json')]
    private array $grantTypes;

    /** @var string[] */
    #[ORM\Column(type: 'json')]
    private array $scopesAllowed;

    /** @var array<string, mixed> */
    #[ORM\Column(type: 'json')]
    private array $dcrMetadata;

    #[ORM\Column(type: 'datetime_immutable')]
    private \DateTimeImmutable $createdAt;

    /**
     * @param string[] $redirectUris  normalized
     * @param string[] $grantTypes
     * @param string[] $scopes
     * @param array<string, mixed> $dcrMetadata
     */
    public function __construct(
        Uuid $id,
        string $name,
        ?string $secretHash,
        array $redirectUris,
        array $grantTypes,
        array $scopes,
        array $dcrMetadata,
        ?\DateTimeImmutable $createdAt = null,
    ) {
        $this->id = $id;
        $this->clientIdentifier = $id->toRfc4122();
        $this->clientName = $name;
        $this->secretHash = $secretHash;
        $this->confidential = $secretHash !== null;
        $this->redirectUris = $redirectUris;
        $this->grantTypes = $grantTypes;
        $this->scopesAllowed = $scopes;
        $this->dcrMetadata = $dcrMetadata;
        $this->createdAt = $createdAt ?? new \DateTimeImmutable();
    }

    // --- ClientEntityInterface ---
    public function getIdentifier(): string { return $this->clientIdentifier; }
    public function getName(): string { return $this->clientName; }
    /** @return string[] */
    public function getRedirectUri(): array { return $this->redirectUris; }
    public function isConfidential(): bool { return $this->confidential; }

    // --- App-side accessors ---
    public function getId(): Uuid { return $this->id; }
    public function getSecretHash(): ?string { return $this->secretHash; }
    /** @return string[] */
    public function getGrantTypes(): array { return $this->grantTypes; }
    /** @return string[] */
    public function getScopesAllowed(): array { return $this->scopesAllowed; }
    /** @return array<string, mixed> */
    public function getDcrMetadata(): array { return $this->dcrMetadata; }
    public function getCreatedAt(): \DateTimeImmutable { return $this->createdAt; }
}
```

**Step 4: Run, expect pass**

**Step 5: Commit**

```bash
git add src/OAuth/Entity/Client.php tests/OAuth/Entity/ClientTest.php
git commit -m "$(cat <<'EOF'
feat: add Client entity (Doctrine + ClientEntityInterface)

UUID v7 PK, JSON columns for redirect_uris/grant_types/scopes/dcr_metadata.
secret_hash NULL means public client (PKCE-only path).

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task B4: `ClientRepository`

**Files:**
- Create: `src/OAuth/Repository/ClientRepository.php`
- Create: `tests/OAuth/Repository/ClientRepositoryTest.php` (Doctrine-backed integration test)
- Create: `tests/OAuth/Support/DoctrineKernelTestCase.php` — base class that spins up the kernel + recreates the schema

**Step 1: Base test case**

```php
<?php

declare(strict_types=1);

namespace App\Tests\OAuth\Support;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Tools\SchemaTool;
use Symfony\Bundle\FrameworkBundle\Test\KernelTestCase;

abstract class DoctrineKernelTestCase extends KernelTestCase
{
    protected EntityManagerInterface $em;

    protected function setUp(): void
    {
        self::bootKernel();
        $this->em = self::getContainer()->get(EntityManagerInterface::class);

        $tool = new SchemaTool($this->em);
        $metas = $this->em->getMetadataFactory()->getAllMetadata();
        $tool->dropDatabase();
        if ($metas !== []) {
            $tool->createSchema($metas);
        }
    }
}
```

**Step 2: Write the failing test**

```php
<?php

declare(strict_types=1);

namespace App\Tests\OAuth\Repository;

use App\OAuth\Entity\Client;
use App\OAuth\Repository\ClientRepository;
use App\Tests\OAuth\Support\DoctrineKernelTestCase;
use Symfony\Component\Uid\Uuid;

final class ClientRepositoryTest extends DoctrineKernelTestCase
{
    public function test_validates_public_client_without_secret(): void
    {
        $repo = self::getContainer()->get(ClientRepository::class);

        $id = Uuid::v7();
        $this->em->persist(new Client(
            id: $id,
            name: 'pub',
            secretHash: null,
            redirectUris: ['http://localhost:8000/cb'],
            grantTypes: ['authorization_code', 'refresh_token'],
            scopes: ['mcp'],
            dcrMetadata: [],
        ));
        $this->em->flush();

        $client = $repo->getClientEntity($id->toRfc4122());
        self::assertNotNull($client);
        self::assertFalse($client->isConfidential());

        self::assertTrue($repo->validateClient($id->toRfc4122(), null, 'authorization_code'));
        self::assertFalse($repo->validateClient($id->toRfc4122(), null, 'client_credentials'));
    }

    public function test_validates_confidential_client_with_secret(): void
    {
        $repo = self::getContainer()->get(ClientRepository::class);

        $id = Uuid::v7();
        $this->em->persist(new Client(
            id: $id,
            name: 'srv',
            secretHash: password_hash('s3cret', PASSWORD_BCRYPT),
            redirectUris: ['https://example.com/cb'],
            grantTypes: ['authorization_code', 'refresh_token'],
            scopes: ['mcp'],
            dcrMetadata: [],
        ));
        $this->em->flush();

        self::assertTrue($repo->validateClient($id->toRfc4122(), 's3cret', 'authorization_code'));
        self::assertFalse($repo->validateClient($id->toRfc4122(), 'wrong', 'authorization_code'));
    }
}
```

**Step 3: Run, expect failure**

**Step 4: Implement** `src/OAuth/Repository/ClientRepository.php`

```php
<?php

declare(strict_types=1);

namespace App\OAuth\Repository;

use App\OAuth\Entity\Client;
use Doctrine\ORM\EntityManagerInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\ClientRepositoryInterface;

final class ClientRepository implements ClientRepositoryInterface
{
    public function __construct(private readonly EntityManagerInterface $em)
    {
    }

    public function getClientEntity(string $clientIdentifier): ?ClientEntityInterface
    {
        return $this->em->getRepository(Client::class)
            ->findOneBy(['clientIdentifier' => $clientIdentifier]);
    }

    public function validateClient(
        string $clientIdentifier,
        ?string $clientSecret,
        ?string $grantType,
    ): bool {
        $client = $this->getClientEntity($clientIdentifier);
        if (!$client instanceof Client) {
            return false;
        }

        if ($grantType !== null && !in_array($grantType, $client->getGrantTypes(), true)) {
            return false;
        }

        if ($client->isConfidential()) {
            if ($clientSecret === null) {
                return false;
            }
            return password_verify($clientSecret, (string) $client->getSecretHash());
        }

        // Public client: no secret expected.
        return $clientSecret === null;
    }

    public function save(Client $client): void
    {
        $this->em->persist($client);
        $this->em->flush();
    }
}
```

**Step 5: Run, expect pass**

```bash
docker compose exec app vendor/bin/phpunit tests/OAuth/Repository/ClientRepositoryTest.php tests/OAuth/Entity/ClientTest.php
```

**Step 6: Commit**

```bash
git add src/OAuth/Entity/Client.php src/OAuth/Repository/ClientRepository.php \
        tests/OAuth/Repository/ClientRepositoryTest.php tests/OAuth/Support/DoctrineKernelTestCase.php
git commit -m "$(cat <<'EOF'
feat: add ClientRepository (Doctrine) with grant-type and secret validation

Public clients (secret_hash NULL) authenticate by client_id only;
confidential clients verify against the password_hash. Grant type is
checked against the per-client allowlist.

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>
EOF
)"
```

---

### Task B5: `User` adapter (bridges Symfony Security ↔ league)

**Why:** `league/oauth2-server` expects a `UserEntityInterface` whose `getIdentifier()` returns a string. We don't store users in DB — they come from `InMemoryUserProvider`. A simple value object suffices.

**Files:**
- Create: `src/OAuth/Entity/User.php`
- Create: `src/OAuth/Repository/UserRepository.php`
- Create: `tests/OAuth/Repository/UserRepositoryTest.php`

**Step 1: Write the test**

```php
<?php

declare(strict_types=1);

namespace App\Tests\OAuth\Repository;

use App\OAuth\Repository\UserRepository;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Security\Core\User\InMemoryUser;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;

final class UserRepositoryTest extends TestCase
{
    public function test_returns_user_entity_when_password_matches(): void
    {
        $hash = password_hash('pw', PASSWORD_BCRYPT);
        $provider = $this->createMock(UserProviderInterface::class);
        $provider->method('loadUserByIdentifier')->willReturnCallback(
            fn (string $id) => $id === 'alice'
                ? new InMemoryUser('alice', $hash)
                : throw new UserNotFoundException(),
        );

        $repo = new UserRepository($provider);

        $entity = $repo->getUserEntityByUserCredentials(
            'alice',
            'pw',
            'authorization_code',
            $this->createMock(ClientEntityInterface::class),
        );

        self::assertNotNull($entity);
        self::assertSame('alice', $entity->getIdentifier());
    }

    public function test_returns_null_for_unknown_user(): void
    {
        $provider = $this->createMock(UserProviderInterface::class);
        $provider->method('loadUserByIdentifier')->willThrowException(new UserNotFoundException());

        $repo = new UserRepository($provider);

        self::assertNull($repo->getUserEntityByUserCredentials(
            'ghost', 'pw', 'authorization_code',
            $this->createMock(ClientEntityInterface::class),
        ));
    }
}
```

**Step 2: Run, expect failure**

**Step 3: Implement**

`src/OAuth/Entity/User.php`:

```php
<?php

declare(strict_types=1);

namespace App\OAuth\Entity;

use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\UserEntityInterface;

final class User implements UserEntityInterface
{
    use EntityTrait;

    public function __construct(string $identifier)
    {
        $this->identifier = $identifier;
    }
}
```

`src/OAuth/Repository/UserRepository.php`:

```php
<?php

declare(strict_types=1);

namespace App\OAuth\Repository;

use App\OAuth\Entity\User;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\UserEntityInterface;
use League\OAuth2\Server\Repositories\UserRepositoryInterface;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;

final class UserRepository implements UserRepositoryInterface
{
    public function __construct(private readonly UserProviderInterface $provider)
    {
    }

    public function getUserEntityByUserCredentials(
        string $username,
        string $password,
        string $grantType,
        ClientEntityInterface $clientEntity,
    ): ?UserEntityInterface {
        try {
            $user = $this->provider->loadUserByIdentifier($username);
        } catch (UserNotFoundException) {
            return null;
        }

        if ($user instanceof PasswordAuthenticatedUserInterface
            && password_verify($password, (string) $user->getPassword())
        ) {
            return new User($user->getUserIdentifier());
        }

        return null;
    }
}
```

**Step 4: Run, expect pass**

**Step 5: Commit**

```bash
git add src/OAuth/Entity/User.php src/OAuth/Repository/UserRepository.php tests/OAuth/Repository/UserRepositoryTest.php
git commit -m "feat: add User entity + UserRepository bridging Symfony Security

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task B6: `AuthCode` entity + repository

Implements `AuthCodeEntityInterface` directly (no traits). Doctrine columns: `code_challenge`, `code_challenge_method`, `resource`, `redirect_uri`, `revoked`.

**Files:**
- Create: `src/OAuth/Entity/AuthCode.php`
- Create: `src/OAuth/Repository/AuthCodeRepository.php`
- Create: `tests/OAuth/Repository/AuthCodeRepositoryTest.php` (kernel-backed)

**Step 1: Write test**

```php
<?php

declare(strict_types=1);

namespace App\Tests\OAuth\Repository;

use App\OAuth\Entity\AuthCode;
use App\OAuth\Entity\Client;
use App\OAuth\Entity\Scope;
use App\OAuth\Repository\AuthCodeRepository;
use App\Tests\OAuth\Support\DoctrineKernelTestCase;
use Symfony\Component\Uid\Uuid;

final class AuthCodeRepositoryTest extends DoctrineKernelTestCase
{
    public function test_persist_and_revoke(): void
    {
        $clientId = Uuid::v7();
        $this->em->persist(new Client(
            id: $clientId, name: 'c', secretHash: null,
            redirectUris: ['http://localhost:8000/cb'],
            grantTypes: ['authorization_code'], scopes: ['mcp'], dcrMetadata: [],
        ));
        $this->em->flush();

        /** @var AuthCodeRepository $repo */
        $repo = self::getContainer()->get(AuthCodeRepository::class);

        $code = $repo->getNewAuthCode();
        $code->setIdentifier('code-123');
        $code->setUserIdentifier('alice');
        $code->setExpiryDateTime(new \DateTimeImmutable('+10 min'));
        $code->setClient($this->em->getRepository(Client::class)->findOneBy([
            'clientIdentifier' => $clientId->toRfc4122(),
        ]));
        $code->setRedirectUri('http://localhost:8000/cb');
        $code->addScope(new Scope('mcp'));
        $code->setCodeChallenge('abc');
        $code->setCodeChallengeMethod('S256');
        $code->setResource('http://localhost:8000/mcp');

        $repo->persistNewAuthCode($code);

        self::assertFalse($repo->isAuthCodeRevoked('code-123'));
        $repo->revokeAuthCode('code-123');
        self::assertTrue($repo->isAuthCodeRevoked('code-123'));
    }
}
```

**Step 2: Run, expect failure**

**Step 3: Implement entity (no traits)**

`src/OAuth/Entity/AuthCode.php`:

```php
<?php

declare(strict_types=1);

namespace App\OAuth\Entity;

use Doctrine\ORM\Mapping as ORM;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;

#[ORM\Entity]
#[ORM\Table(name: 'oauth_auth_codes')]
class AuthCode implements AuthCodeEntityInterface
{
    #[ORM\Id]
    #[ORM\Column(type: 'string', length: 191)]
    private string $identifier;

    #[ORM\Column(type: 'string', length: 191)]
    private string $clientId;

    #[ORM\Column(type: 'string', length: 191, nullable: true)]
    private ?string $userId = null;

    #[ORM\Column(type: 'datetime_immutable')]
    private \DateTimeImmutable $expiryDateTime;

    /** @var string[] */
    #[ORM\Column(type: 'json')]
    private array $scopeIds = [];

    #[ORM\Column(type: 'string', length: 2048, nullable: true)]
    private ?string $redirectUri = null;

    #[ORM\Column(type: 'string', length: 255, nullable: true)]
    private ?string $codeChallenge = null;

    #[ORM\Column(type: 'string', length: 16, nullable: true)]
    private ?string $codeChallengeMethod = null;

    #[ORM\Column(type: 'string', length: 2048, nullable: true)]
    private ?string $resource = null;

    #[ORM\Column(type: 'boolean')]
    private bool $revoked = false;

    /** Runtime references (not persisted directly). */
    private ?ClientEntityInterface $client = null;
    /** @var ScopeEntityInterface[] */
    private array $scopes = [];

    public function getIdentifier(): string { return $this->identifier; }
    public function setIdentifier($identifier): void { $this->identifier = (string) $identifier; }

    public function getClient(): ClientEntityInterface
    {
        if ($this->client === null) {
            throw new \LogicException('Client must be hydrated via setClient() before access.');
        }
        return $this->client;
    }
    public function setClient(ClientEntityInterface $client): void
    {
        $this->client = $client;
        $this->clientId = $client->getIdentifier();
    }
    public function getClientId(): string { return $this->clientId; }

    /** @return ScopeEntityInterface[] */
    public function getScopes(): array { return $this->scopes; }
    public function addScope(ScopeEntityInterface $scope): void
    {
        $this->scopes[] = $scope;
        $this->scopeIds[] = $scope->getIdentifier();
        $this->scopeIds = array_values(array_unique($this->scopeIds));
    }
    /** @return string[] */
    public function getScopeIds(): array { return $this->scopeIds; }

    public function getExpiryDateTime(): \DateTimeImmutable { return $this->expiryDateTime; }
    public function setExpiryDateTime(\DateTimeImmutable $expiryDateTime): void { $this->expiryDateTime = $expiryDateTime; }

    public function getUserIdentifier(): ?string { return $this->userId; }
    public function setUserIdentifier($identifier): void { $this->userId = $identifier === null ? null : (string) $identifier; }

    public function getRedirectUri(): ?string { return $this->redirectUri; }
    public function setRedirectUri($uri): void { $this->redirectUri = $uri; }

    public function getCodeChallenge(): ?string { return $this->codeChallenge; }
    public function setCodeChallenge(?string $codeChallenge): void { $this->codeChallenge = $codeChallenge; }
    public function getCodeChallengeMethod(): ?string { return $this->codeChallengeMethod; }
    public function setCodeChallengeMethod(?string $method): void { $this->codeChallengeMethod = $method; }

    public function getResource(): ?string { return $this->resource; }
    public function setResource(?string $resource): void { $this->resource = $resource; }

    public function isRevoked(): bool { return $this->revoked; }
    public function revoke(): void { $this->revoked = true; }
}
```

**Note:** `AuthCodeEntityInterface` (league v9) extends `TokenInterface`, which requires a few more methods. Run `vendor/bin/phpstan` is not configured; instead use `php -l src/OAuth/Entity/AuthCode.php` to confirm syntax, then let PHPUnit's first failure (`Class … must implement method …`) tell you which methods are missing. Add them as no-op getters/setters around the same fields. Common additions: `setClient()` is already there, `addScope`/`setExpiryDateTime`/`setUserIdentifier`/`getIdentifier` covered above. Most of the remaining are already mirrors of the same data.

**Implement repository** `src/OAuth/Repository/AuthCodeRepository.php`:

```php
<?php

declare(strict_types=1);

namespace App\OAuth\Repository;

use App\OAuth\Entity\AuthCode;
use Doctrine\ORM\EntityManagerInterface;
use League\OAuth2\Server\Entities\AuthCodeEntityInterface;
use League\OAuth2\Server\Repositories\AuthCodeRepositoryInterface;

final class AuthCodeRepository implements AuthCodeRepositoryInterface
{
    public function __construct(private readonly EntityManagerInterface $em) {}

    public function getNewAuthCode(): AuthCodeEntityInterface
    {
        return new AuthCode();
    }

    public function persistNewAuthCode(AuthCodeEntityInterface $authCodeEntity): void
    {
        if (!$authCodeEntity instanceof AuthCode) {
            throw new \LogicException('Unexpected auth code entity');
        }
        $this->em->persist($authCodeEntity);
        $this->em->flush();
    }

    public function revokeAuthCode(string $codeId): void
    {
        $code = $this->em->find(AuthCode::class, $codeId);
        if ($code instanceof AuthCode) {
            $code->revoke();
            $this->em->flush();
        }
    }

    public function isAuthCodeRevoked(string $codeId): bool
    {
        $code = $this->em->find(AuthCode::class, $codeId);
        return $code === null || $code->isRevoked();
    }
}
```

**Step 4: Run, expect pass**

**Step 5: Commit**

```bash
git add src/OAuth/Entity/AuthCode.php src/OAuth/Repository/AuthCodeRepository.php tests/OAuth/Repository/AuthCodeRepositoryTest.php
git commit -m "feat: add AuthCode entity + repository with PKCE/resource columns

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task B7: `AccessToken` Doctrine entity + repository

**Files:**
- Create: `src/OAuth/Entity/AccessToken.php` — Doctrine row, **NOT** the JWT-issuing `AccessTokenEntityInterface` (that's `McpAccessTokenEntity` in Phase C).
- Create: `src/OAuth/Repository/AccessTokenRepository.php`
- Create: `tests/OAuth/Repository/AccessTokenRepositoryTest.php`

**Architectural note:** `league/oauth2-server` calls `getNewToken()` to obtain an `AccessTokenEntityInterface`, then later calls `persistNewAccessToken($entity)`. The entity returned by `getNewToken()` is a JWT-shaped value object (`McpAccessTokenEntity`, Phase C). The Doctrine row is built **in `persistNewAccessToken()` by copying the relevant fields out of the interface implementation**. `AccessToken` (this task) is the Doctrine row only — it does NOT implement `AccessTokenEntityInterface`. Until Phase C lands, `getNewToken()` returns a stub class that satisfies the interface; we replace it in C4.

**Step 1: Test**

```php
<?php

declare(strict_types=1);

namespace App\Tests\OAuth\Repository;

use App\OAuth\Entity\AccessToken;
use App\OAuth\Entity\Client;
use App\OAuth\Repository\AccessTokenRepository;
use App\Tests\OAuth\Support\DoctrineKernelTestCase;
use Symfony\Component\Uid\Uuid;

final class AccessTokenRepositoryTest extends DoctrineKernelTestCase
{
    public function test_persist_and_revoke_round_trip(): void
    {
        $clientId = Uuid::v7();
        $this->em->persist(new Client(
            id: $clientId, name: 'c', secretHash: null,
            redirectUris: ['http://localhost:8000/cb'],
            grantTypes: ['authorization_code'], scopes: ['mcp'], dcrMetadata: [],
        ));
        $this->em->flush();

        /** @var AccessTokenRepository $repo */
        $repo = self::getContainer()->get(AccessTokenRepository::class);

        $row = new AccessToken(
            identifier: 'jti-1',
            clientId: $clientId->toRfc4122(),
            userId: 'alice',
            expiresAt: new \DateTimeImmutable('+1 hour'),
            scopes: ['mcp'],
            audience: ['http://localhost:8000/mcp'],
        );
        $this->em->persist($row);
        $this->em->flush();

        self::assertFalse($repo->isAccessTokenRevoked('jti-1'));
        $repo->revokeAccessToken('jti-1');
        self::assertTrue($repo->isAccessTokenRevoked('jti-1'));
    }
}
```

**Step 2: Run, expect failure**

**Step 3: Implement entity** `src/OAuth/Entity/AccessToken.php`

```php
<?php

declare(strict_types=1);

namespace App\OAuth\Entity;

use Doctrine\ORM\Mapping as ORM;

#[ORM\Entity]
#[ORM\Table(name: 'oauth_access_tokens')]
class AccessToken
{
    #[ORM\Id]
    #[ORM\Column(type: 'string', length: 191)]
    private string $identifier;

    #[ORM\Column(type: 'string', length: 191)]
    private string $clientId;

    #[ORM\Column(type: 'string', length: 191, nullable: true)]
    private ?string $userId;

    #[ORM\Column(type: 'datetime_immutable')]
    private \DateTimeImmutable $expiresAt;

    /** @var string[] */
    #[ORM\Column(type: 'json')]
    private array $scopes;

    /** @var string[] */
    #[ORM\Column(type: 'json')]
    private array $audience;

    #[ORM\Column(type: 'boolean')]
    private bool $revoked = false;

    /**
     * @param string[] $scopes
     * @param string[] $audience
     */
    public function __construct(
        string $identifier,
        string $clientId,
        ?string $userId,
        \DateTimeImmutable $expiresAt,
        array $scopes,
        array $audience,
    ) {
        $this->identifier = $identifier;
        $this->clientId = $clientId;
        $this->userId = $userId;
        $this->expiresAt = $expiresAt;
        $this->scopes = $scopes;
        $this->audience = $audience;
    }

    public function getIdentifier(): string { return $this->identifier; }
    public function getClientId(): string { return $this->clientId; }
    public function getUserId(): ?string { return $this->userId; }
    public function getExpiresAt(): \DateTimeImmutable { return $this->expiresAt; }
    /** @return string[] */
    public function getScopes(): array { return $this->scopes; }
    /** @return string[] */
    public function getAudience(): array { return $this->audience; }

    public function isRevoked(): bool { return $this->revoked; }
    public function revoke(): void { $this->revoked = true; }
}
```

**Step 4: Implement repository** `src/OAuth/Repository/AccessTokenRepository.php`

```php
<?php

declare(strict_types=1);

namespace App\OAuth\Repository;

use App\OAuth\Entity\AccessToken;
use Doctrine\ORM\EntityManagerInterface;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;

final class AccessTokenRepository implements AccessTokenRepositoryInterface
{
    public function __construct(private readonly EntityManagerInterface $em) {}

    public function getNewToken(
        ClientEntityInterface $clientEntity,
        array $scopes,
        $userIdentifier = null,
    ): AccessTokenEntityInterface {
        // Phase B placeholder — replaced in Task C4 with McpAccessTokenEntity.
        throw new \LogicException('AccessTokenRepository::getNewToken() is implemented in Phase C (Task C4).');
    }

    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity): void
    {
        $row = new AccessToken(
            identifier: $accessTokenEntity->getIdentifier(),
            clientId: $accessTokenEntity->getClient()->getIdentifier(),
            userId: $accessTokenEntity->getUserIdentifier() === null
                ? null
                : (string) $accessTokenEntity->getUserIdentifier(),
            expiresAt: $accessTokenEntity->getExpiryDateTime(),
            scopes: array_map(
                fn ($s) => $s->getIdentifier(),
                $accessTokenEntity->getScopes(),
            ),
            audience: method_exists($accessTokenEntity, 'getAudiences')
                ? $accessTokenEntity->getAudiences()
                : [],
        );

        $this->em->persist($row);
        $this->em->flush();
    }

    public function revokeAccessToken(string $tokenId): void
    {
        $row = $this->em->find(AccessToken::class, $tokenId);
        if ($row instanceof AccessToken) {
            $row->revoke();
            $this->em->flush();
        }
    }

    public function isAccessTokenRevoked(string $tokenId): bool
    {
        $row = $this->em->find(AccessToken::class, $tokenId);
        return $row === null || $row->isRevoked();
    }
}
```

**Step 5: Run the test** — it bypasses `getNewToken()` (we instantiate the Doctrine row directly), so the placeholder exception in `getNewToken()` does not block the test. Expected: test passes.

**Step 6: Commit**

```bash
git add src/OAuth/Entity/AccessToken.php src/OAuth/Repository/AccessTokenRepository.php tests/OAuth/Repository/AccessTokenRepositoryTest.php
git commit -m "feat: add AccessToken Doctrine entity + persist/revoke repository

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

### Task B8: `RefreshToken` Doctrine entity + repository (with `family_id`)

**Architectural note:** Same shape as B7 — `RefreshToken` is the Doctrine row, NOT a `RefreshTokenEntityInterface` implementation. The interface impl lives in `src/OAuth/Extension/` (added in Phase C alongside family revocation).

**Files:**
- Create: `src/OAuth/Entity/RefreshToken.php`
- Create: `src/OAuth/Repository/RefreshTokenRepository.php`
- Create: `tests/OAuth/Repository/RefreshTokenRepositoryTest.php`

**Columns:** `identifier`, `access_token_id` (string, FK to `oauth_access_tokens`), `family_id` (uuid), `expires_at`, `revoked`.

**Test must include** (this task):
- Persist + revoke individual token via repository.
- `isRefreshTokenRevoked()` returns true after revocation, false otherwise.

**Test deferred to Phase C (C6):**
- Family revocation on reuse.

**Implementation:** Mirror `AccessToken` / `AccessTokenRepository` shape; key methods on the repository are `getNewRefreshToken()` (placeholder — `LogicException` until C6), `persistNewRefreshToken()`, `revokeRefreshToken()`, `isRefreshTokenRevoked()`.

**Commit message:** `feat: add RefreshToken Doctrine entity + repository with family_id`

---

### Task B9: Initial Doctrine migration

**Why:** After all entities exist, generate the migration so `docker compose up` + `doctrine:migrations:migrate` produces a valid schema.

**Files:**
- Create: `migrations/Version20260429120000.php` (timestamp from `bin/console doctrine:migrations:diff`)
- Modify: `config/packages/doctrine_migrations.yaml` if needed (Flex sets defaults).

**Step 1: Generate migration**

Run:

```bash
docker compose exec app php bin/console doctrine:migrations:diff
```

Expected: a new migration file in `migrations/` with `CREATE TABLE oauth_clients`, `oauth_auth_codes`, `oauth_access_tokens`, `oauth_refresh_tokens` (no `oauth_scopes` — scopes are config-only).

**Step 2: Apply and verify**

```bash
docker compose exec app php bin/console doctrine:migrations:migrate -n
docker compose exec app sqlite3 /app/var/data/oauth.db '.schema'
```

Expected: tables listed.

**Step 3: Commit**

```bash
git add migrations/
git commit -m "feat: add initial migration for OAuth tables

Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>"
```

---

## Phase C — MCP/RFC extension layer

### Task C1: `ServerMetadataBuilder` (RFC 8414)

**Files:**
- Create: `src/OAuth/Extension/ServerMetadataBuilder.php`
- Create: `tests/OAuth/Extension/ServerMetadataBuilderTest.php`

**Step 1: Test**

```php
<?php

declare(strict_types=1);

namespace App\Tests\OAuth\Extension;

use App\OAuth\Extension\ServerMetadataBuilder;
use PHPUnit\Framework\TestCase;

final class ServerMetadataBuilderTest extends TestCase
{
    public function test_builds_required_fields(): void
    {
        $builder = new ServerMetadataBuilder('http://localhost:8000');
        $meta = $builder->build();

        self::assertSame('http://localhost:8000', $meta['issuer']);
        self::assertSame('http://localhost:8000/oauth/authorize', $meta['authorization_endpoint']);
        self::assertSame('http://localhost:8000/oauth/token', $meta['token_endpoint']);
        self::assertSame('http://localhost:8000/oauth/register', $meta['registration_endpoint']);
        self::assertSame('http://localhost:8000/.well-known/jwks.json', $meta['jwks_uri']);
        self::assertSame(['S256'], $meta['code_challenge_methods_supported']);
        self::assertSame(['code'], $meta['response_types_supported']);
        self::assertContains('authorization_code', $meta['grant_types_supported']);
        self::assertContains('refresh_token', $meta['grant_types_supported']);
        self::assertContains('client_secret_basic', $meta['token_endpoint_auth_methods_supported']);
        self::assertContains('none', $meta['token_endpoint_auth_methods_supported']);
        self::assertSame(['mcp'], $meta['scopes_supported']);
    }

    public function test_issuer_is_used_verbatim_for_eq_with_prm(): void
    {
        $builder = new ServerMetadataBuilder('http://localhost:8000/');
        $meta = $builder->build();
        self::assertSame('http://localhost:8000/', $meta['issuer']);  // trailing slash preserved
    }
}
```

**Step 2: Run, expect failure**

**Step 3: Implement**

```php
<?php

declare(strict_types=1);

namespace App\OAuth\Extension;

final class ServerMetadataBuilder
{
    public function __construct(private readonly string $issuer) {}

    /** @return array<string, mixed> */
    public function build(): array
    {
        $base = rtrim($this->issuer, '/');
        return [
            'issuer' => $this->issuer,
            'authorization_endpoint' => $base . '/oauth/authorize',
            'token_endpoint' => $base . '/oauth/token',
            'registration_endpoint' => $base . '/oauth/register',
            'jwks_uri' => $base . '/.well-known/jwks.json',
            'response_types_supported' => ['code'],
            'grant_types_supported' => ['authorization_code', 'refresh_token'],
            'code_challenge_methods_supported' => ['S256'],
            'token_endpoint_auth_methods_supported' => ['client_secret_basic', 'none'],
            'scopes_supported' => ['mcp'],
        ];
    }
}
```

**Step 4: Pass + commit** (`feat: add ServerMetadataBuilder (RFC 8414)`)

---

### Task C2: `ProtectedResourceMetadataBuilder` (RFC 9728)

Same TDD shape. Output:

```json
{
  "resource": "http://localhost:8000/mcp",
  "authorization_servers": ["http://localhost:8000"],
  "scopes_supported": ["mcp"],
  "bearer_methods_supported": ["header"]
}
```

**Required assertions in tests:**
- `authorization_servers[0]` is byte-equal to the issuer string (no trim, no normalization).
- `assertSame(['header'], $meta['bearer_methods_supported'])` — strict equality, must be exactly `["header"]` (no `query`, no `body`).
- `resource` and `scopes_supported` are present and match expected.

**Commit:** `feat: add ProtectedResourceMetadataBuilder (RFC 9728)`

---

### Task C3a: `KidDeriver` (shared between issuer and JWKS)

**Why:** Both `McpAccessTokenEntity` (signs the JWT with `kid` header) and `JwksController` (publishes the JWK with the same `kid`) must produce the same value. Extract once, inject everywhere.

**Files:**
- Create: `src/OAuth/Extension/KidDeriver.php`
- Create: `tests/OAuth/Extension/KidDeriverTest.php`

**Step 1: Test**

```php
<?php

declare(strict_types=1);

namespace App\Tests\OAuth\Extension;

use App\OAuth\Extension\KidDeriver;
use PHPUnit\Framework\TestCase;

final class KidDeriverTest extends TestCase
{
    public function test_kid_is_first_16_hex_chars_of_sha256_of_public_key_pem(): void
    {
        $pem = file_get_contents(__DIR__ . '/../../fixtures/public.key');
        if ($pem === false) {
            self::markTestSkipped('Test fixture missing — see tests/fixtures/README.md');
        }

        $kid = (new KidDeriver(__DIR__ . '/../../fixtures/public.key'))->derive();

        self::assertSame(16, strlen($kid));
        self::assertSame(substr(hash('sha256', $pem), 0, 16), $kid);
    }
}
```

**Step 2: Implement**

```php
<?php

declare(strict_types=1);

namespace App\OAuth\Extension;

final class KidDeriver
{
    public function __construct(private readonly string $publicKeyPath) {}

    public function derive(): string
    {
        $pem = @file_get_contents($this->publicKeyPath);
        if ($pem === false) {
            throw new \RuntimeException('Cannot read public key at ' . $this->publicKeyPath);
        }
        return substr(hash('sha256', $pem), 0, 16);
    }
}
```

**Step 3: Pass + commit** (`feat: add KidDeriver service for JWT/JWKS kid agreement`)

Wire in `services.yaml`:

```yaml
App\OAuth\Extension\KidDeriver:
    arguments: ['%oauth.public_key_path%']
```

---

### Task C3b: `McpAccessTokenEntity` (issues JWT with aud array, iss, kid)

**Why:** `AccessTokenTrait::convertToJWT()` is private. We implement the entity from scratch to inject `aud` (array), `iss`, and a `kid` header that matches `KidDeriver`.

**Files:**
- Create: `src/OAuth/Extension/McpAccessTokenEntity.php`
- Create: `tests/OAuth/Extension/McpAccessTokenEntityTest.php`
- Create: `tests/Stub/StubClient.php`
- Create: `tests/fixtures/private.key`, `tests/fixtures/public.key` (test-only RSA keypair, committed)
- Create: `tests/fixtures/README.md` documenting the keys are test-only

**Reference:** `lcobucci/jwt` v5 Builder API: `Configuration::forAsymmetricSigner($signer, $signingKey, $verificationKey)` requires both keys non-empty; `$config->builder()->getToken($signer, $key)` returns a **`Plain` token whose `toString()` is the already-signed compact serialization**. There is no separate `signer()->sign(...)` step.

**Step 1: Test (decodes the produced JWT and asserts claims)**

```php
<?php

declare(strict_types=1);

namespace App\Tests\OAuth\Extension;

use App\OAuth\Entity\Scope;
use App\OAuth\Extension\McpAccessTokenEntity;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Token\Parser;
use League\OAuth2\Server\CryptKey;
use PHPUnit\Framework\TestCase;

final class McpAccessTokenEntityTest extends TestCase
{
    public function test_jwt_contains_aud_array_iss_and_kid(): void
    {
        $privatePath = __DIR__ . '/../../fixtures/private.key';
        $publicPath  = __DIR__ . '/../../fixtures/public.key';
        // Generate fixtures once (committed test keys, NOT used for prod):
        if (!file_exists($privatePath)) {
            self::markTestSkipped('Generate test keys: see tests/fixtures/README.md');
        }

        $token = new McpAccessTokenEntity(
            'http://localhost:8000',
            new \App\OAuth\Extension\KidDeriver($publicPath),
            $publicPath,
        );
        $token->setIdentifier('jti-1');
        $token->setExpiryDateTime(new \DateTimeImmutable('+1 hour'));
        $token->setUserIdentifier('alice');
        $token->setClient(new \App\Tests\Stub\StubClient('client-1'));
        $token->addScope(new Scope('mcp'));
        $token->setAudiences(['http://localhost:8000/mcp']);
        $token->setPrivateKey(new CryptKey($privatePath, null, false));

        $jwt = (string) $token;

        $parsed = (new Parser(new JoseEncoder()))->parse($jwt);
        self::assertSame('jti-1', $parsed->claims()->get('jti'));
        self::assertSame('http://localhost:8000', $parsed->claims()->get('iss'));
        self::assertSame(['http://localhost:8000/mcp'], $parsed->claims()->get('aud'));
        self::assertSame('alice', $parsed->claims()->get('sub'));
        self::assertNotEmpty($parsed->headers()->get('kid'));
    }
}
```

(Provide `tests/fixtures/README.md` describing key generation; commit a *test-only* key pair so the test is hermetic.)

Stub client: `tests/Stub/StubClient.php` returns a fixed identifier.

**Step 2: Implement**

```php
<?php

declare(strict_types=1);

namespace App\OAuth\Extension;

use DateTimeImmutable;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use League\OAuth2\Server\CryptKey;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Entities\ScopeEntityInterface;

final class McpAccessTokenEntity implements AccessTokenEntityInterface
{
    private string $identifier = '';
    private \DateTimeImmutable $expiryDateTime;
    private CryptKey $privateKey;
    private ClientEntityInterface $client;
    private ?string $userIdentifier = null;
    /** @var ScopeEntityInterface[] */
    private array $scopes = [];
    /** @var string[] */
    private array $audiences = [];

    public function __construct(
        private readonly string $issuer,
        private readonly KidDeriver $kidDeriver,
        private readonly string $publicKeyPath,
    ) {}

    // --- AccessTokenEntityInterface ---
    public function setPrivateKey(CryptKey $privateKey): void { $this->privateKey = $privateKey; }
    public function setClient(ClientEntityInterface $client): void { $this->client = $client; }
    public function getClient(): ClientEntityInterface { return $this->client; }
    public function setUserIdentifier($identifier): void
    {
        $this->userIdentifier = $identifier === null ? null : (string) $identifier;
    }
    public function getUserIdentifier() { return $this->userIdentifier; }
    public function addScope(ScopeEntityInterface $scope): void { $this->scopes[] = $scope; }
    /** @return ScopeEntityInterface[] */
    public function getScopes(): array { return $this->scopes; }
    public function getIdentifier(): string { return $this->identifier; }
    public function setIdentifier($identifier): void { $this->identifier = (string) $identifier; }
    public function getExpiryDateTime(): \DateTimeImmutable { return $this->expiryDateTime; }
    public function setExpiryDateTime(\DateTimeImmutable $expiryDateTime): void { $this->expiryDateTime = $expiryDateTime; }

    /** @param string[] $audiences */
    public function setAudiences(array $audiences): void { $this->audiences = $audiences; }
    /** @return string[] */
    public function getAudiences(): array { return $this->audiences; }

    public function __toString(): string
    {
        $signingKey = InMemory::file(
            $this->privateKey->getKeyPath(),
            $this->privateKey->getPassPhrase() ?? '',
        );
        $verificationKey = InMemory::file($this->publicKeyPath);
        $config = Configuration::forAsymmetricSigner(new Sha256(), $signingKey, $verificationKey);

        $now = new DateTimeImmutable();
        $builder = $config->builder()
            ->withHeader('kid', $this->kidDeriver->derive())
            ->issuedBy($this->issuer)
            ->identifiedBy($this->identifier)
            ->issuedAt($now)
            ->canOnlyBeUsedAfter($now)
            ->expiresAt($this->expiryDateTime)
            ->withClaim('client_id', $this->client->getIdentifier())
            ->withClaim('scope', implode(' ', array_map(
                static fn (ScopeEntityInterface $s) => $s->getIdentifier(),
                $this->scopes,
            )));

        if ($this->userIdentifier !== null) {
            $builder = $builder->relatedTo($this->userIdentifier);
        }
        if ($this->audiences !== []) {
            $builder = $builder->permittedFor(...$this->audiences);
        }

        // getToken() returns a Plain token already signed with the configured signer + key.
        return $builder
            ->getToken($config->signer(), $config->signingKey())
            ->toString();
    }
}
```

**Step 3: Pass + commit** (`feat: add McpAccessTokenEntity with aud-array, iss, kid claims`)

---

### Task C4: `AccessTokenRepository::getNewToken()` returns `McpAccessTokenEntity`

Modify the repository created in B7. Override `getNewToken()` to return a `McpAccessTokenEntity` (with the issuer injected via constructor). Adjust the entity persistence path accordingly.

Add test: `getNewToken()` returns an `McpAccessTokenEntity` with the configured issuer.

**Commit:** `feat: wire McpAccessTokenEntity into AccessTokenRepository`

---

### Task C5: `ResourceIndicatorGrant` (extends `AuthorizationCodeGrant`)

**Why:** Enforces PKCE presence, validates `resource` parameter, calls `setAudiences()` on the issued token.

**Files:**
- Create: `src/OAuth/Extension/ResourceIndicatorGrant.php`
- Create: `tests/OAuth/Extension/ResourceIndicatorGrantTest.php`

**Test (functional-ish — boots the kernel and exercises the grant via `AuthorizationServer`):** see design doc §5 functional cases for shape. Cover:
- Missing `code_challenge` in authorize → `OAuthServerException::invalidRequest()`.
- Missing `resource` in token request → `OAuthServerException::invalidTarget()`.
- `resource` not in `MCP_ALLOWED_RESOURCES` → `invalid_target`.
- `resource` http but not localhost → `invalid_target`.
- Successful flow → access token with `aud` set to the resource value.

Implementation:
- Extend `League\OAuth2\Server\Grant\AuthorizationCodeGrant`.
- **PKCE enforcement.** Override `validateAuthorizationRequest($request)`. Read `code_challenge` and `code_challenge_method` via `$this->getQueryStringParameter(...)`. Missing `code_challenge` → `OAuthServerException::invalidRequest('code_challenge', 'PKCE required')`. `code_challenge_method` not `'S256'` → same exception. After the checks, return `parent::validateAuthorizationRequest($request)` so the rest of the league pipeline runs unchanged. (`enableCodeExchangeProof()` enables PKCE *support* but does not reject missing PKCE for confidential clients in v9; this override closes that gap.)
- **Resource validation + aud injection.** Override `respondToAccessTokenRequest()`:
  1. Read `resource` via `$this->getRequestParameter('resource', $request)`.
  2. If null → `OAuthServerException::invalidTarget('resource is required')`.
  3. If scheme is not `https://` and not `http://localhost...` → `invalidTarget('resource scheme must be https')`.
  4. If `! $this->allowedResources->contains($resource)` → `invalidTarget('resource not allowed')`.
  5. Call parent for the access-token issuance path; the parent fills `$accessToken` via `AccessTokenRepository::getNewToken()` (Phase C4 returns `McpAccessTokenEntity`). Capture the entity before the response is finalized via the league protected hook `issueAccessToken()` — override it to call `$accessToken->setAudiences([$resource])` then delegate to parent. Test that the JWT in the final response has `aud === [$resource]`.

**Commit:** `feat: add ResourceIndicatorGrant enforcing PKCE + RFC 8707`

---

### Task C6: Refresh token family revocation

**Files:**
- Modify: `src/OAuth/Repository/RefreshTokenRepository.php` — track `family_id`, on reuse-detection (a revoked token presented for refresh) revoke all tokens in family.
- Add: `src/OAuth/Extension/RefreshTokenFamily.php` (helper that the repository delegates to, if useful).
- Add: integration test that walks rotation → reuse → confirms family is revoked.

Test asserts:
1. Rotation: old RT is revoked, new RT exists with same `family_id`.
2. Reuse of old RT after rotation → `invalid_grant` AND every RT with that `family_id` is now `revoked=true`.

**Commit:** `feat: add refresh token family revocation on reuse (RFC 9700 §4.14)`

---

### Task C7: `ClientMetadataValidator` (RFC 7591)

**Files:**
- Create: `src/OAuth/Extension/DynamicClientRegistration/ClientMetadataValidator.php`
- Create: `tests/OAuth/Extension/DynamicClientRegistration/ClientMetadataValidatorTest.php`

Validate per `redirect_uri`:
- valid HTTP(S) URI
- host in allowlist (`['localhost', '127.0.0.1']` for Phase 1; injected via constructor)
- if any URI fails, throw `OAuthServerException::invalidClientMetadata('redirect_uris', 'invalid_redirect_uri')`

Validate `grant_types ⊆ ['authorization_code', 'refresh_token']`.

**Commit:** `feat: add DCR client metadata validator with host allowlist`

---

### Task C8: `ClientRegistrar` (RFC 7591 write path)

**Files:**
- Create: `src/OAuth/Extension/DynamicClientRegistration/ClientRegistrar.php`
- Create: `tests/OAuth/Extension/DynamicClientRegistration/ClientRegistrarTest.php`

Behavior:
1. Validate via `ClientMetadataValidator`.
2. **Normalize** `redirect_uris` via `RedirectUriNormalizer` (for storage only).
3. Generate `client_id` (UUID v7) and, only if `token_endpoint_auth_method != "none"`, a `client_secret` (random + hashed via `password_hash`).
4. Persist a new `Client` via `ClientRepository::save()`.
5. Return a metadata payload that includes the **original** (not normalized) `redirect_uris` per RFC 7591 §3.2.1.

Test cases:
- Public client (no secret).
- Confidential client (secret returned in plaintext exactly once).
- Normalization: DB row stores normalized URIs, response body returns original casing.

**Commit:** `feat: add DCR ClientRegistrar (returns original metadata)`

---

## Phase D — Controllers, routes, services wiring

### Task D1: `AuthorizationServerFactory`

**Files:**
- Create: `src/OAuth/Server/AuthorizationServerFactory.php`
- Create: `tests/OAuth/Server/AuthorizationServerFactoryTest.php`

Build the `League\OAuth2\Server\AuthorizationServer` instance:
- Inject all repositories.
- Configure with `OAUTH_PRIVATE_KEY_PATH` and `OAUTH_ENCRYPTION_KEY` (from env).
- Enable `enableCodeExchangeProof()` on the grant.
- Enable refresh token grant with TTL from `OAUTH_REFRESH_TOKEN_TTL`.
- Use `ResourceIndicatorGrant` instead of stock `AuthorizationCodeGrant`.

**Commit:** `feat: add AuthorizationServerFactory wiring league + extensions`

---

### Task D2: `services.yaml` — register extensions and parameters

`%env(csv:VAR)%` splits on comma but does **not** trim whitespace. To satisfy the spec's "trim each element after split", we keep the env processor for split and trim inside the consumer (or register a small factory service).

```yaml
parameters:
    oauth.issuer: '%env(OAUTH_ISSUER)%'
    oauth.allowed_resources_raw: '%env(csv:MCP_ALLOWED_RESOURCES)%'
    oauth.private_key_path: '%env(OAUTH_PRIVATE_KEY_PATH)%'
    oauth.public_key_path: '%env(OAUTH_PUBLIC_KEY_PATH)%'
    oauth.encryption_key: '%env(OAUTH_ENCRYPTION_KEY)%'
    oauth.access_token_ttl: '%env(OAUTH_ACCESS_TOKEN_TTL)%'
    oauth.refresh_token_ttl: '%env(OAUTH_REFRESH_TOKEN_TTL)%'
    oauth.auth_code_ttl: '%env(OAUTH_AUTH_CODE_TTL)%'

services:
    App\OAuth\Repository\ScopeRepository:
        arguments:
            $scopes:
                mcp: 'MCP access'

    App\OAuth\Extension\ServerMetadataBuilder:
        arguments: ['%oauth.issuer%']

    # Trim each element here so consumers see the clean list.
    App\OAuth\Extension\AllowedResources:
        arguments:
            $values: '%oauth.allowed_resources_raw%'

    App\OAuth\Extension\KidDeriver:
        arguments: ['%oauth.public_key_path%']

    App\OAuth\Extension\ProtectedResourceMetadataBuilder:
        arguments:
            $issuer: '%oauth.issuer%'
            $allowedResources: '@App\OAuth\Extension\AllowedResources'

    App\OAuth\Extension\DynamicClientRegistration\ClientMetadataValidator:
        arguments:
            $allowedHosts: ['localhost', '127.0.0.1']
```

`AllowedResources` is a tiny value object that trims its input — add it as part of this task:

```php
<?php
declare(strict_types=1);
namespace App\OAuth\Extension;

final class AllowedResources
{
    /** @var string[] */
    private readonly array $resources;

    /** @param string[] $values */
    public function __construct(array $values)
    {
        $this->resources = array_values(array_filter(array_map('trim', $values), static fn (string $v) => $v !== ''));
    }

    /** @return string[] */
    public function all(): array { return $this->resources; }

    public function contains(string $resource): bool { return in_array($resource, $this->resources, true); }
}
```

Verify with `docker compose exec app php bin/console debug:container App\\OAuth\\…` for each registered service.

**Commit:** `chore: wire OAuth services in services.yaml (with AllowedResources trim)`

---

### Task D3: `JwksController` and the discovery controllers

**Files:**
- Create: `src/Controller/WellKnown/AuthorizationServerMetadataController.php`
- Create: `src/Controller/WellKnown/ProtectedResourceMetadataController.php`
- Create: `src/Controller/WellKnown/JwksController.php`
- Create: `tests/Controller/WellKnown/*` (functional, `WebTestCase`)

`JwksController` reads the RSA public key with `openssl_pkey_get_details()` and publishes a single JWK:

```php
$pem = file_get_contents($publicKeyPath);
$details = openssl_pkey_get_details(openssl_pkey_get_public($pem));
// $details['rsa']['n'] and $details['rsa']['e'] are raw bytes — base64url encode without padding.
$base64url = static fn (string $bytes) => rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');

return new JsonResponse([
    'keys' => [[
        'kty' => 'RSA',
        'use' => 'sig',
        'alg' => 'RS256',
        'kid' => $kidDeriver->derive(),
        'n'   => $base64url($details['rsa']['n']),
        'e'   => $base64url($details['rsa']['e']),
    ]],
]);
```

Inject `KidDeriver` from C3a so the published `kid` matches the one signed into the JWT.

**Tests** assert:
- AS metadata `issuer` is byte-equal to PRM `authorization_servers[0]`.
- JWKS endpoint returns `kty=RSA, alg=RS256` and a non-empty `kid`.
- The same `kid` value also appears in a token issued via the test fixture key (cross-check by parsing a JWT issued from `McpAccessTokenEntity` against the `KidDeriver` output).

**Commit:** `feat: add /.well-known/* discovery endpoints`

---

### Task D4: `ClientRegistrationController` + RateLimiter

**Files:**
- Create: `src/Controller/OAuth/ClientRegistrationController.php`
- Create: `tests/Controller/OAuth/ClientRegistrationControllerTest.php`
- Create: `config/packages/rate_limiter.yaml`

Symfony 8 RateLimiter config (Flex's recipe may stub this):

```yaml
framework:
    rate_limiter:
        dcr:
            policy: 'token_bucket'
            limit: 5
            rate: { interval: '1 minute', amount: 5 }
```

The framework auto-creates a `limiter.dcr` service implementing `RateLimiterFactory`. Inject it into the controller (constructor: `private RateLimiterFactory $dcrLimiter` with the `#[Target('dcr')]` attribute or service id `limiter.dcr`).

In the controller:

```php
$limit = $this->dcrLimiter->create($request->getClientIp() ?? 'anon')->consume(1);
if (!$limit->isAccepted()) {
    return new JsonResponse(['error' => 'too_many_requests'], 429, [
        'Retry-After' => (string) $limit->getRetryAfter()->getTimestamp() - time(),
    ]);
}
```

Functional tests:
- Successful registration → 201, `client_id` in body, **original** `redirect_uris` preserved verbatim in body (per RFC 7591 §3.2.1).
- Invalid `redirect_uri` host → 400, `error=invalid_redirect_uri`.
- 6 rapid POSTs from same IP → last is 429 with `Retry-After`.

**Commit:** `feat: add /oauth/register (DCR) with rate limit and host allowlist`

---

### Task D5a: Login form + Symfony Security firewall

**Files:**
- Modify: `config/packages/security.yaml` — InMemoryUserProvider with one user `alice`, `form_login` firewall covering `/oauth/authorize` and `/oauth/consent`.
- Create: `src/Controller/SecurityController.php` — `#[Route('/login', name: 'app_login')]` and `#[Route('/logout', name: 'app_logout')]`. The route names must match the `login_path`/`logout.path` strings in `security.yaml` below.
- Create: `templates/security/login.html.twig`.
- Create: `tests/Controller/SecurityControllerTest.php` — GET `/login` 200, POST with valid creds → 302 to `/`, with invalid creds → 422 + error.

`security.yaml` skeleton:

```yaml
security:
    password_hashers:
        Symfony\Component\Security\Core\User\InMemoryUser: 'auto'
    providers:
        in_memory:
            memory:
                users:
                    alice: { password: '$argon2id$…paste-output-of-security:hash-password…', roles: ['ROLE_USER'] }
    firewalls:
        dev:
            pattern: ^/(_(profiler|wdt)|css|images|js)/
            security: false
        main:
            lazy: true
            provider: in_memory
            form_login:
                login_path: app_login
                check_path: app_login
                enable_csrf: true
            logout:
                path: app_logout
    access_control:
        - { path: ^/login,    roles: PUBLIC_ACCESS }
        - { path: ^/oauth/(authorize|consent), roles: ROLE_USER }
        - { path: ^/.well-known/, roles: PUBLIC_ACCESS }
        - { path: ^/oauth/(register|token), roles: PUBLIC_ACCESS }
```

For the `alice` password, run once on the host:

```bash
docker compose exec app php bin/console security:hash-password
# enter "password" or another dev value, paste the hash into security.yaml
```

**Commit:** `feat: add login form + InMemory user 'alice', firewall over /oauth/*`

---

### Task D5b: Authorization endpoint with session storage

**Files:**
- Create: `src/Controller/OAuth/AuthorizationController.php` — `GET /oauth/authorize`. Uses `AuthorizationServer::validateAuthorizationRequest()` from `league/oauth2-server`, stores the resulting `AuthorizationRequest` in `Session::set('oauth.pending_authorization_request', …)`, then renders the consent template (the user is guaranteed authenticated by the firewall — no manual redirect needed).
- Create: `templates/oauth/consent.html.twig` — shows client name, requested scopes, Allow / Deny buttons (Symfony form with CSRF token `consent`).
- Create: `tests/Controller/OAuth/AuthorizationControllerTest.php` — covers:
  - Unauthenticated → redirect to `/login`.
  - Authenticated, missing `code_challenge` → 400 with `error=invalid_request`.
  - Authenticated, valid request → 200, consent form rendered, session contains the pending request.

**Commit:** `feat: add /oauth/authorize with session-stored AuthorizationRequest`

---

### Task D5c: Consent endpoint with one-shot consumption

**Files:**
- Create: `src/Controller/OAuth/ConsentController.php` — `POST /oauth/consent`. Steps:
  1. Validate CSRF token `consent`. On failure: 400.
  2. Pop pending request from session (`Session::get(...)` then `remove(...)`). If absent: 400.
  3. Read `decision` form field (`allow` or `deny`). For `deny`, set `$authReq->setAuthorizationApproved(false)`; for `allow`, set the user (Symfony Security's authenticated user wrapped in `App\OAuth\Entity\User($id)`).
  4. Pass `$authReq` to `AuthorizationServer::completeAuthorizationRequest($authReq, $response)` and return the resulting redirect.
- Create: `tests/Controller/OAuth/ConsentControllerTest.php` — covers:
  - CSRF missing → 400.
  - No pending request in session → 400.
  - Allow → 302 to redirect_uri with `code` + `state`.
  - Replay (POST again with same form) → 400 (one-shot consumed).
  - Deny → 302 with `error=access_denied`.

**Commit:** `feat: add /oauth/consent with CSRF + one-shot session consumption`

---

### Task D6: `TokenController`

Thin: receives the request, hands off to `AuthorizationServer::respondToAccessTokenRequest()`. The grant (Phase C5) does the heavy work.

Functional tests as listed in design §5: PKCE mismatch, resource missing/whitelist/scheme, refresh token rotation + family revocation.

**Commit:** `feat: add /oauth/token controller`

---

### Task D7: `OAuthExceptionListener`

Catches `League\OAuth2\Server\Exception\OAuthServerException` and converts to RFC-shaped JSON (`error`, `error_description`, `error_uri`) with the right status. For RS-style 401s (Phase 2), include the `WWW-Authenticate: Bearer realm="…", resource_metadata="…"` header.

For now (Phase 1), the listener only needs to handle AS-side errors. Tests: simulate each exception type and assert the body shape.

**Commit:** `feat: add OAuthExceptionListener for RFC-shaped error responses`

---

### Task D8: Routes wiring

`config/routes.yaml` is already importing `routing.controllers`, so attribute routes are picked up automatically. Verify:

```bash
docker compose exec app php bin/console debug:router | grep oauth
```

Expected: `/oauth/authorize`, `/oauth/consent`, `/oauth/token`, `/oauth/register`, `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource`, `/.well-known/jwks.json` all listed.

No commit needed unless config changes.

---

## Phase E — End-to-end verification

### Task E1: Run full PHPUnit suite

```bash
docker compose exec app vendor/bin/phpunit --testdox
```

Expected: every test from B/C/D passes. Fix anything red before moving on.

**Commit (if fixes were needed):** `test: stabilize <area> tests`

---

### Task E2: Manual flow with `curl`

Follow design §5 手動検収シナリオ. Capture each command and response in a working notes file (do not commit).

1. `curl -s http://localhost:8000/.well-known/oauth-authorization-server | jq .`
2. `curl -s http://localhost:8000/.well-known/oauth-protected-resource | jq .`
3. `curl -s http://localhost:8000/.well-known/jwks.json | jq .`
4. DCR: `curl -X POST http://localhost:8000/oauth/register -H 'Content-Type: application/json' -d '{"redirect_uris":["http://localhost:9000/cb"], "grant_types":["authorization_code","refresh_token"]}'`
5. Authorize in a real browser (PKCE generated in a small helper script; see §5).
6. Token exchange: `curl -X POST http://localhost:8000/oauth/token -d '...'`
7. Decode the JWT at https://jwt.io and verify `iss`, `aud` (array), `scope`, `kid`.

If anything fails, return to the relevant Phase task and add a regression test before fixing.

---

### Task E3: Manual flow with Claude Desktop

Configure Claude Desktop to use `http://localhost:8000/mcp` as a remote MCP server. Even though `/mcp` returns 404, Claude Desktop should:
- Discover via WWW-Authenticate (returned by `/mcp` 404 with the right header — verify this; if not, accept this as a Phase 2 concern and short-circuit by hand-feeding Discovery URL).
- Run DCR → 201.
- Open browser to `/oauth/authorize` → login → consent.
- Exchange the code → JWT.

**Acceptance:** Claude Desktop logs show a JWT was received with correct claims. Note success in `docs/plans/2026-04-29-oauth-2-1-as-phase1-acceptance.md` (commit this notes file).

**Commit:** `docs: record Phase 1 acceptance run`

---

## Notes for the implementer

- **One Task = one commit** unless explicitly split. Keep diffs small enough to read in one sitting.
- **Always re-read the spec** (`docs/plans/2026-04-29-oauth-mcp-poc-design.md` §1 invariants list) before C3/C5/D5 — these are the trickiest tasks and the spec catches things this plan won't.
- **Don't skip step 2 (run-fail)**. If the test passes before you implemented anything, the test is wrong — fix it before continuing.
- **If a task feels too big**, split it. The skill rule is 2-5 minutes per step; 15-20 minutes per task. D5 in particular tends to swell — split aggressively.
- **Stuck for more than 30 minutes on one task?** Stop, write down what you tried in a scratch file, and ask before proceeding.
