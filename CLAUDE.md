# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project state

**Phase 1 (OAuth 2.1 Authorization Server) is merged on `main`.** All AS endpoints (`/.well-known/oauth-{authorization-server,protected-resource}`, `/.well-known/jwks.json`, `/oauth/{register,authorize,consent,token}`, `/login`) are wired and tested (88 tests / 228 assertions). CI on every PR via `.github/workflows/ci.yml`. **Phase 2** adds the co-located MCP Resource Server (`/mcp`) — not yet started.

History: see `docs/plans/2026-04-29-oauth-2-1-as-phase1.md` (implementation plan) and `docs/plans/2026-05-05-phase1-retrospective.md` (lessons learned, **read before starting Phase 2**).

## Intended direction

The repo is a PoC for an **OAuth 2.1 Authorization Server + MCP Resource Server, both written in PHP, hosted in this single Symfony app** (separate from the in-house `logiless-mcp`). The full design lives at `docs/plans/2026-04-29-oauth-mcp-poc-design.md`; key invariants:

- Two phases: **Phase 1 = AS only** (OAuth flow end-to-end, MCP RS not yet present, `/mcp` returns 404). **Phase 2 = add MCP RS in the same app** using a PHP MCP SDK (candidate: `php-mcp/server`). All-PHP single process; do not split by language.
- Adopt **`league/oauth2-server`** as the OAuth core. PKCE-for-all-clients (S256-only) is enforced by overriding `validateAuthorizationRequest` in `ResourceIndicatorGrant` (league v9 removed `enableCodeExchangeProof()` and only mandates PKCE for public clients by default). Do not try to extend `friendsofsymfony/oauth-server-bundle` — PKCE retrofitting was the reason for moving away from it.
- MCP-specific OAuth extensions not provided by `league/oauth2-server` are isolated under `src/OAuth/Extension/` so they can be deleted when upstream catches up:
  - **RFC 8414** Authorization Server Metadata — `/.well-known/oauth-authorization-server` JSON.
  - **RFC 8707** Resource Indicators — `resource` validated at /authorize, **bound onto the auth code** (`oauth_auth_codes.resource`), re-checked at /token, and injected into the JWT `aud` claim via `McpAccessTokenEntity` + `ResourceIndicatorGrant`. Allowed values come from `MCP_ALLOWED_RESOURCES` (comma-separated, exact match).
  - **RFC 7591** Dynamic Client Registration — `/oauth/register`, open registration with redirect-host allowlist + 5/min rate limit.
  - **RFC 9728** Protected Resource Metadata — `/.well-known/oauth-protected-resource`. Lives in this repo because the RS will too (Phase 2).
  - **RFC 9700 §4.14** refresh-token family revocation — `family_id` propagation across rotation (`FamilyAwareRefreshTokenGrant`); replay of a revoked RT poisons the entire family via `RefreshTokenRepository::isRefreshTokenRevoked` side-effect.
  - **Confused-deputy defense at /consent** — `/authorize` mints a fresh `request_id`, the consent form binds the POST to that id (per-id session entry), so a second `/authorize` cannot silently swap which request the user "consents" to.
- Tokens are JWT (RS256). Keys at `config/jwt/{private,public}.key`, generated manually with `openssl genrsa` (committed `.gitkeep` only). JWKS exposed at `/.well-known/jwks.json`; the `kid` header on issued JWTs and the `kid` published in JWKS both come from the shared `KidDeriver` (sha256 of public-key PEM, first 16 hex). The Phase 2 RS should verify tokens by reading the public key file directly (same process), not by HTTP-fetching JWKS.
- Persistence: SQLite + Doctrine ORM at `var/data/oauth.db`. Users are `Symfony\Security` InMemoryUserProvider only (not in DB); `oauth_*.user_id` stores `UserInterface::getUserIdentifier()` as a string.
- OAuth 2.1 hard requirements: PKCE for **all** clients (incl. confidential), exact-match redirect URIs (post-normalize), no Implicit / ROPC grants, refresh tokens rotate, no bearer tokens in URL query strings.
- Out of scope for the PoC: MySQL/Postgres, KMS-managed keys, login throttling beyond DCR rate-limit, CSRF beyond Symfony defaults, PHPStan/Psalm.

## Common commands

The expected workflow is Docker-based. `compose.yaml` runs a single `app` service (PHP 8.4 CLI built-in server on port 8000) with `SYMFONY_DISABLE_DOTENV=1`, so all env values come from the Compose `environment:` block (interpolated from a host-local `.env` via Compose's auto-load, with `${VAR:-default}` fallbacks). There is no `env_file:` directive.

- `cp .env.example .env` — first-time only; `.env` is **gitignored** (see "Secrets" below).
- `docker compose up` — start the AS at `http://localhost:8000`.
- `docker compose exec app php bin/console <command>` — Symfony console. Useful subcommands:
  - `debug:router` — list routes (auto-discovered from `#[Route]` attributes).
  - `debug:container` / `debug:autowiring` — inspect the DI container.
  - `doctrine:migrations:migrate` — apply pending migrations.
  - `doctrine:mapping:info` — show registered Doctrine entities.
  - `security:hash-password` — generate Argon2id hashes for `security.yaml` InMemory users.
- `docker compose exec app composer install` — install dependencies inside the container.
- Tests (run from host via Docker): `docker compose exec -e SYMFONY_DISABLE_DOTENV=0 -e APP_ENV=test app vendor/bin/phpunit`. The two `-e` overrides are needed because the container ships `SYMFONY_DISABLE_DOTENV=1`; tests need to read `.env.test` instead. Single test: append `--filter SomeTest tests/Path/SomeTest.php`. Functional tests use `WebTestCase` + a `DoctrineKernelTestCase` base that drops/recreates the schema in `setUp()`.
- Key generation (host-side, one-time): `openssl genrsa -out config/jwt/private.key 4096 && openssl rsa -in config/jwt/private.key -pubout -out config/jwt/public.key && chmod 600 config/jwt/private.key`.
- No linter/static analyzer is configured. `.editorconfig` is the only style enforcement. CI runs `composer audit` per PR.

## Architecture

- **MicroKernel.** `src/Kernel.php` extends `BaseKernel` with `MicroKernelTrait`. There is no custom `configureRoutes`/`configureContainer` — the trait's defaults load everything from `config/`.
- **Service wiring** (`config/services.yaml`): `autowire` + `autoconfigure` are on, and `App\` is registered as a PSR-4 resource over `src/`. Any class added under `src/` becomes a service (id = FQCN) without further configuration. Add explicit definitions only when autowiring can't infer them.
- **Routing.** `config/routes.yaml` imports the `routing.controllers` resource, which scans `src/Controller/` for `#[Route]` attributes — controllers are auto-registered, no manual entries needed. `config/routes/framework.yaml` mounts the dev error pages under `/_error`.
- **Bundles.** Only `FrameworkBundle` (with `session: true`) is registered. When adding capabilities (security, twig, doctrine, etc.), prefer Symfony Flex recipes (`composer require ...`) so `symfony.lock`, `config/packages/*.yaml`, and `config/bundles.php` stay in sync.
- **Environment.** Inside the container, `SYMFONY_DISABLE_DOTENV=1` is set, so Symfony does **not** read `.env` / `.env.local` at runtime — values flow through Compose's `environment:` block. The host's `.env` (gitignored) is used for Compose's `${VAR}` interpolation; `.env.example` is the committed template. `OAUTH_ENCRYPTION_KEY` has no Compose default — copy `.env.example`, paste the output of `vendor/bin/generate-defuse-key` into your local `.env`. **Never commit a real key**, even a "dev-only" one — see "Secrets" below.

## Secrets

- **`.env` is gitignored.** Use `.env.example` as the template. CI seeds `.env` from the example before `composer install` (the `@auto-scripts` post-install hook boots the kernel and `Dotenv::bootEnv()` requires the file to exist).
- **`.env.test`** ships `OAUTH_ENCRYPTION_KEY=GENERATE_AT_RUNTIME`. `tests/bootstrap.php` swaps that sentinel for a freshly-generated `defuse/php-encryption` key per test run, so no real secret lives in the repo.
- **`tests/fixtures/{private,public}.key`** are committed test-only RSA keys for hermetic JWT-issuance tests. They MUST NOT be used to sign real tokens. GitGuardian allowlist is in `.gitguardian.yml`.
- **`config/jwt/{private,public}.key`** are gitignored; production keys would be loaded from a KMS in a real deployment.

## Conventions carried over from Phase 1 (apply in Phase 2)

These are not "nice to haves" — each was learned the hard way by either ultrareview, the post-merge code review, or CI. Full retrospective with attribution: `docs/plans/2026-05-05-phase1-retrospective.md`.

- **State stash on a singleton grant must be cleared in `finally`.** Both `ResourceIndicatorGrant` (`$pendingResource`, `$pendingCodeResource`) and `FamilyAwareRefreshTokenGrant` (`$pendingFamilyId`) use `try { parent::... } finally { $this->pending = null; }`. Without `finally`, an exception leaves the property set, and on RoadRunner / FrankenPHP / Swoole the next request inherits it. **If you add a similar pending field, copy the try/finally pattern.**
- **`league/oauth2-server`'s `issue*Token` methods need to be re-implemented when you want to inject one extra setter before persist.** Look at `ResourceIndicatorGrant::issueAuthCode` / `issueAccessToken` / `issueRefreshToken` and `FamilyAwareRefreshTokenGrant::issueRefreshToken`. They are near-identical copies of `AbstractGrant`'s loops with a single setter inserted. Until league exposes a before-persist hook, copy this pattern.
- **Repository methods that "validate" can also fire defenses.** `RefreshTokenRepository::isRefreshTokenRevoked` is the only safe place to trigger family revocation because league calls it during refresh-flow validation (see RFC 9700 §4.14 hook discussion in the file). The side-effect is documented in-line; preserve that contract.
- **`%env(VAR)%` returns the env value as-is.** If the value contains `%kernel.project_dir%` or another parameter reference (e.g. `.env.test` paths), wrap with `%env(resolve:VAR)%` so the substitution happens. Tests passed locally without `resolve:` only because Docker compose was setting an absolute path; CI exposed the gap.
- **CI before code.** Symfony's `@auto-scripts` post-install hook boots the kernel during `composer install`, so anything that boot needs (notably `.env`) has to exist by then. Mirror the order in `.github/workflows/ci.yml` if you add new install-time steps.
- **Don't commit `.env` "for the PoC".** Even values labelled "dev only" trigger GitGuardian incidents and require a `git filter-repo` + force-push to clean up. `.env.example` + `.env` (gitignored) was the right shape from day 1.
- **Test naming = attack scenario.** Names like `test_refresh_token_reuse_kills_the_legitimate_chain` /  `test_token_resource_mismatch_with_bound_value_returns_invalid_target` made review painless because each test name described what attack it was preventing. Keep this style.
- **One commit per task.** 44 commits in the merge — each `feat:` / `fix:` / `chore:` / `test:` / `docs:` traceable to a plan task. ultrareview reports cite specific lines; reverting a single problem is `git revert <sha>`.

## When starting Phase 2

The MCP Resource Server (`/mcp`) needs:
- JWT verification using `config/jwt/public.key` directly (same process — do **not** HTTP-fetch JWKS).
- `aud` claim validation against the configured resource value.
- `iss` claim validation against `OAUTH_ISSUER`.
- `kid` header check against `KidDeriver::derive()` (so a future key-rotation just changes the file).
- 401 response with `WWW-Authenticate: Bearer realm="...", resource_metadata="..."` per RFC 9728 § 5.1 — that's how MCP clients discover the AS.

These are the spots most likely to be wrong on the first pass; write the negative tests first.
