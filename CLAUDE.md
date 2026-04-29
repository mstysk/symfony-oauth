# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project state

This is a freshly scaffolded Symfony 8.0 skeleton (PHP >= 8.4). Only `FrameworkBundle` is enabled (`config/bundles.php`), `src/Controller/` is empty, and there is no `tests/` directory or PHPUnit dependency. Treat anything beyond the skeleton as not-yet-built.

## Intended direction

The repo is a PoC for an **OAuth 2.1 Authorization Server + MCP Resource Server, both written in PHP, hosted in this single Symfony app** (separate from the in-house `logiless-mcp`). The full design lives at `docs/plans/2026-04-29-oauth-mcp-poc-design.md`; key invariants:

- Two phases: **Phase 1 = AS only** (OAuth flow end-to-end, MCP RS not yet present, `/mcp` returns 404). **Phase 2 = add MCP RS in the same app** using a PHP MCP SDK (candidate: `php-mcp/server`). All-PHP single process; do not split by language.
- Adopt **`league/oauth2-server`** as the OAuth core (PKCE built in via `enableCodeExchangeProof()`). Do not try to extend `friendsofsymfony/oauth-server-bundle` — PKCE retrofitting was the reason for moving away from it.
- MCP-specific OAuth extensions not provided by `league/oauth2-server` are isolated under `src/OAuth/Extension/` so they can be deleted when upstream catches up:
  - **RFC 8414** Authorization Server Metadata — `/.well-known/oauth-authorization-server` JSON.
  - **RFC 8707** Resource Indicators — `resource` parameter accepted, injected into the JWT `aud` claim via a custom `AccessTokenEntityInterface` implementation and a subclassed `AuthorizationCodeGrant`. Allowed values come from `MCP_ALLOWED_RESOURCES` (comma-separated, exact match).
  - **RFC 7591** Dynamic Client Registration — `/oauth/register`, open registration (no initial access token) for the PoC.
  - **RFC 9728** Protected Resource Metadata — `/.well-known/oauth-protected-resource`. Lives in this repo because the RS will too (Phase 2).
- Tokens are JWT (RS256). Keys at `config/jwt/{private,public}.key`, generated manually with `openssl genrsa` (committed `.gitkeep` only). JWKS exposed at `/.well-known/jwks.json`. The Phase 2 RS verifies tokens by reading the public key file directly (same process), not by HTTP-fetching JWKS.
- Persistence: SQLite + Doctrine ORM at `var/data/oauth.db`. Users are `Symfony\Security` InMemoryUserProvider only (not in DB); `oauth_*.user_id` stores `UserInterface::getUserIdentifier()` as a string.
- OAuth 2.1 hard requirements: PKCE for **all** clients (incl. confidential), exact-match redirect URIs, no Implicit / ROPC grants, refresh tokens rotate, no bearer tokens in URL query strings.
- Out of scope for the PoC: MySQL/Postgres, KMS-managed keys, rate limiting, CSRF beyond Symfony defaults, GitHub Actions, PHPStan/Psalm.

## Common commands

The expected workflow is Docker-based. `compose.yaml` runs a single `app` service (PHP 8.4 CLI built-in server on port 8000) with `SYMFONY_DISABLE_DOTENV=1`, so all env values come from the Compose `environment:` block (interpolated from `.env` via Compose's auto-load, with `${VAR:-default}` fallbacks). There is no `env_file:` directive.

- `docker compose up` — start the AS at `http://localhost:8000`.
- `docker compose exec app php bin/console <command>` — Symfony console. Useful subcommands:
  - `debug:router` — list routes (referenced from `config/routes.yaml`).
  - `debug:container` / `debug:autowiring` — inspect the DI container.
  - `doctrine:migrations:migrate` — apply pending migrations (Phase 1 onward).
  - `security:hash-password` — generate Argon2id hashes for `security.yaml` InMemory users.
- `docker compose exec app composer install` — install dependencies inside the container.
- `vendor/bin/phpunit` (run via `docker compose exec app …`) — once `symfony/test-pack` is added, single test: `vendor/bin/phpunit --filter SomeTest tests/Path/SomeTest.php`. Functional tests use `WebTestCase` and reset the SQLite schema in `setUp()`.
- Key generation (host-side, one-time): `openssl genrsa -out config/jwt/private.key 4096 && openssl rsa -in config/jwt/private.key -pubout -out config/jwt/public.key && chmod 600 config/jwt/private.key`.
- No linter/static analyzer is configured. `.editorconfig` is the only style enforcement.

## Architecture

- **MicroKernel.** `src/Kernel.php` extends `BaseKernel` with `MicroKernelTrait`. There is no custom `configureRoutes`/`configureContainer` — the trait's defaults load everything from `config/`.
- **Service wiring** (`config/services.yaml`): `autowire` + `autoconfigure` are on, and `App\` is registered as a PSR-4 resource over `src/`. Any class added under `src/` becomes a service (id = FQCN) without further configuration. Add explicit definitions only when autowiring can't infer them.
- **Routing.** `config/routes.yaml` imports the `routing.controllers` resource, which scans `src/Controller/` for `#[Route]` attributes — controllers are auto-registered, no manual entries needed. `config/routes/framework.yaml` mounts the dev error pages under `/_error`.
- **Bundles.** Only `FrameworkBundle` (with `session: true`) is registered. When adding capabilities (security, twig, doctrine, etc.), prefer Symfony Flex recipes (`composer require ...`) so `symfony.lock`, `config/packages/*.yaml`, and `config/bundles.php` stay in sync.
- **Environment.** Inside the container, `SYMFONY_DISABLE_DOTENV=1` is set, so Symfony does **not** read `.env` / `.env.local` at runtime — values flow through Compose's `environment:` block. The committed `.env` exists for Symfony Flex recipe compatibility and host-side fallback only; treat it as a defaults file (no real secrets). `OAUTH_ENCRYPTION_KEY` is required and intentionally has no Compose default — set it in `.env` (committed dev value is OK for PoC) or export it before `docker compose up`.
