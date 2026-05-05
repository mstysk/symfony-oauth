# symfony-oauth — OAuth 2.1 AS for MCP

[![CI](https://github.com/mstysk/symfony-oauth/actions/workflows/ci.yml/badge.svg)](https://github.com/mstysk/symfony-oauth/actions/workflows/ci.yml)

OAuth 2.1 Authorization Server in PHP/Symfony 8, designed to satisfy the
Model Context Protocol (MCP) authorization profile end-to-end.

> **Status:** Phase 1 (Authorization Server) complete. Phase 2 will add
> the co-located MCP Resource Server (`/mcp`) in the same Symfony app.
> Detailed design: [`docs/plans/2026-04-29-oauth-mcp-poc-design.md`](docs/plans/2026-04-29-oauth-mcp-poc-design.md).
> Phase 1 implementation plan: [`docs/plans/2026-04-29-oauth-2-1-as-phase1.md`](docs/plans/2026-04-29-oauth-2-1-as-phase1.md).

## What it does

A PHP/Symfony AS that an MCP client (e.g. Claude Desktop) can run the
full Discovery → Dynamic Client Registration → Authorize → Token
Exchange flow against. It is built on top of `league/oauth2-server` for
the standard OAuth core, with MCP-specific RFC layers isolated under
`src/OAuth/Extension/` so they can be removed when upstream catches up.

| Concern | Implementation |
|---|---|
| Core OAuth grants | `league/oauth2-server` v9 |
| JWT signing | `lcobucci/jwt` v5 (RS256) |
| Token encryption (auth code, refresh token wrappers) | `defuse/php-encryption` |
| Persistence | Doctrine ORM + SQLite (`var/data/oauth.db`) |
| Users | Symfony Security `InMemoryUserProvider` (PoC) |

## Endpoints

| Path | Method | Purpose |
|---|---|---|
| `/.well-known/oauth-authorization-server` | GET | RFC 8414 AS metadata |
| `/.well-known/oauth-protected-resource` | GET | RFC 9728 PRM (Phase 2 RS) |
| `/.well-known/jwks.json` | GET | JWKS (RSA `n`/`e`, `kid` agrees with issued JWTs) |
| `/oauth/register` | POST | RFC 7591 Dynamic Client Registration (rate limited 5/min) |
| `/oauth/authorize` | GET | OAuth 2.1 authorize, with RFC 8707 `resource` binding |
| `/oauth/consent` | POST | One-shot CSRF-protected consent submit |
| `/oauth/token` | POST | Authorization code + refresh token grants |
| `/login`, `/logout` | GET\|POST | InMemory user login form |

## MCP-spec invariants enforced

- **PKCE (S256) required for all clients** — confidential included; stricter than league's default.
- **Strict redirect_uri match** post-normalize; no Implicit / ROPC.
- **RFC 8707 `resource` binding** — validated at `/authorize`, persisted on the auth code, re-checked at `/token`, injected as `aud[]` in the JWT (audience-confused-deputy defense).
- **JWKS / JWT `kid` agreement** — both derived from the same `KidDeriver` so verifiers can pin keys.
- **Refresh token rotation + RFC 9700 §4.14 family revocation** — replaying a revoked refresh token poisons the entire family.
- **Consent is bound to a per-request `request_id`** — defeats session-key overwrite confused-deputy.
- **DCR open registration** with redirect-host allowlist.
- **No bearer tokens in URL query strings** (PRM `bearer_methods_supported = ["header"]`).

## Architecture

```
src/
├── Controller/
│   ├── OAuth/                      # /oauth/{authorize,consent,register,token}
│   ├── WellKnown/                  # /.well-known/oauth-* + jwks
│   └── SecurityController.php      # /login, /logout
├── EventListener/
│   └── OAuthExceptionListener.php  # league exception → RFC-shaped JSON / 302
├── OAuth/
│   ├── Entity/                     # Doctrine + league entity adapters
│   ├── Extension/                  # MCP/RFC layers absent from league
│   │   ├── ResourceIndicatorGrant.php       # PKCE-required + RFC 8707
│   │   ├── FamilyAwareRefreshTokenGrant.php # RFC 9700 §4.14
│   │   ├── McpAccessTokenEntity.php         # JWT issuer (aud[], iss, kid)
│   │   ├── KidDeriver.php                   # JWT/JWKS kid agreement
│   │   ├── ServerMetadataBuilder.php        # RFC 8414
│   │   ├── ProtectedResourceMetadataBuilder.php # RFC 9728
│   │   └── DynamicClientRegistration/       # RFC 7591
│   ├── Repository/                 # Doctrine repos + league interface adapters
│   └── Server/
│       └── AuthorizationServerFactory.php   # league AS wiring
config/
├── packages/
│   ├── doctrine.yaml               # types: { uuid: UuidType }
│   ├── rate_limiter.yaml           # dcr: 5/min token bucket
│   └── security.yaml               # InMemory provider, firewall
└── services.yaml                   # explicit DI for env-driven services
docs/plans/                         # design + phase plans (source of truth)
```

## Quick start

```bash
# 1. Bootstrap your local .env from the committed template (gitignored).
cp .env.example .env

# 2. Generate RSA signing keys (one-time, host-side; gitignored).
openssl genrsa -out config/jwt/private.key 4096
openssl rsa -in config/jwt/private.key -pubout -out config/jwt/public.key
chmod 600 config/jwt/private.key

# 3. Generate the defuse/php-encryption key and paste it into .env
#    as OAUTH_ENCRYPTION_KEY.
docker compose run --rm app vendor/bin/generate-defuse-key

# 4. Boot
docker compose up

# 5. Apply migrations
docker compose exec app php bin/console doctrine:migrations:migrate -n

# 6. Verify discovery
curl -s http://localhost:8000/.well-known/oauth-authorization-server | jq .
```

## Tests

```bash
docker compose exec \
  -e SYMFONY_DISABLE_DOTENV=0 -e APP_ENV=test \
  app vendor/bin/phpunit
```

The `SYMFONY_DISABLE_DOTENV=0` override is needed because the container
sets it to `1` in dev so Compose-injected env wins; tests, however, need
to read `.env.test`.

CI runs the same suite plus `composer audit` on every PR — see
[`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## Secrets handling

- `.env` is **gitignored**. `.env.example` is the committed template; copy it locally and fill in real values.
- `.env.test` ships with `OAUTH_ENCRYPTION_KEY=GENERATE_AT_RUNTIME`. `tests/bootstrap.php` swaps the sentinel for a freshly-generated `defuse/php-encryption` key per test run, so no real secret ever lives in the repo.
- `tests/fixtures/{private,public}.key` are committed **test-only** RSA keys for hermetic JWT-issuance tests. They MUST NOT be used to sign real tokens. See [`tests/fixtures/README.md`](tests/fixtures/README.md).
- Production keys live under `config/jwt/` and are gitignored.

## Useful Docker commands

```bash
# Show registered routes
docker compose exec app php bin/console debug:router

# Show registered services in the App\OAuth namespace
docker compose exec app php bin/console debug:container 'App\OAuth\\'

# Inspect Doctrine entity mapping
docker compose exec app php bin/console doctrine:mapping:info

# Hash a password for the InMemory provider
docker compose exec app php bin/console security:hash-password
```

## Out of scope (Phase 1)

- The MCP Resource Server (`/mcp`) — Phase 2.
- MySQL/Postgres (SQLite only for the PoC).
- KMS-managed signing keys; secret rotation.
- Login throttling beyond DCR rate-limit.
- PHPStan / Psalm static analysis.
- Multi-tenant / multi-issuer.
