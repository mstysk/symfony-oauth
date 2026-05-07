# symfony-oauth — OAuth 2.1 AS + MCP RS

[![CI](https://github.com/mstysk/symfony-oauth/actions/workflows/ci.yml/badge.svg)](https://github.com/mstysk/symfony-oauth/actions/workflows/ci.yml)

OAuth 2.1 Authorization Server **and** co-located MCP Resource Server in
PHP/Symfony 8, in a single app process.

> **Status:** Phase 1 (Authorization Server) and Phase 2 (MCP Resource
> Server with Bearer JWT auth + an `echo` tool) are both complete.
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
| `/mcp` | POST | MCP Resource Server (JSON-RPC 2.0; Bearer JWT required) |

## MCP-spec invariants enforced

- **PKCE (S256) required for all clients** — confidential included; stricter than league's default.
- **Strict redirect_uri match** post-normalize; no Implicit / ROPC.
- **RFC 8707 `resource` binding** — validated at `/authorize`, persisted on the auth code, re-checked at `/token`, injected as `aud[]` in the JWT (audience-confused-deputy defense).
- **JWKS / JWT `kid` agreement** — both derived from the same `KidDeriver` so verifiers can pin keys.
- **Refresh token rotation + RFC 9700 §4.14 family revocation** — replaying a revoked refresh token poisons the entire family.
- **Consent is bound to a per-request `request_id`** — defeats session-key overwrite confused-deputy.
- **DCR open registration** with redirect-host allowlist.
- **No bearer tokens in URL query strings** (PRM `bearer_methods_supported = ["header"]`).
- **/mcp validates the JWT in-process** — same Symfony app reads the public key directly (no HTTP-fetched JWKS), then checks signature → exp/nbf → iss → aud (allow-list) → kid header → revocation, in that order. Missing scope is 403 with RFC 6750 §3.1 `error="insufficient_scope"`; missing/invalid Bearer is 401 with RFC 9728 §5.1 `resource_metadata` pointing at `/.well-known/oauth-protected-resource`.

## Architecture

```
src/
├── Controller/
│   ├── OAuth/                      # /oauth/{authorize,consent,register,token}
│   ├── WellKnown/                  # /.well-known/oauth-* + jwks
│   ├── Mcp/McpController.php       # /mcp (Phase 2)
│   └── SecurityController.php      # /login, /logout
├── EventListener/
│   ├── OAuthExceptionListener.php  # league exception → RFC-shaped JSON / 302
│   └── McpAuthenticationListener.php  # WWW-Authenticate on /mcp 401/403 (Phase 2)
├── Mcp/                            # Phase 2 — JSON-RPC dispatch + tools
│   ├── JsonRpcDispatcher.php       # initialize / tools/list / tools/call
│   ├── JsonRpcException.php        # JSON-RPC 2.0 error codes
│   └── Tool/                       # ToolInterface + EchoTool (autoconfigured)
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
├── Security/                       # Phase 2 — Bearer JWT validation + firewall
│   ├── JwtAccessTokenValidator.php # signature/exp/iss/aud/kid/scope/revocation
│   ├── BearerJwtAuthenticator.php  # Symfony Authenticator for ^/mcp
│   ├── ValidatedToken.php          # parsed-claims value object
│   └── InvalidJwt{Exception,Reason}.php
config/
├── packages/
│   ├── doctrine.yaml               # types: { uuid: UuidType }
│   ├── nelmio_cors.yaml            # MCP Inspector preflight (Phase 2)
│   ├── rate_limiter.yaml           # dcr: 5/min token bucket
│   └── security.yaml               # InMemory provider + ^/mcp Bearer firewall
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

## Calling /mcp

`/mcp` accepts a single JSON-RPC 2.0 message per POST. A request without a
valid Bearer JWT gets 401 + `WWW-Authenticate` pointing at the
protected-resource metadata URL — that's how an MCP Inspector or Claude
Desktop client discovers the AS to acquire a token from.

```bash
# Discovery (no auth required)
curl -i -X POST http://localhost:8000/mcp -H 'Content-Type: application/json' -d '{}'
# → 401, WWW-Authenticate: Bearer realm="symfony-oauth",
#                         resource_metadata="…/.well-known/oauth-protected-resource"

# After acquiring a token (drive /authorize → /consent → /token):
TOKEN=…
curl -s -X POST http://localhost:8000/mcp \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"message":"hi"}}}'
# → {"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"hi"}],"isError":false}}
```

**MCP Inspector v0.21+:**

```bash
npx @modelcontextprotocol/inspector
```

Connect to `http://localhost:8000/mcp` with the Bearer token from the
flow above. The Inspector's CORS preflight is allow-listed for
`localhost:6274` (and Vite at `:5173`); other origins are rejected.

## Tests

```bash
docker compose exec \
  -e SYMFONY_DISABLE_DOTENV=0 -e APP_ENV=test \
  app vendor/bin/phpunit
```

The `SYMFONY_DISABLE_DOTENV=0` override is needed because the container
sets it to `1` in dev so Compose-injected env wins; tests, however, need
to read `.env.test`.

CI runs the same suite plus `composer audit` and `phpstan analyse` (level
6) on every PR — see [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

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

## Out of scope (PoC)

- MySQL/Postgres (SQLite only for the PoC).
- KMS-managed signing keys; secret rotation.
- Login throttling beyond DCR rate-limit.
- MCP `resources` / `prompts` / `sampling` (Phase 2 covers tools only).
- SSE streaming / session resumability on `/mcp`.
- Multi-tenant / multi-issuer.
