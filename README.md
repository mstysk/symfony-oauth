# symfony-oauth — OAuth 2.1 AS for MCP

PoC of an OAuth 2.1 Authorization Server (and, in Phase 2, a co-located
MCP Resource Server) written in PHP/Symfony 8. Spec lives at
`docs/plans/2026-04-29-oauth-mcp-poc-design.md`.

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

# 6. Open http://localhost:8000/.well-known/oauth-authorization-server
```

### Secrets handling

- `.env` is gitignored — never commit one with real values. `.env.example`
  is the committed template.
- `.env.test` ships with `OAUTH_ENCRYPTION_KEY=GENERATE_AT_RUNTIME`;
  `tests/bootstrap.php` swaps in a freshly-generated defuse key per test
  run, so no real key lives in the repo.
- `tests/fixtures/{private,public}.key` are committed test-only RSA keys,
  used by the unit suite for hermetic JWT tests. They MUST NOT be used to
  sign real tokens.

## Tests

```bash
docker compose exec -e SYMFONY_DISABLE_DOTENV=0 -e APP_ENV=test app vendor/bin/phpunit
```

The `SYMFONY_DISABLE_DOTENV=0` override is needed because the container
sets it to `1` in dev so Compose-injected env wins; tests, however, need
to read `.env.test`.
