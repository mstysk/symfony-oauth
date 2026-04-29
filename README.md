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
docker compose exec -e SYMFONY_DISABLE_DOTENV=0 -e APP_ENV=test app vendor/bin/phpunit
```

The `SYMFONY_DISABLE_DOTENV=0` override is needed because the container
sets it to `1` in dev so Compose-injected env wins; tests, however, need
to read `.env.test`.
