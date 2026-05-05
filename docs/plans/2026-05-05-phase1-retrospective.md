# Phase 1 Retrospective — OAuth 2.1 Authorization Server

Merged: 2026-05-05 (PR #1, 44 commits, 88 tests / 228 assertions).
Implementation plan: `docs/plans/2026-04-29-oauth-2-1-as-phase1.md`.

This is a permanent record of what worked, what we'd do differently,
and the conventions that apply going into Phase 2 (MCP Resource Server).
The `CLAUDE.md` "Conventions" section is the operational extract; this
file holds the reasoning.

## What worked

### TDD with one-commit-per-task

The implementation plan broke 30+ tasks into 2-5 minute steps. Sticking
to **one commit per task** (with `feat:` / `fix:` / `chore:` / `test:` /
`docs:` prefixes) gave:

- ultrareview / code-review reports that cited specific commits and
  line ranges (instead of a giant blob).
- `git revert <sha>` for any single problem.
- Easy to walk the history backwards and find when a behaviour was
  introduced.

44 commits felt heavy at first but proved cheap once review started.

### Layered review — three independent passes each found different bugs

| Layer | Found | Examples |
|---|---|---|
| ultrareview (cloud, multi-agent) | 6 | RFC 8707 audience-confused-deputy, refresh-token reuse defense not actually wired, RFC 7591 `client_secret_expires_at` missing, RFC 6749 §4.1.2.1 errors not redirecting, RefreshTokenGrant never enabled, consent confused-deputy via session-key overwrite |
| Self-review (`/review`) | 1 | `$pendingFamilyId` leaks across requests when `issueRefreshToken` throws |
| CI | 2 | `.env` ordering vs `composer install`'s post-install hook; `%kernel.project_dir%` not expanded in env values without `resolve:` |

None of the layers was redundant — each caught a class of bug the
others missed. ultrareview was best at "did you implement the spec",
self-review at "is the pattern consistent across files", CI at
"does this work outside the local Docker environment".

### Spec citations in code

Comments like `// RFC 9700 §4.14 — re-use detected. Revoke the entire
family.` made later review trivial. When the next maintainer asks
"why does this method have a side effect?" the answer is right there.

### `Extension/` isolation

`src/OAuth/Extension/` holds every RFC layer that league/oauth2-server
doesn't ship: `ServerMetadataBuilder`, `ProtectedResourceMetadataBuilder`,
`KidDeriver`, `McpAccessTokenEntity`, `ResourceIndicatorGrant`,
`FamilyAwareRefreshTokenGrant`, `SimpleRefreshTokenEntity`,
`AuthorizationRequest`, `RedirectUriNormalizer`, `AllowedResources`,
`DynamicClientRegistration/{ClientMetadataValidator,ClientRegistrar}`.

When upstream catches up to RFC 8707 / 9728 / 7591 / 9700 §4.14, those
files can be deleted in one PR without touching `Repository/` or
`Server/`.

## What we'd do differently

### CI from day 1

CI was added at commit ~32 of 44. Two CI-only failures appeared
immediately:

1. `composer install` runs Symfony's `@auto-scripts` post-install hook,
   which calls `cache:clear`, which boots the kernel, which calls
   `Dotenv::bootEnv()`. If `.env` isn't there, the install fails. The
   workflow has to `cp .env.example .env` **before** install.
2. `.env.test` uses `%kernel.project_dir%/tests/fixtures/...` for
   key paths. With plain `%env(OAUTH_PUBLIC_KEY_PATH)%` Symfony returns
   the value verbatim — `%kernel.project_dir%` is not substituted. We
   needed `%env(resolve:OAUTH_PUBLIC_KEY_PATH)%`. **Locally with Docker
   the bug was masked** because `compose.yaml` sets an absolute path
   that doesn't need substitution.

Both bugs would have surfaced in week 1 if CI had run from the start.

### Don't commit `.env` "for the PoC"

The original `CLAUDE.md` said dev values in `.env` were OK, and we
followed that. **GitGuardian disagreed.** Cleanup required:
`git filter-repo --replace-text` to scrub three secret strings from
all 44 commits, then `--force-with-lease` push to main and the PR
branch (PR commit hashes all changed, lost the original PR-1 comment
attribution to specific SHAs).

The fix that actually works:
- `.env.example` (committed template, placeholders only).
- `.env` in `.gitignore`.
- `.env.test` with `OAUTH_ENCRYPTION_KEY=GENERATE_AT_RUNTIME`,
  resolved by `tests/bootstrap.php` to a fresh defuse key per run.

Adopt this from the first commit in any future PoC.

### Pattern consistency in similar files

`ResourceIndicatorGrant` had `try { parent::... } finally {
$this->pendingResource = null; }` from the start. When we copied that
class to make `FamilyAwareRefreshTokenGrant`, the try/finally got
dropped — only the success-path assignment to `null` survived. On a
long-running PHP runtime (RoadRunner / FrankenPHP / Swoole) that
silently leaks state across requests.

**Lesson:** when copying a class to make a similar one, copy *every*
defensive idiom, not just the structural skeleton. A simple grep for
"try { parent" or similar across the new file would have caught it
before review.

### Compositions to look at before writing the plan

- `composer why-not <package> <version>` for any constraint chosen in
  the plan. Phase 1 plan said `doctrine/doctrine-bundle:^2`; turned
  out only `^3` supported Symfony 8 — three runs of the install
  command before I noticed.
- league's actual method visibilities. The plan assumed
  `validateAuthorizationCode` was overridable; it's `private` in v9, so
  we had to decrypt the auth-code payload in our overridden
  `respondToAccessTokenRequest` instead. Read the upstream first.

### Avoid magic in `.env.test` paths

`OAUTH_PUBLIC_KEY_PATH='%kernel.project_dir%/tests/fixtures/public.key'`
relies on Symfony's parameter resolution, which only happens with
`%env(resolve:...)%` at the consumer. If the consumer forgets `resolve:`,
the literal string is passed to `file_get_contents` and the failure
message looks like a missing file rather than a config bug. **Building
the path in `tests/bootstrap.php`** (where `dirname(__DIR__)` is
unambiguous) is a flatter dependency.

## Code smells we explicitly tolerated

### Three near-identical `issue*Token` overrides

`ResourceIndicatorGrant::issueAuthCode`, `issueAccessToken`, and
`issueRefreshToken` are each ~30-line copies of league's
`AbstractGrant::issueAuthCode` / `issueAccessToken` / `issueRefreshToken`,
with a single `set*` call inserted before `persist*`. Same for
`FamilyAwareRefreshTokenGrant::issueRefreshToken`.

Why we did it: league has no "before persist" hook, and we needed the
new entity to carry the resource / audiences / family_id by the time
the row is written.

When to revisit: open a PR upstream proposing a hook (something like
`protected function decorate*Token($entity): void` called between
`getNew*` and `persistNew*`). If accepted, our four copies collapse
to four small overrides.

### Three explicit `App\OAuth\Extension\:` re-declarations under `when@test:`

Symfony's `services.yaml` `when@test:` block has its own
`_defaults: { autowire, autoconfigure, public }`. The PSR-4 resource
patterns under that block override any explicit definitions made above
— so `App\OAuth\Repository\ScopeRepository`'s `arguments: { $scopes: ... }`
gets blown away unless we **re-declare it under `when@test:`** too. We
did, three times (Scope, AccessToken, multiple Extension classes).

When to revisit: Symfony 9 may simplify this. For now the
"re-declare under when@test" rule is in the file as a comment.

## Test conventions that paid off

- **Attack-scenario test names** —
  `test_refresh_token_reuse_kills_the_legitimate_chain`,
  `test_token_resource_mismatch_with_bound_value_returns_invalid_target`,
  `test_authorize_with_resource_outside_allowlist_redirects_with_invalid_target`.
  Each name describes the behavior being defended; reading the test
  file feels like reading a threat model.
- **Functional E2E flow** — `TokenControllerTest` walks the full
  `/oauth/authorize → /oauth/consent (allow) → /oauth/token` flow and
  parses the resulting JWT to check `aud=[resource]` and `iss`. Worth
  the setup; it caught two bugs that unit tests missed.
- **`DoctrineKernelTestCase` base** — drops/recreates the schema in
  `setUp()`. Avoids per-test DB-cleanup boilerplate. The cost of
  re-creating SQLite is low (~50ms).
- **Hermetic test fixtures** — `tests/fixtures/{private,public}.key`
  are committed RSA keys (2048-bit, test-only) so JWT-issuance tests
  don't depend on host openssl invocations. GitGuardian allowlisted.

## Counts

- 44 commits on the merged branch.
- 88 PHPUnit tests, 228 assertions, all passing.
- 9 endpoints registered (`/.well-known/*` × 3, `/oauth/*` × 4,
  `/login`, `/logout`).
- 0 production secrets in git history (post-scrub).
- 6 ultrareview-found bugs fixed before merge.
- 1 self-review-found bug fixed before merge.
- 2 CI-only bugs fixed before merge.

## Open items for Phase 2

1. **Concurrent rotation race** in `RefreshTokenRepository::isRefreshTokenRevoked`
   — RFC 9700 §4.14 acknowledges this; needs `SELECT … FOR UPDATE` for
   correctness. TODO comment is in the file.
2. **IPv6 localhost** — `ResourceIndicatorGrant::isAcceptableResourceScheme`
   now strips brackets, but `ClientMetadataValidator::$allowedHosts`
   doesn't include `::1`. If MCP clients ever come from IPv6 localhost,
   add it (or a config switch).
3. **MCP Resource Server itself** — see `CLAUDE.md` "When starting
   Phase 2" for the verification checklist.
4. **Static analysis** — Phase 1 explicitly excluded PHPStan/Psalm.
   Worth adding to CI for Phase 2; the plan was getting non-trivial
   enough that "does this signature still match the interface" became
   a recurring concern.
