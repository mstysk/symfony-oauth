# OAuth 2.1 AS + MCP RS PoC 設計

- **作成日**: 2026-04-29
- **対象リポジトリ**: `mstysk/symfony-oauth`
- **目的**: リモート MCP サーバー向けの OAuth 2.1 Authorization Server を PHP/Symfony 単一アプリで PoC する。Phase 2 では同一アプリ内に MCP Resource Server も載せ、すべて PHP で完結させる。

## 1. アーキテクチャ全体

```
┌──────────────────────┐         ┌──────────────────────────────┐
│  MCP Client          │         │  symfony-oauth (this repo)   │
│  (Claude Desktop)    │         │  単一 Symfony アプリ          │
│                      │         │                              │
│  Phase 1: OAuth flow │         │  ┌─────────────────────────┐ │
│  1. Discovery ──────────────►  │  │ Authorization Server    │ │
│  2. DCR ────────────────────►  │  │  - league/oauth2-server │ │
│  3. /authorize ─────────────►  │  │  - InMemory users       │ │
│  4. /token ─────────────────►  │  │  - SQLite/Doctrine      │ │
│                      │         │  │  - JWKS                 │ │
│                      │         │  └─────────────────────────┘ │
│                      │         │            ▲                 │
│  Phase 2: MCP        │         │            │ in-proc 検証    │
│  5. POST /mcp ──────────────►  │  ┌─────────────────────────┐ │
│     (Bearer JWT)     │         │  │ MCP Resource Server     │ │
│                      │         │  │  - php-mcp/server (TBD) │ │
│                      │         │  │  - Streamable HTTP      │ │
│                      │         │  │  - aud/sig 検証         │ │
│                      │         │  └─────────────────────────┘ │
└──────────────────────┘         └──────────────────────────────┘
```

### フェーズ分け

| フェーズ | スコープ | 終了条件 |
|---|---|---|
| Phase 1 | OAuth 2.1 AS のみ | Claude Desktop が Discovery → DCR → 認可 → トークン発行までできる。MCP RS はまだなく、`aud` には固定の Phase 2 用 URL を入れて発行する |
| Phase 2 | 同一アプリに MCP RS を追加 | 同 Symfony アプリ内で `/mcp` エンドポイントが Bearer JWT を受け、`aud` を検証して MCP ツールを返す |

### 採用判断

- ユーザー認証は Symfony Security の **InMemoryUserProvider** + フォームログイン (PoC のため)。
- OAuth ステート (クライアント、認可コード、トークン) は **SQLite + Doctrine ORM**。
- トークン形式は **JWT (RS256)**。署名鍵はホスト側で `openssl genrsa` 生成し `config/jwt/` に手動配置。
- MCP RS が同居するため `/.well-known/oauth-protected-resource` (RFC 9728) もこのリポジトリで提供する。
- `aud` 検証は同プロセス内のため JWKS HTTP 取得ではなく公開鍵ファイル直読み。

## 2. コンポーネント分割

```
src/
├── Kernel.php
│
├── Controller/
│   ├── OAuth/
│   │   ├── AuthorizationController.php       # GET /oauth/authorize
│   │   ├── ConsentController.php             # POST /oauth/consent
│   │   ├── TokenController.php               # POST /oauth/token
│   │   └── ClientRegistrationController.php  # POST /oauth/register   (RFC 7591)
│   ├── WellKnown/
│   │   ├── AuthorizationServerMetadataController.php   # RFC 8414
│   │   ├── ProtectedResourceMetadataController.php     # RFC 9728
│   │   └── JwksController.php                          # /.well-known/jwks.json
│   └── Mcp/                                  # ── Phase 2 ──
│       └── McpController.php                 # POST /mcp
│
├── OAuth/
│   ├── Server/                               # league の Factory ラッパー
│   │   ├── AuthorizationServerFactory.php
│   │   └── ResourceServerFactory.php
│   ├── Entity/                               # Doctrine + league 両対応
│   │   ├── Client.php
│   │   ├── User.php
│   │   ├── Scope.php
│   │   ├── AuthCode.php
│   │   ├── AccessToken.php
│   │   └── RefreshToken.php
│   ├── Repository/                           # league Repository インターフェース実装
│   │   ├── ClientRepository.php
│   │   ├── ScopeRepository.php
│   │   ├── UserRepository.php
│   │   ├── AuthCodeRepository.php
│   │   ├── AccessTokenRepository.php
│   │   └── RefreshTokenRepository.php
│   └── Extension/                            # ★ 薄いアダプタ層 (upstream 追従時に削除候補)
│       ├── McpAccessTokenEntity.php          # aud claim 注入  (RFC 8707)
│       ├── ResourceIndicatorGrant.php        # AuthorizationCodeGrant 拡張
│       ├── DynamicClientRegistration/        # RFC 7591
│       │   ├── ClientMetadataValidator.php
│       │   └── ClientRegistrar.php
│       └── ServerMetadataBuilder.php         # /.well-known/... JSON ビルダー
│
├── Security/                                 # 必要があれば UserChecker など
│
└── Mcp/                                      # ── Phase 2 ──
    ├── Server/
    └── Tool/
```

### 責務の分離原則

- `OAuth/Server`、`OAuth/Entity`、`OAuth/Repository` は `league/oauth2-server` のインターフェースに直接依存する素直な実装。
- `OAuth/Extension/` は MCP/最新 RFC 対応の自前実装を集めた**隔離レイヤ**。upstream が追従したら削除する想定でこのディレクトリに集約。
- `Controller/` は薄く保ち、各エンドポイントは `OAuth/Server` か `OAuth/Extension` に処理を委譲。
- `Mcp/` は Phase 2 で初めて作る。Phase 1 中はディレクトリも存在しない。

## 3. OAuth 認可フロー & 例外処理

### Phase 1 シーケンス (Authorization Code + PKCE + RFC 8707 + DCR)

```
MCP Client                       symfony-oauth (AS)                 (Phase 2: MCP RS)
     │                                │
     │ ① GET /.well-known/oauth-authorization-server
     ├───────────────────────────────►│
     │ ◄───────────────────────────── │ JSON: endpoints, jwks_uri, …
     │                                │
     │ ② POST /oauth/register  (DCR)  │
     ├───────────────────────────────►│ → RFC 7591 検証 → Client 永続化
     │ ◄───────────────────────────── │ 201: { client_id, client_secret? }
     │                                │
     │ ③ ブラウザを開く                │
     │ GET /oauth/authorize           │
     │  response_type=code            │
     │  client_id=…                   │
     │  redirect_uri=…  (完全一致)    │
     │  code_challenge=…  S256        │
     │  resource=https://.../mcp      │
     │  state=…  scope=mcp            │
     ├───────────────────────────────►│
     │                                │ → 未ログインなら login form
     │                                │ → ログイン済 → consent form
     │                                │ → POST /oauth/consent (Allow)
     │ ◄───────────────────────────── │ 302 redirect_uri?code=…&state=…
     │                                │
     │ ④ POST /oauth/token            │
     │   grant_type=authorization_code│
     │   code=…  code_verifier=…      │
     │   resource=https://.../mcp     │
     ├───────────────────────────────►│ → PKCE 検証 → resource ホワイトリスト一致
     │                                │ → JWT 発行 (aud=resource, scope, sub)
     │ ◄───────────────────────────── │ { access_token, refresh_token, … }
     │                                │
     │ ⑤ Bearer JWT で /mcp にリクエスト                     ┌─────────────┐
     ├───────────────────────────────────────────────────► │ MCP RS     │
     │                                                      │ 公開鍵検証  │
     │                                                      │ aud 検証   │
     │                                                      │ scope 検証 │
     │ ◄────────────────────────────────────────────────── │ 200 / 401   │
     │                                                      └─────────────┘
```

### Phase 2 トークン検証 (同プロセス)

`Controller/Mcp/McpController` は `league/oauth2-server` の `ResourceServer::validateAuthenticatedRequest()` を `EventListener` 経由で呼び出す。

- 署名検証は `OAUTH_PUBLIC_KEY_PATH` のファイルを直接読む (HTTP 経由の JWKS 取得は不要)。
- `aud` claim が `MCP_ALLOWED_RESOURCES` のいずれかと一致するか検証。違えば 401。
- `scope` に `mcp` が含まれるか検証。違えば 403。

### 例外処理

| エンドポイント | 失敗ケース | 返却 |
|---|---|---|
| `/oauth/authorize` | `redirect_uri` 不一致 / `client_id` 不存在 | HTML エラーページ (リダイレクトしない) |
| `/oauth/authorize` | `response_type` 未対応 / `scope` 不正 | 302 redirect_uri に `?error=invalid_request&state=…` |
| `/oauth/authorize` | ユーザー Deny | 302 redirect_uri に `?error=access_denied&state=…` |
| `/oauth/token` | `code_verifier` ミスマッチ | 400 `{"error":"invalid_grant"}` |
| `/oauth/token` | `resource` がホワイトリスト外 | 400 `{"error":"invalid_target"}` |
| `/oauth/token` | `client_id` 認証失敗 | 401 `{"error":"invalid_client"}` |
| `/oauth/register` | metadata 検証失敗 | 400 `{"error":"invalid_redirect_uri"}` 等 |
| `/.well-known/*` | (常に 200) | エラーパスなし |
| `/mcp` (Phase 2) | Bearer 不正 | 401 `WWW-Authenticate: Bearer realm="…", resource_metadata="…"` |
| `/mcp` (Phase 2) | `aud` 不一致 | 401 同上 |
| `/mcp` (Phase 2) | `scope` 不足 | 403 `{"error":"insufficient_scope"}` |

`league/oauth2-server` は `OAuthServerException` を投げる設計のため、`App\EventListener\OAuthExceptionListener` で捕捉し RFC 準拠の JSON / HTML レスポンスに変換する。

## 4. データモデル & 設定

### Doctrine スキーマ

| エンティティ | 主なカラム | 備考 |
|---|---|---|
| `oauth_clients` | `id` (uuid PK), `name`, `secret_hash` (nullable), `is_confidential`, `redirect_uris` (JSON), `grant_types` (JSON), `scopes` (JSON), `dcr_metadata` (JSON), `created_at` | `secret_hash` NULL = public client。`dcr_metadata` には RFC 7591 の任意フィールドをそのまま格納 |
| `oauth_scopes` | `identifier` (varchar PK), `description` | 初期は `mcp` 1 行 |
| `oauth_auth_codes` | `identifier` (PK), `client_id`, `user_id`, `expires_at`, `scopes` (JSON), `redirect_uri`, `code_challenge`, `code_challenge_method`, `resource`, `revoked` | PKCE / RFC 8707 値を保持 |
| `oauth_access_tokens` | `identifier` (PK = `jti`), `client_id`, `user_id`, `expires_at`, `scopes` (JSON), `audience`, `revoked` | JWT 発行のため監査・失効用 |
| `oauth_refresh_tokens` | `identifier` (PK), `access_token_id` (FK), `expires_at`, `revoked` | ローテーション時に旧トークンを `revoked=true` |

InMemory ユーザーは Doctrine に乗せない。`oauth_*.user_id` には `UserInterface::getUserIdentifier()` 戻り値を文字列で入れる。

マイグレーションは `doctrine-migrations-bundle`。

### 環境変数の管理方針

`.env` は既存の Symfony Flex 管理ファイルを 1 本だけ使う。Compose は同ファイルを変数補間で自動ロードする。`.env.local` 系はホスト直叩き時のオーバーライド用 (Docker からは見えない)。

### `compose.yaml`

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
    volumes:
      - .:/app
      - var-data:/app/var
volumes:
  var-data:
```

ポイント:

- `${VAR:-default}` 構文で `.env` が無くても起動可。
- `OAUTH_ENCRYPTION_KEY` だけ default を持たない (未設定で起動を止めて事故防止)。
- `SYMFONY_DISABLE_DOTENV=1` でコンテナ内 Symfony は `.env` を読まない。値はすべて Compose の `environment:` 経由でプロセス環境に存在。
- `env_file:` 不使用。

### `Dockerfile`

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

`pdo_sqlite` は SQLite 共有ライブラリのリンクのみ。SQLite 自体はサーバープロセスを持たないため `app` 1 サービスで完結する。

### 鍵ファイル運用

- `config/jwt/.gitkeep` のみコミット。`*.key` は `.gitignore`。
- `README.md` に手順:
  ```bash
  openssl genrsa -out config/jwt/private.key 4096
  openssl rsa -in config/jwt/private.key -pubout -out config/jwt/public.key
  chmod 600 config/jwt/private.key
  ```

### `security.yaml` のユーザー定義 (PoC)

```yaml
security:
    providers:
        in_memory:
            memory:
                users:
                    alice: { password: '$argon2id$...', roles: ['ROLE_USER'] }
```

ユーザー追加は `bin/console security:hash-password` でハッシュ生成して直書き。

## 5. テスト戦略 & 検収手順

### テストレイヤ

| レイヤ | ツール | 何を見る |
|---|---|---|
| ユニット | PHPUnit | `OAuth/Extension/` 配下の自前ロジック (DCR 検証、`aud` 注入、ServerMetadata ビルダー) |
| 機能 | `WebTestCase` | well-known エンドポイント、`/oauth/register` の正常 + バリデーション、`/oauth/authorize` から `/oauth/token` までの全段、`aud` ホワイトリスト、Refresh Token ローテーション |
| E2E (手動) | Claude Desktop 実機 | リモート MCP 登録 → Discovery → DCR → 認可 → トークン発行までを実機でなぞる |

### テスト用 DB

`config/packages/test/doctrine.yaml` で `DATABASE_URL=sqlite:///%kernel.project_dir%/var/test.db` に上書き。各機能テストの `setUp()` で `doctrine:schema:drop --force && doctrine:schema:create`。

### Phase 1 検収条件 (テストケース)

```
[Unit]
- ClientMetadataValidator: redirect_uri が http(s)/有効URI / grant_types に未対応値が無い / 不正値で例外
- McpAccessTokenEntity: aud claim が JWT に含まれる / 単一 / 複数 audience
- ServerMetadataBuilder: 必須フィールド (issuer, authorization_endpoint, token_endpoint,
  jwks_uri, code_challenge_methods_supported) が出力される

[Functional]
- GET /.well-known/oauth-authorization-server → 200, JSON, 期待フィールド
- GET /.well-known/jwks.json → 200, JWK 1 個 (RS256), kid あり
- POST /oauth/register (正常) → 201, client_id 返却, DB に永続化
- POST /oauth/register (redirect_uri 欠落) → 400, error=invalid_redirect_uri
- 認可コードフロー (PKCE):
   1. GET /oauth/authorize 未ログイン → ログインフォーム
   2. POST ログイン → consent フォーム
   3. POST /oauth/consent (allow) → 302 redirect_uri に code+state
   4. POST /oauth/token (code, code_verifier, resource) → 200, JWT
   5. JWT decode 結果が aud=resource, scope=mcp, exp 妥当
- POST /oauth/token (PKCE 不一致) → 400, error=invalid_grant
- POST /oauth/token (resource がホワイトリスト外) → 400, error=invalid_target
- POST /oauth/token (refresh_token grant) → 旧トークン失効、新ペアを発行
```

### Phase 1 手動検収シナリオ (Claude Desktop)

1. `docker compose up` で `http://localhost:8000` に AS が立つ。
2. Claude Desktop に MCP サーバー URL `http://localhost:8000/mcp` を登録 (Phase 2 まで `/mcp` は 404 でよい)。
3. Claude Desktop が WWW-Authenticate ヘッダから AS Discovery URL を辿り、`/oauth/register` で自己登録、ブラウザで `/oauth/authorize` に到達。
4. ブラウザでログイン → consent 画面で Allow。
5. Claude Desktop が `/oauth/token` でコードをトークン交換、ログに JWT を記録。
6. JWT を `jwt.io` で decode し、`aud`, `scope`, `iss`, `kid` が期待値であることを目視。

`/mcp` 部分の挙動は Phase 1 では「DCR と認可までは通る」が合格ライン。

### 静的解析 / リンタ / CI

PoC のスコープ外。`bin/console lint:container` などの組み込みリンタは手動で十分。GitHub Actions も別途必要になったタイミングで追加する。

## 6. オープン項目 (Phase 2 以降に持ち越す)

- **PHP MCP SDK の選定** — 候補は `php-mcp/server`。Phase 1 完了時点で実装互換性を確認。
- **`OAuth/Server` の内部インターフェース化** — `league/oauth2-server` 上流が停滞した場合の差し替えに備え、ラッパーを薄く挟むかは Phase 2 着手時に判断。
- **同意の永続化** — PoC ではしない。Phase 2 以降で UX 検証時に検討。
- **本番化 (Postgres 移行、KMS による鍵管理、観測性、Rate Limit、CSRF 強化)** — PoC のスコープ外。
