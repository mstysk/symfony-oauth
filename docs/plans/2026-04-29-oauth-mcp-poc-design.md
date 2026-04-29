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
| Phase 1 | OAuth 2.1 AS のみ | Claude Desktop が Discovery → DCR → 認可 → トークン発行までできる。MCP RS は未実装で `/mcp` は 404。**`aud` はクライアントが渡す `resource` パラメータの値**を `MCP_ALLOWED_RESOURCES` ホワイトリストと完全一致検証して JWT に **JSON 配列で**入れる (RFC 8707)。Phase 2 で実 URL に揃える前提 |
| Phase 2 | 同一アプリに MCP RS を追加 | 同 Symfony アプリ内で `/mcp` エンドポイントが Bearer JWT を受け、`aud` を検証して MCP ツールを返す |

### 採用判断

- ユーザー認証は Symfony Security の **InMemoryUserProvider** + フォームログイン (PoC のため)。
- OAuth ステート (クライアント、認可コード、トークン) は **SQLite + Doctrine ORM**。
- トークン形式は **JWT (RS256)**。署名鍵はホスト側で `openssl genrsa` 生成し `config/jwt/` に手動配置。`kid` ヘッダは公開鍵の SHA-256 ハッシュから派生させて JWKS と一致させる。
- MCP RS が同居するため `/.well-known/oauth-protected-resource` (RFC 9728) もこのリポジトリで提供する。
- `aud` 検証は同プロセス内のため JWKS HTTP 取得ではなく公開鍵ファイル直読み。

### MCP 仕様準拠の不変条件

実装中ぶれがちな仕様要件をリストアップ。設計の各項はこれを満たさなければならない。

- **PKCE は全クライアントで必須** — `code_challenge`/`code_challenge_method=S256` 欠落は 400 で拒否。`league/oauth2-server` の `enableCodeExchangeProof()` は PKCE を「サポート」するだけで強制ではないため、`AuthorizationCodeGrant` 拡張側で明示的にチェックする。
- **`aud` は JSON 配列**で発行 (RFC 8707 §3)。単一値でも配列で出す。
- **`resource` パラメータは `/oauth/token` で必須**。未指定なら `invalid_target` を返す。
- **`resource` は `https://` 必須**。例外として `http://localhost*` のみ許可 (PoC のため明文化)。それ以外の HTTP URL は `invalid_target`。
- **AS Metadata の `issuer` と PRM の `authorization_servers[*]` は文字列完全一致** (末尾スラッシュ含む)。Discovery 失敗の温床なので生成側に正規化ヘルパーを置く。
- **PRM の `bearer_methods_supported` は `["header"]` のみ**。クエリ・ボディは禁止 (OAuth 2.1 + MCP)。
- **`WWW-Authenticate: Bearer realm="…", resource_metadata="…"`** — 401 を返す全エンドポイントで `resource_metadata` パラメータに PRM URL を含める (RFC 9728 §5.1)。
- **Refresh Token は family 失効** — ローテーション時に旧トークンを `revoked=true` にするだけでなく、再使用検知時は同 family の全トークンを失効させる (OAuth 2.1 BCP / RFC 9700 §4.14)。
- **`redirect_uri` は完全一致** — ホスト名は小文字化、末尾スラッシュは無視せず厳密比較する正規化ルールを Repository 側で固定。
- **DCR は Phase 1 ではオープン登録だがレート制限必須** — `App\RateLimiter` で IP あたり毎分数件に制限し、`redirect_uri` のホストを Phase 1 用 allowlist (`localhost`, `127.0.0.1`) に絞る。本番化時に Initial Access Token に切り替える。
- **`MCP_ALLOWED_RESOURCES` は カンマ区切り**。各要素は `trim()` 後に完全一致比較する。JSON 配列ではない。
- **DCR レスポンスは正規化前の原文を返す** (RFC 7591 §3.2.1)。`redirect_uris` の正規化は **保存と比較時のみ** に適用し、`POST /oauth/register` のレスポンスボディには受け取った原文をそのまま反映する。
- **JWT には `iss` claim を必ず含める** — `lcobucci/jwt` の `Builder::issuedBy($issuer)` を呼び出す。値は `/.well-known/oauth-authorization-server` の `issuer` と完全一致 (末尾スラッシュ含む)。

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
│       ├── McpAccessTokenEntity.php          # AccessTokenTrait を再実装し aud 配列 + kid を注入
│       ├── ResourceIndicatorGrant.php        # AuthorizationCodeGrant 拡張: PKCE 強制 / resource 検証
│       ├── RefreshTokenFamily.php            # ローテーション + family 失効 (RFC 9700 §4.14)
│       ├── DynamicClientRegistration/        # RFC 7591
│       │   ├── ClientMetadataValidator.php
│       │   └── ClientRegistrar.php
│       ├── ServerMetadataBuilder.php         # /.well-known/oauth-authorization-server JSON ビルダー
│       └── ProtectedResourceMetadataBuilder.php # /.well-known/oauth-protected-resource JSON ビルダー
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

### `league/oauth2-server` 拡張時の落とし穴

実装する人が必ず踏む罠を先回りで明文化:

- `convertToJWT()` が `AccessTokenTrait` の private メソッドのため、エンティティで単に `__toString()` をオーバーライドしただけでは `aud` を注入できない。`McpAccessTokenEntity` は **`AccessTokenTrait` 自体をコピーして再実装** する (`use AccessTokenTrait` を外す)。`lcobucci/jwt` の `Builder::permittedFor()` を使って `aud` を配列で出し、`Builder::withHeader('kid', …)` で `kid` を付ける。
- `AccessTokenRepository::getNewToken()` が `McpAccessTokenEntity` を返すよう差し替える。ここで `setAudiences()` を呼ぶ。
- `AuthorizationCodeGrant` の拡張は `respondToAccessTokenRequest()` をオーバーライドし、`resource` パラメータの読み出し → ホワイトリスト検証 → `AccessToken::setAudiences()` までを行う。`code_challenge` 欠落チェックは `respondToAuthorizationRequest()` 側で。
- `RefreshTokenRepository::isRefreshTokenRevoked()` で family 失効済みフラグを返す。`persistNewRefreshToken()` で旧トークンに family_id を引き継がせる。
- `enableCodeExchangeProof()` は呼ぶが、それと **重ねて** 拡張 Grant 側で `code_challenge` 欠落を `OAuthServerException::invalidRequest()` で投げる。ここを忘れると confidential client が PKCE を回避できる。

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
     ├───────────────────────────────►│ → PKCE 検証 (欠落で invalid_request) → resource 必須+ホワイトリスト一致
     │                                │ → JWT 発行 (aud=[resource], scope, sub, kid)
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

### Symfony フォームログイン統合

`/oauth/authorize` でユーザーが未認証の場合、Symfony の `form_login` にリダイレクトされる。素のままだと認可リクエストのクエリ文字列がログイン成功後に失われるので、以下のいずれかで保持:

- **採用案**: `App\Security\OAuthAuthorizationRequestStorage` が `/oauth/authorize` 到達時に `request.attributes` から認可リクエスト全パラメータをセッションに保存し、ログインフォームに `_target_path` (= `/oauth/authorize?...` の元 URL) を hidden で乗せる。`AuthenticationSuccessHandler` 不要。
- 代替案: 専用 `AuthenticationSuccessHandler` を実装する。実装は重いので採用しない。

ログイン後、`/oauth/authorize` に再到達した時点でセッションから認可リクエストを復元 → consent フォームを描画。

### Consent の state リプレイ防止

consent フォームで Allow/Deny を押す前に、認可リクエストはセッションに 1 件だけ保存される (`Session::set('oauth_pending_authorization', …)`)。`/oauth/consent` ハンドラは:

1. セッションから認可リクエストを取り出す (`session_id` + `state` で検証)。
2. **取り出した瞬間にセッションから削除** (one-shot 消費)。
3. CSRF トークン (Symfony の `csrf_token('consent')`) を検証。
4. Allow なら認可コードを発行し、redirect_uri に 302。

この経路で同じ `code` の二重発行と consent の再生攻撃を遮断する。

### Phase 2 トークン検証 (同プロセス)

`Controller/Mcp/McpController` は `league/oauth2-server` の `ResourceServer::validateAuthenticatedRequest()` を `EventListener` 経由で呼び出す。

- 署名検証は `OAUTH_PUBLIC_KEY_PATH` のファイルを直接読む (HTTP 経由の JWKS 取得は不要)。
- `aud` claim が `MCP_ALLOWED_RESOURCES` のいずれかと一致するか検証。違えば 401。
- `scope` に `mcp` が含まれるか検証。違えば 403。

### 例外処理

| エンドポイント | 失敗ケース | 返却 |
|---|---|---|
| `/oauth/authorize` | `redirect_uri` 不一致 / `client_id` 不存在 | HTML エラーページ (リダイレクトしない) |
| `/oauth/authorize` | `code_challenge` 欠落 / `code_challenge_method != S256` | 302 redirect_uri に `?error=invalid_request&state=…` |
| `/oauth/authorize` | `response_type` 未対応 / `scope` 不正 | 302 redirect_uri に `?error=invalid_request&state=…` |
| `/oauth/authorize` | ユーザー Deny | 302 redirect_uri に `?error=access_denied&state=…` |
| `/oauth/consent` | CSRF トークン不正 / セッションに認可リクエストなし | 400 (HTML) |
| `/oauth/token` | `code_verifier` ミスマッチ | 400 `{"error":"invalid_grant"}` |
| `/oauth/token` | `resource` 未指定 / ホワイトリスト外 / `https://` 違反 | 400 `{"error":"invalid_target"}` |
| `/oauth/token` | Refresh Token の再使用検知 | 400 `{"error":"invalid_grant"}` + 同 family 全失効 |
| `/oauth/token` | `client_id` 認証失敗 | 401 `{"error":"invalid_client"}` |
| `/oauth/register` | metadata 検証失敗 / `redirect_uri` ホストが allowlist 外 | 400 `{"error":"invalid_redirect_uri"}` 等 |
| `/oauth/register` | レート制限超過 | 429 `Retry-After: …` |
| `/.well-known/*` | (常に 200) | エラーパスなし |
| `/mcp` (Phase 2) | Bearer 不正 | 401 `WWW-Authenticate: Bearer realm="…", resource_metadata="…"` |
| `/mcp` (Phase 2) | `aud` 不一致 | 401 同上 |
| `/mcp` (Phase 2) | `scope` 不足 | 403 `{"error":"insufficient_scope"}` |

`league/oauth2-server` は `OAuthServerException` を投げる設計のため、`App\EventListener\OAuthExceptionListener` で捕捉し RFC 準拠の JSON / HTML レスポンスに変換する。

## 4. データモデル & 設定

### Doctrine スキーマ

| エンティティ | 主なカラム | 備考 |
|---|---|---|
| `oauth_clients` | `id` (uuid PK), `name`, `secret_hash` (nullable), `is_confidential`, `redirect_uris` (JSON array, 正規化済み), `grant_types` (JSON), `scopes` (JSON), `dcr_metadata` (JSON), `created_at` | `secret_hash` NULL = public client。`dcr_metadata` には RFC 7591 の任意フィールドをそのまま格納。`redirect_uris` はホスト小文字化・末尾スラッシュ厳密のまま保存 |
| `oauth_scopes` | `identifier` (varchar PK), `description` | 初期は `mcp` 1 行 |
| `oauth_auth_codes` | `identifier` (PK), `client_id`, `user_id`, `expires_at`, `scopes` (JSON), `redirect_uri`, `code_challenge`, `code_challenge_method`, `resource`, `revoked` | PKCE / RFC 8707 値を保持。`code_challenge` 必須 (NULL 拒否) |
| `oauth_access_tokens` | `identifier` (PK = `jti`), `client_id`, `user_id`, `expires_at`, `scopes` (JSON), `audience` (**JSON array**), `revoked` | JWT 発行のため監査・失効用。`audience` は単一値でも配列で格納 |
| `oauth_refresh_tokens` | `identifier` (PK), `access_token_id` (FK), `family_id` (uuid), `expires_at`, `revoked` | ローテーション時に旧トークンを `revoked=true`。再使用検知時は同 `family_id` の全レコードを `revoked=true` に更新 |

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
      - vendor:/app/vendor       # `.:/app` bind mount より長いパスが優先されるため vendor/ のみホスト側から切り離される。macOS で composer install を高速化
volumes:
  var-data:
  vendor:
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

### 鍵ファイル / シークレット運用

- `config/jwt/.gitkeep` のみコミット。`*.key` は `.gitignore`。
- 署名鍵生成 (ホスト側、初回のみ):
  ```bash
  openssl genrsa -out config/jwt/private.key 4096
  openssl rsa -in config/jwt/private.key -pubout -out config/jwt/public.key
  chmod 600 config/jwt/private.key
  ```
- `OAUTH_ENCRYPTION_KEY` は **`defuse/php-encryption` 専用形式** (`def00000…`)。生成は同パッケージのスクリプトで行う:
  ```bash
  docker compose run --rm app vendor/bin/generate-defuse-key
  ```
  出力された文字列をそのまま `.env` の `OAUTH_ENCRYPTION_KEY=` に貼る。`base64_encode(random_bytes(32))` ではフォーマット違反で `league/oauth2-server` 起動時に例外。

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
- ClientMetadataValidator: redirect_uri が http(s)/有効URI / grant_types に未対応値が無い /
  ホストが allowlist (localhost/127.0.0.1) 内 / 不正値で例外
- McpAccessTokenEntity: aud claim が JSON 配列で JWT に含まれる / 単一値でも配列 / kid ヘッダあり
- ServerMetadataBuilder: 必須フィールド (issuer, authorization_endpoint, token_endpoint,
  registration_endpoint, jwks_uri, code_challenge_methods_supported=[S256]) が出力される
- ProtectedResourceMetadataBuilder: bearer_methods_supported=["header"], authorization_servers
  が AS の issuer と完全一致 (末尾スラッシュ含む)
- RedirectUriNormalizer: ホスト小文字化、scheme/path はそのまま、末尾スラッシュ保持

[Functional]
- GET /.well-known/oauth-authorization-server → 200, JSON, 期待フィールド
- GET /.well-known/oauth-protected-resource → 200, JSON, authorization_servers が AS issuer と一致
- GET /.well-known/jwks.json → 200, JWK 1 個 (RS256), kid あり, kid が JWT ヘッダの kid と一致
- POST /oauth/register (正常) → 201, client_id 返却, DB に永続化
- POST /oauth/register (redirect_uri 欠落 / ホスト allowlist 外) → 400, invalid_redirect_uri
- POST /oauth/register (連続呼び出しでレート制限超過) → 429, Retry-After ヘッダ
- 認可コードフロー (PKCE 必須):
   1. GET /oauth/authorize (code_challenge 欠落) → 302 invalid_request
   2. GET /oauth/authorize (正常) 未ログイン → ログインフォーム
   3. POST ログイン → consent フォーム (CSRF トークン込み)
   4. POST /oauth/consent (CSRF 不正) → 400
   5. POST /oauth/consent (allow) → 302 redirect_uri に code+state
   6. POST /oauth/consent (再送) → 400 (one-shot 消費済み)
   7. POST /oauth/token (code, code_verifier, resource) → 200, JWT
   8. JWT decode 結果が aud=[resource] (配列), scope=mcp, exp 妥当, kid 一致
- POST /oauth/token (PKCE 不一致) → 400, invalid_grant
- POST /oauth/token (resource 未指定 / ホワイトリスト外 / http スキーム非localhost) → 400, invalid_target
- POST /oauth/token (refresh_token grant) → 旧 RT 失効、新ペアを発行
- POST /oauth/token (失効済み RT で再使用) → 400 invalid_grant + 同 family の全 RT が revoked=true
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
- **同意の永続化** — PoC ではしない (one-shot 消費のみ)。Phase 2 以降で UX 検証時に検討。
- **DCR の Initial Access Token / クライアント認証強化** — Phase 1 はオープン登録 + レート制限 + ホスト allowlist。本番化時に Initial Access Token (RFC 7591 §3) または mTLS への切り替えを検討。
- **Token Introspection (RFC 7662) / Token Revocation (RFC 7009)** — エンドポイント未実装。MCP RS が JWT 直検証で完結するため Phase 1 には不要。リソースが増えたら検討。
- **JWKS のキーローテーション** — Phase 1 は単一鍵。複数 `kid` 対応とローテーション運用は本番化時。
- **本番化 (Postgres 移行、KMS による鍵管理、観測性、CSRF 強化)** — PoC のスコープ外。
