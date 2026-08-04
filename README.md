# better-auth-server

[![CI](https://github.com/oumarbarry/better-auth-py/actions/workflows/ci.yml/badge.svg)](https://github.com/oumarbarry/better-auth-py/actions/workflows/ci.yml)

**Authentication for Python, ported from [better-auth](https://better-auth.com). Ships with FastAPI, Litestar, Flask and Django integrations — and a Python client.**

Docs: **[better-auth-py.oumarbarry.tech](https://better-auth-py.oumarbarry.tech)**

Your users, sessions and accounts live in your own database. There is no hosted service to depend on and no per-user pricing, and the API surface is the one the TypeScript original has proven in production.

Full parity with better-auth (TypeScript) **v1.6.25**: same routes, JSON shapes and error codes, 35 social providers, 26 built-in plugins.

```python
from better_auth import BetterAuth, EmailAndPassword
from better_auth.integrations.fastapi import BetterAuthFastAPI
from fastapi import Depends, FastAPI

auth = BetterAuth(
    secret="...",  # openssl rand -base64 32
    base_url="http://localhost:8000",
    email_and_password=EmailAndPassword(enabled=True),
)

app = FastAPI()
ba = BetterAuthFastAPI(auth)
app.include_router(ba.router)  # mounts /api/auth/*

@app.get("/me")
async def me(result: dict = Depends(ba.require_session)):
    return result["user"]
```

These twenty lines are a working auth server. Sign-up, sign-in, sessions, sign-out, password reset, email verification and social login are mounted under `/api/auth`, with the same routes, JSON shapes and error codes as better-auth.

## Features

- Email and password: sign-up, sign-in, change/set/verify password, reset flow, email verification.
- Social sign-in (OAuth2/OIDC): 35 built-in providers (GitHub, Google, Discord, Apple, GitLab, Microsoft Entra ID, Slack, Spotify, Twitch, Zoom, ...), custom providers in a few lines. PKCE, single-use database-backed state, token refresh, JWKS/id-token verification, and account linking guarded by provider email verification.
- Sessions in your database: HMAC-signed cookies, sliding expiry (`expires_in`/`update_age`), `rememberMe`, list and revoke endpoints, bearer tokens for API clients, an optional signed cookie cache to skip the DB read on `/get-session`.
- Two adapters out of the box: in-memory for dev and tests, SQLAlchemy 2 async for SQLite, PostgreSQL and MySQL (SQLModel engines work as-is). A custom adapter implements nine async CRUD methods over dict rows.
- 26 built-in plugins covering two-factor auth, admin, organization (teams + dynamic access control), API keys, passkeys (WebAuthn), JWT, an OAuth 2.1 authorization-server (`oauth-provider`), SSO (OIDC), generic OAuth, device authorization, SIWE (Sign-In with Ethereum), magic link, email OTP, username, anonymous sessions, multi-session and more. Plugins add routes, extend the database schema, and hook before/after every request.
- Pluggable secondary storage (Redis-shaped protocol), configurable rate limiting with better-auth's per-path rules, trusted-proxy client-IP resolution, and secrets rotation via versioned `SecretConfig`.
- Secure defaults: scrypt password hashing, CSRF origin checks, open-redirect protection on every `callbackURL`, timing-equalized sign-in, XChaCha20-Poly1305 cross-runtime encryption for stored secrets.
- The core is framework-agnostic. The FastAPI layer is about 80 lines over plain request/response dataclasses, and the Litestar (`BetterAuthLitestar`), Flask (`BetterAuthFlask`) and Django (`BetterAuthDjango`) layers prove the pattern — WSGI included.

## Compatibility with better-auth (TypeScript)

The wire protocol and storage format follow the TypeScript implementation closely. A Python service can share a database with a TypeScript better-auth app:

| | |
|---|---|
| Routes and JSON shapes | Same paths (`/sign-in/email`, `/get-session`, `/callback/{provider}`, ...), same success and error bodies, same codes (`USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL` 422, `INVALID_EMAIL_OR_PASSWORD` 401, ...) |
| Database schema | Identical `user` / `session` / `account` / `verification` tables, camelCase columns |
| Password hashes | Exact scrypt format (`N=16384, r=16, p=1, dkLen=64`, NFKC, hex `salt:key`). Passwords created by the TypeScript library verify in Python, and vice versa. |
| Session cookies | Same name (`better-auth.session_token`, `__Secure-` over HTTPS) and signing scheme (HMAC-SHA256, base64, URI-encoded `token.sig`) |
| IDs and tokens | Same alphabets and lengths (62-character IDs, 64-character state and verification tokens) |

Known divergences: reset-password tokens are stored in the database (email-verification tokens are stateless HS256 JWTs, matching the TypeScript library); bearer-token reading is built into the core session layer (a plugin over there, `bearer` here only adds the response-side `set-auth-token` header); SAML (part of the `sso` plugin), `scim`, `stripe` and the browser client/expo/electron/cli packages are out of scope (server-side parity only — see the changelog; for calling a Better Auth server *from* Python there is [`better-auth-client`](https://pypi.org/project/better-auth-client/)).

## Install

```bash
uv add better-auth-server[fastapi,sqlalchemy]
# or: pip install "better-auth-server[fastapi,sqlalchemy]"
```

Extras: `fastapi` (the FastAPI integration), `litestar` (the Litestar integration), `flask` (the Flask integration), `django` (the Django integration), `sqlalchemy` (the async SQLAlchemy adapter), `passkey` (WebAuthn via `webauthn`, for the `passkey` plugin), `sso` (DNS TXT lookups via `dnspython`, for the `sso` plugin's domain verification). Requires Python 3.10–3.14.

## Quickstart

Run the included demo:

```bash
uv run uvicorn examples.fastapi_app:app --reload
```

```bash
# health
curl -s localhost:8000/api/auth/ok

# sign up (sets a session cookie)
curl -s -c /tmp/jar -X POST localhost:8000/api/auth/sign-up/email \
  -H 'content-type: application/json' \
  -d '{"name": "Ada", "email": "ada@example.com", "password": "s3cret-password"}'

# who am I?
curl -s -b /tmp/jar localhost:8000/api/auth/get-session
curl -s -b /tmp/jar localhost:8000/me

# sign out
curl -s -b /tmp/jar -c /tmp/jar -X POST localhost:8000/api/auth/sign-out
```

API clients can skip cookies entirely and send `Authorization: Bearer <token>` with the `token` returned by sign-in or sign-up.

## Configuration

```python
from better_auth import (
    BetterAuth, EmailAndPassword, EmailVerification, SessionOptions, RateLimit, GitHub, Google,
)

async def send_reset(user, url, token): ...       # plug your mailer
async def send_verification(user, url, token): ...

auth = BetterAuth(
    secret=os.environ["BETTER_AUTH_SECRET"],       # >= 32 chars, required
    base_url="https://example.com",                # cookies become Secure/__Secure- on https
    base_path="/api/auth",                         # default
    adapter=SQLAlchemyAdapter(engine),             # default: MemoryAdapter() (dev only!)
    email_and_password=EmailAndPassword(
        enabled=True,
        min_password_length=8,
        require_email_verification=False,
        auto_sign_in=True,
        send_reset_password=send_reset,
        revoke_sessions_on_password_reset=False,
    ),
    email_verification=EmailVerification(
        send_verification_email=send_verification,
        send_on_sign_up=False,
        auto_sign_in_after_verification=False,
    ),
    social_providers={
        "github": GitHub(client_id="...", client_secret="..."),
        "google": Google(client_id="...", client_secret="..."),
    },
    session=SessionOptions(expires_in=7 * 86400, update_age=86400),
    rate_limit=RateLimit(enabled=True),            # better-auth path rules built in
    trusted_origins=["https://app.example.com"],   # extra origins for CSRF + redirects
    plugins=[...],
    hooks={"before": ..., "after": ...},           # around every auth request
    database_hooks={"user": {"create": {"before": ..., "after": ...}}},
)
```

## Database

Tables follow better-auth's core schema (`user`, `session`, `account`, `verification`).

```python
from sqlalchemy.ext.asyncio import create_async_engine
from better_auth.adapters.sqlalchemy import SQLAlchemyAdapter

engine = create_async_engine("postgresql+asyncpg://...")  # or sqlite+aiosqlite, mysql+aiomysql
adapter = SQLAlchemyAdapter(engine)
auth = BetterAuth(secret=..., adapter=adapter, ...)
await adapter.create_tables()  # dev convenience; use Alembic in production
```

A custom adapter implements nine async methods over dict rows. See `better_auth.adapters.base.BaseAdapter` (`create`, `find_one`, `find_many`, `update`, `update_many`, `delete`, `delete_many`, `count`, `transaction`); atomic `consume_one`/`increment_one` are derived from `transaction` for free.

## Social providers

35 providers are built in — GitHub, Google, Discord, Apple, Atlassian, AWS Cognito, Dropbox, Facebook, Figma, GitLab, Hugging Face, Kakao, Kick, LINE, Linear, LinkedIn, Microsoft Entra ID, Naver, Notion, Paybin, PayPal, Polar, Railway, Reddit, Roblox, Salesforce, Slack, Spotify, TikTok, Twitch, Twitter/X, Vercel, VK, WeChat and Zoom (see `better_auth.oauth.PROVIDER_REGISTRY` for the full name → class map). Configure by instance or by name:

```python
from better_auth import GitHub

social_providers = {
    "github": GitHub(client_id=..., client_secret=...),
    # or name-keyed, resolved against PROVIDER_REGISTRY:
    "gitlab": {"client_id": ..., "client_secret": ...},
}
```

`POST /api/auth/sign-in/social {"provider": "github", "callbackURL": "/dashboard"}` returns `{"url": ..., "redirect": true}`. Send the browser to that URL; the callback sets the session cookie and redirects to `callbackURL`. A custom provider is one dataclass:

```python
from better_auth import OAuthProvider

okta = OAuthProvider(
    client_id=..., client_secret=..., provider_id="okta",
    authorization_endpoint="https://your-org.okta.com/oauth2/v1/authorize",
    token_endpoint="https://your-org.okta.com/oauth2/v1/token",
    userinfo_endpoint="https://your-org.okta.com/oauth2/v1/userinfo",  # OIDC userinfo shape
    scopes=["openid", "email", "profile"], use_pkce=True,
)
```

Override `fetch_user()` for providers whose user payload is not OIDC-shaped (see the GitHub and Discord sources).

## Plugins

26 plugins ship with the package under `better_auth.plugins_ext` (two-factor, admin,
organization, api-key, passkey, jwt, oauth-provider, sso, generic-oauth,
device-authorization, siwe, magic-link, and more — see `plugins_ext.__all__` for the
full list). Pass instances via `plugins=[...]` on `BetterAuth`. Writing your own is a
`Plugin` subclass:

```python
from better_auth import AuthResponse, Plugin

class ApiKeys(Plugin):
    id = "api-keys"
    schema = {"apikey": {...}}                      # extra tables, migrated like core ones

    def routes(self):
        return [("POST", "/api-keys/create", self.create)]

    async def create(self, ctx):
        result = await ctx.require_session()
        ...
        return {"key": "..."}

    async def before(self, ctx):                    # runs before every endpoint
        return None                                 # or AuthResponse(...) to short-circuit
```

## Security notes

- Non-GET requests are origin-checked (CSRF) against `base_url` and `trusted_origins`.
- Every `callbackURL` and `redirectTo` is validated against trusted origins, which blocks open redirects.
- Sign-in runs a dummy scrypt when the user does not exist, so unknown email and wrong password take the same time and return the same 401.
- Rate limiting defaults to in-memory, per process (`RateLimit(storage="memory")`); `"database"` and `"secondary-storage"` back it with the shared adapter or a KV store for multi-worker deployments. `ip_address=IPAddressOptions(...)` controls how the client IP is resolved from proxy headers (trusted-proxy chain, custom header list).
- `MemoryAdapter` is the default so quickstarts work. Switch to a real adapter for anything persistent.

## Roadmap

v0.2.0 closed the parity campaign against better-auth v1.6.23 — see the
[changelog](CHANGELOG.md) for what landed. Still open: framework integrations beyond
FastAPI (Litestar, Django, Flask) and CLI schema migrations. Deliberately out of
scope: `open-api`, telemetry/logger config groups, SAML, `scim`, `stripe`, and the
TypeScript `client`/expo/electron/cli packages (server-side parity only — see
`docs/plans/ACTIVE.md`'s decision log).

## Development

```bash
uv sync --all-extras
uv run pre-commit install
uv run pytest            # e2e over ASGI, both adapters, mocked OAuth
uv run ruff check .
uv run ty check
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. Commits follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).

## For AI agents

`npx skills add oumarbarry/better-auth-py` installs the `better-auth-server` skill (setup, plugins, providers, TS-to-Python migration — every snippet executed and verified) for Claude Code and compatible harnesses. The documentation site serves [llms.txt](https://llmstxt.org) at `/llms.txt` (index) and `/llms-full.txt` (all pages, one file). Agents contributing to this repo are governed by [AGENTS.md](AGENTS.md); the details live on the [AI agents](docs-site/guide/agents.md) docs page.

## License

[MIT](LICENSE). Inspired by and API-compatible with [better-auth](https://github.com/better-auth/better-auth), also MIT.
