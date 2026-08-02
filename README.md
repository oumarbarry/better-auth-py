# better-auth-server

[![CI](https://github.com/oumarbarry/better-auth-py/actions/workflows/ci.yml/badge.svg)](https://github.com/oumarbarry/better-auth-py/actions/workflows/ci.yml)

**Authentication for Python, ported from [better-auth](https://better-auth.com). Ships with a FastAPI integration.**

Your users, sessions and accounts live in your own database. There is no hosted service to depend on and no per-user pricing, and the API surface is the one the TypeScript original has proven in production.

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
- Social sign-in (OAuth2/OIDC): GitHub, Google and Discord built in, custom providers in a few lines. PKCE, single-use database-backed state, and account linking guarded by provider email verification.
- Sessions in your database: HMAC-signed cookies, sliding expiry (`expires_in`/`update_age`), `rememberMe`, list and revoke endpoints, bearer tokens for API clients.
- Two adapters out of the box: in-memory for dev and tests, SQLAlchemy 2 async for SQLite, PostgreSQL and MySQL (SQLModel engines work as-is). A custom adapter is five methods.
- Plugins can add routes, extend the database schema, and hook before and after every request.
- Secure defaults: scrypt password hashing, CSRF origin checks, open-redirect protection on every `callbackURL`, timing-equalized sign-in, rate limiting with better-auth's per-path rules.
- The core is framework-agnostic. The FastAPI layer is about 80 lines over plain request/response dataclasses, so Litestar or Django integrations can follow the same pattern.

## Compatibility with better-auth (TypeScript)

The wire protocol and storage format follow the TypeScript implementation closely. A Python service can share a database with a TypeScript better-auth app:

| | |
|---|---|
| Routes and JSON shapes | Same paths (`/sign-in/email`, `/get-session`, `/callback/{provider}`, ...), same success and error bodies, same codes (`USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL` 422, `INVALID_EMAIL_OR_PASSWORD` 401, ...) |
| Database schema | Identical `user` / `session` / `account` / `verification` tables, camelCase columns |
| Password hashes | Exact scrypt format (`N=16384, r=16, p=1, dkLen=64`, NFKC, hex `salt:key`). Passwords created by the TypeScript library verify in Python, and vice versa. |
| Session cookies | Same name (`better-auth.session_token`, `__Secure-` over HTTPS) and signing scheme (HMAC-SHA256, base64, URI-encoded `token.sig`) |
| IDs and tokens | Same alphabets and lengths (62-character IDs, 64-character state and verification tokens) |

Known divergences in v0.1: email-verification and reset tokens are stored in the database (the TypeScript library signs verify-email tokens as JWTs), bearer auth is built into the core (a plugin over there), and cookie cache plus secondary storage are not implemented yet.

## Install

```bash
uv add better-auth-server[fastapi,sqlalchemy]
# or: pip install "better-auth-server[fastapi,sqlalchemy]"
```

The core has a single dependency, `httpx`. The `fastapi` and `sqlalchemy` extras pull in the rest.

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
    hooks={"user_created_before": ..., "user_created_after": ...},
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

A custom adapter implements five async methods over dict rows. See `better_auth.adapters.base.BaseAdapter` (`create`, `find_one`, `find_many`, `update`, `delete_many`).

## Social providers

```python
social_providers={"github": GitHub(client_id=..., client_secret=...)}
```

`POST /api/auth/sign-in/social {"provider": "github", "callbackURL": "/dashboard"}` returns `{"url": ..., "redirect": true}`. Send the browser to that URL; the callback sets the session cookie and redirects to `callbackURL`. A custom provider is one dataclass:

```python
from better_auth import OAuthProvider

gitlab = OAuthProvider(
    client_id=..., client_secret=..., provider_id="gitlab",
    authorize_url="https://gitlab.com/oauth/authorize",
    token_url="https://gitlab.com/oauth/token",
    userinfo_url="https://gitlab.com/oauth/userinfo",  # OIDC userinfo shape
    scopes=["openid", "email", "profile"], use_pkce=True,
)
```

Override `fetch_user()` for providers whose user payload is not OIDC-shaped (see the GitHub and Discord sources).

## Plugins

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
- Rate limiting is in-memory, per process. Behind a multi-worker or proxied setup, also rate-limit at the edge. `x-forwarded-for` is honored for the client IP.
- `MemoryAdapter` is the default so quickstarts work. Switch to a real adapter for anything persistent.

## Roadmap

Core: `change-email`, `delete-user`, `link-social`, `refresh-token`/`get-access-token`, cookie cache, secondary storage (Redis), CLI schema migrations. Plugins: two-factor, magic link, username, organization, admin, API keys, passkeys. Integrations: Litestar, Django, Flask.

## Development

```bash
uv sync --all-extras
uv run pre-commit install
uv run pytest            # e2e over ASGI, both adapters, mocked OAuth
uv run ruff check .
uv run ty check
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines. Commits follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/).

## License

[MIT](LICENSE). Inspired by and API-compatible with [better-auth](https://github.com/better-auth/better-auth), also MIT.
