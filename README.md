# better-auth-py

**Comprehensive, framework-agnostic authentication for Python — a port of [better-auth](https://better-auth.com), with first-class [FastAPI](https://fastapi.tiangolo.com) integration.**

Own your auth. No third-party service, no per-user pricing: users, sessions and accounts live in *your* database, behind the same battle-tested API surface as the TypeScript original.

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

That's a working auth server: sign-up, sign-in, sessions, sign-out, password reset, email verification, social login — the same routes, JSON shapes and error codes as better-auth.

## Features

- **Email & password** — sign-up, sign-in, change/set password, reset flows, email verification
- **Social sign-in (OAuth2/OIDC)** — GitHub, Google, Discord built in; custom providers in a few lines; PKCE, single-use DB-backed state, account linking with verified-email guard
- **Sessions** — DB-backed, HMAC-signed cookies, sliding expiry (`expires_in`/`update_age`), `rememberMe`, multi-session management (list/revoke), bearer-token support for API clients
- **Database adapters** — in-memory (dev/tests) and SQLAlchemy 2 async (SQLite/PostgreSQL/MySQL — works with SQLModel engines too); tiny 5-method protocol for custom adapters
- **Plugins** — add routes, extend the DB schema, hook before/after every request
- **Secure defaults** — scrypt password hashing, CSRF origin checks, open-redirect protection on every `callbackURL`, timing-equalized sign-in, rate limiting with better-auth's per-path rules
- **Framework-agnostic core** — the FastAPI layer is ~80 lines over plain request/response dataclasses; Litestar/Django/Flask integrations can follow the same pattern

## Compatibility with better-auth (TypeScript)

The wire protocol and storage format follow the TS implementation closely — a Python service can sit on the **same database** as a TS better-auth app:

| | |
|---|---|
| Routes & JSON shapes | Same paths (`/sign-in/email`, `/get-session`, `/callback/{provider}`, …), same success/error bodies and codes (`USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL` 422, `INVALID_EMAIL_OR_PASSWORD` 401, …) |
| DB schema | Identical `user` / `session` / `account` / `verification` tables, camelCase columns |
| Password hashes | Exact scrypt format (`N=16384, r=16, p=1, dkLen=64`, NFKC, hex `salt:key`) — **existing TS-created passwords verify in Python and vice-versa** |
| Session cookies | Same name (`better-auth.session_token`, `__Secure-` over HTTPS) and signing scheme (HMAC-SHA256, base64, URI-encoded `token.sig`) |
| IDs & tokens | Same alphabets/lengths (62-char IDs, 64-char state/verification tokens) |

Known divergences (v0.1): email-verification/reset tokens are DB-backed (TS uses signed JWTs for verify-email), bearer auth is built in (a plugin in TS), cookie cache & secondary storage not yet implemented.

## Install

```bash
uv add better-auth-py[fastapi,sqlalchemy]
# or: pip install "better-auth-py[fastapi,sqlalchemy]"
```

The core has a single dependency (`httpx`). Extras: `fastapi`, `sqlalchemy`.

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

API clients can skip cookies entirely: `Authorization: Bearer <token>` with the `token` returned by sign-in/sign-up.

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
await adapter.create_tables()  # dev convenience — use Alembic & co. in production
```

A custom adapter implements five async methods over dict rows — see `better_auth.adapters.base.BaseAdapter` (`create`, `find_one`, `find_many`, `update`, `delete_many`).

## Social providers

```python
social_providers={"github": GitHub(client_id=..., client_secret=...)}
```

`POST /api/auth/sign-in/social {"provider": "github", "callbackURL": "/dashboard"}` returns `{"url": ..., "redirect": true}`; send the browser there, and the callback sets the session cookie and redirects to `callbackURL`. Custom providers are one dataclass:

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

Override `fetch_user()` for non-OIDC user payloads (see the GitHub/Discord sources).

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

- Origin-checked non-GET requests (CSRF) against `base_url` + `trusted_origins`
- Every `callbackURL`/`redirectTo` is validated against trusted origins (open-redirect protection)
- Sign-in runs a dummy scrypt on unknown users (timing equalization); unknown email and wrong password return the same 401
- Rate limiting is in-memory (single process). Behind a multi-worker/proxy setup, also rate-limit at the edge; `x-forwarded-for` is honoured for the client IP.
- `MemoryAdapter` is the default so quickstarts work — switch to a real adapter for anything persistent.

## Roadmap

Core: `change-email`, `delete-user`, `link-social`, `refresh-token`/`get-access-token`, cookie cache, secondary storage (Redis), CLI schema migrations. Plugins: two-factor, magic link, username, organization, admin, API keys, passkeys. Integrations: Litestar, Django, Flask.

## Development

```bash
uv sync --all-extras
uv run pytest            # 84 tests: e2e over ASGI, both adapters, mocked OAuth
uv run ruff check .
```

## License

[MIT](LICENSE) — inspired by and API-compatible with [better-auth](https://github.com/better-auth/better-auth) (MIT).
