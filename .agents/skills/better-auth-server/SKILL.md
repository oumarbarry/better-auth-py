---
name: better-auth-server
description:
  Guide for better-auth-server, the Python port of better-auth (TypeScript) with a
  FastAPI integration. Use this when adding auth to a FastAPI or Python server —
  "add auth to fastapi", "better auth python", "authentication python server" —
  when a project imports `better_auth` or configures `BetterAuth`, or when migrating
  a Node better-auth server to Python.
---

# better-auth-server

Server-side authentication for Python, ported from [better-auth](https://better-auth.com)
at parity with **v1.6.25**: same routes, JSON bodies, error codes and camelCase database
columns, so a Python and a TypeScript server can share one database. 35 social providers,
26 plugins, 2006 tests. PyPI package `better-auth-server`; import name `better_auth`.

## Project detection

| Signal | What it means |
|---|---|
| `better-auth-server` in `pyproject.toml` / `import better_auth` | Already installed — read the existing `BetterAuth(...)` call before changing anything |
| `auth.ts` / `betterAuth({...})` in the repo | A Node better-auth server exists → read `references/migrate-from-ts.md` first |
| FastAPI app, no auth | The path below; install with the `fastapi` extra |
| Litestar / Django / Flask | Core is framework-agnostic (`await auth.handle(AuthRequest(...))`), but only FastAPI ships an integration |

## Install

```bash
uv add "better-auth-server[fastapi,sqlalchemy]"
# or: pip install "better-auth-server[fastapi,sqlalchemy]"
```

Extras: `fastapi` (the integration), `sqlalchemy` (async adapter), `passkey`
(WebAuthn, required by the `passkey` plugin), `sso` (dnspython, for the `sso` plugin's
domain verification). Python 3.10–3.14.

## Minimal server

```python
import os

from better_auth import BetterAuth, EmailAndPassword
from better_auth.integrations.fastapi import BetterAuthFastAPI
from fastapi import Depends, FastAPI

auth = BetterAuth(
    secret=os.environ["BETTER_AUTH_SECRET"],  # >= 32 chars
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

Generate the secret with `openssl rand -base64 32`. That is a working auth server:
sign-up, sign-in, sign-out, sessions, password reset and email verification are live
under `/api/auth` with better-auth's exact wire format. Smoke-test it with
`curl -s -c jar -X POST localhost:8000/api/auth/sign-up/email -H 'content-type:
application/json' -d '{"name":"Ada","email":"a@b.co","password":"s3cret-password"}'`
then `curl -s -b jar localhost:8000/api/auth/get-session`.

## Production config

```python
from better_auth import BetterAuth, EmailAndPassword, RateLimit, SessionOptions
from better_auth.adapters.sqlalchemy import SQLAlchemyAdapter
from sqlalchemy.ext.asyncio import create_async_engine

engine = create_async_engine("postgresql+asyncpg://...")  # or sqlite+aiosqlite / mysql+aiomysql
adapter = SQLAlchemyAdapter(engine)

auth = BetterAuth(
    secret=os.environ["BETTER_AUTH_SECRET"],
    base_url="https://api.example.com",           # https => Secure/__Secure- cookies
    adapter=adapter,                               # default is MemoryAdapter — dev only
    email_and_password=EmailAndPassword(enabled=True, require_email_verification=True),
    session=SessionOptions(expires_in=7 * 86400, update_age=86400),
    rate_limit=RateLimit(enabled=True, storage="database"),
    trusted_origins=["https://app.example.com"],  # the frontend origin
)

await adapter.create_tables()  # dev convenience; use Alembic in production
```

The `sqlalchemy` extra installs SQLAlchemy but **no DBAPI driver** — add the one your URL
needs or `create_async_engine` raises `ModuleNotFoundError`: `uv add aiosqlite` (SQLite),
`uv add asyncpg` (PostgreSQL), `uv add aiomysql` (MySQL).

## Wiring `create_tables` and testing

`create_tables()` is async, so hook it in a FastAPI lifespan — and then **use
`TestClient` as a context manager**, or the lifespan never runs and every request fails
with `no such table: user` (a 500, not a helpful error).

```python
from contextlib import asynccontextmanager

from fastapi.testclient import TestClient


@asynccontextmanager
async def lifespan(app: FastAPI):
    await adapter.create_tables()  # dev only; use Alembic in production
    yield


app = FastAPI(lifespan=lifespan)
creds = {"name": "Ada", "email": "a@b.co", "password": "s3cret-password"}

with TestClient(app) as client:  # the `with` is what runs the lifespan
    client.post("/api/auth/sign-up/email", json=creds)  # sets the session cookie
    assert client.get("/me").status_code == 200
```

## Protecting routes

`BetterAuthFastAPI` exposes two dependencies over the same session lookup:

| Dependency | Unauthenticated |
|---|---|
| `ba.session` | returns `None` |
| `ba.require_session` | raises `HTTPException(401)` |

Both return **`{"session": {...}, "user": {...}}`** — never the user directly.

Use `Depends(ba.session)` (typed `dict | None`) for routes that also serve anonymous
visitors. Scoping an existing resource to the caller — the usual reason you are here — is
one line: key it by `result["user"]["id"]`.

```python
@app.get("/dashboard")
async def dashboard(result: dict = Depends(ba.require_session)):
    return {"id": result["user"]["id"], "expires": result["session"]["expiresAt"]}


@app.get("/todos")
async def list_todos(result: dict = Depends(ba.require_session)):
    return {"todos": await db.todos_for(result["user"]["id"])}


@app.post("/todos")
async def add_todo(text: str, result: dict = Depends(ba.require_session)):
    return await db.add_todo(user_id=result["user"]["id"], text=text)
```

Keys are camelCase (`emailVerified`, `expiresAt`, `userId`) — the TypeScript column
names, not snake_case.

## Sessions

- Cookie `better-auth.session_token` (`__Secure-` prefixed when `use_secure_cookies`),
  HMAC-SHA256 signed, sliding expiry via `expires_in` / `update_age`.
- API clients can skip cookies: send `Authorization: Bearer <token>` with the `token`
  returned by `/sign-in/email` or `/sign-up/email`.
- Outside FastAPI: `await auth.load_session(AuthRequest(...))` returns the same dict.
- `SessionOptions(cookie_cache=CookieCache(enabled=True))` (import `CookieCache` from
  `better_auth.config`) skips the DB read on `/get-session`;
  `SessionOptions(additional_fields={...})` adds columns.

## The 5 classic mistakes

1. **Secret under 32 characters.** `BetterAuth(secret="dev")` raises
   `ValueError: secret must be at least 32 characters` at construction. Not a warning —
   the app will not start.
2. **`base_url` that is not the origin the browser sees.** It drives OAuth redirect URIs,
   the CSRF origin check *and* the cookie `Secure` flag (`https://` → `True`,
   `http://` → `False`). An `http://` `base_url` in production yields non-Secure cookies.
   For preview deployments pass `DynamicBaseURL(allowed_hosts=[...])` instead of a string
   — an empty `allowed_hosts` raises at construction.
3. **Shipping `MemoryAdapter`.** It is the *silent default* when `adapter=` is omitted, so
   everything works in dev and every user vanishes on restart (and each worker gets its
   own store). Always pass an adapter in production.
4. **Forgetting `trusted_origins` for the frontend.** A browser POST from
   `http://localhost:5173` to an API on `:8000` is rejected `403 INVALID_ORIGIN` until that
   origin is listed. Only `base_url`'s own origin is trusted by default; wildcards
   (`https://*.preview.example.com`) and relative paths are allowed.
5. **Reading `require_session`'s result as the user.** It is
   `{"session": ..., "user": ...}`. `result["email"]` is a `KeyError`;
   `result["user"]["email"]` is the email. Same shape for `ba.session` and
   `auth.load_session`.

## References

Read one only when the task needs it — do not load them all.

| File | Read when |
|---|---|
| `references/plugins.md` | Adding 2FA, admin, organizations, API keys, passkeys, JWT, SSO, magic link, OTP, usernames… (all 26, with config) |
| `references/providers.md` | Configuring social sign-in (all 35 names) or a custom OAuth provider |
| `references/security.md` | Rate limiting, proxies and client IPs, CSRF/origin model, secret rotation, cookie hardening |
| `references/migrate-from-ts.md` | A Node better-auth server exists; same-database migration and the config-key mapping |
