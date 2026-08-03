# Getting started

`better-auth-server` is a server-side Python port of
[better-auth](https://better-auth.com), at full parity with the TypeScript
library **v1.6.25**. The PyPI package is `better-auth-server`; the import name
is `better_auth`.

## Install

```bash
uv add better-auth-server[fastapi,sqlalchemy]
```

```bash
pip install "better-auth-server[fastapi,sqlalchemy]"
```

Requires Python 3.10–3.14. Four extras are available:

| Extra | Pulls in | Needed for |
| --- | --- | --- |
| `fastapi` | `fastapi` | The `BetterAuthFastAPI` integration |
| `sqlalchemy` | `sqlalchemy` | The async SQLAlchemy adapter |
| `passkey` | `webauthn` | The `passkey` plugin (WebAuthn/FIDO2) |
| `sso` | `dnspython` | The `sso` plugin's DNS TXT domain verification |

## The minimal server

```python
from better_auth import BetterAuth, EmailAndPassword
from better_auth.integrations.fastapi import BetterAuthFastAPI
from fastapi import Depends, FastAPI

auth = BetterAuth(
    secret="...",  # openssl rand -base64 32 — must be at least 32 characters
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

That is the whole server. `include_router` mounts 34 endpoints under
`base_path` (`/api/auth` by default): sign-up, sign-in, session read and
revoke, sign-out, password change/set/reset, email verification, social sign-in
and callback, and account linking.

::: warning No adapter means no persistence
Leaving `adapter` unset gives you `MemoryAdapter()`, so a quickstart runs with
zero setup — and everything disappears when the process exits. Point it at a
real database before you store anything you care about.
:::

## Add a database

```python
from sqlalchemy.ext.asyncio import create_async_engine
from better_auth.adapters.sqlalchemy import SQLAlchemyAdapter

engine = create_async_engine("postgresql+asyncpg://…")  # or sqlite+aiosqlite, mysql+aiomysql
adapter = SQLAlchemyAdapter(engine)

auth = BetterAuth(secret=..., adapter=adapter)

await adapter.create_tables()  # dev convenience; use Alembic in production
```

Four tables are created — `user`, `session`, `account` and `verification` —
with better-auth's exact camelCase column names. Plugins that need storage
declare their own tables the same way.

## Try it

```bash
uv run uvicorn examples.fastapi_app:app --reload
```

```bash
# health
curl -s localhost:8000/api/auth/ok
# → {"ok":true}

# sign up (sets a session cookie)
curl -s -c /tmp/jar -X POST localhost:8000/api/auth/sign-up/email \
  -H 'content-type: application/json' \
  -d '{"name": "Ada", "email": "ada@example.com", "password": "s3cret-password"}'

# who am I?
curl -s -b /tmp/jar localhost:8000/api/auth/get-session
curl -s -b /tmp/jar localhost:8000/me

# sign out
curl -s -b /tmp/jar -c /tmp/jar -X POST localhost:8000/api/auth/sign-out
# → {"success":true}
```

`POST /api/auth/sign-up/email` returns the session token alongside the created
user:

```json
{
  "token": "5hYe5WqRTIfc3C1QuBHxVnOBUulRhHO0",
  "user": {
    "id": "3JQKm8qvXNXQ5mRo720N6s8gjdTdBW6i",
    "name": "Ada",
    "email": "ada@example.com",
    "emailVerified": false,
    "image": null,
    "createdAt": "2026-08-02T05:52:24.191919Z",
    "updatedAt": "2026-08-02T05:52:24.191919Z"
  }
}
```

and sets the session cookie:

```http
set-cookie: better-auth.session_token=5hYe5WqRTIfc3C1QuBHxVnOBUulRhHO0.wyoOI2A09rsQDq%2BEoKZ1F3Rsojg7j…
```

`GET /api/auth/get-session` returns both halves:

```json
{
  "session": {
    "id": "gsTlLZ53w6icjY1v8Mj8QFKoJhBfLjWc",
    "token": "5hYe5WqRTIfc3C1QuBHxVnOBUulRhHO0",
    "userId": "3JQKm8qvXNXQ5mRo720N6s8gjdTdBW6i",
    "expiresAt": "2026-08-09T05:52:24.261924Z",
    "ipAddress": "127.0.0.1",
    "userAgent": "python-httpx/0.28.1",
    "createdAt": "2026-08-02T05:52:24.261924Z",
    "updatedAt": "2026-08-02T05:52:24.261924Z"
  },
  "user": { "id": "3JQKm8qvXNXQ5mRo720N6s8gjdTdBW6i", "…": "…" }
}
```

## Protecting your own routes

The integration exposes two dependencies:

```python
@app.get("/me")
async def me(result: dict = Depends(ba.require_session)):
    # 401 when unauthenticated
    return result["user"]

@app.get("/maybe")
async def maybe(result: dict | None = Depends(ba.session)):
    # None when unauthenticated
    return {"signed_in": result is not None}
```

Both return the same `{"session": ..., "user": ...}` dict shape as
`/get-session`, so `result["user"]["id"]` is the user id. Reading `result["id"]`
is the most common mistake — that key does not exist.

## API clients without cookies

Skip the cookie jar entirely: sign-in and sign-up both return a `token`, and
every endpoint accepts it as a bearer token.

```bash
curl -s localhost:8000/me -H "Authorization: Bearer $TOKEN"
```

Bearer reading is built into the core session layer, so no plugin is required.
Add [`BearerPlugin`](/plugins/bearer) only if you also want the token echoed
back on a `set-auth-token` response header.

## Errors

Failures use better-auth's exact codes and statuses, so a client written
against the TypeScript server needs no changes:

```json
// POST /sign-in/email with a wrong password → 401
{ "code": "INVALID_EMAIL_OR_PASSWORD", "message": "Invalid email or password" }
```

```json
// POST /sign-up/email with a taken address → 422
{ "code": "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL", "message": "User already exists. Use another email." }
```

Note that sign-in runs a dummy scrypt hash when the user does not exist, so an
unknown address and a wrong password take the same time and return the same
401.

## Next

- [Core concepts](/guide/concepts) — sessions, adapters, plugins, what parity buys you.
- [Configuration](/guide/configuration) — every option on `BetterAuth`.
- [Social providers](/providers/) — the 35 built-ins and custom ones.
- [Production deploy](/deploy/production) — secrets, proxies, rate limits.
