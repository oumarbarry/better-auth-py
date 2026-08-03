# Migrating from Node

The short version: point a Python service at the database your TypeScript
Better Auth app already uses, and your users keep their passwords, their linked
accounts, and their open sessions. Nobody is signed out. There is no export
step, no dual-write window, and no password reset email to the whole user base.

That works because the port treats the TypeScript repository as canonical for
anything touching the wire or storage — same routes, same JSON, same columns,
same crypto encodings.

## What is already compatible

| | |
| --- | --- |
| **Tables** | `user`, `session`, `account`, `verification` — same names, same camelCase columns |
| **Password hashes** | scrypt `N=16384, r=16, p=1, dkLen=64`, NFKC-normalized, hex `salt:key`. A hash written by the TypeScript library verifies in Python and the reverse |
| **Session cookies** | `better-auth.session_token`, promoted to `__Secure-` over HTTPS; value is URI-encoded `token.sig`, signed HMAC-SHA256 |
| **Routes and bodies** | `/sign-in/email`, `/get-session`, `/callback/{provider}` … same paths, same success and error JSON |
| **Error codes** | Same strings and statuses — `INVALID_EMAIL_OR_PASSWORD` 401, `USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL` 422 |
| **Ids and tokens** | Same alphabets and lengths: 62-character ids, 64-character state and verification tokens |
| **Encrypted values** | XChaCha20-Poly1305, cross-runtime compatible, for stored provider secrets |

scrypt, XChaCha20-Poly1305, JWK and HOTP/TOTP are pinned in the test suite by
vectors shared with the TypeScript implementation, so "compatible" is a test
result rather than an intention.

## The migration

**1. Use the same secret.** The cookie signature is HMAC-SHA256 with
`BETTER_AUTH_SECRET`. A different secret invalidates every live session — which
is exactly the thing you are trying to avoid.

```python
auth = BetterAuth(secret=os.environ["BETTER_AUTH_SECRET"])
```

**2. Use the same `base_url` and `base_path`.** The cookie name depends on the
scheme (`__Secure-` over HTTPS) and `cookie_prefix`; the callback URL registered
with each OAuth provider depends on both.

```python
auth = BetterAuth(
    secret=...,
    base_url="https://example.com",     # same origin as the Node app
    base_path="/api/auth",              # the default, and Node's default
)
```

**3. Point at the same database. Do not run a migration.**

```python
from sqlalchemy.ext.asyncio import create_async_engine
from better_auth.adapters.sqlalchemy import SQLAlchemyAdapter

adapter = SQLAlchemyAdapter(create_async_engine(os.environ["DATABASE_URL"]))
auth = BetterAuth(secret=..., adapter=adapter)
```

The tables already exist with the right shape. `create_tables()` is a
development convenience for a fresh database — skip it here.

**4. Re-declare your options.** Configuration does not live in the database, so
it has to be restated. TypeScript camelCase becomes Python snake_case, one to
one:

```ts
// auth.ts
betterAuth({
  emailAndPassword: { enabled: true, requireEmailVerification: true },
  session: { expiresIn: 60 * 60 * 24 * 7, updateAge: 60 * 60 * 24 },
  socialProviders: { github: { clientId: "…", clientSecret: "…" } },
  plugins: [twoFactor({ issuer: "Example" }), organization()],
})
```

```python
# auth.py
BetterAuth(
    secret=os.environ["BETTER_AUTH_SECRET"],
    base_url=os.environ["BETTER_AUTH_URL"],
    adapter=adapter,
    email_and_password=EmailAndPassword(enabled=True, require_email_verification=True),
    session=SessionOptions(expires_in=7 * 86400, update_age=86400),
    social_providers={"github": GitHub(client_id="…", client_secret="…")},
    plugins=[TwoFactorPlugin(issuer="Example"), OrganizationPlugin()],
)
```

**5. Verify against the running database.** With both processes up, a session
created by one must be readable by the other:

```bash
# sign in against Node
curl -s -c /tmp/jar -X POST https://node.example.com/api/auth/sign-in/email \
  -H 'content-type: application/json' \
  -d '{"email": "ada@example.com", "password": "…"}'

# read it from Python — same cookie, same answer
curl -s -b /tmp/jar https://python.example.com/api/auth/get-session
```

Because both runtimes are stateless over one database, you can cut over a
percentage of traffic at the load balancer and roll back by moving it away.
During the transition, Python services can also consume the still-running Node
server over HTTP with [`better-auth-client`](https://pypi.org/project/better-auth-client/)
— the wire is the same on both sides.

## Translating configuration

| TypeScript | Python |
| --- | --- |
| `betterAuth({...})` | `BetterAuth(...)` |
| `emailAndPassword` | `EmailAndPassword(...)` |
| `emailVerification` | `EmailVerification(...)` |
| `session` | `SessionOptions(...)` |
| `session.cookieCache` | `CookieCache(...)` (from `better_auth.config`) |
| `user` / `user.changeEmail` | `UserOptions(...)` / `ChangeEmailOptions(...)` (from `better_auth.config`) |
| `account.accountLinking` | `AccountOptions(account_linking=AccountLinking(...))` |
| `socialProviders` | `social_providers={...}` |
| `rateLimit` | `RateLimit(...)` |
| `trustedOrigins` | `trusted_origins=[...]` |
| `secondaryStorage` | `secondary_storage=...` |
| `advanced.ipAddress` | `ip_address=IPAddressOptions(...)` |
| `advanced.database.generateId` | `AdvancedDatabase(generate_id=...)` on the adapter |
| `baseURL.allowedHosts` | `DynamicBaseURL(allowed_hosts=[...])` |
| `databaseHooks` | `database_hooks={...}` (same `model → op → phase` shape) |
| `plugins: [twoFactor()]` | `plugins=[TwoFactorPlugin()]` |

Plugin options follow the same rule: every constructor keyword is the
TypeScript option in snake_case, with the same default. See the
[plugin reference](/plugins/) and the [configuration page](/guide/configuration).

## Deliberate divergences

None of these are visible on the wire, and all are documented where they live.

- **Reset-password tokens are stored in the database.** Email-verification
  tokens stay stateless HS256 JWTs, as in TypeScript.
- **Bearer reading is core, not a plugin.** `Authorization: Bearer <token>`
  works with no plugin installed; `BearerPlugin` here only adds the
  response-side `set-auth-token` header.
- **`GET /get-session` and `POST /get-session` are both mounted**, matching the
  TypeScript router.

## Out of scope

This is a **server-side** port. These are deliberately not implemented, per the
project's parity decision log:

- **SAML** (the SAML half of the `sso` plugin — OIDC federation is ported),
  **`scim`**, **`stripe`**.
- **`open-api`** (developer tooling, no wire or storage contract) and the
  telemetry and logger option groups (logging stays on the standard library's
  `logging`).
- The JavaScript **`client`**, **expo**, **electron** and **cli** packages.
  Your frontend does not need to change: the HTTP API is identical, so an
  existing `better-auth` JavaScript client keeps working unchanged against the
  Python server. For Python-side callers, the separate
  [`better-auth-client`](https://pypi.org/project/better-auth-client/) package
  covers the HTTP client role.

Also still open, and not blockers for a migration: framework integrations
beyond FastAPI (Litestar, Django, Flask) and CLI schema migrations.

## After the cutover

Read [Production deploy](/deploy/production) for the parts that are
infrastructure rather than parity — trusted proxy headers, rate-limit storage
behind multiple workers, and secret rotation.
