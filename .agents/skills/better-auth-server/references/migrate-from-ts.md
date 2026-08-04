# Migrating from Node better-auth

The port targets better-auth (TypeScript) **v1.6.25** at wire and storage parity. The
migration path is therefore *not* an export/import: point the Python server at the same
database, keep the same secret, and existing users stay signed in.

## What is byte-compatible

| | Detail |
|---|---|
| **Database schema** | Identical `user` / `session` / `account` / `verification` tables, same camelCase columns. No migration, no new tables (unless you add plugins the TS side did not run). |
| **Password hashes** | scrypt `N=16384, r=16, p=1, dkLen=64`, NFKC-normalized, stored as hex `salt:key`. A hash written by Node verifies in Python and vice versa. |
| **Session cookies** | Same name `better-auth.session_token` (`__Secure-` prefixed over HTTPS) and the same signing scheme: `encodeURIComponent(value + "." + base64(HMAC-SHA256(secret, value)))`. A cookie minted by the Node server is accepted by the Python server on the same secret. |
| **Encrypted values** | XChaCha20-Poly1305, same `symmetricEncrypt` output; versioned secrets use the same `$ba$<v>$<hex>` envelope. |
| **IDs and tokens** | Same alphabets and lengths — 62-char IDs, 64-char OAuth state and verification tokens. |
| **Routes, bodies, error codes** | Same paths, same JSON, same strings (`USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL` 422, `INVALID_EMAIL_OR_PASSWORD` 401, …), so an existing frontend — including the TS `better-auth/client` — keeps working unchanged. |

**Keep `BETTER_AUTH_SECRET` identical.** It signs cookies and encrypts stored tokens; a new
secret invalidates every live session and makes encrypted columns unreadable.

## Config-key mapping

TypeScript uses a camelCase options object; Python uses keyword arguments and typed
dataclasses, all snake_case. The `advanced` group is **flattened onto the constructor**
(there is no `advanced=` argument), except `advanced.database`, which is passed to the
adapter as `AdvancedDatabase`.

| TypeScript | Python |
|---|---|
| `baseURL` / `basePath` | `base_url` / `base_path` |
| `database` | `adapter=` (`SQLAlchemyAdapter(engine)`, `MemoryAdapter()`, or your own) |
| `emailAndPassword: {...}` | `email_and_password=EmailAndPassword(...)` |
| `emailVerification: {...}` | `email_verification=EmailVerification(...)` |
| `socialProviders: { github: { clientId } }` | `social_providers={"github": {"client_id": ...}}` |
| `session: {...}` | `session=SessionOptions(...)` |
| `user` / `account` | `user=UserOptions(...)` / `account=AccountOptions(...)` |
| `rateLimit: {...}` | `rate_limit=RateLimit(...)` |
| `trustedOrigins` | `trusted_origins` |
| `databaseHooks` / `hooks` / `plugins` | `database_hooks` / `hooks` / `plugins` |
| `secondaryStorage` | `secondary_storage` |
| `onAPIError` / `disabledPaths` | `on_api_error=OnAPIError(...)` / `disabled_paths` |
| `advanced.cookiePrefix` | `cookie_prefix` |
| `advanced.useSecureCookies` | `use_secure_cookies` |
| `advanced.crossSubDomainCookies` | `cross_sub_domain_cookies=CrossSubDomainCookies(...)` |
| `advanced.ipAddress` | `ip_address=IPAddressOptions(...)` |
| `advanced.disableCSRFCheck` | `disable_csrf_check` |
| `advanced.database` | `SQLAlchemyAdapter(engine, advanced=AdvancedDatabase(...))` |

Plugin options follow the same rule: `twoFactor({ totpOptions: { digits: 6 } })` becomes
`TwoFactorPlugin(totp_options={"digits": 6})`.

## Side by side

```ts
// auth.ts
import { betterAuth } from "better-auth";

export const auth = betterAuth({
  secret: process.env.BETTER_AUTH_SECRET,
  baseURL: "https://api.example.com",
  basePath: "/api/auth",
  database: pool,
  emailAndPassword: {
    enabled: true,
    minPasswordLength: 8,
    requireEmailVerification: true,
    sendResetPassword: sendReset,
  },
  emailVerification: { sendVerificationEmail: sendVerification, sendOnSignUp: true },
  socialProviders: {
    github: { clientId: process.env.GH_ID, clientSecret: process.env.GH_SECRET },
    google: { clientId: process.env.G_ID, clientSecret: process.env.G_SECRET },
  },
  session: { expiresIn: 60 * 60 * 24 * 7, updateAge: 60 * 60 * 24 },
  rateLimit: { enabled: true, window: 60, max: 100 },
  trustedOrigins: ["https://app.example.com"],
});
```

```python
# auth.py
import os

from better_auth import (
    BetterAuth, EmailAndPassword, EmailVerification, GitHub, Google, RateLimit, SessionOptions,
)
from better_auth.adapters.sqlalchemy import SQLAlchemyAdapter
from sqlalchemy.ext.asyncio import create_async_engine

auth = BetterAuth(
    secret=os.environ["BETTER_AUTH_SECRET"],
    base_url="https://api.example.com",
    base_path="/api/auth",
    adapter=SQLAlchemyAdapter(create_async_engine(os.environ["DATABASE_URL"])),
    email_and_password=EmailAndPassword(
        enabled=True,
        min_password_length=8,
        require_email_verification=True,
        send_reset_password=send_reset,
    ),
    email_verification=EmailVerification(
        send_verification_email=send_verification, send_on_sign_up=True
    ),
    social_providers={
        "github": GitHub(client_id=os.environ["GH_ID"], client_secret=os.environ["GH_SECRET"]),
        "google": Google(client_id=os.environ["G_ID"], client_secret=os.environ["G_SECRET"]),
    },
    session=SessionOptions(expires_in=7 * 86400, update_age=86400),
    rate_limit=RateLimit(enabled=True, window=60, max=100),
    trusted_origins=["https://app.example.com"],
)
```

Callbacks are `async def` and receive positional arguments rather than an object:
`send_reset_password(user, url, token)`, `send_verification_email(user, url, token)`,
`send_change_email_confirmation(user, new_email, url, token)`.

## Deliberate divergences

Neither is wire- or storage-visible, but know them before cutting over:

- **Reset-password tokens** are stored in the database here (email-verification tokens
  stay stateless HS256 JWTs, as in TypeScript). A reset link issued by the Node server
  before the cutover will not verify on the Python server; verification links will.
- **Bearer token reading** is built into the core session layer, not a plugin. The
  `bearer` plugin here only adds the response-side `set-auth-token` header, so drop the
  plugin if all you needed was `Authorization: Bearer`.

## Out of scope

Not ported, and not planned — keep these on the Node side or drop them:

- **SAML** (the non-OIDC half of the `sso` plugin), **`scim`**, **`stripe`**.
- **`open-api`**, telemetry / logger config groups.
- The TS client packages: `better-auth/client`, `expo`, `electron`, `cli`. This is a
  **server-side** port. The TS client library talks to the Python server unchanged
  (same routes and JSON), so keep using it on the frontend. For Python callers
  (scripts, CLIs, service-to-service) there is a separate PyPI package,
  `better-auth-client` (import `better_auth_client`), speaking the same wire. There is
  no `better-auth migrate` CLI — manage the schema with Alembic (or
  `adapter.create_tables()` in dev).

`better_auth.plugins_ext` covers 26 plugins and `PROVIDER_REGISTRY` 35 providers; if the
TS app uses a plugin outside that set, check `plugins.md` before migrating.
