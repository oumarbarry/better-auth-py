# Configuration

Every option lives on the `BetterAuth` constructor, and every one is
keyword-only. Option groups are dataclasses rather than nested dicts, so a
typo is a `TypeError` at startup instead of a silently ignored key.

```python
from better_auth import BetterAuth

auth = BetterAuth(secret=...)
```

## Required

### `secret`

```python
auth = BetterAuth(secret=os.environ["BETTER_AUTH_SECRET"])
```

Signs session cookies, OAuth state and every derived key. Must be at least 32
characters. Shorter raises at construction:

```
ValueError: secret must be at least 32 characters. Generate one with `openssl rand -base64 32`
```

### `secrets`: rotation

```python
auth = BetterAuth(
    secret=os.environ["BETTER_AUTH_SECRET"],
    secrets=[
        (2, os.environ["BETTER_AUTH_SECRET"]),
        (1, os.environ["BETTER_AUTH_SECRET_V1"]),
    ],
)
```

Versioned `(version, secret)` pairs. Values written under an old version keep
verifying while new ones are written under the highest, so a rotation does not
sign everyone out.

## URLs and mounting

```python
auth = BetterAuth(
    secret=...,
    base_url="https://example.com",   # default "http://localhost:8000"
    base_path="/api/auth",            # default
    trusted_origins=["https://app.example.com"],
    cookie_prefix="better-auth",      # default; changes the cookie name
)
```

`base_url` is the origin the browser sees. Setting it to an `https` URL is what
promotes cookies to `Secure` and the `__Secure-` name prefix, and it is the
origin the CSRF check and every `callbackURL` are validated against.
`trusted_origins` adds more (a list, or a callable resolved per request).

For deployments serving several hostnames from one process:

```python
from better_auth import DynamicBaseURL

auth = BetterAuth(
    secret=...,
    base_url=DynamicBaseURL(
        allowed_hosts=["example.com", "*.vercel.app"], protocol="https"
    ),
)
```

The base URL is then derived per request from the `Host` header, restricted to
`allowed_hosts` (each of which becomes a trusted origin). An empty
`allowed_hosts` can never resolve, so it raises at construction rather than on
the first request.

### `trusted_proxy_headers`

```python
auth = BetterAuth(
    secret=...,
    base_url=DynamicBaseURL(allowed_hosts=["example.com"], protocol="https"),
    trusted_proxy_headers=True,  # default False
)
```

When `True`, the host and protocol of a request come from `X-Forwarded-Host`
and `X-Forwarded-Proto` when present. This is used to resolve a
`DynamicBaseURL` and to infer the origin of a form posted with
`Origin: null`. It is off by default, as in better-auth 1.7, because a client
can send those headers itself. Turn it on only behind a proxy that overwrites
both headers on every request: see
[Production deploy](/deploy/production#forwarded-host-and-protocol).

## Storage

```python
from sqlalchemy.ext.asyncio import create_async_engine
from better_auth.adapters.sqlalchemy import SQLAlchemyAdapter

engine = create_async_engine("postgresql+asyncpg://…")
auth = BetterAuth(secret=..., adapter=SQLAlchemyAdapter(engine))
```

Omitting `adapter` gives you `MemoryAdapter()`: fine for a quickstart, wrong
for anything that must survive a restart. See
[Core concepts](/guide/concepts#adapters) for the custom-adapter contract.

### Schema check

On first use, `SQLAlchemyAdapter` checks that every table and column Better
Auth writes exists, and that no required column is one Better Auth never
fills. On a mismatch it logs one report and every auth request fails with
`SchemaMismatchError`, including routes that never touch the database:

```
Database schema mismatch

  Missing columns
    team.memberCount
```

Apply your migrations, or run `await adapter.create_tables()` on a
development database. The check runs again after `create_tables()`. To turn it
off:

```python
from better_auth.config import AdvancedDatabase

adapter = SQLAlchemyAdapter(engine, advanced=AdvancedDatabase(validate_schema=False))
```

Other adapters cannot validate the schema. The server logs that at startup:
a warning if you set `validate_schema=True`, a debug message otherwise.

## Email and password

```python
from better_auth import EmailAndPassword

async def send_reset(user, url, token): ...   # plug your mailer

EmailAndPassword(
    enabled=True,                             # default False
    min_password_length=8,
    max_password_length=128,
    disable_sign_up=False,
    require_email_verification=False,
    auto_sign_in=True,                        # sign in immediately after sign-up
    send_reset_password=send_reset,
    reset_password_token_expires_in=3600,
    revoke_sessions_on_password_reset=False,
)
```

`send_reset_password` receives `(user, url, token)`. Without it, the reset
endpoints have nowhere to send anything.

## Email verification

```python
from better_auth import EmailVerification

EmailVerification(
    send_verification_email=send_verification,   # (user, url, token)
    send_on_sign_up=False,
    send_on_sign_in=False,
    auto_sign_in_after_verification=False,
    expires_in=3600,
)
```

Verification tokens are stateless HS256 JWTs, matching the TypeScript library.

## Sessions

```python
from better_auth import Field, SessionOptions
from better_auth.config import CookieCache

SessionOptions(
    expires_in=7 * 86400,     # 7 days
    update_age=86400,         # extend once a day of use has passed
    fresh_age=86400,          # window in which a session counts as recently authenticated
    cookie_cache=CookieCache(enabled=True, max_age=300),
    additional_fields={"tenantId": Field(type="string", required=False)},
)
```

`CookieCache` trades a database read on `/get-session` for a signed cookie
valid for `max_age` seconds. Revocation is not instant while a cache is live,
so keep `max_age` small. The cache cookie is only used together with the
session cookie it was issued for.

`strategy` picks the cookie format:

| Strategy | Format |
| --- | --- |
| `"compact"` (default) | base64url payload with an HMAC-SHA256 signature |
| `"jwt"` | an HS256 JWT signed with `secret` |

With `strategy="jwt"` and `JWTPlugin(session_cookie_cache=True)`, the cookie is
signed with the plugin's JWKS keys instead, so another service can verify it
with `better_auth.cookie_cache.verify_session_cookie_jwt_with_jwks`. See
[JWT](/plugins/jwt). The `jwe` strategy of better-auth is not ported.

## Users and accounts

```python
from better_auth import AccountLinking, AccountOptions, Field
from better_auth.config import ChangeEmailOptions, UserOptions

UserOptions(
    additional_fields={"plan": Field(type="string", required=False, default="free")},
    change_email=ChangeEmailOptions(
        enabled=True, send_change_email_confirmation=send_confirm
    ),
)

AccountOptions(
    encrypt_oauth_tokens=True,        # XChaCha20-Poly1305 at rest
    update_account_on_sign_in=True,
    account_linking=AccountLinking(
        enabled=True,
        trusted_providers=["github", "google"],
        allow_different_emails=False,
        require_local_email_verified=True,
        disable_implicit_linking=False,
    ),
)
```

::: tip Import location
`UserOptions`, `ChangeEmailOptions`, `DeleteUserOptions`, `CookieCache` and
`AdvancedDatabase` live in `better_auth.config`. `AccountOptions`,
`AccountLinking`, `SessionOptions`, `EmailAndPassword`, `EmailVerification`,
`RateLimit`, `IPAddressOptions` and `DynamicBaseURL` are re-exported at the
package root.
:::

`additional_fields` extends the schema, the migration and the input allowlist
together: `/update-user` will not accept a field you have not declared.

### `validate_user_info`

A hook that runs before Better Auth creates a user, links a provider account,
or signs a returning OAuth user in. Return `None` to allow, or an error to
refuse:

```python
async def validate_user_info(data, ctx):
    user, source = data["user"], data["source"]
    if source["method"] == "oauth" and not user["email"].endswith("@example.com"):
        return {
            "error": "domain_not_allowed",
            "errorDescription": "Use your example.com account",
        }
    return None

UserOptions(validate_user_info=validate_user_info)
```

`source["method"]` names how the user arrived: `"email-password"`, `"oauth"`,
`"sso-oidc"`, `"admin"`, `"anonymous"`, `"email-otp"`, `"magic-link"`,
`"phone-number"` or `"siwe"`. For OAuth, `source["oauth"]` holds the
`providerId` and the provider `profile`. A refusal is a `403` whose code is
your `error`; redirect flows pass it on as `?error=`. A hook that raises
refuses too. The hook may be sync or async.

### `legacy_account_selection`

`/unlink-account`, `/get-access-token`, `/refresh-token` and `/account-info`
select the account by its Better Auth `id` (`accountId` in the body, from
`/list-accounts`). `AccountOptions(legacy_account_selection=True)` also accepts
the 1.0 bodies (`providerId` with an optional provider `accountId`) while
clients migrate. It is deprecated and will be removed. See
[Upgrade from 1.0](/migrate/from-1-0#accounts).

## Social providers

```python
from better_auth import GitHub

auth = BetterAuth(
    secret=...,
    social_providers={
        "github": GitHub(client_id="…", client_secret="…"),
        "gitlab": {"client_id": "…", "client_secret": "…"},  # name-keyed
    },
)
```

Both forms work for all 36 built-ins. See [Social providers](/providers/).

## Rate limiting

```python
from better_auth import RateLimit

RateLimit(
    enabled=True,
    window=10,                 # seconds
    max=100,
    storage="memory",          # "memory" | "database" | "secondary-storage"
    custom_rules={"/sign-in/email": {"window": 10, "max": 3}},
)
```

Better Auth's per-path rules are built in; `custom_rules` overrides them.
`storage="memory"` counts per process: behind more than one worker, use
`"database"` or `"secondary-storage"`.

Each request is decided in one atomic step. A custom rate-limit storage can
implement `consume(key, rule)` to do that itself; one with only `get` and `set`
keeps working through a non-atomic path and logs a warning once.

## Secondary storage

```python
from better_auth import MemorySecondaryStorage

auth = BetterAuth(secret=..., secondary_storage=MemorySecondaryStorage())
```

A Redis-shaped protocol (`get` / `set` / `delete`) used for rate-limit counters
and, when configured, verification values and OAuth state. Any object
implementing the `SecondaryStorage` protocol works: the in-memory one ships so
tests do not need Redis.

Also implement `increment(key, ttl)` (an atomic counter whose ttl is set when
the key is created) and `get_and_delete(key)` (an atomic read and delete, for
single-use values). better-auth 1.7 requires both. Without them the server
falls back to a non-atomic read then write and logs a warning once.

## Client IP behind a proxy

```python
from better_auth import IPAddressOptions

IPAddressOptions(
    # default ["x-forwarded-for"]
    ip_address_headers=["cf-connecting-ip", "x-forwarded-for"],
    trusted_proxies=["10.0.0.0/8"],
    disable_ip_tracking=False,
)
```

Without `trusted_proxies`, a client can forge `x-forwarded-for` and defeat
per-IP rate limiting. See [Production deploy](/deploy/production#trust-your-proxy-not-the-client).

## Hooks

Two independent systems. **Request hooks** wrap the pipeline:

```python
async def before(ctx):
    ...                 # return an AuthResponse to short-circuit, or None to continue

async def after(ctx):
    ...                 # return an AuthResponse to replace the outgoing one

auth = BetterAuth(secret=..., hooks={"before": before, "after": after})
```

::: warning The keys are `"before"` and `"after"`
Not `"user_created_before"` / `"user_created_after"`. Unknown keys are ignored
silently, so a misspelled hook simply never runs.
:::

**Database hooks** wrap model writes, keyed `model → operation → phase`:

```python
async def stamp(data, ctx):
    return {"data": {"name": data["name"].strip()}}   # merged into the row

async def announce(user, ctx):
    await notify(user["id"])

auth = BetterAuth(
    secret=...,
    database_hooks={"user": {"create": {"before": stamp, "after": announce}}},
)
```

A `before` hook returning `False` aborts the write; returning `{"data": {...}}`
merges those keys into what is persisted. The merge applies to the stored row
(and therefore to the next `/get-session`), not to the body of the request that
triggered it.

## Plugins

```python
from better_auth.plugins_ext import OrganizationPlugin, TwoFactorPlugin

auth = BetterAuth(
    secret=...,
    plugins=[TwoFactorPlugin(issuer="Example"), OrganizationPlugin()],
)
```

See the [plugin reference](/plugins/) for all 27.

## Escape hatches

| Option | Default | Effect |
| --- | --- | --- |
| `disabled_paths` | `None` | Removes endpoints from the router entirely |
| `disable_csrf_check` | `None` | Skips the CSRF check (testing only) |
| `disable_origin_check` | `False` | `True` globally, or a list of paths to skip |
| `cross_sub_domain_cookies` | `None` | `CrossSubDomainCookies(enabled=True, domain=".example.com")` |
| `use_secure_cookies` | `None` | Forces the `Secure` flag; inferred from `base_url` otherwise |
| `skip_trailing_slashes` | `False` | Matches `/sign-in/email/` as `/sign-in/email` |
| `on_api_error` | `None` | `OnAPIError(throw=..., on_error=..., error_url=...)` |
| `http_client` | `None` | Bring your own `httpx.AsyncClient` for outbound OAuth calls |
| `trusted_proxy_headers` | `False` | Reads host and protocol from `X-Forwarded-*` headers ([above](#trusted-proxy-headers)) |
| `verification` | `None` | `VerificationOptions(store_identifier=..., store_in_database=...)` |

## A realistic production configuration

```python
import os

from sqlalchemy.ext.asyncio import create_async_engine

from better_auth import (
    AccountLinking, AccountOptions, BetterAuth, EmailAndPassword, EmailVerification,
    GitHub, IPAddressOptions, RateLimit, SessionOptions,
)
from better_auth.adapters.sqlalchemy import SQLAlchemyAdapter
from better_auth.config import CookieCache
from better_auth.plugins_ext import OrganizationPlugin, TwoFactorPlugin

auth = BetterAuth(
    secret=os.environ["BETTER_AUTH_SECRET"],
    base_url=os.environ["BETTER_AUTH_URL"],
    adapter=SQLAlchemyAdapter(create_async_engine(os.environ["DATABASE_URL"])),
    email_and_password=EmailAndPassword(
        enabled=True,
        require_email_verification=True,
        send_reset_password=send_reset,
        revoke_sessions_on_password_reset=True,
    ),
    email_verification=EmailVerification(
        send_verification_email=send_verification,
        send_on_sign_up=True,
    ),
    social_providers={
        "github": GitHub(
            client_id=os.environ["GITHUB_CLIENT_ID"],
            client_secret=os.environ["GITHUB_CLIENT_SECRET"],
        ),
    },
    session=SessionOptions(
        expires_in=7 * 86400,
        update_age=86400,
        cookie_cache=CookieCache(enabled=True, max_age=300),
    ),
    account=AccountOptions(
        encrypt_oauth_tokens=True,
        account_linking=AccountLinking(trusted_providers=["github"]),
    ),
    rate_limit=RateLimit(enabled=True, storage="database"),
    ip_address=IPAddressOptions(trusted_proxies=["10.0.0.0/8"]),
    trusted_origins=[os.environ["APP_ORIGIN"]],
    plugins=[TwoFactorPlugin(issuer="Example"), OrganizationPlugin()],
)
```
