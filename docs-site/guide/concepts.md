# Core concepts

Four ideas carry the whole library: sessions live in your database, adapters
are the only thing that touches storage, plugins add everything else, and
parity means the wire and the storage format are not yours to change.

## Sessions

A session is a row in the `session` table plus a signed cookie pointing at it.
There is no JWT in the default path and nothing is stored in memory, so
revoking a session is a delete and it takes effect on the next request.

```json
{
  "id": "gsTlLZ53w6icjY1v8Mj8QFKoJhBfLjWc",
  "token": "5hYe5WqRTIfc3C1QuBHxVnOBUulRhHO0",
  "userId": "3JQKm8qvXNXQ5mRo720N6s8gjdTdBW6i",
  "expiresAt": "2026-08-09T05:52:24.261924Z",
  "ipAddress": "127.0.0.1",
  "userAgent": "python-httpx/0.28.1",
  "createdAt": "2026-08-02T05:52:24.261924Z",
  "updatedAt": "2026-08-02T05:52:24.261924Z"
}
```

**The cookie.** Named `better-auth.session_token`, or
`__Secure-better-auth.session_token` once `base_url` is `https`. Its value is
`token.sig`, URI-encoded, where the signature is base64 HMAC-SHA256 over the
token with your `secret`. The `better-auth` part is `cookie_prefix`, so
changing that changes the cookie name.

**Sliding expiry.** `SessionOptions(expires_in=..., update_age=...)`. A session
is valid for `expires_in` (7 days by default); once more than `update_age`
(1 day) has passed since it was written, the next request extends it. A quiet
week signs the user out; an active one never does.

**Freshness.** `fresh_age` (1 day) marks a session as recently authenticated.
Sensitive endpoints (deleting the account, changing the email) require it.

**Skipping the read.** `CookieCache(enabled=True, max_age=300)` puts a signed,
short-lived copy of the session in a second cookie so `/get-session` answers
without touching the database. The signature is compared in constant time,
the cache is ignored the moment it expires, and it is only used with the
session cookie it was issued for. It can also be a JWT
(`CookieCache(strategy="jwt")`), which another service can verify: see
[Configuration](/guide/configuration#sessions).

**Bearer tokens.** `/sign-in/email` and `/sign-up/email` return a `token`, and
the core session layer reads `Authorization: Bearer <token>` on every request.
API clients never need a cookie jar. (In the TypeScript library this is a
plugin; here it is built in, and [`BearerPlugin`](/plugins/bearer) only adds
the response-side `set-auth-token` header.)

## Adapters

Everything the library stores goes through one object. Two ship with the
package:

```python
from better_auth import MemoryAdapter                       # dev and tests
from better_auth.adapters.sqlalchemy import SQLAlchemyAdapter  # SQLite, PostgreSQL, MySQL
```

`SQLAlchemyAdapter` takes any async engine, so a SQLModel engine works as-is.
`MemoryAdapter` is the default precisely so a quickstart runs with no setup.
It is not a production option.

A custom adapter is a `BaseAdapter` subclass implementing nine async methods
over plain dict rows:

| | |
| --- | --- |
| Read | `find_one`, `find_many`, `count` |
| Write | `create`, `update`, `update_many` |
| Delete | `delete`, `delete_many` |
| Atomicity | `transaction` |

`consume_one` and `increment_one` (the atomic single-use-token and
attempt-counter primitives the plugins rely on) come for free: the base
class builds them as guarded updates on top of the methods above, retried on
conflict, and an adapter can override them with a native single statement.
`SQLAlchemyAdapter` does so on PostgreSQL and SQLite.

`SQLAlchemyAdapter` also checks on first use that the database holds every
table and column Better Auth writes. See
[Schema check](/guide/configuration#schema-check).

Filters arrive as a list of `Where` objects rather than raw SQL, and the
adapter is also what generates ids, which is why
`advanced.database.generate_id` applies uniformly to core and plugin tables.

## The schema

Four core tables, with Better Auth's exact camelCase columns:

| Table | Columns |
| --- | --- |
| `user` | `id`, `name`, `email`, `emailVerified`, `image`, `createdAt`, `updatedAt` |
| `session` | `id`, `expiresAt`, `token`, `ipAddress`, `userAgent`, `userId`, `createdAt`, `updatedAt` |
| `account` | `id`, `accountId`, `providerId`, `userId`, `accessToken`, `refreshToken`, `idToken`, `accessTokenExpiresAt`, `refreshTokenExpiresAt`, `scope`, `password`, `createdAt`, `updatedAt` |
| `verification` | `id`, `identifier`, `value`, `expiresAt`, `createdAt`, `updatedAt` |

Credentials are accounts too: an email/password user gets an `account` row with
`providerId` = `credential`, the user id in `accountId` and the scrypt hash in
`password`. That is why linking a social account to a password user is just
another row.

An account is identified by its `(providerId, accountId)` pair, where
`accountId` is the provider's id for the user. Routes that act on one account
(`/unlink-account`, `/get-access-token`, `/refresh-token`, `/account-info`)
take the row's own `id` instead, as listed by `/list-accounts`. `scope` holds
the granted scopes as a comma-separated list.

You can add columns without forking anything: `UserOptions(additional_fields=...)`
and `SessionOptions(additional_fields=...)` merge into the schema, the input
allowlist, and the migration.

## Plugins

A plugin is one class. It may add routes, extend the schema, and hook the
request pipeline; everything it does not override is a no-op.

```python
from better_auth import AuthResponse, Field, Plugin

class ApiKeys(Plugin):
    id = "api-keys"   # namespace for hooks and conflicts
    schema = {        # extra tables, migrated like core ones
        "apikey": {
            "key": Field(type="string", required=True, unique=True),
            "userId": Field(type="string", required=True),
        }
    }

    def routes(self):
        return [("POST", "/api-keys/create", self.create)]

    async def create(self, ctx):
        result = await ctx.require_session()
        return {"key": "…", "userId": result["user"]["id"]}

    async def before(self, ctx) -> AuthResponse | None:
        return None   # or AuthResponse(...) to short-circuit
```

Register instances on `BetterAuth(plugins=[...])`. Beyond `routes`, `schema`,
`before` and `after`, the base class offers `init(auth)` (mutate configuration
once at startup), `middlewares()` (path-scoped, `/prefix/**` matching),
`hooks()` (matcher-gated before/after pairs), `rate_limit()` (per-path rules),
and `on_request` / `on_response` for the outermost phases.

The [27 built-in plugins](/plugins/) use exactly this surface: there is no
private API they reach for that yours cannot.

## What parity means

The TypeScript repository is canonical. Anything that touches the wire or the
storage matches it exactly, which is a stronger claim than "similar API":

- **Routes and bodies.** Same paths, same success and error JSON, same
  error-code strings and HTTP statuses (`INVALID_EMAIL_OR_PASSWORD` 401,
  `USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL` 422).
- **Password hashes.** scrypt with `N=16384, r=16, p=1, dkLen=64`, NFKC
  normalization, hex `salt:key`. Hashes cross runtimes in both directions.
- **Cookies.** Same name, same `__Secure-` promotion, same HMAC-SHA256 signing
  and URI encoding.
- **Ids and tokens.** Same alphabets and lengths: 62-character ids,
  64-character state and verification tokens.
- **Cross-runtime crypto.** scrypt, XChaCha20-Poly1305, JWK and HOTP/TOTP are
  pinned by test vectors shared with the TypeScript implementation.

The practical consequence is on the [migration page](/migrate/from-node): both
runtimes can serve the same database at the same time.

**Known divergences**, all deliberate and none visible on the wire:
reset-password tokens are stored in the database (email-verification tokens
stay stateless HS256 JWTs, as in TypeScript); bearer reading is core rather
than a plugin. The account cookie (`useAccountCookie`) and the `jwe` cookie
cache strategy are not ported. SAML (part of `sso`), `scim`, `stripe` and the
JavaScript client/expo/electron/cli packages are out of scope. This is a
server-side port.
