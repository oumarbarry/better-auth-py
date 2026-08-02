# Production deploy

Everything on this page is infrastructure rather than API surface: the five
things that are fine on localhost and wrong in production.

## Secrets

```python
auth = BetterAuth(secret=os.environ["BETTER_AUTH_SECRET"])
```

```bash
openssl rand -base64 32
```

At least 32 characters, or construction fails:

```
ValueError: secret must be at least 32 characters — generate one with `openssl rand -base64 32`
```

The secret signs session cookies, OAuth state and every derived key. Changing
it signs everyone out, which is why rotation is versioned rather than a
swap:

```python
auth = BetterAuth(
    secret=os.environ["BETTER_AUTH_SECRET"],          # the current one
    secrets=[
        (2, os.environ["BETTER_AUTH_SECRET"]),
        (1, os.environ["BETTER_AUTH_SECRET_V1"]),     # keep until old values expire
    ],
)
```

New values are written under the highest version; old ones keep verifying
until you drop the pair. Retire a version once nothing signed with it can still
be live — one `session.expires_in` window is the safe floor.

## A real adapter

`MemoryAdapter` is the default so a quickstart runs with no setup. It is
per-process and it forgets everything on restart.

```python
from sqlalchemy.ext.asyncio import create_async_engine
from better_auth.adapters.sqlalchemy import SQLAlchemyAdapter

engine = create_async_engine(os.environ["DATABASE_URL"], pool_pre_ping=True)
auth = BetterAuth(secret=..., adapter=SQLAlchemyAdapter(engine))
```

Use real migrations. `await adapter.create_tables()` is a development
convenience — in production, let Alembic own the schema so plugin tables and
`additional_fields` are versioned with your code.

## `base_url` and HTTPS

```python
auth = BetterAuth(
    secret=...,
    base_url="https://example.com",              # not localhost, not http
    trusted_origins=["https://app.example.com"], # a separate frontend origin
)
```

An `https` `base_url` is what turns on `Secure` cookies and the `__Secure-`
name prefix. It is also the origin that CSRF checks and every `callbackURL` and
`redirectTo` are validated against — which is what makes open redirects
impossible. A frontend on another origin must be listed in `trusted_origins` or
its requests will be rejected.

For one process behind several hostnames:

```python
from better_auth import DynamicBaseURL

auth = BetterAuth(
    secret=...,
    base_url=DynamicBaseURL(allowed_hosts=["example.com", "*.vercel.app"], protocol="https"),
)
```

The base URL is derived per request from the `Host` header and restricted to
`allowed_hosts`; each pattern also becomes a trusted origin. This is the option
for preview deployments — for social sign-in from preview URLs specifically,
see the [`oauth-proxy` plugin](/plugins/#oauth-proxy).

## Trust your proxy, not the client

Behind a load balancer, the socket address is the proxy's. The client IP comes
from a header, and a header can be forged — an attacker who controls
`x-forwarded-for` defeats per-IP rate limiting entirely.

```python
from better_auth import IPAddressOptions

auth = BetterAuth(
    secret=...,
    ip_address=IPAddressOptions(
        ip_address_headers=["cf-connecting-ip", "x-forwarded-for"],
        trusted_proxies=["10.0.0.0/8"],     # only these may set the header
    ),
)
```

List the CIDR ranges of your own proxies in `trusted_proxies`. The chain is
walked from the right, and the first address outside the trusted set is the
client. Set `disable_ip_tracking=True` if you would rather not store IPs at
all.

## Rate limiting across workers

```python
from better_auth import RateLimit

auth = BetterAuth(
    secret=...,
    rate_limit=RateLimit(
        enabled=True,
        window=10,
        max=100,
        storage="database",                 # or "secondary-storage"
        custom_rules={"/sign-in/email": {"window": 10, "max": 3}},
    ),
)
```

better-auth's per-path rules ship built in. The trap is the default:
`storage="memory"` counts per process, so four uvicorn workers means four times
the limit. Use `"database"` for the shared adapter, or `"secondary-storage"`
with a Redis-shaped store:

```python
auth = BetterAuth(secret=..., secondary_storage=my_redis, rate_limit=RateLimit(
    enabled=True, storage="secondary-storage",
))
```

Any object implementing the `SecondaryStorage` protocol works.
`MemorySecondaryStorage` ships for tests.

## Running it

```bash
uvicorn app:app --host 0.0.0.0 --port 8000 --workers 4 --proxy-headers
```

`--proxy-headers` is what makes uvicorn read `X-Forwarded-Proto`, so the
application sees `https` and cookies come out `Secure`. Pair it with
`--forwarded-allow-ips` set to your proxy's addresses.

With more than one worker, in-process state is per worker: use a shared
rate-limit store (above), and a shared `secondary_storage` if you use one at
all.

### Vercel

The Python function runtime serves an ASGI app directly, so
`BetterAuthFastAPI` needs nothing special. Set `BETTER_AUTH_SECRET`,
`BETTER_AUTH_URL` and `DATABASE_URL` as environment variables, and use a
connection pooler (Neon, Supabase pooler, PgBouncer) — serverless invocations
open connections faster than a database wants.

Preview deployments get a different hostname on every push, which breaks the
one redirect URI registered with each OAuth provider. Two fixes: `DynamicBaseURL`
with `allowed_hosts=["*.vercel.app"]`, or the
[`oauth-proxy` plugin](/plugins/#oauth-proxy) to bounce callbacks through
production.

## What is already hardened

You do not have to configure these; they are the defaults.

- **CSRF.** Non-GET requests are origin-checked against `base_url` and
  `trusted_origins`.
- **Open redirects.** Every `callbackURL` and `redirectTo` is validated against
  trusted origins.
- **User enumeration.** Sign-in runs a dummy scrypt when the user does not
  exist, so an unknown address and a wrong password take the same time and
  return the same 401.
- **Password storage.** scrypt at `N=16384, r=16, p=1, dkLen=64`.
- **Secrets at rest.** `AccountOptions(encrypt_oauth_tokens=True)` encrypts
  stored provider tokens with XChaCha20-Poly1305.
- **Constant-time comparison** on the cookie-cache signature.

Two options exist to turn parts of this off — `disable_csrf_check` and
`disable_origin_check`. Both are for tests. If a production request is being
rejected, the answer is an entry in `trusted_origins`.

## A production checklist

- [ ] `secret` from the environment, ≥32 characters, never in the repository
- [ ] A real adapter, with schema managed by migrations
- [ ] `base_url` on `https`, real frontend origins in `trusted_origins`
- [ ] `trusted_proxies` set if you are behind a load balancer
- [ ] `rate_limit.storage` not `"memory"` when running more than one worker
- [ ] `--proxy-headers` (and `--forwarded-allow-ips`) on uvicorn
- [ ] Mailer callbacks wired: `send_reset_password`, `send_verification_email`
- [ ] `encrypt_oauth_tokens=True` if you store provider tokens
- [ ] `CookieCache` `max_age` small enough that revocation is timely
