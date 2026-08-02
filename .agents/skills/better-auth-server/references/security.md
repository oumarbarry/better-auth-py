# Security and hardening

## Rate limiting

`RateLimit` is a rolling window keyed by client IP + path. `enabled=None` (the default)
means "on in production only" — `BETTER_AUTH_ENV` or `NODE_ENV` == `production`, matching
the TypeScript library. Set it explicitly if you want it on in dev.

Three storages:

| `storage` | Backing store | Use when |
|---|---|---|
| `"memory"` (default) | in-process dict with a per-key TTL | single process, dev |
| `"database"` | the `rateLimit` table via your adapter | multi-worker, no Redis. Adds `rateLimit` to `auth.schema`, so migrate after configuring |
| `"secondary-storage"` | the `secondary_storage` KV (Redis-shaped) | multi-worker with Redis. Wire-compatible with the TS secondary-storage limiter |

```python
from better_auth import BetterAuth, MemorySecondaryStorage, RateLimit

auth = BetterAuth(
    secret=...,
    secondary_storage=MemorySecondaryStorage(),  # swap for your Redis-shaped store
    rate_limit=RateLimit(
        enabled=True,
        window=60,
        max=100,
        storage="secondary-storage",
        custom_rules={
            "/sign-in/email": (10, 3),   # (window seconds, max requests)
            "/sign-up/email": (60, 5),
            "/get-session": False,       # skip rate limiting entirely
            "/two-factor/*": (10, 3),    # `*` wildcard on the path
        },
    ),
)
```

A rule value can also be a callable `(request, {"window": w, "max": m}) -> (window, max) |
False`. Over the limit the router answers `429` with an `x-retry-after` header. Bring your
own backend with `custom_storage=` (implement `adapters.rate_limit.RateLimitStorage`:
`get`/`set`).

## Client IP behind a proxy

`advanced.ipAddress` → `IPAddressOptions`. The resolved IP is the rate-limit key and the
`session.ipAddress` column, so getting it wrong means one shared bucket (or a bucket per
spoofed header).

```python
from better_auth import BetterAuth, IPAddressOptions

auth = BetterAuth(
    secret=...,
    ip_address=IPAddressOptions(
        ip_address_headers=["cf-connecting-ip", "x-forwarded-for"],  # checked in order
        trusted_proxies=["10.0.0.0/8", "172.16.0.0/12"],             # IPs or CIDRs
        ipv6_subnet=64,          # collapse IPv6 to a /64 before keying
        disable_ip_tracking=False,  # True => no IP stored, one shared rate-limit bucket
    ),
)
```

**The non-obvious part:** without `trusted_proxies`, a *multi-hop* `X-Forwarded-For` is
treated as unresolvable and resolution falls back to the socket peer — a client-supplied
`X-Forwarded-For: 1.2.3.4, <real>` cannot forge the key. With `trusted_proxies` set, the
chain is walked right-to-left, trusted hops are skipped, and the first untrusted address
wins; a malformed hop fails closed (no IP). Set `trusted_proxies` to your load balancer's
ranges — do not leave it empty and expect header trust.

`trusted_proxy_headers=True` (default, separate flag) controls whether
`x-forwarded-host` / `x-forwarded-proto` are trusted when resolving a dynamic `base_url`.

## Origin / CSRF model

Every non-GET request is origin-checked (`origin.py`, a port of
`api/middlewares/origin-check.ts`): `Origin` with a `Referer` fallback,
`MISSING_OR_NULL_ORIGIN` when cookies are present with no origin, and a
Fetch-Metadata cross-site block on first-login forms. A rejected request gets
`403 INVALID_ORIGIN`.

Trusted set = **`base_url`'s own origin** + `trusted_origins`. Nothing else. A separate
frontend origin (Vite on `:5173`, a marketing site, a mobile web view) must be listed.

```python
auth = BetterAuth(
    secret=...,
    base_url="https://api.example.com",
    trusted_origins=[
        "https://app.example.com",
        "https://*.preview.example.com",  # wildcard, `**` spans path separators
    ],
)
```

`trusted_origins` also accepts a callable `(request) -> list[str]` for per-tenant origins.
The same list validates every `callbackURL` / `redirectTo` / `errorCallbackURL` /
`newUserCallbackURL`, which is what blocks open redirects — relative paths pass, off-origin
absolute URLs get `INVALID_CALLBACK_URL` 403.

Escape hatches, in order of preference: `disable_origin_check=["/path"]` (a list scopes it
to those paths), `disable_origin_check=True`, `disable_csrf_check=True`. Prefer widening
`trusted_origins`.

### Dynamic `base_url`

For preview deployments and wildcard subdomains, pass `DynamicBaseURL` instead of a
string. Its `allowed_hosts` **double as trusted origins**, so you do not list them twice.

```python
from better_auth import BetterAuth, DynamicBaseURL

auth = BetterAuth(
    secret=...,
    base_url=DynamicBaseURL(
        allowed_hosts=["example.com", "*.vercel.app"],
        fallback="https://example.com",  # used when the host is missing or unlisted
        protocol="https",                # "http" | "https" | "auto" (x-forwarded-proto) | None
    ),
)
```

An empty `allowed_hosts` raises at construction. With `protocol=None` (TS "unset") only
`https://` origins are added to the trusted set. Outside a request (a direct
`auth.<method>` call), `base_url` resolves to `fallback`; without one it raises 500 — so
always set `fallback` if anything calls auth outside `handle`/`load_session`.

## Secret rotation

`secret=` alone is the bare-hex path. Pass `secrets=[(version, value), ...]` — **the first
entry is the current version** — to get a versioned `SecretConfig`. New ciphertext is
wrapped in a `$ba$<version>$<hex>` envelope; old envelopes and pre-rotation bare-hex
payloads still decrypt, so rotation needs no data migration.

```python
auth = BetterAuth(
    secret=os.environ["BETTER_AUTH_SECRET"],  # legacy key, kept to read old bare-hex payloads
    secrets=[
        (2, os.environ["BETTER_AUTH_SECRET_V2"]),  # current: everything new is encrypted with this
        (1, os.environ["BETTER_AUTH_SECRET_V1"]),  # retained so v1 envelopes still decrypt
    ],
)
```

Construction raises on an empty list, a negative or duplicate version, or an empty value.
Retiring a version whose envelopes still exist makes those payloads unreadable — drop a
key only after the data encrypted with it is gone. Encryption is XChaCha20-Poly1305,
byte-compatible with the TypeScript `symmetricEncrypt`.

## Cookies

`use_secure_cookies` is *derived*, not defaulted: `True` when `base_url` starts with
`https://`, `False` otherwise. When it is `True` the session cookie is named
`__Secure-better-auth.session_token`; otherwise `better-auth.session_token`. A dynamic
`base_url` uses its `protocol` (`"https"` → `True`, `"http"` → `False`, `auto`/unset →
`BETTER_AUTH_ENV`/`NODE_ENV` == `production`). Pass `use_secure_cookies=True` explicitly
when terminating TLS at a proxy that forwards plain HTTP with an `http://` `base_url`.

For a frontend on a sibling subdomain:

```python
from better_auth.config import CrossSubDomainCookies

auth = BetterAuth(
    secret=...,
    base_url="https://api.example.com",
    cross_sub_domain_cookies=CrossSubDomainCookies(enabled=True, domain=".example.com"),
)
```

`domain` defaults to the `base_url` hostname when enabled. `cookie_prefix="better-auth"`
renames the whole cookie family.

## Other hardening already on by default

- **scrypt** password hashing (`N=16384, r=16, p=1, dkLen=64`, NFKC), exact better-auth
  format.
- **Timing-equalized sign-in**: a dummy hash runs when the user does not exist, so unknown
  email and wrong password cost the same and both return `401 INVALID_EMAIL_OR_PASSWORD`.
- **Account-linking gates**: `AccountOptions(account_linking=AccountLinking(...))` —
  `require_local_email_verified=True` by default blocks account preemption via a
  pre-registered unverified local row.
- **`AccountOptions(encrypt_oauth_tokens=True)`** encrypts stored access/refresh tokens at
  rest (off by default).
- **`disabled_paths=["/sign-up/email"]`** 404s routes you do not want exposed.
- Consider the `have-i-been-pwned`, `captcha` and `two-factor` plugins — see
  `plugins.md`.
