---
title: Python client
---

# Python client

`better-auth-client` is the Python HTTP client for Better Auth servers, on
PyPI. It talks to any server that speaks the Better Auth wire — the original
TypeScript library or [`better-auth-server`](/guide/getting-started) — with
the same calls either way. Sync and async shells share one surface, and
`httpx` is the only dependency.

## Install

```bash
uv add better-auth-client
```

```bash
pip install better-auth-client
```

## Quickstart

Sync, over `httpx.Client`:

```python
from better_auth_client import AuthClient

client = AuthClient("http://localhost:8000")  # base_path defaults to /api/auth

client.sign_up.email(name="Ada", email="ada@example.com", password="s3cret-password")
client.sign_in.email(email="ada@example.com", password="s3cret-password")
session = client.get_session()  # dict, or None when unauthenticated
```

Async, over `httpx.AsyncClient` — the same surface, awaited:

```python
from better_auth_client import AsyncAuthClient

client = AsyncAuthClient("http://localhost:8000")

await client.sign_up.email(name="Ada", email="ada@example.com", password="s3cret-password")
await client.sign_in.email(email="ada@example.com", password="s3cret-password")
session = await client.get_session()
```

Both are context managers (`with` / `async with`), and both pass extra
constructor kwargs straight to httpx, so anything `httpx.Client` accepts —
`timeout`, `transport`, `verify` — works here too.

## Sessions

Signing in sets the session cookie and httpx's cookie jar keeps it, so
consecutive calls on one client are one browsing session. Nothing to wire up.

For cookieless callers there is bearer mode. When the server runs the
[Bearer Token plugin](/plugins/bearer), it echoes the session token on a
`set-auth-token` response header after sign-in — the client captures it
automatically and sends `Authorization: Bearer ...` from then on.

You can also set a token explicitly, which is the service-to-service pattern:
a frontend forwards the token it stored, and a backend validates it without
ever having signed in itself.

```python
service = AuthClient("http://auth.internal")

service.set_bearer(forwarded_token)  # from the set-auth-token response header
session = service.get_session()      # None if the token is invalid or expired
```

## Errors

Every non-2xx response raises `APIError` carrying the exact wire error:
`status` (HTTP status), `code` (the wire code string), `message`, and `body`
(the parsed JSON body, when there is one).

```python
from better_auth_client import APIError

try:
    client.sign_in.email(email="ada@example.com", password="wrong-password")
except APIError as error:
    print(error.status, error.code)  # 401 INVALID_EMAIL_OR_PASSWORD
```

OAuth-shaped routes (the device plugin, `/oauth2/token`) use
`{error, error_description}` on the wire; `APIError` lifts those into the
same `code` and `message` fields.

Redirect responses are returned as `httpx.Response` objects, never followed —
an OAuth authorization URL is something to hand to a browser, not to fetch.
Endpoints designed for backends return the URL as JSON instead:

```python
result = client.sign_in.social(provider="google", callbackURL="/app")
result["url"]  # send the user's browser here
```

Kwargs are sent verbatim as wire keys — JSON body on POST, query params on
GET — so camelCase wire fields stay camelCase, as `callbackURL` does above.

## The namespace surface

Every endpoint method is a snake_case mirror of its wire route, generated
from a single catalog: `client.sign_in.email(...)` is `POST /sign-in/email`,
`client.organization.create(...)` is `POST /organization/create`. If you know
the route, you know the method — 158 endpoints in all.

| Namespace | Sample methods |
| --- | --- |
| Core (root) | `sign_up.email`, `get_session`, `list_sessions`, `change_password` |
| `two_factor` | `enable`, `verify_totp`, `generate_backup_codes` |
| `organization` | `create`, `list_members`, `update_member_role` — teams and dynamic roles included |
| `admin` | `create_user`, `ban_user`, `impersonate_user` |
| `api_key` | `create`, `list`, `delete` |
| Sign-in methods | `sign_in.magic_link`, `email_otp.send_verification_otp`, `phone_number.verify`, `is_username_available`, `sign_in.anonymous`, `siwe.verify` |
| `device` | `flow`, `approve`, `deny` |
| `multi_session` | `list_device_sessions`, `set_active`, `revoke` |
| `one_time_token` | `generate`, `verify` |
| `sso` | `register`, `providers`, `verify_domain` |
| `oauth2` | `register` (DCR), `authorize`, `introspect`, `client.rotate_secret` |
| JWT (root) | `token()`, `jwks()` |

Plus `passkey`, `one_tap`, and the rest — the
[README on PyPI](https://pypi.org/project/better-auth-client/) lists the full
catalog.

## Device flow

For CLIs and other input-constrained programs, `device.flow()` runs the whole
RFC 8628 loop against a server with the
[Device Authorization plugin](/plugins/device-authorization):

```python
from better_auth_client import AuthClient

client = AuthClient("https://auth.example.com")

flow = client.device.flow("my-cli")
print(f"Visit {flow.verification_uri} and enter {flow.user_code}")

token = flow.poll()  # blocks until approved, denied, or expired
client.set_bearer(token["access_token"])
print(client.get_session()["user"]["email"])
```

`poll()` honors the server's polling `interval`, backs off five seconds on
`slow_down`, keeps waiting on `authorization_pending`, and raises `APIError`
on denial or expiry. On `AsyncAuthClient` both `device.flow(...)` and
`poll()` are awaited.

## What is not in the client

The catalog has one inclusion rule: a method exists when the request is
genuinely emitted by a Python program — headless, or relaying for a browser
(a BFF, server-rendered pages, CLIs). Routes only the end user's own browser
ever requests are deliberately absent: OAuth redirect callbacks,
`/oauth2/continue` (backends redirect *to* it, never call it), and the OAuth
Popup plugin's popup navigation. If a route is missing, that is the reason —
not an oversight.

## Next

- [Getting started](/guide/getting-started) — stand up the server this client talks to.
- [Bearer Token](/plugins/bearer) — the server side of `set-auth-token`.
- [Device Authorization](/plugins/device-authorization) — the server side of `device.flow()`.
