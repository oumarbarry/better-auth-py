# better-auth-client

Python HTTP client for [better-auth](https://github.com/better-auth/better-auth)
servers — the TypeScript original or
[`better-auth-server`](https://pypi.org/project/better-auth-server/) (same wire).

```sh
pip install better-auth-client
```

## Quickstart

Sync (`httpx.Client`):

```python
from better_auth_client import AuthClient

client = AuthClient("http://localhost:8000")  # base_path defaults to /api/auth

client.sign_up.email(name="Ada", email="ada@example.com", password="s3cret-password")
client.sign_in.email(email="ada@example.com", password="s3cret-password")
session = client.get_session()          # dict, or None when unauthenticated
client.sign_out()
```

Async (`httpx.AsyncClient`) — same surface, awaited:

```python
from better_auth_client import AsyncAuthClient

client = AsyncAuthClient("http://localhost:8000")
await client.sign_in.email(email="ada@example.com", password="s3cret-password")
session = await client.get_session()
```

Kwargs are sent verbatim as wire keys (JSON body on POST, query params on GET), so
camelCase wire fields stay camelCase: `client.forget_password(email=..., redirectTo=...)`.

Errors raise `APIError(status, code, message, body)` with the exact wire `code`.
Redirect responses (e.g. the OAuth authorization step) are returned as-is, never
followed.

## Service-to-service

Validate a forwarded session token (server `bearer` plugin) without cookies:

```python
client = AuthClient("http://auth.internal")
client.set_bearer(forwarded_token)      # from the set-auth-token response header
session = client.get_session()          # None if the token is invalid/expired
```

When the server has the bearer plugin enabled, the client also captures
`set-auth-token` automatically after sign-in.

## Device flow (RFC 8628)

For CLIs and other input-constrained clients (server `device-authorization` plugin):

```python
flow = client.device.flow("my-cli")
print(f"Visit {flow.verification_uri} and enter {flow.user_code}")
token = flow.poll()                     # blocks (awaits, for AsyncAuthClient)
client.set_bearer(token["access_token"])
```

`poll()` honors the server's `interval`, backs off on `slow_down`, keeps waiting on
`authorization_pending`, and raises `APIError` on denial or expiry.

## Coverage

161 endpoints, mirroring the server routes: the full core surface plus

- `sign_in.*` — `email`, `social`, `username`, `phone_number`, `anonymous`,
  `magic_link`, `email_otp`, `oauth2` (generic-oauth), `sso`
- `two_factor`, `organization` (teams and dynamic roles included), `admin`,
  `api_key`, `magic_link`, `email_otp`, `device`
- `phone_number`, `passkey`, `siwe`, `one_tap`, `one_time_token`,
  `multi_session`, `oauth_popup`, `sso` (domain verification included)
- `oauth2` — generic-oauth (`link`) plus the whole oauth-provider surface
  (DCR `register`, client CRUD, `client.rotate_secret`, `authorize`, `token`,
  `introspect`, `revoke`, `userinfo`, `end_session`, consent + consent CRUD;
  `/oauth2/continue` is `oauth2.continue_authorization` — `continue` is a Python keyword)
- root-mounted jwt-plugin routes as `token()` / `jwks()`, plus
  `is_username_available()` and `delete_anonymous_user()`

Server plugins without mounted routes need no client namespace: `bearer`
(automatic `set-auth-token` capture, above), `captcha`, `have-i-been-pwned`,
`last-login-method`, `custom-session` (shadows `get_session`), `oauth-proxy`
(browser-redirect callback only).
