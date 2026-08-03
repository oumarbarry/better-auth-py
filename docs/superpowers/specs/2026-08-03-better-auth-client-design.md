# better-auth-client — design

Python HTTP client for better-auth servers (the TS original or this port —
same wire). Approved by user 2026-08-03 (4 structural answers + "let's go").

## Decisions (user, 2026-08-03)

- **Both usages in v0**: service-to-service (validate forwarded sessions,
  admin/M2M ops) AND end-user scripts/CLI (full sign-in flows).
- **Monorepo**: uv workspace member `packages/better-auth-client/` in the
  better-auth-py repo. Integration tests run against the in-repo server.
- **TS-mirror namespaced surface**: `client.sign_in.email(...)`,
  `client.two_factor.verify_totp(...)` — calque of `createAuthClient`.
- **Sync AND async in v0**: `AuthClient` / `AsyncAuthClient` (httpx duo).
- **Device flow in v0** (Fable reco, post-brainstorm): the CLI is an
  input-constrained client — exactly what RFC 8628 is for, and the server
  plugin is already ported. `client.device` namespace + one high-level
  poll helper.

## Non-goals (v0)

- No framework hooks (react/vue equivalents are meaningless in Python).
- No OAuth browser orchestration (social sign-in URL is returned, opening a
  browser is the caller's job).
- No retry/backoff machinery beyond the device-flow poll loop (httpx
  transport options are exposed; users can pass their own client).
- Plugin namespaces beyond the seven listed below land incrementally.

## Package mechanics

- Path `packages/better-auth-client/`, PyPI name `better-auth-client`,
  import `better_auth_client`, version starts 0.1.0 (independent of the
  server package).
- Root `pyproject.toml` gains `[tool.uv.workspace] members =
  ["packages/better-auth-client"]`; root stays the server package.
- Runtime dependency: `httpx` only (floor = tested version). Python floor
  matches the server (3.10).
- Release: tag scheme `client-v*`, its own workflow file, trusted
  publishing (user registers the pending publisher on PyPI once, before
  the first release).

## Architecture

**One endpoint catalog, two thin shells.** The catalog is data: each entry
maps a dotted client path (`sign_in.email`) to HTTP method + route path +
calling convention (json body from kwargs / query params / no body).
`AuthClient` (wraps `httpx.Client`) and `AsyncAuthClient`
(`httpx.AsyncClient`) each implement a single `_call(entry, kwargs)`;
namespaces are generated objects that close over `_call`. Adding an
endpoint = one catalog line, both clients get it.

**Sessions.** Cookie jar = httpx's, automatic. Bearer mode: a response
hook captures the `set-auth-token` header (server bearer plugin) and
subsequent requests carry `Authorization: Bearer …`; also settable
explicitly (`client.set_bearer(token)`) for S2S validation of forwarded
tokens. `get_session()` returns the dict or `None` (never raises on null).

**CSRF.** Every request defaults `Origin` to the client's `base_url`
(the server's origin check requires it on state-changing POSTs).

**Errors.** `APIError(status, code, message, body)` raised on non-2xx,
fields lifted from the wire shape `{code, message}`. Redirect responses
(302) are returned, not followed, for OAuth URLs.

## Surface v0

Core (mirrors the server's core routes): `sign_up.email`,
`sign_in.email`, `sign_in.social` (returns the authorization URL),
`sign_out`, `get_session`, `list_sessions`, `revoke_session`,
`revoke_sessions`, `revoke_other_sessions`, `forget_password`,
`reset_password`, `change_password`, `set_password`, `verify_email`,
`send_verification_email`, `change_email`, `update_user`, `delete_user`,
`list_accounts`, `link_social`, `unlink_account`, `refresh_token`,
`get_access_token`, `account_info`.

Plugin namespaces (7): `two_factor`, `organization`, `admin`, `api_key`,
`magic_link`, `email_otp`, `device` (device-authorization). Exact method
lists come from the server plugin routes — the implementer reads
`plugin.routes()` on the installed package and mirrors names in
snake_case; nothing invented.

**Device-flow helper.** `client.device.flow(client_id, scope=None)`
requests the code pair, exposes `user_code`/`verification_uri`, then
polls the token endpoint honoring `interval` and the `slow_down` /
`authorization_pending` error codes until grant, denial, or `expires_in`
lapse. Sync blocks; async awaits. This is the one place v0 has flow
logic rather than 1:1 route calls.

## Testing

In-process, no sockets, dogfooding the integrations:

- Async client → `httpx.ASGITransport` over the FastAPI integration app.
- Sync client → `httpx.WSGITransport` over the Flask integration app.

Same server fixture (conftest-style `make_auth` with the 7 plugins
enabled) on both. Round-trip e2e per namespace, error-shape tests
(APIError code passthrough), bearer capture test, device-flow test
driving approve/deny through the server. The repo gate extends to the
workspace: root pytest collects `packages/better-auth-client/tests`,
ruff/format/ty cover the package (tests included).

## Docs

v0 ships a README in the package (install, sync+async quickstart, S2S
snippet, device-flow snippet). Docs-site page comes with the first
release, not before.
