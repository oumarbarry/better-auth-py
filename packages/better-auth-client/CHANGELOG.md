# Changelog

All notable changes to better-auth-client are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-08-03

### Removed

- Three entries whose requests are only ever emitted by the end user's own
  browser, never by a Python program (headless or relaying): `oauth_popup.start`
  (popup navigation; the plugin leaves the client), `oauth2.continue_`
  (post-login browser redirect — backends redirect *to* it, never call it)
  and the redundant `siwe.get_nonce` wire alias (`siwe.nonce` is the
  operation). This is now the documented inclusion rule for the catalog.

## [0.2.0] - 2026-08-03

### Added

- Full plugin coverage — 59 new endpoints (161 total), one namespace per
  server plugin with mounted routes:
  - `sign_in.username` / `is_username_available`, `sign_in.phone_number` +
    `phone_number.*`, `sign_in.anonymous` / `delete_anonymous_user`,
    `sign_in.oauth2` (generic-oauth) and `sign_in.sso`;
  - `passkey.*` (WebAuthn options/verify/list/update/delete),
    `siwe.*` (`nonce`, its mounted `get_nonce` alias, `verify`),
    `one_tap.callback`, `one_time_token.*`, `multi_session.*`,
    `oauth_popup.start`, `sso.*` (provider CRUD + domain verification);
  - the oauth-provider surface under `oauth2.*`: DCR `register`, client CRUD
    + `client.rotate_secret`, `authorize`, `token`, `introspect`, `revoke`,
    `userinfo`, `end_session`, `consent`/`continue_`/consent CRUD
    (`/oauth2/continue` was exposed as `continue_` — Python keyword);
  - root-mounted jwt-plugin routes as `token()` and `jwks()`.
- Namespaces now nest to any depth (`client.oauth2.client.rotate_secret`).

Plugins without mounted routes (`bearer`, `captcha`, `have-i-been-pwned`,
`last-login-method`) and `custom-session` (shadows the core `/get-session`)
add no namespace; browser-only OAuth callbacks with path params stay excluded.

## [0.1.0] - 2026-08-03

Initial release.

### Added

- `AuthClient` (sync) and `AsyncAuthClient` (async), both generated from a
  single endpoint catalog — TS-mirror namespaced surface
  (`client.sign_in.email(...)`, `client.organization.create(...)`).
- 102 endpoints: the full core surface plus the `two_factor`,
  `organization` (teams and dynamic roles included), `admin`, `api_key`,
  `magic_link`, `email_otp` and `device` namespaces.
- Sessions on httpx's cookie jar; bearer mode via automatic
  `set-auth-token` capture or explicit `set_bearer()`.
- `device.flow()`: RFC 8628 device-authorization poll loop
  (`interval`, `slow_down` +5s, `authorization_pending`).
- `APIError` lifting both `{code, message}` and OAuth
  `{error, error_description}` wire shapes; 302 responses returned,
  never followed; `Origin` defaults to the base URL.

Works against any better-auth server — the TypeScript original or
[better-auth-server](https://pypi.org/project/better-auth-server/) — same wire.

[0.3.0]: https://github.com/oumarbarry/better-auth-py/compare/client-v0.2.0...client-v0.3.0
[0.2.0]: https://github.com/oumarbarry/better-auth-py/compare/client-v0.1.0...client-v0.2.0
[0.1.0]: https://github.com/oumarbarry/better-auth-py/releases/tag/client-v0.1.0
