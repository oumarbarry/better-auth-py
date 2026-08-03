# Changelog

All notable changes to better-auth-client are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.1.0]: https://github.com/oumarbarry/better-auth-py/releases/tag/client-v0.1.0
