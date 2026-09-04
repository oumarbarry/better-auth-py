# Changelog

All notable changes to this package are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the package adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-09-04

First public release of `better-auth-client`, the Python HTTP client for
better-auth servers (the TypeScript original or `better-auth-server`).

### Added

- Sync (`AuthClient`) and async (`AsyncAuthClient`) clients over httpx, with the
  same namespaced surface as the server routes.
- 158 endpoints: the core surface plus two-factor, organization, admin, API
  keys, magic link, email OTP, device authorization, passkey, SSO, Sign-In with
  Ethereum, Google One Tap, one-time token, multi-session, phone number,
  username, anonymous, generic OAuth and the OAuth provider surface.
- Bearer token support with automatic capture of the server's `set-auth-token`
  header, for service-to-service calls.
- Device flow helper (RFC 8628) that polls with the server's interval, backs off
  on `slow_down` and raises on denial or expiry.
- Errors raise `APIError` carrying the exact wire status, code and message.
