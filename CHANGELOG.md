# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.2] - 2026-09-24

### Fixed

- Passwords longer than `max_password_length` are now rejected with
  `PASSWORD_TOO_LONG` before any hashing on sign-in (email, username, phone
  number), verify-password, change-password (`currentPassword`), delete-user,
  the two-factor endpoints that take a password, and admin create-user.
  Sign-up and password reset already did this. Matches better-auth #11324.
- The `PASSWORD_TOO_SHORT` and `PASSWORD_TOO_LONG` messages now read
  "Password too short" and "Password too long", the same strings as
  better-auth.
- The captcha plugin logs a warning when Cloudflare Turnstile rejects a token,
  with the error codes or the action or hostname that did not match.
- Readme links are absolute, so they also work on the PyPI project page.

## [1.0.1] - 2026-09-04

### Fixed

- Package metadata and readme now link to the documentation site at its
  current address.

## [1.0.0] - 2026-09-04

First public release of `better-auth-server`, the server-side Python port of
[better-auth](https://github.com/better-auth/better-auth).

### Added

- Wire and storage parity with better-auth (TypeScript) v1.6.29: same routes,
  JSON bodies, error codes, camelCase database columns and token encodings, so a
  Python server and a TypeScript one can share a database.
- Email and password sign-up and sign-in, email verification, password reset,
  account management and user deletion.
- Sessions stored in your database with signed cookies, sliding expiry, an
  optional signed cookie cache, bearer tokens for API clients, and list and
  revoke endpoints.
- 35 social sign-in providers with PKCE, token refresh, id-token verification
  and account linking, plus custom providers declared as one dataclass.
- 26 plugins: two-factor authentication, admin, organization with teams and
  dynamic access control, API keys, passkeys, JWT, an OAuth 2.1 authorization
  server, SSO over OIDC, generic OAuth, device authorization, Sign-In with
  Ethereum, magic link, email OTP, phone number, username, anonymous sessions,
  multi-session, one-time tokens, Google One Tap, OAuth proxy and more.
- Adapters: in-memory for development and tests, SQLAlchemy 2 async for SQLite,
  PostgreSQL and MySQL. A custom adapter implements nine async methods.
- Secondary storage protocol, rate limiting with database or key-value backends,
  trusted-proxy client IP resolution, secret rotation through a versioned
  secret configuration.
- Integrations for FastAPI, Litestar, Flask and Django.
- Security defaults: scrypt password hashing, CSRF origin checks, open-redirect
  protection on every callback URL, timing-equalized sign-in, XChaCha20-Poly1305
  encryption for stored secrets, compatible with the TypeScript implementation.
