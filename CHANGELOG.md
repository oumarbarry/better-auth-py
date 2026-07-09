# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-07-09

### Added

- Email and password authentication: sign-up, sign-in, change/set/verify password, password reset flow, email verification.
- Social sign-in with built-in GitHub, Google and Discord providers, plus a generic `OAuthProvider` for custom ones. PKCE, single-use database-backed state with a signed state cookie, and account linking guarded by provider email verification.
- Database-backed sessions: signed cookies, sliding expiry, `rememberMe`, list/revoke endpoints, bearer token support for API clients.
- Database adapters behind a five-method protocol: `MemoryAdapter` and async `SQLAlchemyAdapter` (SQLite, PostgreSQL, MySQL).
- Plugin system: custom routes, schema extension, before/after request hooks, and `user_created_before`/`user_created_after` database hooks.
- FastAPI integration: `BetterAuthFastAPI` exposing a mountable router and `session`/`require_session` dependencies.
- Wire and storage compatibility with better-auth (TypeScript): same routes, JSON shapes, error codes, database schema, scrypt password format and session cookie scheme.
- Security defaults: CSRF origin checks, open-redirect protection on callback URLs, timing-equalized sign-in, rate limiting with better-auth's per-path rules.

[Unreleased]: https://github.com/oumarbarry/better-auth-py/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/oumarbarry/better-auth-py/releases/tag/v0.1.0
