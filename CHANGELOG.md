# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `InternalAdapter.reserve_verification_value`: a first-writer-wins insert
  keyed by an id derived from the identifier (the same id as better-auth).
  It backs the lock used by the unverified-account cleanup.
- `MicrosoftEntraId(account_id_claim=...)`: the ID token claim used as the
  account id, `"oid"` by default.
- SQLAlchemy adapter schema check, on by default: on first use it checks
  that every table and column Better Auth writes exists and that no required
  column is one Better Auth never fills. On a mismatch it logs one report and
  database operations fail with `SchemaMismatchError`. Turn it off with
  `AdvancedDatabase(validate_schema=False)`.
- `consume_one` and `increment_one` run as a single statement on PostgreSQL
  and SQLite.
- Custom rate-limit storages can implement `consume(key, rule)` to decide a
  request in one atomic step.

### Changed

- Microsoft Entra ID accounts are identified by the `oid` claim instead of
  `sub`, as in better-auth 1.7. Existing `account` rows for the `microsoft`
  provider hold `sub` values and no longer match, so a returning user is
  treated as a new sign-in (implicit linking by email, or a refusal). Migrate
  those rows to `oid` before upgrading, or pass
  `MicrosoftEntraId(account_id_claim="sub")` to keep the old ids. A token
  without a usable claim is refused with `unable_to_get_user_info`.
- OAuth sign-in resolves an account only by its exact
  `(providerId, accountId)` pair. When two `account` rows share that pair,
  sign-in is refused and no session is issued. Before, the first row found
  won. This failure, like a failed user lookup during OAuth sign-in,
  redirects to `on_api_error.error_url` (default `<base path>/error`) with
  `error=internal_server_error`, not to the flow's error callback URL.
  Remove the duplicate rows to restore sign-in for that account. `InternalAdapter.find_account_by_key` raises
  `BetterAuthError` for the same case.
- An OAuth account whose user row no longer exists is refused with
  `unable_to_link_account` instead of signing in a missing user. Repair or
  delete the orphaned `account` row.
- The link-social callback reports `unable_to_link_account` (was
  `account_not_linked`) for an untrusted provider with an unverified email,
  and `email_does_not_match` (was `email_doesnt_match`) for a different
  email, matching better-auth. Relinking an account the user already owns
  now refreshes its tokens.
- Linking with an ID token (`POST /link-social` with `idToken`) returns
  `409 SOCIAL_ACCOUNT_ALREADY_LINKED` when the provider account belongs to
  another user. Before, it answered success without linking. Relinking your
  own account refreshes its tokens. The new account row no longer stores the
  `scopes` sent with the ID token, as in better-auth 1.7.
- Magic-link and email OTP sign-in to an unverified user now delete every
  account linked to that user (OAuth links too, not only the password) and
  its sessions, then mark the email verified. The cleanup runs under a lock
  stored as a verification row. `InternalAdapter.revoke_unproven_account_access`
  returns the updated user, and callers no longer update `emailVerified`
  themselves.
- `account.scope` holds the granted scopes as a comma-separated list, as
  better-auth stores it. Sign-in after the first one no longer rewrites it,
  `/refresh-token` no longer rewrites it and returns the stored value, and
  the link-social callback adds new scopes to the stored ones. Rows written
  space-separated by earlier releases are still read correctly.
- ID token sign-in (`POST /sign-in/social` with `idToken`) no longer stores
  the `idToken.scopes` or `idToken.refreshToken` sent by the client on the
  account, as in better-auth.
- Rate limiting decides each request in one atomic step per backend.
  Secondary storage uses the store's `increment` and keeps a plain integer
  counter whose expiry is set when the window opens, as better-auth 1.7 does.
  A counter left in the older JSON format is replaced on its next request,
  which restarts that window. Database counters use guarded updates and
  prune expired rows when a window resets. A window now resets exactly when
  it has elapsed.
- A secondary storage without `increment` or `get_and_delete`, or a custom
  rate-limit storage with only `get` and `set`, keeps working through the
  older non-atomic path and logs a warning once.
- `increment_one` raises `BetterAuthError` instead of `ValueError` when both
  `increment` and `set` are empty.

### Fixed

- Linking with an ID token and a different email now answers with the
  better-auth message `Account not linked - different emails not allowed`.
- A new OAuth user and its first account are created in one transaction. If
  the account insert fails, no user row is left behind and the callback
  redirects with `unable_to_create_user`.
- Signing in again with a provider that omits a token (for example no
  refresh token) keeps the stored value instead of clearing it.
- With `override_user_info_on_sign_in`, a user update that returns nothing
  keeps the existing user for the session and logs a warning.
- A provider response with an empty account id is refused
  (`unable_to_get_user_info` on the callback, `401 FAILED_TO_GET_USER_INFO`
  for ID token sign-in) instead of creating an account with an empty id.
- `scopes` in `/list-accounts` and `/get-access-token` are trimmed and empty
  entries dropped.
- Email OTP sign-in returns the user with `emailVerified: true` after it
  verifies a previously unverified address.
- Custom adapters without native atomic methods no longer lose concurrent
  `increment_one` updates: the shared fallback guards on the counter values
  and retries up to five times.
- A failed memory adapter transaction no longer erases writes made
  concurrently outside it.

## [1.0.3] - 2026-09-25

### Fixed

- Single-use values (magic links, one-time tokens, email and phone OTP codes,
  two-factor challenges, password reset and account deletion tokens, device
  codes) can no longer be used twice when two requests race on a database
  shared by several processes. Consuming one now deletes the row by id and
  succeeds only for the request that actually removed it, as better-auth
  does.
- Password reset and account deletion tokens are stored and read through the
  verification storage, so they follow `verification.store_identifier` and
  secondary storage like other verification values.
- An expired account deletion link is rejected with `INVALID_TOKEN` instead
  of deleting the account.
- Database hooks on `verification` deletes run once, for the consumed row. A
  `before` hook that returns `False` now stops the consume.
- A guarded counter update changes only the row it read, even when the
  condition matches several rows.

## [1.0.2] - 2026-09-25

### Fixed

- Sign-in with email rejects a malformed address with `INVALID_EMAIL` (400)
  before looking up the user, as better-auth does.
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
