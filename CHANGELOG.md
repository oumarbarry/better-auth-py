# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.1] - 2026-08-03

### Fixed

- `better_auth.plugins_ext` now imports without the `[passkey]` extra
  installed. The package eagerly imported the passkey plugin, whose
  unguarded `webauthn` import crashed `from better_auth.plugins_ext
  import <any plugin>` on wheels installed without that extra.
  `PasskeyPlugin` is imported lazily, and requesting it without the
  extra raises an error naming `better-auth-server[passkey]`.

## [0.5.0] - 2026-08-02

### Added

- **Django integration**: `BetterAuthDjango` completes the framework
  matrix — `.urls` to splat into `urlpatterns`, sync `session()`/
  `require_session(request)` helpers, repeated `Set-Cookie` preserved
  through `response.cookies` under both WSGI and ASGI. Same
  dedicated-event-loop bridge as the Flask layer (stdlib only). The
  auth view is `csrf_exempt`; the core's Origin check is the CSRF
  protection, as on every framework. New `[django]` extra (Django ≥ 5.0).

## [0.4.0] - 2026-08-02

### Added

- **Flask integration**: `BetterAuthFlask` mirrors the FastAPI/Litestar
  surface for WSGI apps — mountable blueprint, sync `session()`/
  `require_session()` helpers, repeated `Set-Cookie` preserved. The
  sync→async bridge is a dedicated event loop in a daemon thread
  (stdlib only), so loop-bound resources (async SQLAlchemy pools, the
  cached HTTP client) behave exactly as under ASGI. New `[flask]`
  extra (flask ≥ 3.0).

## [0.3.0] - 2026-08-02

### Added

- **Litestar integration**: `BetterAuthLitestar` mirrors the FastAPI surface
  (mountable router, `session`/`require_session` DI helpers, repeated
  `Set-Cookie` preserved). New `[litestar]` extra (litestar ≥ 2.24).
- `session.defer_session_refresh` (TS parity): GET `/get-session` becomes
  read-only and reports `needsRefresh`; POST performs the refresh and
  expired-session cleanup. Without the option, POST returns the TS-exact
  405 `METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED`.
- `session.disable_session_refresh` (TS parity): disables sliding-expiry
  refresh on every session read, regardless of `update_age`.
- Public `origin.validate_form_csrf` seam (the per-endpoint force-validation
  used by cookieless send endpoints; TS `formCsrfMiddleware` analog).

### Fixed

- `POST /get-session` previously returned a generic 405; now byte-exact
  with TypeScript (code and message).
- Organization `listMembers`/full-org population resolves users in one
  `in` query instead of N per-member round trips.
- `better_auth.__version__` is now derived from package metadata (it had
  been stuck at "0.1.0" through two releases).

## [0.2.1] - 2026-08-02

Catch-up to better-auth (TypeScript) **v1.6.25** — all 60 upstream commits
triaged, 7 server-side fixes ported, 5 non-changes proven with regression
tests. 2006 tests.

### Fixed

- **Security**: `/email-otp/send-verification-otp` now force-validates the
  Origin header like the TS `formCsrfMiddleware` — a cookieless cross-origin
  POST could previously trigger an OTP email to an arbitrary address.
  (magic-link was already covered by the `/sign-in` prefix rule; regression
  tests added.)
- Apple OAuth now sends the S256 PKCE challenge in the authorization request
  and forwards the verifier at token exchange.
- One-tap sign-in honors the registered Google provider's `disable_sign_up`
  restriction instead of always creating users.
- Organization: invitation, member, team and teamMember ids are now generated
  by the database adapter (respects `advanced.database.generate_id`);
  membership fetch in `listMembers` proven unbounded; delete hooks receive
  the endpoint context.
- `verify_id_token` provider overrides receive the request context (`ctx`);
  legacy 3-argument overrides keep working.

### Added

- last-login-method: `before_store_cookie` option (GDPR) — a falsy or raising
  callback skips storing the cookie.

## [0.2.0] - 2026-07-25

Full parity with better-auth (TypeScript) v1.6.23. This release closes the
entire parity campaign tracked in `docs/plans/ACTIVE.md`: 1975 tests, ruff
and ty clean.

### Added

- **35 social providers** via a declarative `ProviderConfig` + name-keyed
  `social_providers={"github": {...}}` registry (`PROVIDER_REGISTRY`):
  GitHub, Google, Discord plus 32 more (Apple, Atlassian, Cognito, Dropbox,
  Facebook, Figma, GitLab, Hugging Face, Kakao, Kick, Line, Linear,
  LinkedIn, Microsoft Entra ID, Naver, Notion, Paybin, PayPal, Polar,
  Railway, Reddit, Roblox, Salesforce, Slack, Spotify, TikTok, Twitch,
  Twitter/X, Vercel, VK, WeChat, Zoom).
- **26 plugins ported**, including two-factor, admin, organization
  (teams + dynamic access control), jwt (full `JWKOptions` alg union:
  EdDSA/ES256/ES512/PS256/RS256), oauth-provider (RFC 6749/7009/7636/7662,
  4-phase: clients/DCR/discovery/JWKS, authorize/consent, token
  grants + introspection, userinfo/revocation/end-session), api-key,
  passkey (WebAuthn/FIDO2), sso (OIDC), generic-oauth,
  device-authorization, siwe (Sign-In with Ethereum), oauth-proxy,
  oauth-popup, one-tap, multi-session, magic-link, email-otp,
  phone-number, username, anonymous, bearer, captcha, custom-session,
  haveibeenpwned, last-login-method, one-time-token.
- **Core machinery**: internal-adapter seam fronting all model reads/writes,
  `databaseHooks` (before/after per model), pluggable secondary storage
  (`SecondaryStorage` protocol + in-memory implementation), TS-parity rate
  limiting (per-path rules, pluggable storage), `advanced.ipAddress`
  trusted-proxy chain for client-IP resolution, dynamic `base_url` with
  `allowedHosts` for multi-domain deployments, versioned `SecretConfig`
  for secrets rotation (`$ba$<version>$` envelope) and encrypted OAuth
  client secrets, XChaCha20-Poly1305 cross-runtime-compatible symmetric
  encryption, TOTP/HOTP + `otpauth://` URLs, Ed25519 JWK material.
- Expanded database adapter contract: `create`, `find_one`, `find_many`,
  `update`, `update_many`, `delete`, `delete_many`, `count`, `transaction`,
  plus atomic `consume_one`/`increment_one` derived primitives; insensitive
  `in`/`not_in` matching on the SQLAlchemy adapter.
- `install extras`: `[passkey]` (`webauthn`) and `[sso]` (`dnspython`),
  alongside the existing `[fastapi]` and `[sqlalchemy]`.

### Changed

- **Package renamed to `better-auth-server`** (PyPI: `better-auth-py` and
  `better-auth` were already taken). The import is unchanged:
  `import better_auth`. The GitHub repository keeps its historical name.

### Fixed

Security fixes shipped during the parity campaign:

- `/update-session` accepted arbitrary non-core session fields (privilege
  escalation vector); now enforces a schema-driven input allowlist.
- Origin/CSRF check: a non-empty `disable_origin_check` per-path skip list
  disabled the check globally due to a truthiness bug.
- Cookie-cache signature comparison used `!=` instead of a constant-time
  compare (timing side-channel).
- `/sign-up/email` created the user row before password validation ran,
  leaving an orphaned user with no credential account on a rejected
  password.
- IDOR in `/refresh-token` and `/get-access-token`: responses could leak
  tokens across accounts.

### Out of scope (parity decision log)

Deliberately not ported, per `docs/plans/ACTIVE.md`'s decision log:
open-api (dev-tooling only, no wire/storage contract), telemetry and
logger config groups (no wire contract; logging stays on stdlib
`logging`), SAML, scim, stripe, and the JS `client`/expo/electron/cli
packages (server-side parity only — a Python client is a separate,
unscoped project).

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

[Unreleased]: https://github.com/oumarbarry/better-auth-py/compare/v0.5.1...HEAD
[0.5.1]: https://github.com/oumarbarry/better-auth-py/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/oumarbarry/better-auth-py/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/oumarbarry/better-auth-py/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/oumarbarry/better-auth-py/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/oumarbarry/better-auth-py/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/oumarbarry/better-auth-py/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/oumarbarry/better-auth-py/releases/tag/v0.1.0
