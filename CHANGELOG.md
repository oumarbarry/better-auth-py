# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/oumarbarry/better-auth-py/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/oumarbarry/better-auth-py/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/oumarbarry/better-auth-py/releases/tag/v0.1.0
