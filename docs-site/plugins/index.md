---
title: Plugins
---

# Plugins

26 plugins ship with the package under `better_auth.plugins_ext`. Each one is a
class; pass instances to `BetterAuth(plugins=[...])`.

```python
from better_auth import BetterAuth
from better_auth.plugins_ext import OrganizationPlugin, TwoFactorPlugin

auth = BetterAuth(
    secret="a-strong-32-character-minimum-secret",
    plugins=[TwoFactorPlugin(issuer="Example"), OrganizationPlugin()],
)
```

Plugins add routes under `base_path`, extend the database schema (their tables
migrate exactly like the core ones), and hook the request pipeline. Every
constructor option mirrors the TypeScript option of the same name in
snake_case, with the same default. `better_auth.plugins_ext.__all__` is the
authoritative list. Each plugin has its own page:

## Sign-in methods

- [Username](./username) — sign in with a username instead of an email
- [Magic Link](./magic-link) — passwordless sign-in through a single-use link
- [Email OTP](./email-otp) — one-time codes by email
- [Phone Number](./phone-number) — SMS one-time codes
- [Passkey (WebAuthn)](./passkey) — WebAuthn/FIDO2
- [Anonymous](./anonymous) — throwaway guest users, linked on real sign-up
- [Sign-In with Ethereum](./siwe) — SIWE (ERC-4361) wallet authentication
- [Google One Tap](./one-tap) — sign in from Google's One Tap prompt
- [Two-Factor Authentication](./two-factor) — TOTP, OTP and backup codes as a second factor

## Organizations and access control

- [Admin](./admin) — user administration, bans, impersonation
- [Organization](./organization) — organizations, members, invitations, teams

## Tokens and keys

- [API Key](./api-key) — long-lived database-backed API keys
- [JWT](./jwt) — signed JWTs plus a published JWKS
- [Bearer Token](./bearer) — the `set-auth-token` response header
- [One-Time Token](./one-time-token) — single-use session handoff tokens

## Being an OAuth server

- [OAuth Provider](./oauth-provider) — a full OAuth 2.1 / OIDC authorization server
- [Device Authorization](./device-authorization) — the RFC 8628 device flow

## Federating outward

- [SSO (OIDC)](./sso) — OIDC identity providers per domain or organization
- [Generic OAuth](./generic-oauth) — any OAuth2/OIDC provider, configured at runtime
- [OAuth Proxy](./oauth-proxy) — social login from preview deployments
- [OAuth Popup](./oauth-popup) — social sign-in in a popup window

## Session shaping

- [Multi-Session](./multi-session) — several accounts signed in at once
- [Custom Session](./custom-session) — reshape the `/get-session` payload
- [Last Login Method](./last-login-method) — the "you last signed in with…" hint

## Abuse prevention

- [Captcha](./captcha) — CAPTCHA checks before protected endpoints
- [Have I Been Pwned](./have-i-been-pwned) — reject breached passwords

## Writing your own

Everything above uses the same public surface your plugin has — see
[Core concepts](/guide/concepts#plugins).
