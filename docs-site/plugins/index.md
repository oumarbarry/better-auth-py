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

- [username](./username) — sign in with a username instead of an email
- [magic-link](./magic-link) — passwordless sign-in through a single-use link
- [email-otp](./email-otp) — one-time codes by email
- [phone-number](./phone-number) — SMS one-time codes
- [passkey](./passkey) — WebAuthn/FIDO2
- [anonymous](./anonymous) — throwaway guest users, linked on real sign-up
- [siwe](./siwe) — Sign-In with Ethereum
- [one-tap](./one-tap) — Google One Tap
- [two-factor](./two-factor) — TOTP, OTP and backup codes as a second factor

## Organizations and access control

- [admin](./admin) — user administration, bans, impersonation
- [organization](./organization) — organizations, members, invitations, teams

## Tokens and keys

- [api-key](./api-key) — long-lived database-backed API keys
- [jwt](./jwt) — signed JWTs plus a published JWKS
- [bearer](./bearer) — the `set-auth-token` response header
- [one-time-token](./one-time-token) — single-use session handoff tokens

## Being an OAuth server

- [oauth-provider](./oauth-provider) — a full OAuth 2.1 / OIDC authorization server
- [device-authorization](./device-authorization) — the RFC 8628 device flow

## Federating outward

- [sso](./sso) — OIDC identity providers per domain or organization
- [generic-oauth](./generic-oauth) — any OAuth2/OIDC provider, configured at runtime
- [oauth-proxy](./oauth-proxy) — social login from preview deployments
- [oauth-popup](./oauth-popup) — social sign-in in a popup window

## Session shaping

- [multi-session](./multi-session) — several accounts signed in at once
- [custom-session](./custom-session) — reshape the `/get-session` payload
- [last-login-method](./last-login-method) — the "you last signed in with…" hint

## Abuse prevention

- [captcha](./captcha) — CAPTCHA checks before protected endpoints
- [have-i-been-pwned](./have-i-been-pwned) — reject breached passwords

## Writing your own

Everything above uses the same public surface your plugin has — see
[Core concepts](/guide/concepts#plugins).
