# Plugins

All 26 first-party plugins live in `better_auth.plugins_ext` (the `plugins_ext` name is
deliberate — `better_auth.plugins` is the plugin *framework*). Pass instances via
`plugins=[...]`:

```python
from better_auth import BetterAuth
from better_auth.plugins_ext import TwoFactorPlugin, UsernamePlugin

auth = BetterAuth(secret=..., plugins=[UsernamePlugin(), TwoFactorPlugin(issuer="Example")])
```

Every constructor takes **keyword arguments in snake_case**, mirroring the TypeScript
option object one-for-one with the same defaults. Plugins add routes and, for some, extra
tables — `BetterAuth` merges those into `auth.schema`, so `adapter.create_tables()` (or
your migration) must run *after* the plugins are registered.

## Sign-in methods

### `UsernamePlugin` — `username`

Adds `/sign-in/username` and username/displayUsername columns on `user`, with length
bounds, custom validators and normalization (TS `username()`).

```python
UsernamePlugin(min_username_length=3, max_username_length=30)
```

### `MagicLinkPlugin` — `magic-link`

Passwordless email links: `/sign-in/magic-link` sends a token, `/magic-link/verify`
consumes it. `send_magic_link` is required.

```python
MagicLinkPlugin(send_magic_link=send_email, expires_in=300)
```

### `EmailOTPPlugin` — `email-otp`

Numeric codes over email for sign-in, verification, password reset and email change.
`send_verification_otp` is required; `store_otp` can be `"plain"`, `"hashed"` or an
encryption config.

```python
EmailOTPPlugin(
    send_verification_otp=send_email, otp_length=6, expires_in=300, allowed_attempts=3
)
```

### `PhoneNumberPlugin` — `phone-number`

SMS OTP sign-in, phone verification and phone-based password reset. `send_otp` is
required in practice (endpoints answer `SEND_OTP_NOT_IMPLEMENTED` 501 without it).

```python
PhoneNumberPlugin(send_otp=send_sms, otp_length=6, require_verification=True)
```

### `PasskeyPlugin` — `passkey` (extra: `passkey`)

WebAuthn registration and authentication; adds the `passkey` table. Needs the `passkey`
extra (`webauthn`) — importing `plugins_ext` without it raises `ModuleNotFoundError`.

```python
PasskeyPlugin(rp_id="example.com", rp_name="Example", origin="https://example.com")
```

### `AnonymousPlugin` — `anonymous`

Creates throwaway users so a guest can hold a session, then links their data on real
sign-up via `on_link_account`.

```python
AnonymousPlugin(email_domain_name="example.com")
```

### `SiwePlugin` — `siwe`

Sign-In with Ethereum; adds the `walletAddress` table. You supply `get_nonce` and
`verify_message` (the signature check is yours — the plugin does not bundle a web3 lib).

```python
SiwePlugin(domain="example.com", get_nonce=make_nonce, verify_message=verify_siwe)
```

### `OneTapPlugin` — `one-tap`

Verifies a Google One Tap ID token and issues a session.

```python
OneTapPlugin(client_id="...apps.googleusercontent.com")
```

## Multi-tenant and authorization

### `AdminPlugin` — `admin`

User administration: list/ban/unban, impersonation, role management, session revocation —
gated by `admin_roles` or `admin_user_ids`.

```python
AdminPlugin(default_role="user", admin_roles=["admin"], admin_user_ids=["usr_1"])
```

### `OrganizationPlugin` — `organization`

Organizations, members, invitations, teams and dynamic access control. Adds the
`organization`, `member` and `invitation` tables. Roles are built from an access-control
statement set.

```python
from better_auth.access_control import create_access_control

ac = create_access_control({"project": ["create", "share", "update", "delete"]})

OrganizationPlugin(
    ac=ac,
    roles={"admin": ac.new_role({"project": ["create", "update", "delete"]})},
    creator_role="owner",
    membership_limit=100,
    send_invitation_email=send_email,
)
```

## Machine and token access

### `ApiKeyPlugin` — `api-key`

Long-lived API keys with hashing, prefixes, metadata, per-key rate limits and
permissions; adds the `apikey` table. Config is a **dict** (or a list of dicts, each with
a `config_id`), not kwargs. This port supports `storage="database"` only.

```python
ApiKeyPlugin({"default_key_length": 64, "default_prefix": "sk_", "enable_metadata": True})
```

### `BearerPlugin` — `bearer`

Adds the response-side `set-auth-token` header. Reading `Authorization: Bearer` is already
built into the core session layer here (it is a plugin in TypeScript), so you only need
this plugin for the header — or `require_signature=True` to demand signed tokens.

```python
BearerPlugin(require_signature=False)
```

### `JWTPlugin` — `jwt`

Issues JWTs for your session and publishes a JWKS at `jwks_path`; adds the `jwks` table.
Private keys are encrypted at rest unless `disable_private_key_encryption=True`.

```python
JWTPlugin(jwks_path="/jwks", expiration_time="15m", issuer="https://api.example.com")
```

### `OAuthProviderPlugin` — `oauth-provider`

Turns your server into an OAuth 2.1 / OIDC **authorization server** (auth code + PKCE,
refresh, client credentials, dynamic client registration, consent). Adds `oauthClient`,
`oauthConsent`, `oauthAccessToken` and `oauthRefreshToken`.
**Requires `JWTPlugin` alongside it** — without it, construction raises
`ValueError: oauth-provider requires the jwt plugin to be installed`.

```python
plugins=[
    JWTPlugin(),
    OAuthProviderPlugin(
        login_page="/login", consent_page="/consent", allow_dynamic_client_registration=True
    ),
]
```

### `DeviceAuthorizationPlugin` — `device-authorization`

RFC 8628 device flow for TVs and CLIs; adds the `deviceCode` table. Durations are
duration strings.

```python
DeviceAuthorizationPlugin(expires_in="30m", interval="5s")
```

### `OneTimeTokenPlugin` — `one-time-token`

Short-lived single-use tokens to hand a session across contexts (SSR handoff, desktop app
callback).

```python
OneTimeTokenPlugin(expires_in=3)  # seconds
```

## Federation

### `SSOPlugin` — `sso` (extra: `sso` for domain verification)

OIDC single sign-on per domain or organization; adds the `ssoProvider` table.
Domain-verification via DNS TXT needs the `sso` extra (`dnspython`). SAML is out of scope
in this port.

```python
SSOPlugin(provision_user_on_every_login=False, trust_email_verified=False)
```

### `GenericOAuthPlugin` — `generic-oauth`

Any OAuth2/OIDC provider configured at runtime, by discovery URL or explicit endpoints.
Config entries are `GenericOAuthConfig` dataclasses.

```python
from better_auth.plugins_ext.generic_oauth import GenericOAuthConfig

GenericOAuthPlugin(
    config=[
        GenericOAuthConfig(
            provider_id="keycloak",
            client_id="my-client",
            client_secret="my-secret",
            discovery_url="https://sso.example.com/realms/main/.well-known/openid-configuration",
            scopes=["openid", "email", "profile"],
            pkce=True,
        )
    ]
)
```

### `OAuthProxyPlugin` — `oauth-proxy`

Routes social-OAuth callbacks through one production deployment so preview URLs work with
a single registered redirect URI.

```python
OAuthProxyPlugin(production_url="https://example.com")
```

### `OAuthPopupPlugin` — `oauth-popup`

Swaps the OAuth callback redirect for a page that posts the session token back to the
opener window. Takes no options; pair with `BearerPlugin`.

```python
OAuthPopupPlugin()
```

## Sessions

### `MultiSessionPlugin` — `multi-session`

Keeps several accounts signed in at once (device sessions) with a cap.

```python
MultiSessionPlugin(maximum_sessions=5)
```

### `CustomSessionPlugin` — `custom-session`

Overrides `GET /get-session` to reshape the payload — join a role, an organization, a
plan. The callable receives and returns the session dict.

```python
CustomSessionPlugin(lambda session: {**session, "role": "user"})
```

### `LastLoginMethodPlugin` — `last-login-method`

Remembers how the user last signed in, in a cookie and optionally on the `user` row, so
the login page can highlight it.

```python
LastLoginMethodPlugin(store_in_database=True)
```

## Hardening

### `TwoFactorPlugin` — `two-factor`

TOTP, email/SMS OTP, backup codes, trusted devices and account lockout; adds the
`twoFactor` table. Sub-options are snake_case dicts mirroring the TS option groups.

```python
TwoFactorPlugin(
    issuer="Example",
    totp_options={"digits": 6, "period": 30},
    backup_code_options={"amount": 10, "length": 10},
)
```

### `HaveIBeenPwnedPlugin` — `have-i-been-pwned`

Rejects breached passwords via the HIBP k-anonymity range API on every password-hashing
path (sign-up, reset, change).

```python
HaveIBeenPwnedPlugin(custom_password_compromised_message="This password has been leaked.")
```

### `CaptchaPlugin` — `captcha`

Gates chosen endpoints behind Cloudflare Turnstile, Google reCAPTCHA, hCaptcha or
CaptchaFox.

```python
CaptchaPlugin(
    provider="cloudflare-turnstile",
    secret_key=os.environ["TURNSTILE_SECRET"],
    endpoints=["/sign-up/email", "/sign-in/email"],
)
```

## Writing your own

```python
from better_auth import AuthResponse, Plugin


class Audit(Plugin):
    id = "audit"
    schema = {"auditLog": {}}  # extra tables, migrated like the core ones

    def routes(self):
        return [("POST", "/audit/list", self.list_events)]

    async def list_events(self, ctx):
        result = await ctx.require_session()
        return {"events": [], "userId": result["user"]["id"]}

    async def before(self, ctx):  # runs before every endpoint
        return None  # or AuthResponse(...) to short-circuit
```
