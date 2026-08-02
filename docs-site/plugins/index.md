---
title: Plugins
---

# Plugins

26 plugins ship with the package under `better_auth.plugins_ext`. Each one is a
class; pass instances to `BetterAuth(plugins=[...])`.

```python
from better_auth.plugins_ext import OrganizationPlugin, TwoFactorPlugin

auth = BetterAuth(secret=..., plugins=[TwoFactorPlugin(issuer="Example"), OrganizationPlugin()])
```

Plugins add routes under `base_path`, extend the database schema (their tables
migrate exactly like the core ones), and hook the request pipeline. Every
constructor option below mirrors the TypeScript option of the same name in
snake_case, with the same default. `better_auth.plugins_ext.__all__` is the
authoritative list.

<ul class="ba-index">
<li><a href="#admin">admin</a></li>
<li><a href="#organization">organization</a></li>
<li><a href="#two-factor">two-factor</a></li>
<li><a href="#passkey">passkey</a></li>
<li><a href="#email-otp">email-otp</a></li>
<li><a href="#magic-link">magic-link</a></li>
<li><a href="#phone-number">phone-number</a></li>
<li><a href="#username">username</a></li>
<li><a href="#anonymous">anonymous</a></li>
<li><a href="#siwe">siwe</a></li>
<li><a href="#one-tap">one-tap</a></li>
<li><a href="#api-key">api-key</a></li>
<li><a href="#jwt">jwt</a></li>
<li><a href="#bearer">bearer</a></li>
<li><a href="#one-time-token">one-time-token</a></li>
<li><a href="#oauth-provider">oauth-provider</a></li>
<li><a href="#device-authorization">device-authorization</a></li>
<li><a href="#sso">sso</a></li>
<li><a href="#generic-oauth">generic-oauth</a></li>
<li><a href="#oauth-proxy">oauth-proxy</a></li>
<li><a href="#oauth-popup">oauth-popup</a></li>
<li><a href="#multi-session">multi-session</a></li>
<li><a href="#custom-session">custom-session</a></li>
<li><a href="#last-login-method">last-login-method</a></li>
<li><a href="#captcha">captcha</a></li>
<li><a href="#have-i-been-pwned">have-i-been-pwned</a></li>
</ul>

## Access control

<div class="ba-card">

### admin <span class="ba-id ignore-header">AdminPlugin</span> {#admin}

User administration: roles and permissions, ban and unban, impersonation,
session management, setting a user's password or email, and permission checks.
Adds 15 routes under `/admin/`.

```python
from better_auth.plugins_ext import AdminPlugin

AdminPlugin(
    default_role="user",
    admin_roles=["admin"],
    impersonation_session_duration=3600,
    allow_impersonating_admins=False,
)
```

</div>

<div class="ba-card">

### organization <span class="ba-id ignore-header">OrganizationPlugin</span> {#organization}

Organizations, members, invitations, teams, and dynamic access control. The
largest plugin in the set: 20 routes under `/organization/`, covering creation,
slug checks, membership, roles, invitations and team management.

```python
from better_auth.plugins_ext import OrganizationPlugin

OrganizationPlugin(
    creator_role="owner",
    membership_limit=100,
    invitation_expires_in=172800,          # 2 days
    invitation_limit=100,
    allow_user_to_create_organization=True,
    cancel_pending_invitations_on_re_invite=False,
)
```

</div>

## Sign-in methods

<div class="ba-card">

### two-factor <span class="ba-id ignore-header">TwoFactorPlugin</span> {#two-factor}

TOTP, email OTP and backup codes as a second factor, with a short-lived
two-factor cookie between the password step and the code step, trusted devices,
and optional account lockout. Adds 8 routes under `/two-factor/`.

```python
from better_auth.plugins_ext import TwoFactorPlugin

TwoFactorPlugin(
    issuer="Example",                       # shown in the authenticator app
    skip_verification_on_enable=False,
    two_factor_cookie_max_age=600,
    trust_device_max_age=2592000,           # 30 days
    totp_options={"digits": 6, "period": 30},
    backup_code_options={"amount": 10},
)
```

</div>

<div class="ba-card">

### passkey <span class="ba-id ignore-header">PasskeyPlugin</span> {#passkey}

WebAuthn/FIDO2 registration and authentication — Touch ID, Windows Hello,
hardware keys. Requires the `passkey` extra (`webauthn`). Adds 7 routes under
`/passkey/`.

```python
from better_auth.plugins_ext import PasskeyPlugin

PasskeyPlugin(
    rp_id="example.com",                    # the registrable domain, no scheme
    rp_name="Example",
    origin="https://example.com",
    authenticator_selection={"residentKey": "preferred", "userVerification": "preferred"},
)
```

</div>

<div class="ba-card">

### email-otp <span class="ba-id ignore-header">EmailOTPPlugin</span> {#email-otp}

One-time codes by email for sign-in, verification, email change and password
reset — nine routes under `/email-otp/`. Codes can be stored hashed, and the
send endpoint is origin-checked so a cookieless cross-origin POST cannot mail a
code to an arbitrary address.

```python
from better_auth.plugins_ext import EmailOTPPlugin

EmailOTPPlugin(
    send_verification_otp=send_otp,         # (email, otp, type) -> None
    otp_length=6,
    expires_in=300,
    allowed_attempts=3,
    store_otp="plain",                      # or "hashed"
)
```

</div>

<div class="ba-card">

### magic-link <span class="ba-id ignore-header">MagicLinkPlugin</span> {#magic-link}

Passwordless sign-in through a single-use link. Adds `/sign-in/magic-link` and
`/magic-link/verify`.

```python
from better_auth.plugins_ext import MagicLinkPlugin

MagicLinkPlugin(
    send_magic_link=send_link,              # (email, url, token, request) -> None
    expires_in=300,
    disable_sign_up=False,
    store_token="plain",                    # or "hashed"
)
```

</div>

<div class="ba-card">

### phone-number <span class="ba-id ignore-header">PhoneNumberPlugin</span> {#phone-number}

SMS one-time codes for sign-in, phone verification and password reset. Adds 5
routes, including `/sign-in/phone-number`.

```python
from better_auth.plugins_ext import PhoneNumberPlugin

PhoneNumberPlugin(
    send_otp=send_sms,                      # (phone_number, code) -> None
    otp_length=6,
    expires_in=300,
    allowed_attempts=3,
    require_verification=False,
)
```

</div>

<div class="ba-card">

### username <span class="ba-id ignore-header">UsernamePlugin</span> {#username}

Adds `username` and `displayUsername` to the user model, `/sign-in/username`,
and `/is-username-available`, with configurable validation and normalisation.

```python
from better_auth.plugins_ext import UsernamePlugin

UsernamePlugin(
    min_username_length=3,
    max_username_length=30,
    username_validator=None,                # (username) -> bool
)
```

</div>

<div class="ba-card">

### anonymous <span class="ba-id ignore-header">AnonymousPlugin</span> {#anonymous}

A throwaway user and session for visitors who have not signed up. When the same
visitor later authenticates for real, the anonymous account is linked and
cleaned up.

```python
from better_auth.plugins_ext import AnonymousPlugin

AnonymousPlugin(
    email_domain_name="example.com",        # domain for the generated address
    disable_delete_anonymous_user=False,
    on_link_account=None,                   # ({anonymousUser, newUser}) -> None
)
```

</div>

<div class="ba-card">

### siwe <span class="ba-id ignore-header">SiwePlugin</span> {#siwe}

Sign-In with Ethereum (ERC-4361). You supply nonce generation and signature
verification — the plugin owns the session half. Adds `/siwe/nonce` and
`/siwe/verify`.

```python
from better_auth.plugins_ext import SiwePlugin

SiwePlugin(
    domain="example.com",
    get_nonce=generate_nonce,               # () -> str
    verify_message=verify_signature,        # ({message, signature, address, ...}) -> bool
    anonymous=True,
)
```

</div>

<div class="ba-card">

### one-tap <span class="ba-id ignore-header">OneTapPlugin</span> {#one-tap}

Google One Tap: the browser posts an id token to `/one-tap/callback` and gets a
session back. Honours the registered Google provider's `disable_sign_up`.

```python
from better_auth.plugins_ext import OneTapPlugin

OneTapPlugin(client_id="….apps.googleusercontent.com", disable_signup=False)
```

</div>

## Tokens and keys

<div class="ba-card">

### api-key <span class="ba-id ignore-header">ApiKeyPlugin</span> {#api-key}

Long-lived API keys backed by the database: create, list, update, delete and
verify, with prefixes, expiry windows, per-key rate limits, metadata and
permissions. Adds 5 routes under `/api-key/`.

```python
from better_auth.plugins_ext import ApiKeyPlugin

ApiKeyPlugin({
    "default_prefix": "ba_",
    "default_key_length": 64,
    "enable_metadata": True,
    "rate_limit": {"enabled": True, "max_requests": 10},
})
```

</div>

<div class="ba-card">

### jwt <span class="ba-id ignore-header">JWTPlugin</span> {#jwt}

Issues signed JWTs for the current session and publishes a JWKS so other
services can verify them without calling back. EdDSA by default; the full
`ES256`/`ES512`/`PS256`/`RS256`/`HS256` union is supported. Adds `/token` and
`/jwks`.

```python
from better_auth.plugins_ext import JWTPlugin

JWTPlugin(
    expiration_time="15m",
    jwks_path="/jwks",
    issuer=None,                            # defaults to base_url
    audience=None,
    disable_private_key_encryption=False,
)
```

</div>

<div class="ba-card">

### bearer <span class="ba-id ignore-header">BearerPlugin</span> {#bearer}

Echoes the session token back on a `set-auth-token` response header. Reading
`Authorization: Bearer …` is already built into the core session layer, so this
plugin is only needed for the response side.

```python
from better_auth.plugins_ext import BearerPlugin

BearerPlugin(require_signature=False)
```

</div>

<div class="ba-card">

### one-time-token <span class="ba-id ignore-header">OneTimeTokenPlugin</span> {#one-time-token}

Mints a short-lived, single-use token from an existing session and exchanges it
back for that session — the standard cross-domain handoff. Adds
`/one-time-token/generate` and `/one-time-token/verify`.

```python
from better_auth.plugins_ext import OneTimeTokenPlugin

OneTimeTokenPlugin(
    expires_in=3,                           # minutes
    disable_client_request=False,
    store_token="plain",                    # or "hashed"
)
```

</div>

## Being an OAuth server

<div class="ba-card">

### oauth-provider <span class="ba-id ignore-header">OAuthProviderPlugin</span> {#oauth-provider}

Turns your app into an OAuth 2.1 / OIDC authorization server: client
registration and management, discovery, JWKS, authorize and consent, every
token grant, introspection, userinfo, revocation and end-session. 21 routes,
covering RFC 6749, 7009, 7636 and 7662.

```python
from better_auth.plugins_ext import OAuthProviderPlugin

OAuthProviderPlugin(
    scopes=["openid", "profile", "email"],
    code_expires_in=600,
    access_token_expires_in=3600,
    refresh_token_expires_in=2592000,
    allow_dynamic_client_registration=False,
)
```

</div>

<div class="ba-card">

### device-authorization <span class="ba-id ignore-header">DeviceAuthorizationPlugin</span> {#device-authorization}

The OAuth 2.0 Device Authorization Grant (RFC 8628) — the "enter this code on
another device" flow for TVs and CLIs. Adds 5 routes under `/device`.

```python
from better_auth.plugins_ext import DeviceAuthorizationPlugin

DeviceAuthorizationPlugin(
    expires_in="30m",
    interval="5s",
    user_code_length=8,
    device_code_length=40,
)
```

</div>

## Federating outward

<div class="ba-card">

### sso <span class="ba-id ignore-header">SSOPlugin</span> {#sso}

OIDC federation: register identity providers per domain or organisation and
route `/sign-in/sso` to the right one, with optional DNS TXT domain
verification (needs the `sso` extra) and user provisioning. 8 routes. SAML is
out of scope.

```python
from better_auth.plugins_ext import SSOPlugin

SSOPlugin(
    provision_user=provision,                # (payload) -> None
    provision_user_on_every_login=False,
    trust_email_verified=False,
    disable_implicit_sign_up=False,
)
```

</div>

<div class="ba-card">

### generic-oauth <span class="ba-id ignore-header">GenericOAuthPlugin</span> {#generic-oauth}

Any OAuth2/OIDC provider that is not in the registry, configured at runtime
rather than as a class — point it at a discovery URL or spell out the three
endpoints. Adds `/sign-in/oauth2`, `/oauth2/callback/{providerId}` and
`/oauth2/link`.

```python
from better_auth.plugins_ext import GenericOAuthPlugin
from better_auth.plugins_ext.generic_oauth import GenericOAuthConfig

GenericOAuthPlugin(config=[
    GenericOAuthConfig(
        provider_id="okta",
        client_id="…",
        client_secret="…",
        discovery_url="https://your-org.okta.com/.well-known/openid-configuration",
        scopes=["openid", "email", "profile"],
        pkce=True,
    ),
])
```

</div>

<div class="ba-card">

### oauth-proxy <span class="ba-id ignore-header">OAuthProxyPlugin</span> {#oauth-proxy}

Lets preview and branch deployments finish a social login against the one
redirect URI registered with the provider, by proxying the callback through
production.

```python
from better_auth.plugins_ext import OAuthProxyPlugin

OAuthProxyPlugin(production_url="https://example.com", max_age=60)
```

</div>

<div class="ba-card">

### oauth-popup <span class="ba-id ignore-header">OAuthPopupPlugin</span> {#oauth-popup}

Runs social sign-in in a popup: the callback renders a page that posts the
session token back to the opener instead of redirecting. Takes no options;
pair it with `BearerPlugin`.

```python
from better_auth.plugins_ext import BearerPlugin, OAuthPopupPlugin

plugins = [OAuthPopupPlugin(), BearerPlugin()]
```

</div>

## Session shaping

<div class="ba-card">

### multi-session <span class="ba-id ignore-header">MultiSessionPlugin</span> {#multi-session}

Several accounts signed in at once, each with its own cookie, plus endpoints to
list, switch and revoke device sessions.

```python
from better_auth.plugins_ext import MultiSessionPlugin

MultiSessionPlugin(maximum_sessions=5)
```

</div>

<div class="ba-card">

### custom-session <span class="ba-id ignore-header">CustomSessionPlugin</span> {#custom-session}

Wraps `GET /get-session` so you can reshape or enrich what clients receive —
joining a subscription, a role, a tenant.

```python
from better_auth.plugins_ext import CustomSessionPlugin

async def with_plan(session, ctx):
    return {**session, "plan": await lookup_plan(session["user"]["id"])}

CustomSessionPlugin(with_plan)
```

</div>

<div class="ba-card">

### last-login-method <span class="ba-id ignore-header">LastLoginMethodPlugin</span> {#last-login-method}

Records which method was used on the most recent successful sign-in, in a
cookie and optionally in the database — the "you last signed in with GitHub"
hint. `before_store_cookie` gates the cookie for consent purposes.

```python
from better_auth.plugins_ext import LastLoginMethodPlugin

LastLoginMethodPlugin(
    cookie_name="better-auth.last_used_login_method",
    max_age=2592000,
    store_in_database=True,
)
```

</div>

## Abuse prevention

<div class="ba-card">

### captcha <span class="ba-id ignore-header">CaptchaPlugin</span> {#captcha}

Verifies an `x-captcha-response` header against a CAPTCHA provider before the
protected sign-up and sign-in endpoints run.

```python
from better_auth.plugins_ext import CaptchaPlugin

CaptchaPlugin(
    provider="cloudflare-turnstile",
    secret_key=os.environ["TURNSTILE_SECRET"],
    endpoints=["/sign-up/email", "/sign-in/email"],
    min_score=0.5,
)
```

</div>

<div class="ba-card">

### have-i-been-pwned <span class="ba-id ignore-header">HaveIBeenPwnedPlugin</span> {#have-i-been-pwned}

Rejects passwords found in the Have I Been Pwned breach corpus, using a
k-anonymity range query so the password never leaves your server. Runs before
hashing.

```python
from better_auth.plugins_ext import HaveIBeenPwnedPlugin

HaveIBeenPwnedPlugin(
    custom_password_compromised_message="Please choose a different password.",
    enabled=True,
)
```

</div>

## Writing your own

Everything above uses the same public surface your plugin has — see
[Core concepts](/guide/concepts#plugins).
