---
title: Social providers
---

# Social providers

36 OAuth2/OIDC providers are built in. Every one gets PKCE where the provider
supports it, single-use database-backed state with a signed state cookie,
token refresh, and JWKS or id-token verification where the provider is OIDC.

## Configuring

Two equivalent forms. By instance:

```python
from better_auth import BetterAuth, GitHub, Google

auth = BetterAuth(
    secret=...,
    social_providers={
        "github": GitHub(client_id="…", client_secret="…"),
        "google": Google(client_id="…", client_secret="…"),
    },
)
```

Or name-keyed, resolved against `PROVIDER_REGISTRY`:

```python
auth = BetterAuth(
    secret=...,
    social_providers={
        "gitlab": {"client_id": "…", "client_secret": "…"},
        "slack": {"client_id": "…", "client_secret": "…"},
    },
)
```

::: tip Import path
`GitHub`, `Google` and `Discord` are re-exported at the package root. The other
33 classes live in `better_auth.oauth.providers_ext`:

```python
from better_auth.oauth.providers_ext import Apple, MicrosoftEntraId, Slack
```

The name-keyed form needs no import at all.
:::

## The flow

```bash
curl -s -X POST localhost:8000/api/auth/sign-in/social \
  -H 'content-type: application/json' \
  -d '{"provider": "github", "callbackURL": "/dashboard"}'
```

```json
{
  "url": "https://github.com/login/oauth/authorize?…",
  "redirect": true
}
```

Send the browser to `url`. The provider comes back to
`{base_url}/api/auth/callback/{provider}`, which sets the session cookie and
redirects to `callbackURL`. Every `callbackURL` is validated against
`base_url` and `trusted_origins`, so it cannot be turned into an open redirect.

The redirect URI you register with the provider is
`{base_url}{base_path}/callback/{provider_id}`, for example
`https://example.com/api/auth/callback/github`. Override it with
`redirect_uri=` when the provider insists on something else.

## The 36 providers

Each page covers endpoints, real dataclass options, default scopes, and
per-provider quirks:

- [Apple](/providers/apple)
- [Atlassian](/providers/atlassian)
- [Cloudflare](/providers/cloudflare)
- [Amazon Cognito](/providers/cognito)
- [Discord](/providers/discord)
- [Dropbox](/providers/dropbox)
- [Facebook](/providers/facebook)
- [Figma](/providers/figma)
- [GitHub](/providers/github)
- [GitLab](/providers/gitlab)
- [Google](/providers/google)
- [Hugging Face](/providers/huggingface)
- [Kakao](/providers/kakao)
- [Kick](/providers/kick)
- [LINE](/providers/line)
- [Linear](/providers/linear)
- [LinkedIn](/providers/linkedin)
- [Microsoft Entra ID](/providers/microsoft)
- [Naver](/providers/naver)
- [Notion](/providers/notion)
- [Paybin](/providers/paybin)
- [PayPal](/providers/paypal)
- [Polar](/providers/polar)
- [Railway](/providers/railway)
- [Reddit](/providers/reddit)
- [Roblox](/providers/roblox)
- [Salesforce](/providers/salesforce)
- [Slack](/providers/slack)
- [Spotify](/providers/spotify)
- [TikTok](/providers/tiktok)
- [Twitch](/providers/twitch)
- [Twitter (X)](/providers/twitter)
- [Vercel](/providers/vercel)
- [VK](/providers/vk)
- [WeChat](/providers/wechat)
- [Zoom](/providers/zoom)

The link slug is the registry key: the name you use in `social_providers` and
in the callback path. `better_auth.oauth.PROVIDER_REGISTRY` is the same map at
runtime:

```python
from better_auth.oauth import PROVIDER_REGISTRY

len(PROVIDER_REGISTRY)   # 36
```

## Per-provider options

Every provider inherits the same option surface (`ProviderConfig`):

```python
from better_auth import GitHub

GitHub(
    client_id="…",
    client_secret="…",
    scopes=["read:user", "user:email"],
    redirect_uri=None,          # overrides {base_url}{base_path}/callback/{id}
    authorize_params={"prompt": "consent"},  # extra authorize-URL params
    disable_default_scope=False,             # drop the baked-in scopes first
    disable_sign_up=False,                   # never create a user via this provider
    disable_implicit_sign_up=False,          # require requestSignUp:true to register
    override_user_info_on_sign_in=False,     # re-sync the profile on every sign-in
    authentication="post",                   # or "basic" for the token endpoint
    token_endpoint_auth=None,                # explicit client auth, wins over the above
    require_email_verification=False,        # no session while the email is unverified
    allow_idp_initiated=False,               # accept a callback that has no state
)
```

| Option | Default | What it does |
| --- | --- | --- |
| `require_email_verification` | `False` | A user whose email is unverified gets no session. The callback redirects with `error=email_not_verified` (ID token sign-in answers `403 EMAIL_NOT_VERIFIED`), and a verification email goes out on sign-up (and on sign-in with `send_on_sign_in`) when `send_verification_email` is set. |
| `allow_idp_initiated` | `False` | A callback that carries a `code` but no `state` (sign-in started from the provider's side) restarts the flow with fresh state and PKCE instead of failing with `state_not_found`. |
| `token_endpoint_auth` | `None` | A `TokenEndpointAuth` for token and refresh requests. Methods: `"client_secret_basic"`, `"client_secret_post"`, `"none"`, `"private_key_jwt"` (needs `get_client_assertion`) and `"custom"` (needs `customize_request`). `None` falls back to `authentication`. |

`TokenEndpointAuth` and the assertion helper live in `better_auth.oauth.machinery`.
For `private_key_jwt`, `create_private_key_jwt_client_assertion_getter` signs a
fresh RFC 7523 assertion for each request from a JWK or a PEM key:

```python
from better_auth.oauth.machinery import (
    TokenEndpointAuth,
    create_private_key_jwt_client_assertion_getter,
)

auth_method = TokenEndpointAuth(
    "private_key_jwt",
    get_client_assertion=create_private_key_jwt_client_assertion_getter(
        private_key_pem=PEM, kid="key-1"
    ),
)
```

A client secret cannot be combined with `private_key_jwt` or `none`.

### Per-request parameters

`POST /sign-in/social` and `POST /link-social` also accept:

- `loginHint`: sent as `login_hint` by providers that support it.
- `additionalParams`: an object of string values added to the authorize URL. They
  win over the provider's `authorize_params`. The framework-owned parameters
  `state`, `client_id`, `redirect_uri`, `response_type`, `code_challenge`,
  `code_challenge_method`, `nonce` and `scope` are refused with a
  `400 VALIDATION_ERROR`. A few providers keep their own required values (Notion
  `owner`, Atlassian `audience`, TikTok `client_key`, WeChat `appid`).

Reserved parameters cannot be overridden through `authorize_params` either: they
are dropped from the URL. On token refresh, extra parameters never replace
`grant_type` or `refresh_token`.

::: warning Changed in 1.1
Several behaviors changed for every provider. See
[Upgrade from 1.0](/migrate/from-1-0).

- ID tokens go through one shared verifier: signature against the provider JWKS
  (every key with the token's `kid` is tried), issuer, audience, nonce, and the
  provider's algorithm and maximum age rules.
- New users of providers that return no email (Reddit, Roblox, TikTok, Twitter,
  WeChat) get a placeholder email `<id>@<provider>.placeholder.invalid`, for
  example `12345@reddit.placeholder.invalid`. Existing users keep their stored email.
- A provider response with an empty account id is refused with
  `unable_to_get_user_info` (`401 FAILED_TO_GET_USER_INFO` for ID token sign-in).
:::

To refuse an OAuth sign-up, account link or returning sign-in from your own code
(an email domain rule, say), set `validate_user_info` on the user options. See
[Configuration](/guide/configuration).

## A custom provider

Anything not in the registry is one dataclass:

```python
from better_auth import OAuthProvider

okta = OAuthProvider(
    client_id="…",
    client_secret="…",
    provider_id="okta",
    authorization_endpoint="https://your-org.okta.com/oauth2/v1/authorize",
    token_endpoint="https://your-org.okta.com/oauth2/v1/token",
    userinfo_endpoint="https://your-org.okta.com/oauth2/v1/userinfo",
    scopes=["openid", "email", "profile"],
    use_pkce=True,
)

auth = BetterAuth(secret=..., social_providers={"okta": okta})
```

`OAuthProvider` is an alias of `ProviderConfig`. The default `fetch_user()`
expects an OIDC-shaped userinfo payload (`sub`, `email`, `email_verified`,
`name`, `picture`). For a provider whose payload differs, either supply a
`profile_mapper`, or subclass and override `fetch_user()`. The GitHub and
Discord sources are the two worked examples in the codebase.

For a provider you would rather configure at runtime than as a class (from a
database row, say), use the [Generic OAuth plugin](/plugins/generic-oauth),
which also supports OIDC discovery URLs.

## Account linking

A social sign-in whose verified email matches an existing user links to that
user instead of creating a second one. This is guarded:
`AccountLinking(require_local_email_verified=True)` is the default, and
`trusted_providers` controls which providers may link at all.

```python
from better_auth import AccountLinking, AccountOptions

AccountOptions(
    encrypt_oauth_tokens=True,
    account_linking=AccountLinking(
        enabled=True,
        trusted_providers=["github", "google"],
        allow_different_emails=False,
    ),
)
```

`/link-social`, `/list-accounts`, `/unlink-account` and `/account-info` manage
links for an already-signed-in user. `allow_unlinking_all=False` (the default)
stops a user from removing their last credential.
