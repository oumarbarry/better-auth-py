---
title: Social providers
---

# Social providers

35 OAuth2/OIDC providers are built in. Every one gets PKCE where the provider
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
32 classes live in `better_auth.oauth.providers_ext`:

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
{ "url": "https://github.com/login/oauth/authorize?…", "redirect": true }
```

Send the browser to `url`. The provider comes back to
`{base_url}/api/auth/callback/{provider}`, which sets the session cookie and
redirects to `callbackURL`. Every `callbackURL` is validated against
`base_url` and `trusted_origins`, so it cannot be turned into an open redirect.

The redirect URI you register with the provider is
`{base_url}{base_path}/callback/{provider_id}` — for example
`https://example.com/api/auth/callback/github`. Override it with
`redirect_uri=` when the provider insists on something else.

## The 35 providers

One page per provider — endpoints, real dataclass options, default scopes,
and per-provider quirks:

- [Apple](/providers/apple)
- [Atlassian](/providers/atlassian)
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

The link slug is the registry key — the name you use in `social_providers` and
in the callback path. `better_auth.oauth.PROVIDER_REGISTRY` is the same map at
runtime:

```python
from better_auth.oauth import PROVIDER_REGISTRY

len(PROVIDER_REGISTRY)   # 35
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
)
```

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
`profile_mapper`, or subclass and override `fetch_user()` — the GitHub and
Discord sources are the two worked examples in the codebase.

For a provider you would rather configure at runtime than as a class — from a
database row, say — use the [Generic OAuth plugin](/plugins/generic-oauth),
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
