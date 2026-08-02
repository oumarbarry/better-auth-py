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

## The registry

Key is the name you use in `social_providers` and in the callback path.

| Key | Class | Default scopes | Notes |
| --- | --- | --- | --- |
| `apple` | `Apple` | `email name` | PKCE · id-token |
| `atlassian` | `Atlassian` | `read:jira-user offline_access` | PKCE |
| `cognito` | `Cognito` | `openid profile email` | PKCE · id-token · needs `domain`, `region`, `user_pool_id` |
| `discord` | `Discord` | `identify email` | |
| `dropbox` | `Dropbox` | `account_info.read` | PKCE |
| `facebook` | `Facebook` | `email public_profile` | id-token |
| `figma` | `Figma` | `current_user:read` | PKCE |
| `github` | `GitHub` | `read:user user:email` | |
| `gitlab` | `Gitlab` | `read_user` | PKCE |
| `google` | `Google` | `openid email profile` | PKCE · nonce · id-token |
| `huggingface` | `Huggingface` | `openid profile email` | PKCE |
| `kakao` | `Kakao` | `account_email profile_image profile_nickname` | |
| `kick` | `Kick` | `user:read` | PKCE |
| `line` | `Line` | `openid profile email` | PKCE |
| `linear` | `Linear` | `read` | |
| `linkedin` | `LinkedIn` | `profile email openid` | |
| `microsoft` | `MicrosoftEntraId` | `openid profile email User.Read offline_access` | PKCE · id-token · `tenant_id` (default `common`) |
| `naver` | `Naver` | `profile email` | |
| `notion` | `Notion` | — | |
| `paybin` | `Paybin` | `openid email profile` | PKCE |
| `paypal` | `Paypal` | — | PKCE · id-token |
| `polar` | `Polar` | `openid profile email` | PKCE |
| `railway` | `Railway` | `openid email profile` | PKCE |
| `reddit` | `Reddit` | `identity` | |
| `roblox` | `Roblox` | `openid profile` | |
| `salesforce` | `Salesforce` | `openid email profile` | PKCE |
| `slack` | `Slack` | `openid profile email` | |
| `spotify` | `Spotify` | `user-read-email` | PKCE |
| `tiktok` | `TikTok` | `user.info.profile` | |
| `twitch` | `Twitch` | `user:read:email openid` | |
| `twitter` | `Twitter` | `users.read tweet.read offline.access users.email` | PKCE |
| `vercel` | `Vercel` | — | PKCE |
| `vk` | `VK` | `email phone` | PKCE |
| `wechat` | `WeChat` | `snsapi_login` | comma-joined scopes · `lang` |
| `zoom` | `Zoom` | — | PKCE |

`better_auth.oauth.PROVIDER_REGISTRY` is the same map at runtime:

```python
from better_auth.oauth import PROVIDER_REGISTRY

len(PROVIDER_REGISTRY)   # 35
```

### Providers that need more than a client id

```python
from better_auth.oauth.providers_ext import Cognito, MicrosoftEntraId

social_providers = {
    "cognito": Cognito(
        client_id="…", client_secret="…",
        domain="your-domain", region="eu-west-1", user_pool_id="eu-west-1_XXXX",
    ),
    "microsoft": MicrosoftEntraId(client_id="…", client_secret="…", tenant_id="common"),
}
```

Cognito raises at construction if `domain`, `region` or `user_pool_id` is
missing, rather than failing on the first sign-in.

## Per-provider options

Every provider inherits the same option surface (`ProviderConfig`):

```python
from better_auth import GitHub

GitHub(
    client_id="…",
    client_secret="…",
    scopes=["read:user", "user:email"],
    redirect_uri=None,                       # overrides {base_url}{base_path}/callback/{id}
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
database row, say — use the [`generic-oauth` plugin](/plugins/#generic-oauth),
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
