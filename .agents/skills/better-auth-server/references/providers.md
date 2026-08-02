# Social providers

35 providers ship built in. Configure them with the `social_providers` mapping on
`BetterAuth`, keyed by the provider **name** (that key becomes the `providerId` stored on
the `account` row and the `/callback/{provider}` path segment).

## Name-keyed config (shortest form)

A plain dict is resolved against `better_auth.oauth.PROVIDER_REGISTRY` and constructed for
you. Keys of the inner dict are the `OAuthProvider` fields in snake_case.

```python
import os

from better_auth import BetterAuth

auth = BetterAuth(
    secret=os.environ["BETTER_AUTH_SECRET"],
    base_url="https://api.example.com",
    social_providers={
        "github": {"client_id": os.environ["GH_ID"], "client_secret": os.environ["GH_SECRET"]},
        "google": {"client_id": os.environ["G_ID"], "client_secret": os.environ["G_SECRET"]},
        "microsoft": {"client_id": os.environ["MS_ID"], "client_secret": os.environ["MS_SECRET"]},
    },
)
```

An unknown key fails loudly at construction:
`ValueError: Unknown social provider 'okta'. Valid names: apple, atlassian, …`

## Instance form (when you need extra options)

```python
from better_auth import BetterAuth, GitHub

auth = BetterAuth(
    secret=...,
    base_url="https://api.example.com",
    social_providers={
        "github": GitHub(
            client_id=os.environ["GH_ID"],
            client_secret=os.environ["GH_SECRET"],
            scopes=["user:email", "read:org"],
            redirect_uri="https://api.example.com/api/auth/callback/github",
        ),
    },
)
```

Mixing forms in one dict is fine. Only `GitHub`, `Google`, `Discord` and `OAuthProvider`
are re-exported at the top level (and from `better_auth.oauth`). The other 32 classes live
in `better_auth.oauth.providers_ext.<module>` (`apple`, `microsoft_entra_id`, `gitlab`, …)
— easiest is to skip the import and use the name-keyed dict, or
`PROVIDER_REGISTRY["apple"](client_id=..., client_secret=...)`.

## The 35 names

Registry key → class (`better_auth.oauth.PROVIDER_REGISTRY`):

| | | | |
|---|---|---|---|
| `apple` → `Apple` | `atlassian` → `Atlassian` | `cognito` → `Cognito` | `discord` → `Discord` |
| `dropbox` → `Dropbox` | `facebook` → `Facebook` | `figma` → `Figma` | `github` → `GitHub` |
| `gitlab` → `Gitlab` | `google` → `Google` | `huggingface` → `Huggingface` | `kakao` → `Kakao` |
| `kick` → `Kick` | `line` → `Line` | `linear` → `Linear` | `linkedin` → `LinkedIn` |
| `microsoft` → `MicrosoftEntraId` | `naver` → `Naver` | `notion` → `Notion` | `paybin` → `Paybin` |
| `paypal` → `Paypal` | `polar` → `Polar` | `railway` → `Railway` | `reddit` → `Reddit` |
| `roblox` → `Roblox` | `salesforce` → `Salesforce` | `slack` → `Slack` | `spotify` → `Spotify` |
| `tiktok` → `TikTok` | `twitch` → `Twitch` | `twitter` → `Twitter` | `vercel` → `Vercel` |
| `vk` → `VK` | `wechat` → `WeChat` | `zoom` → `Zoom` | |

Note the key/class mismatches: `microsoft` (Microsoft Entra ID), `twitter` (X), `gitlab`
(lowercase `l` in `Gitlab`).

## The sign-in flow

`POST /api/auth/sign-in/social` with `{"provider": "github", "callbackURL": "/dashboard"}`
returns `{"url": "https://github.com/login/oauth/authorize?...", "redirect": true}`. Send
the browser there; `/api/auth/callback/github` sets the session cookie and redirects to
`callbackURL`. `callbackURL` is validated against trusted origins, so an off-origin value
is rejected rather than followed.

Register `{base_url}{base_path}/callback/{name}` (e.g.
`https://api.example.com/api/auth/callback/github`) as the redirect URI with the provider.

## A custom provider

`OAuthProvider` is a dataclass — one instance is a whole provider:

```python
from better_auth import BetterAuth, OAuthProvider

okta = OAuthProvider(
    client_id=os.environ["OKTA_ID"],
    client_secret=os.environ["OKTA_SECRET"],
    provider_id="okta",
    authorization_endpoint="https://your-org.okta.com/oauth2/v1/authorize",
    token_endpoint="https://your-org.okta.com/oauth2/v1/token",
    userinfo_endpoint="https://your-org.okta.com/oauth2/v1/userinfo",
    scopes=["openid", "email", "profile"],
    use_pkce=True,
)

auth = BetterAuth(secret=..., base_url=..., social_providers={"okta": okta})
```

`provider_id` defaults to the mapping key when omitted.

Other fields: `use_nonce`, `authentication` (`"post"` | `"basic"`), `redirect_uri`,
`authorize_params`, `scope_joiner`, `disable_default_scope`, `disable_sign_up`,
`disable_implicit_sign_up`, `override_user_info_on_sign_in`, `supports_refresh`,
`jwks_url` + `issuers` (id-token verification), `profile_mapper` and `id_token_mapper`.

For a provider whose userinfo payload is not OIDC-shaped, subclass and override
`fetch_user()` — see `GitHub` and `Discord` in `better_auth/oauth/providers.py`. For
providers configured at runtime (per-tenant, from the database) use the `generic-oauth`
plugin instead; for OIDC identity providers per domain use `sso`.
