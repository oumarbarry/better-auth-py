---
title: Cloudflare
---

# Cloudflare

Sign in with a Cloudflare account, registry key `cloudflare`. OAuth2 with PKCE (S256). No id token: the profile comes from the Cloudflare API.

## Configure

Create an OAuth client in the Cloudflare dashboard (**Manage Account**, then **OAuth clients**). Use the Authorization Code flow and mark **User Details Read** as a required scope.

```python
from better_auth import BetterAuth
from better_auth.oauth.providers_ext import Cloudflare

auth = BetterAuth(
    secret=...,
    social_providers={
        "cloudflare": Cloudflare(client_id="…", client_secret="…"),
    },
)
```

Or name-keyed (no import):

```python
auth = BetterAuth(
    secret=...,
    social_providers={
        "cloudflare": {"client_id": "…", "client_secret": "…"},
    },
)
```

## Options

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `client_id` | `str \| list[str]` | required | |
| `client_secret` | `str` | `""` | Optional. Without it the client is public and token requests use `none` authentication (PKCE only). |
| `token_endpoint_auth_method` | `str \| None` | `None` | `"client_secret_basic"`, `"client_secret_post"` or `"none"`. `None` means `client_secret_basic` with a secret and `none` without one. Match the method set on the Cloudflare OAuth client. |

All shared [`ProviderConfig` options](/providers/#per-provider-options) apply. An explicit `token_endpoint_auth` wins over `token_endpoint_auth_method`.

## Notes

- Default scopes: `user-details.read`. Setting `scopes=` replaces the default list, so keep `user-details.read` in it when you add Cloudflare API scopes (for example `scopes=["user-details.read", "workers-platform.read"]`). Only request scopes that are enabled on the OAuth client.
- Register `{base_url}{base_path}/callback/cloudflare` as the redirect URL on the OAuth client.
- Endpoints: authorize `https://dash.cloudflare.com/oauth2/auth`, token `https://dash.cloudflare.com/oauth2/token`.
- Cloudflare's OIDC userinfo endpoint only returns `sub`, so the profile is read from the Cloudflare API `GET https://api.cloudflare.com/client/v4/user` (this is why `user-details.read` must be granted). A response without `success` and a `result` fails the sign-in.
- The user's `id` is the account id. The name is `first_name` and `last_name` joined, falling back to the email.
- Cloudflare does not expose whether the email is verified: `email_verified` is always `False`.
- The authorize URL carries only the configured `authorize_params`. A `loginHint` or `additionalParams` sent with the sign-in request is not forwarded.
