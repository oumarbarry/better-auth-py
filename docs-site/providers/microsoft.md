---
title: Microsoft Entra ID
---

# Microsoft Entra ID

Microsoft Entra ID (Azure AD), registry key `microsoft`. OIDC with PKCE (S256) and id-token verification, including hand-rolled multi-tenant issuer validation.

## Configure

```python
from better_auth import BetterAuth
from better_auth.oauth.providers_ext import MicrosoftEntraId

auth = BetterAuth(
    secret=...,
    social_providers={
        "microsoft": MicrosoftEntraId(client_id="…", client_secret="…", tenant_id="common"),
    },
)
```

Or name-keyed (no import):

```python
auth = BetterAuth(
    secret=...,
    social_providers={
        "microsoft": {"client_id": "…", "client_secret": "…"},
    },
)
```

## Options

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `client_id` | `str \| list[str]` | required | |
| `client_secret` | `str` | `""` | Optional — public clients (SPA/native + PKCE) are supported. |
| `tenant_id` | `str \| None` | `None` | Tenant segment of every endpoint; `None` means `common`. Also `organizations`, `consumers`, or a specific tenant id. |
| `authority` | `str \| None` | `None` | Base authority URL; `None` means `https://login.microsoftonline.com` (trailing slashes trimmed). |
| `profile_photo_size` | `int` | `48` | Pixel size of the Microsoft Graph photo fetch. |
| `disable_profile_photo` | `bool` | `False` | Skip the Graph photo fetch. |
| `prompt` | `str \| None` | `None` | Forwarded as the `prompt` authorize param. |
| `disable_id_token_sign_in` | `bool` | `False` | Refuse direct id-token sign-in. |

All shared [`ProviderConfig` options](/providers/#per-provider-options) apply.

## Notes

- Default scopes: `openid profile email User.Read offline_access`.
- Register `{base_url}{base_path}/callback/microsoft` as a redirect URI on the app registration.
- Endpoints are `{authority}/{tenant}/oauth2/v2.0/authorize|token` with JWKS at `{authority}/{tenant}/discovery/v2.0/keys`.
- Multi-tenant id-token verification: for `common`/`organizations`/`consumers` there is no single expected `iss`, so the token's `tid` claim is cross-checked against its `iss` (`{authority}/{tid}/v2.0`); `organizations` rejects consumer-tenant tokens, `consumers` requires them. Max token age is 1 hour, and the nonce is checked when present.
- The profile photo is fetched from Microsoft Graph (`/me/photos/{size}x{size}/$value`) and inlined as a `data:` URI; a photo failure never blocks sign-in.
- `email_verified` falls back to membership in `verified_primary_email`/`verified_secondary_email` when the optional claim is absent.
