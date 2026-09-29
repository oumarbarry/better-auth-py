---
title: Microsoft Entra ID
---

# Microsoft Entra ID

Microsoft Entra ID (Azure AD), registry key `microsoft`. OIDC with PKCE (S256) and id-token verification, including multi-tenant issuer validation.

## Configure

```python
from better_auth import BetterAuth
from better_auth.oauth.providers_ext import MicrosoftEntraId

auth = BetterAuth(
    secret=...,
    social_providers={
        "microsoft": MicrosoftEntraId(
            client_id="…", client_secret="…", tenant_id="common"
        ),
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
| `client_secret` | `str` | `""` | Optional: public clients (SPA/native + PKCE) are supported. Cannot be combined with `client_assertion`. |
| `tenant_id` | `str \| None` | `None` | Tenant segment of every endpoint; `None` means `common`. Also `organizations`, `consumers`, or a specific tenant id. |
| `authority` | `str \| None` | `None` | Base authority URL; `None` means `https://login.microsoftonline.com` (trailing slashes trimmed). |
| `profile_photo_size` | `int` | `48` | Pixel size of the Microsoft Graph photo fetch. |
| `disable_profile_photo` | `bool` | `False` | Skip the Graph photo fetch. |
| `prompt` | `str \| None` | `None` | Forwarded as the `prompt` authorize param. |
| `disable_id_token_sign_in` | `bool` | `False` | Refuse direct id-token sign-in. |
| `account_id_claim` | `str` | `"oid"` | ID token claim stored as the account id. `"sub"` keeps the ids stored by 1.0. |
| `client_assertion` | callable or `None` | `None` | Authenticates token requests with `private_key_jwt` instead of a secret. Called with `{"clientId", "tokenEndpoint", "grantType"}`, returns the signed JWT (may be async). |

All shared [`ProviderConfig` options](/providers/#per-provider-options) apply.

::: warning Changed in 1.1
The account id is the `oid` claim (the user's object id), not `sub`. Rows that 1.0
stored for the `microsoft` provider hold `sub` values and no longer match, so a
returning user is treated as a new sign-in: linked by email, or refused. Migrate
those `account.accountId` values to `oid` before upgrading, or pass
`account_id_claim="sub"` to keep the old ids. A token without a usable value for
the claim is refused with `unable_to_get_user_info`. See
[Upgrade from 1.0](/migrate/from-1-0).
:::

### Client assertion

To authenticate with a certificate or key instead of a client secret, pass
`client_assertion`. The helper below signs a fresh RFC 7523 assertion per request:

```python
from better_auth.oauth.machinery import create_private_key_jwt_client_assertion_getter
from better_auth.oauth.providers_ext import MicrosoftEntraId

MicrosoftEntraId(
    client_id="…",
    tenant_id="your-tenant-id",
    client_assertion=create_private_key_jwt_client_assertion_getter(
        private_key_pem=PEM, kid="key-1"
    ),
)
```

## Notes

- Default scopes: `openid profile email User.Read offline_access`.
- Register `{base_url}{base_path}/callback/microsoft` as a redirect URI on the app registration.
- Endpoints are `{authority}/{tenant}/oauth2/v2.0/authorize|token` with JWKS at `{authority}/{tenant}/discovery/v2.0/keys`.
- Multi-tenant id-token verification: for `common`/`organizations`/`consumers` there is no single expected `iss`, so the token's `tid` claim is cross-checked against its `iss` (`{authority}/{tid}/v2.0`); `organizations` rejects consumer-tenant tokens, `consumers` requires them. Max token age is 1 hour, and the nonce is checked when present.
- Token refresh sends the configured scopes again.
- The profile photo is fetched from Microsoft Graph (`/me/photos/{size}x{size}/$value`) and inlined as a `data:` URI; a photo failure never blocks sign-in.
- `email_verified` falls back to membership in `verified_primary_email`/`verified_secondary_email` when the optional claim is absent.
