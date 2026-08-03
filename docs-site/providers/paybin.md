---
title: Paybin
---

# Paybin

Paybin identity provider (OIDC-shaped) with **required** PKCE (S256). User info comes from the decoded id token — no userinfo call.

## Configure

```python
from better_auth import BetterAuth
from better_auth.oauth.providers_ext import Paybin

auth = BetterAuth(
    secret=...,
    social_providers={
        "paybin": Paybin(client_id="…", client_secret="…"),
    },
)
```

Or name-keyed (no import):

```python
auth = BetterAuth(
    secret=...,
    social_providers={
        "paybin": {"client_id": "…", "client_secret": "…"},
    },
)
```

## Options

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `client_id` | `str \| list[str]` | required | Checked before the authorize URL is built (`CLIENT_ID_AND_SECRET_REQUIRED`). |
| `client_secret` | `str` | required | Also checked up front. |
| `issuer` | `str` | `"https://idp.paybin.io"` | Authorize/token endpoints derive from it (`{issuer}/oauth2/authorize|token`) unless explicitly overridden. |

All shared [`ProviderConfig` options](/providers/#per-provider-options) apply.

## Notes

- Default scopes: `openid email profile`.
- Register `{base_url}{base_path}/callback/paybin` as the redirect URI with Paybin.
- PKCE is mandatory — building the authorize URL without a code verifier raises (matching TS).
- User info is the decoded (unverified, per TS `decodeJwt`) `id_token`; there is no JWKS, so direct id-token sign-in is not available.
- Display name prefers `name`, falling back to `preferred_username`.
