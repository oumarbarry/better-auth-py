---
title: Apple
---

# Apple

Sign in with Apple. OIDC with PKCE (S256); id tokens are verified against Apple's JWKS. User info comes from the id token — Apple has no userinfo endpoint.

## Configure

```python
from better_auth import BetterAuth
from better_auth.oauth.providers_ext import Apple

auth = BetterAuth(
    secret=...,
    social_providers={
        "apple": Apple(client_id="…", client_secret="…"),
    },
)
```

Or name-keyed (no import):

```python
auth = BetterAuth(
    secret=...,
    social_providers={
        "apple": {"client_id": "…", "client_secret": "…"},
    },
)
```

## Options

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `client_id` | `str \| list[str]` | required | The Services ID. Required before the authorize URL is built (`CLIENT_ID_AND_SECRET_REQUIRED`). |
| `client_secret` | `str` | required | An ES256 JWT, not a static string — see `generate_client_secret` below. Also required up front. |
| `app_bundle_identifier` | `str \| None` | `None` | Native iOS id tokens carry the app bundle id as audience, not the Services ID. |
| `audience` | `str \| list[str] \| None` | `None` | Explicit accepted id-token audience(s); overrides `app_bundle_identifier` and `client_id`. |
| `disable_id_token_sign_in` | `bool` | `False` | Refuse direct id-token sign-in. |

All shared [`ProviderConfig` options](/providers/#per-provider-options) apply.

## Notes

- Default scopes: `email name`.
- Register `{base_url}{base_path}/callback/apple` (e.g. `https://example.com/api/auth/callback/apple`) as the return URL in the Apple developer console. Apple **POSTs** the callback: the authorize URL uses `response_type=code id_token` with `response_mode=form_post`.
- Id-token verification: JWKS `https://appleid.apple.com/auth/keys`, issuer `https://appleid.apple.com`, 1-hour max token age. The nonce is accepted either raw or as `sha256hex(nonce)` — Apple's native SDKs sometimes hash it client-side. `email_verified` / `is_private_email` arrive as booleans or the strings `"true"`/`"false"` and are coerced.
- `Apple.generate_client_secret(client_id=…, team_id=…, key_id=…, private_key=…)` builds the ES256 client-secret JWT from your `.p8` key (Apple rejects secrets expiring more than six months out).
