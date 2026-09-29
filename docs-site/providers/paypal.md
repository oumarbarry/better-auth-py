---
title: PayPal
---

# PayPal

PayPal "Log in with PayPal". OAuth2 with PKCE and environment-selected endpoints. ID token sign-in is off by default.

## Configure

```python
from better_auth import BetterAuth
from better_auth.oauth.providers_ext import Paypal

auth = BetterAuth(
    secret=...,
    social_providers={
        "paypal": Paypal(client_id="…", client_secret="…", environment="live"),
    },
)
```

Or name-keyed (no import):

```python
auth = BetterAuth(
    secret=...,
    social_providers={
        "paypal": {"client_id": "…", "client_secret": "…"},
    },
)
```

## Options

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `client_id` | `str \| list[str]` | required | Checked before the authorize URL is built (`CLIENT_ID_AND_SECRET_REQUIRED`). |
| `client_secret` | `str` | required | Also checked up front. With `legacy_id_token_sign_in`, it doubles as the HS256 verification key. |
| `environment` | `str` | `"sandbox"` | `"sandbox"` or `"live"`: selects every endpoint host (authorize, token, userinfo, issuer, JWKS). |
| `prompt` | `str \| None` | `None` | Forwarded as the `prompt` authorize param. |
| `request_shipping_address` | `bool` | `False` | Parity field from the TS options surface; not read by the flow. |
| `legacy_id_token_sign_in` | `bool` | `False` | Turns direct id-token sign-in back on, as in 1.0. |
| `disable_id_token_sign_in` | `bool` | `False` | Refuse direct id-token sign-in even with `legacy_id_token_sign_in`. |

All shared [`ProviderConfig` options](/providers/#per-provider-options) apply.

## Notes

- Default scopes: none. Permissions are configured in the PayPal dashboard, so the authorize URL carries no `scope` param.
- Register `{base_url}{base_path}/callback/paypal` as the return URL on the PayPal app. **The default environment is `sandbox`**. Set `environment="live"` for production.
- Token exchange and refresh use the shared token flow with `client_secret_basic` (HTTP Basic) client authentication.
- Direct id-token sign-in (`POST /sign-in/social` with `idToken`) answers `404 ID_TOKEN_NOT_SUPPORTED` unless `legacy_id_token_sign_in=True`. With it, verification accepts `RS256` (published JWKS) or `HS256` (raw `client_secret` as HMAC key); any other algorithm is rejected. Issuer/audience checked, 1-hour max token age, nonce checked when present.

::: warning Changed in 1.1
PayPal ID token sign-in is off by default. Set `legacy_id_token_sign_in=True` to keep it. See [Upgrade from 1.0](/migrate/from-1-0).
:::
- Userinfo (`?schema=paypalv1.1`) is bound to the id token when the token response carries one: its `sub`/`user_id` must match the id token's `sub`, else the sign-in is rejected.
