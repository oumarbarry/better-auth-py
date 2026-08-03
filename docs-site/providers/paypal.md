---
title: PayPal
---

# PayPal

PayPal "Log in with PayPal". OIDC with PKCE, dual-algorithm id-token verification (RS256 via JWKS or HS256 via the client secret), and environment-selected endpoints.

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
| `client_secret` | `str` | required | Also checked up front; doubles as the HS256 verification key. |
| `environment` | `str` | `"sandbox"` | `"sandbox"` or `"live"` — selects every endpoint host (authorize, token, userinfo, issuer, JWKS). |
| `prompt` | `str \| None` | `None` | Forwarded as the `prompt` authorize param. |
| `request_shipping_address` | `bool` | `False` | Parity field from the TS options surface; not read by the flow. |
| `disable_id_token_sign_in` | `bool` | `False` | Refuse direct id-token sign-in. |

All shared [`ProviderConfig` options](/providers/#per-provider-options) apply.

## Notes

- Default scopes: none — permissions are configured in the PayPal dashboard, so the authorize URL carries an empty `scope` param.
- Register `{base_url}{base_path}/callback/paypal` as the return URL on the PayPal app. **The default environment is `sandbox`** — set `environment="live"` for production.
- Token exchange and refresh are hand-rolled: HTTP Basic auth plus `accept-language: en_US`, and the exchange body deliberately omits `code_verifier` (PKCE is only on the authorize URL, matching TS).
- Id-token verification accepts `RS256` (published JWKS) or `HS256` (raw `client_secret` as HMAC key); any other algorithm is rejected. Issuer/audience checked, 1-hour max token age, nonce checked when present.
- Userinfo (`?schema=paypalv1.1`) is bound to the id token: its `sub`/`user_id` must match the id token's `sub`, else the sign-in is rejected.
