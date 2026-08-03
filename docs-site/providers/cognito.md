---
title: Amazon Cognito
---

# Amazon Cognito

Amazon Cognito user pools. OIDC with PKCE (S256) and id-token verification against the pool's JWKS. Per-pool config is required at construction.

## Configure

```python
from better_auth import BetterAuth
from better_auth.oauth.providers_ext import Cognito

auth = BetterAuth(
    secret=...,
    social_providers={
        "cognito": Cognito(
            client_id="…", client_secret="…",
            domain="your-domain.auth.eu-west-1.amazoncognito.com",
            region="eu-west-1",
            user_pool_id="eu-west-1_XXXX",
        ),
    },
)
```

Or name-keyed (no import):

```python
auth = BetterAuth(
    secret=...,
    social_providers={
        "cognito": {
            "client_id": "…", "client_secret": "…",
            "domain": "your-domain.auth.eu-west-1.amazoncognito.com",
            "region": "eu-west-1",
            "user_pool_id": "eu-west-1_XXXX",
        },
    },
)
```

## Options

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `client_id` | `str \| list[str]` | required | |
| `client_secret` | `str` | required | |
| `domain` | `str` | required | Hosted-UI domain; a leading `https://` is stripped. Missing → `ValueError` at construction. |
| `region` | `str` | required | AWS region of the pool. Missing → `ValueError` at construction. |
| `user_pool_id` | `str` | required | Missing → `ValueError` at construction. |
| `require_client_secret` | `bool` | `False` | Parity field from the TS options surface; not read by the flow. |
| `disable_id_token_sign_in` | `bool` | `False` | Refuse direct id-token sign-in. |

All shared [`ProviderConfig` options](/providers/#per-provider-options) apply.

## Notes

- Default scopes: `openid profile email`.
- Register `{base_url}{base_path}/callback/cognito` as an allowed callback URL on the app client.
- Endpoints derive from `domain` (`https://{domain}/oauth2/authorize|token|userinfo`); JWKS and issuer derive from `region` + `user_pool_id` (`https://cognito-idp.{region}.amazonaws.com/{user_pool_id}`).
- Id tokens are verified with a 1-hour max token age.
- AWS requires `%20`-encoded scopes (not `+`), so the authorize URL's query is re-encoded accordingly.
- User info prefers the decoded `id_token`; the userinfo endpoint is the fallback.
