---
title: Google
---

# Google

Google OIDC with PKCE (S256), a nonce on the authorize URL, and id-token verification against Google's JWKS.

## Configure

```python
from better_auth import BetterAuth, Google

auth = BetterAuth(
    secret=...,
    social_providers={
        "google": Google(client_id="…", client_secret="…"),
    },
)
```

Or name-keyed (no import):

```python
auth = BetterAuth(
    secret=...,
    social_providers={
        "google": {"client_id": "…", "client_secret": "…"},
    },
)
```

## Options

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `client_id` | `str \| list[str]` | required | A list accepts several audiences on id-token verification (e.g. web + iOS client ids). |
| `client_secret` | `str` | required | |

All shared [`ProviderConfig` options](/providers/#per-provider-options) apply — e.g. `authorize_params={"access_type": "offline", "prompt": "consent"}` to get a refresh token.

## Notes

- Default scopes: `openid email profile`.
- Register `{base_url}{base_path}/callback/google` as an authorized redirect URI in the Google Cloud console.
- `Google` is re-exported at the package root (`from better_auth import Google`).
- OIDC: a nonce is generated, sent on the authorize URL and checked at verification. Id tokens are verified against `https://www.googleapis.com/oauth2/v3/certs` with issuers `https://accounts.google.com` and `accounts.google.com`, enabling direct id-token sign-in.
