---
title: Google
---

# Google

Google OIDC with PKCE (S256) and id-token verification against Google's JWKS.

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
| `client_secret` | `str` | required | Checked before the authorize URL is built (`CLIENT_ID_AND_SECRET_REQUIRED`). |
| `prompt` | `str \| None` | `None` | Sent as the `prompt` authorize param, e.g. `"consent"` or `"select_account"`. |
| `access_type` | `str \| None` | `None` | `"offline"` asks for a refresh token. |
| `display` | `str \| None` | `None` | Sent as the `display` authorize param. |
| `hd` | `str \| None` | `None` | Google Workspace hosted domain. Sent as the `hd` hint and enforced on the ID token `hd` claim; `"*"` accepts any hosted domain but refuses personal accounts. Falls back to `authorize_params["hd"]`. |
| `include_granted_scopes` | `bool` | `True` | Sends `include_granted_scopes=true` (incremental authorization). |

All shared [`ProviderConfig` options](/providers/#per-provider-options) apply, e.g. `Google(..., access_type="offline", prompt="consent")` to get a refresh token.

## Notes

- Default scopes: `email profile openid`.
- Register `{base_url}{base_path}/callback/google` as an authorized redirect URI in the Google Cloud console.
- `Google` is re-exported at the package root (`from better_auth import Google`).
- Id tokens are verified against `https://www.googleapis.com/oauth2/v3/certs` with issuers `https://accounts.google.com` and `accounts.google.com`, RS256 only and at most one hour old. Every key with the token's `kid` is tried. This supports direct id-token sign-in; pass the `nonce` your client used, and it is checked.
- The redirect flow sends no nonce. The profile is read from the ID token returned by the token endpoint (no userinfo call), and a hosted-domain mismatch with `hd` fails the sign-in.

::: warning Changed in 1.1
The redirect flow no longer sends a nonce, the callback profile comes from the ID token instead of the userinfo endpoint, and ID tokens must be RS256. See [Upgrade from 1.0](/migrate/from-1-0).
:::
