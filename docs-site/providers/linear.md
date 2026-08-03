---
title: Linear
---

# Linear

Linear OAuth2. No PKCE, no id token. User info comes from Linear's GraphQL API.

## Configure

```python
from better_auth import BetterAuth
from better_auth.oauth.providers_ext import Linear

auth = BetterAuth(
    secret=...,
    social_providers={
        "linear": Linear(client_id="…", client_secret="…"),
    },
)
```

Or name-keyed (no import):

```python
auth = BetterAuth(
    secret=...,
    social_providers={
        "linear": {"client_id": "…", "client_secret": "…"},
    },
)
```

## Options

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `client_id` | `str \| list[str]` | required | |
| `client_secret` | `str` | required | |

All shared [`ProviderConfig` options](/providers/#per-provider-options) apply.

## Notes

- Default scopes: `read`.
- Register `{base_url}{base_path}/callback/linear` as the callback URL in the Linear OAuth application.
- User info is a GraphQL query — `POST https://api.linear.app/graphql` with a `viewer { id name email avatarUrl … }` query, not a REST GET. A response without `viewer` rejects the sign-in.
- Linear never returns an `email_verified` claim — mapped as `False`.
