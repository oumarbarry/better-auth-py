---
title: Slack
---

# Slack

Sign in with Slack (`openid.connect` flavor). No PKCE, no id-token direct sign-in.

## Configure

```python
from better_auth import BetterAuth
from better_auth.oauth.providers_ext import Slack

auth = BetterAuth(
    secret=...,
    social_providers={
        "slack": Slack(client_id="…", client_secret="…"),
    },
)
```

Or name-keyed (no import):

```python
auth = BetterAuth(
    secret=...,
    social_providers={
        "slack": {"client_id": "…", "client_secret": "…"},
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

- Default scopes: `openid profile email`.
- Register `{base_url}{base_path}/callback/slack` as a redirect URL on the Slack app (Slack requires HTTPS redirect URLs).
- Slack namespaces most userinfo claims under literal `https://slack.com/…` URIs: the user id is `https://slack.com/user_id`, and the avatar falls back to `https://slack.com/user_image_512` when `picture` is absent.
