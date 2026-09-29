---
title: OAuth Proxy
---

# OAuth Proxy

Lets preview and branch deployments finish a social login against the single
redirect URI registered with the provider, by proxying the callback through the
fixed production deployment. Mirrors the TS `oAuthProxy()` plugin.

## Enable

```python
from better_auth import BetterAuth
from better_auth.plugins_ext import OAuthProxyPlugin

auth = BetterAuth(
    secret="a-strong-32-character-minimum-secret",
    plugins=[OAuthProxyPlugin(production_url="https://example.com")],
)
```

## Options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `current_url` | `str \| None` | `None` (request origin, then vendor env URL, then `base_url`) | The current deployment URL; trusted as-is. |
| `production_url` | `str \| None` | `None` (`BETTER_AUTH_URL` / `base_url`) | The fixed production URL; requests already on this origin are not proxied. |
| `max_age` | `int` | `60` | Max age (seconds) of an encrypted profile before it is rejected as a replay. |
| `secret` | `str \| None` | `None` (`auth.secret`) | Dedicated proxy secret, used instead of `auth.secret` for all proxy encryption; must be shared across every environment in the flow. |

## Endpoints

| Method | Path |
| --- | --- |
| GET | `/callback/{provider}/oauth-proxy` |
| GET | `/oauth-proxy-callback` (deprecated alias) |

The rest of the plugin is request hooks around `/sign-in/social`,
`/link-social` and `/callback/{provider}`.

::: warning Changed in 1.1
Proxied sign-ins now complete on `/callback/{provider}/oauth-proxy`, so hooks
that match `/callback/` (such as [Last Login Method](./last-login-method))
run for them. `/oauth-proxy-callback` still works but is deprecated. The 1.0
Generic OAuth route `/sign-in/oauth2` is no longer proxied: use
`/sign-in/social`. See [Upgrade from 1.0](/migrate/from-1-0).
:::

## Notes

- Production runs the code-to-token-to-userinfo exchange, encrypts the resulting
  profile under the shared secret, and 302s it back to the preview's
  `/callback/{provider}/oauth-proxy`, which creates the user and session
  locally. The
  preview and production do not need to share `BETTER_AUTH_SECRET` (set
  `secret` if they don't).
- Deploy checklist: see [production deployment](/deploy/production).
- Account linking through `/link-social` is proxied the same way: the
  preview links the provider account to the signed-in user instead of
  creating a session.
- Works with both registry [providers](/providers/) and
  [Generic OAuth](./generic-oauth) providers, through `/sign-in/social` and
  `/link-social`.
