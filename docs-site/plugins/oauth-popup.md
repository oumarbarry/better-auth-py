---
title: OAuth Popup
---

# OAuth Popup

Runs social sign-in in a popup window: the client navigates the popup to
`/oauth-popup/start`, and on the OAuth callback the plugin swaps the redirect
for a page that posts the session token (or error) back to the opener. Mirrors
the TS `oauthPopup()` plugin.

## Enable

```python
from better_auth import BetterAuth
from better_auth.plugins_ext import BearerPlugin, OAuthPopupPlugin

auth = BetterAuth(
    secret="a-strong-32-character-minimum-secret",
    plugins=[OAuthPopupPlugin(), BearerPlugin()],
)
```

## Options

None — the plugin takes no options (same as TS).

## Endpoints

| Method | Path |
| --- | --- |
| GET | `/oauth-popup/start` |

## Notes

- Pair it with [bearer](./bearer) so the opener can use the posted token.
- The completion page's inline script is byte-identical to TS and its sha256
  is pinned in the response CSP.
- `ponytail`: state is stored as a verification row plus signed CSRF cookie
  (this port's OAuth-state convention), so the normal `/callback` and
  `/oauth2/callback` routes consume it unchanged; `additionalData` is nested
  under its own key with internal state keys stripped.
