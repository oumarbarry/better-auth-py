---
title: Magic Link
---

# Magic Link

Passwordless sign-in through a single-use emailed link. Mirrors the TS
`magicLink()` plugin.

## Enable

```python
from better_auth import BetterAuth
from better_auth.plugins_ext import MagicLinkPlugin

async def send_magic_link(email, url, token, request):
    ...  # mail the url

auth = BetterAuth(
    secret="a-strong-32-character-minimum-secret",
    plugins=[MagicLinkPlugin(send_magic_link=send_magic_link)],
)
```

## Options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `send_magic_link` | `callable` | required | `(email, url, token, request) -> None`, delivers the link. |
| `expires_in` | `int` | `300` | Link lifetime in seconds. |
| `allowed_attempts` | `int \| None` | `None` | Deprecated in TS; tokens are single-use regardless. Any value other than `1` logs a warning. |
| `disable_sign_up` | `bool` | `False` | Only sign in existing users; never create one from a link. |
| `rate_limit` | `dict[str, int] \| None` | `None` | Rate-limit overrides. |
| `generate_token` | `callable \| None` | `None` | Custom token generator, `(email) -> str`. |
| `store_token` | `str \| dict` | `"plain"` | `"plain"`, `"hashed"`, or a custom-hasher config for the stored token. |

## Endpoints

| Method | Path |
| --- | --- |
| POST | `/sign-in/magic-link` |
| GET | `/magic-link/verify` |

## Schema

No extra tables — tokens live in the core `verification` table, keyed by the
*stored* token with value `JSON({email, name?})`, byte-compatible with TS.

## Notes

- Verification consumes the token atomically: N racing verifies mint at most
  one session; invalid/expired tokens redirect to
  `errorCallbackURL?error=INVALID_TOKEN`.
- Each callback URL is origin-checked before redirecting.
- Adopting an existing unverified user revokes its unproven credential and
  sessions before marking the email verified.
