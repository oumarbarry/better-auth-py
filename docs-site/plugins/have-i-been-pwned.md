---
title: Have I Been Pwned
---

# Have I Been Pwned

Rejects passwords found in the Have I Been Pwned breach corpus, using a
k-anonymity range query so the password never leaves your server. Runs before
hashing on every configured password path. Mirrors the TS `haveIBeenPwned()`
plugin.

## Enable

```python
from better_auth import BetterAuth
from better_auth.plugins_ext import HaveIBeenPwnedPlugin

auth = BetterAuth(
    secret="a-strong-32-character-minimum-secret",
    plugins=[HaveIBeenPwnedPlugin()],
)
```

## Options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `custom_password_compromised_message` | `str \| None` | `None` | Message returned when a password is found in a breach. |
| `paths` | `list[str] \| None` | `None` | Paths to check. Default: `/sign-up/email`, `/change-password`, `/reset-password`, `/email-otp/reset-password`, `/phone-number/reset-password`, `/admin/create-user`, `/admin/set-user-password`. |
| `enabled` | `bool` | `True` | Turn the check off without removing the plugin. |

## Endpoints

None — the plugin registers a password check run by `hash_password_checked`
before every password hash on the configured paths.

## Notes

- Only the first five characters of the SHA-1 hash are sent to the HIBP range
  API; the match is done locally.
- Plugin-owned paths in the default list only take effect when the matching
  plugin (e.g. [Admin](./admin), [Email OTP](./email-otp),
  [Phone Number](./phone-number)) is installed — the check is keyed on the
  request path.
