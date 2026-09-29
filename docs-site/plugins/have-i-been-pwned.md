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

None. The plugin registers a password check run by `hash_password_checked`
before every password hash on the configured paths.

## Check a password yourself

`is_password_compromised` runs the same lookup outside the configured paths,
for example in a custom password form:

```python
from better_auth.plugins_ext.haveibeenpwned import is_password_compromised

if await is_password_compromised(password, http=auth.http):
    ...  # ask for another password
```

It returns `True` when the password appears in the corpus. `http` is
optional: without it a one-off `httpx.AsyncClient` is used. When the lookup
cannot complete it raises a 500 `APIError`; if the range API answered with an
error, the message includes its HTTP status.

## Notes

- Only the first five characters of the SHA-1 hash are sent to the HIBP range
  API; the match is done locally.
- Every password on a configured path is checked, including an empty one.
- Padding entries in the range response (a count of `0`) never flag a
  password.
- Plugin-owned paths in the default list only take effect when the matching
  plugin (e.g. [Admin](./admin), [Email OTP](./email-otp),
  [Phone Number](./phone-number)) is installed: the check is keyed on the
  request path.
