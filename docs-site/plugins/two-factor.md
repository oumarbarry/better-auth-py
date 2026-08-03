---
title: Two-Factor
---

# Two-Factor

Second-factor authentication via TOTP, emailed/SMS OTP and backup codes, with a
short-lived two-factor cookie between the password step and the code step,
trusted devices, and optional account lockout. Mirrors the TS `twoFactor()`
plugin.

## Enable

```python
from better_auth import BetterAuth
from better_auth.plugins_ext import TwoFactorPlugin

auth = BetterAuth(
    secret="a-strong-32-character-minimum-secret",
    plugins=[TwoFactorPlugin(issuer="Example")],
)
```

## Options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `issuer` | `str \| None` | `None` | Issuer shown in the authenticator app (defaults to the app name). |
| `two_factor_table` | `str` | `"twoFactor"` | Model name for the plugin's table. |
| `totp_options` | `dict \| None` | `None` | TOTP group, e.g. `{"digits": 6, "period": 30}`. |
| `otp_options` | `dict \| None` | `None` | OTP group, e.g. `{"send_otp": fn, "period": 3, "store_otp": "plain"}`. |
| `backup_code_options` | `dict \| None` | `None` | Backup-code group, e.g. `{"amount": 10, "length": 10}`. |
| `skip_verification_on_enable` | `bool` | `False` | Enable 2FA without requiring a first verified code. |
| `allow_passwordless` | `bool` | `False` | Allow enabling 2FA on accounts without a password credential. |
| `two_factor_cookie_max_age` | `int` | `600` | Lifetime (seconds) of the sign-in challenge cookie. |
| `trust_device_max_age` | `int` | `2592000` | Lifetime (seconds) of the trusted-device cookie (30 days). |
| `account_lockout` | `dict \| None` | `None` | Lockout group (failed-attempt threshold and duration). |

Sub-option dicts use snake_case keys mirroring the TS option groups.

## Endpoints

8 routes under `/two-factor/`:

| Method | Path |
| --- | --- |
| POST | `/two-factor/enable` |
| POST | `/two-factor/disable` |
| POST | `/two-factor/get-totp-uri` |
| POST | `/two-factor/verify-totp` |
| POST | `/two-factor/send-otp` |
| POST | `/two-factor/verify-otp` |
| POST | `/two-factor/verify-backup-code` |
| POST | `/two-factor/generate-backup-codes` |

The TS server-only endpoints `/totp/generate` and
`/two-factor/view-backup-codes` are not mounted as HTTP routes; they are
exposed as plain async methods on the plugin instance —
`generate_totp_code(secret)` and `view_backup_codes(user_id)` — following the
[email-otp](./email-otp) precedent.

## Schema

| Table | Columns |
| --- | --- |
| `user` | adds `twoFactorEnabled` |
| `twoFactor` | `secret`, `backupCodes`, `userId`, `verified`, `failedVerificationCount`, `lockedUntil` |

## Notes

- Cross-runtime storage parity: `secret` and `backupCodes` are
  XChaCha20-Poly1305 encrypted exactly like TS; a row written by the TS library
  verifies here and vice versa.
- Sign-in with 2FA enabled returns
  `{"twoFactorRedirect": true, "twoFactorMethods": [...]}` and sets the signed
  `two_factor` challenge cookie instead of a session.
