---
title: Email OTP
---

# Email OTP

One-time codes by email for sign-in, email verification, email change and
password reset. Mirrors the TS `emailOTP()` plugin.

## Enable

```python
from better_auth import BetterAuth
from better_auth.plugins_ext import EmailOTPPlugin

async def send_verification_otp(email, otp, otp_type):
    ...  # send the code by email

auth = BetterAuth(
    secret="a-strong-32-character-minimum-secret",
    plugins=[EmailOTPPlugin(send_verification_otp=send_verification_otp)],
)
```

## Options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `send_verification_otp` | `callable` | required | `(email, otp, type) -> None`, delivers the code. |
| `otp_length` | `int` | `6` | Number of digits. |
| `expires_in` | `int` | `300` | Code lifetime in seconds. |
| `generate_otp` | `callable \| None` | `None` | Custom code generator. |
| `send_verification_on_sign_up` | `bool` | `False` | Send an email-verification OTP after sign-up. |
| `disable_sign_up` | `bool` | `False` | Never create a user implicitly from an OTP sign-in. |
| `allowed_attempts` | `int` | `3` | Wrong-code budget per stored OTP. |
| `store_otp` | `str \| dict` | `"plain"` | `"plain"`, `"hashed"`, `"encrypted"`, or a custom hash/encrypt config. |
| `resend_strategy` | `str` | `"rotate"` | What a resend does to the pending code. |
| `change_email` | `dict \| None` | `None` | Email-change sub-options. |
| `override_default_email_verification` | `bool` | `False` | Replace the core link-based email verification with OTP emails. |
| `rate_limit` | `dict[str, int] \| None` | `None` | Per-endpoint rate-limit overrides. |

## Endpoints

9 routes:

| Method | Path |
| --- | --- |
| POST | `/email-otp/send-verification-otp` |
| POST | `/email-otp/check-verification-otp` |
| POST | `/email-otp/verify-email` |
| POST | `/sign-in/email-otp` |
| POST | `/email-otp/request-password-reset` |
| POST | `/forget-password/email-otp` |
| POST | `/email-otp/reset-password` |
| POST | `/email-otp/request-email-change` |
| POST | `/email-otp/change-email` |

The TS server-only endpoints `createVerificationOTP` / `getVerificationOTP` are
not mounted as HTTP routes (their paths 404). They are exposed as plain async
methods on the plugin instance: `create_verification_otp(email, otp_type)` and
`get_verification_otp(email, otp_type)`.

## Schema

No extra tables — codes live in the core `verification` table, identifier
scheme `<type>-otp-<email>`, value `"<storedOTP>:<attempts>"`, byte-compatible
with TS.

## Notes

- The send endpoint is origin-checked, so a cookieless cross-origin POST
  cannot mail a code to an arbitrary address.
- Sign-in codes for unknown emails are silently dropped (no user enumeration).
- `get_verification_otp` raises a 400 when `store_otp` is hashed — the plain
  text is unrecoverable.
- Codes are consumed atomically: one code can never satisfy two verifications.
