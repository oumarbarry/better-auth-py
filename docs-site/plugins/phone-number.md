---
title: Phone Number
---

# Phone Number

SMS one-time codes for sign-in, phone verification and password reset. Mirrors
the TS `phoneNumber()` plugin.

## Enable

```python
from better_auth import BetterAuth
from better_auth.plugins_ext import PhoneNumberPlugin

async def send_otp(data, ctx=None):
    ...  # send data["code"] by SMS to data["phoneNumber"]

auth = BetterAuth(
    secret="a-strong-32-character-minimum-secret",
    plugins=[PhoneNumberPlugin(send_otp=send_otp)],
)
```

## Options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `otp_length` | `int` | `6` | Number of digits. |
| `expires_in` | `int` | `300` | Code lifetime in seconds. |
| `allowed_attempts` | `int` | `3` | Wrong-code budget per stored OTP. `0` means no attempt is allowed. |
| `send_otp` | `callable \| None` | `None` | `({"phoneNumber", "code"}, ctx) -> None`, sync or async. Required in practice: endpoints answer `SEND_OTP_NOT_IMPLEMENTED` (501) without it. |
| `verify_otp` | `callable \| None` | `None` | `({"phoneNumber", "code"}, ctx) -> bool`, a custom verifier replacing the stored-code comparison. |
| `send_password_reset_otp` | `callable \| None` | `None` | Separate sender for password-reset codes, same signature as `send_otp`. |
| `phone_number_validator` | `callable \| None` | `None` | `(phone_number) -> bool` format check. |
| `require_verification` | `bool` | `False` | Block `/sign-in/phone-number` until the number is verified. |
| `callback_on_verification` | `callable \| None` | `None` | Called after a successful verification. |
| `sign_up_on_verification` | `dict \| None` | `None` | Auto-create a user on first verification (temp-email settings). |

## Endpoints

| Method | Path |
| --- | --- |
| POST | `/sign-in/phone-number` |
| POST | `/phone-number/send-otp` |
| POST | `/phone-number/verify` |
| POST | `/phone-number/request-password-reset` |
| POST | `/phone-number/reset-password` |

## Schema

| Table | Added columns |
| --- | --- |
| `user` | `phoneNumber`, `phoneNumberVerified` |

## Notes

- Storage parity with TS: codes stored as `"<code>:<attempts>"` under the raw
  phone number; reset OTPs under `"<phoneNumber>-request-password-reset"`.
- Codes are consumed atomically: one code never satisfies two verifications.
- `await plugin.consume_phone_number_otp(phone_number, code)` checks and burns
  a sign-in or verification code on the server, without a session, a user
  update or a new session. It returns `{"status": True}` and raises the same
  `APIError` as `/phone-number/verify` on a wrong, expired or exhausted code.
  It is a method on the plugin instance, not an HTTP route. It uses
  `verify_otp` when one is configured.
- A new user created by `/phone-number/verify` (with
  `sign_up_on_verification`) goes through `user.validate_user_info` when it is
  set, with `source` set to `{"action": "create-user", "method": "phone-number"}`.
- A corrupt attempt counter in a stored code counts as zero attempts instead
  of causing a server error.

::: warning Changed in 1.1
In 1.0, `allowed_attempts=0` fell back to the default of 3. It now means zero
attempts, so every code is refused. See [Upgrade from 1.0](/migrate/from-1-0).
:::
- Deliberate simplifications: the TS per-instance `schema` field-name override
  is not exposed, and SMS-send failures are not isolated in a background task
  (no `advanced.backgroundTasks` seam in this port).
