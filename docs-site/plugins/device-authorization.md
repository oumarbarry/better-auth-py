---
title: Device Authorization
---

# Device Authorization

The OAuth 2.0 Device Authorization Grant (RFC 8628) — the "enter this code on
another device" flow for TVs and CLIs. Mirrors the TS `deviceAuthorization()`
plugin.

## Enable

```python
from better_auth import BetterAuth
from better_auth.plugins_ext import DeviceAuthorizationPlugin

auth = BetterAuth(
    secret="a-strong-32-character-minimum-secret",
    plugins=[DeviceAuthorizationPlugin(expires_in="30m", interval="5s")],
)
```

## Options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `expires_in` | `str` | `"30m"` | Device/user-code lifetime (duration string). |
| `interval` | `str` | `"5s"` | Minimum polling interval (duration string). |
| `device_code_length` | `int` | `40` | Length of the device code. |
| `user_code_length` | `int` | `8` | Length of the user-facing code. |
| `generate_device_code` | `callable \| None` | `None` | Custom device-code generator. |
| `generate_user_code` | `callable \| None` | `None` | Custom user-code generator. |
| `validate_client` | `callable \| None` | `None` | `(client_id) -> bool` gate on `/device/code`. |
| `on_device_auth_request` | `callable \| None` | `None` | Observer called when a device requests a code. |
| `verification_uri` | `str \| None` | `None` | Override the advertised verification URI. |

## Endpoints

| Method | Path |
| --- | --- |
| POST | `/device/code` |
| POST | `/device/token` |
| GET | `/device` |
| POST | `/device/approve` |
| POST | `/device/deny` |

## Schema

| Table | Columns |
| --- | --- |
| `deviceCode` | `deviceCode`, `userCode`, `userId`, `expiresAt`, `status`, `lastPolledAt`, `pollingInterval`, `clientId`, `scope` |

## Notes

- Errors are OAuth-shaped on the wire (`{"error", "error_description"}`, RFC
  6749 style), not this port's usual `{"code", "message"}` envelope — matching
  TS.
- Redemption of an approved code is atomic (delete-and-return): concurrent
  pollers race on the same delete and exactly one mints a session. The pending
  claim and polling-interval bump use a guarded compare-and-swap, closing the
  race behind TS's GHSA-cq3f-vc6p-68fh fix.
- Pairs naturally with [oauth-provider](./oauth-provider) when you are the
  authorization server.
