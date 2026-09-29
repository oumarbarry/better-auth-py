---
title: Device Authorization
---

# Device Authorization

The OAuth 2.0 Device Authorization Grant (RFC 8628): the "enter this code on
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

This plugin signs the device in to your own app: `/device/token` returns a
Better Auth session token. To issue OAuth tokens to registered OAuth clients
instead, use `OAuthDeviceAuthorizationPlugin` with the OAuth provider. See
[Device authorization grant](./oauth-provider#device-authorization-grant).

## Options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `expires_in` | `str` | `"30m"` | Device/user-code lifetime (duration string). |
| `interval` | `str` | `"5s"` | Minimum polling interval (duration string). |
| `device_code_length` | `int` | `40` | Length of the device code. At most 191. |
| `user_code_length` | `int` | `8` | Length of the user-facing code. At most 191. |
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

`/device/code`, `/device/token`, `/device/approve` and `/device/deny` accept a
JSON or a form-encoded (`application/x-www-form-urlencoded`) body. In a form
body, an empty `client_id`, `user_id` or `scope` counts as omitted, and a
repeated one is refused with `invalid_request`.

`/device` is rate limited to 5 requests per code lifetime (`expires_in`), to
slow down user-code guessing.

`GET /device?user_code=...` returns the code `status`. For the signed-in user
who owns the code, it also returns the requesting `client_id` and `scope`, so
your verification page can show them before the user approves.

## Schema

| Table | Columns |
| --- | --- |
| `deviceCode` | `deviceCode` (unique), `userCode` (unique), `userId`, `expiresAt`, `status`, `lastPolledAt`, `pollingInterval`, `clientId`, `scope` |

::: warning Changed in 1.1
`deviceCode` and `userCode` are unique and limited to 191 characters.
`device_code_length` and `user_code_length` above 191 fail at startup, and a
custom generator that returns a longer code fails the request. Run your
migrations. See [Upgrade from 1.0](/migrate/from-1-0).
:::

## Notes

- Errors are OAuth-shaped on the wire (`{"error", "error_description"}`, RFC
  6749 style), not this port's usual `{"code", "message"}` envelope, matching
  TS.
- Redemption of an approved code is atomic (delete-and-return): concurrent
  pollers race on the same delete and exactly one mints a session. The pending
  claim and polling-interval bump use a guarded compare-and-swap, closing the
  race behind TS's GHSA-cq3f-vc6p-68fh fix.
- When a generated code collides with an existing one, a new pair is
  generated (up to 3 attempts).
- Pairs naturally with [OAuth Provider](./oauth-provider) when you are the
  authorization server.
