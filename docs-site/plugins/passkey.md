---
title: Passkey
---

# Passkey

WebAuthn/FIDO2 registration and authentication — Touch ID, Windows Hello,
hardware keys. Mirrors the TS `@better-auth/passkey` plugin. Requires the
`passkey` extra (`pip install "better-auth-server[passkey]"`, which pulls in
`webauthn`).

## Enable

```python
from better_auth import BetterAuth
from better_auth.plugins_ext import PasskeyPlugin

auth = BetterAuth(
    secret="a-strong-32-character-minimum-secret",
    plugins=[
        PasskeyPlugin(rp_id="example.com", rp_name="Example", origin="https://example.com")
    ],
)
```

## Options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `rp_id` | `str \| None` | `None` (hostname of `base_url`) | The relying-party id — the registrable domain, no scheme. |
| `rp_name` | `str` | `"Better Auth"` | Human-readable relying-party name. |
| `origin` | `str \| list[str] \| None` | `None` (request `Origin` header) | Expected WebAuthn origin(s). |
| `authenticator_selection` | `dict \| None` | `None` | WebAuthn authenticator selection criteria, e.g. `{"residentKey": "preferred", "userVerification": "preferred"}`. |
| `challenge_cookie` | `str` | `"better-auth-passkey"` | Name of the signed challenge cookie. |
| `registration` | `dict \| None` | `None` | Registration ceremony overrides. |
| `authentication` | `dict \| None` | `None` | Authentication ceremony overrides. |

## Endpoints

7 routes under `/passkey/`:

| Method | Path |
| --- | --- |
| GET | `/passkey/generate-register-options` |
| POST | `/passkey/verify-registration` |
| GET | `/passkey/generate-authenticate-options` |
| POST | `/passkey/verify-authentication` |
| GET | `/passkey/list-user-passkeys` |
| POST | `/passkey/delete-passkey` |
| POST | `/passkey/update-passkey` |

## Schema

| Table | Columns |
| --- | --- |
| `passkey` | `name`, `publicKey`, `userId`, `credentialID`, `counter`, `deviceType`, `backedUp`, `transports`, `createdAt`, `aaguid` |

## Notes

- Cross-runtime storage parity is exact: `publicKey` is standard padded base64
  of the raw COSE bytes, `credentialID` is unpadded base64url, `deviceType` is
  camelCase (`"singleDevice"`/`"multiDevice"`) — a row written by the TS plugin
  verifies here and vice versa.
- Challenges are single-use: a signed cookie (max age 300s) plus a verification
  row consumed atomically on verify.
- Importing `better_auth.plugins_ext` without the `passkey` extra installed
  raises `ModuleNotFoundError`.
