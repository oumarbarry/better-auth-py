---
title: Sign-In with Ethereum
---

# Sign-In with Ethereum

Sign-In with Ethereum (SIWE, ERC-4361) wallet authentication. You supply nonce
generation and signature verification; the plugin owns message parsing and the
session half. Mirrors the TS `siwe()` plugin.

## Enable

```python
from better_auth import BetterAuth
from better_auth.plugins_ext import SiwePlugin

async def get_nonce():
    ...  # return a fresh nonce string

async def verify_message(args):
    ...  # {"message", "signature", "address", "chainId", ...} -> bool

auth = BetterAuth(
    secret="a-strong-32-character-minimum-secret",
    plugins=[
        SiwePlugin(
            domain="example.com", get_nonce=get_nonce, verify_message=verify_message
        )
    ],
)
```

## Options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `domain` | `str` | required | The domain the SIWE message must be bound to. |
| `get_nonce` | `callable` | required | `() -> str`, generates a nonce: 8 to 250 letters and digits. |
| `verify_message` | `callable` | required | `(dict) -> bool`, recovers/checks the secp256k1 signature (bring your own web3 library). |
| `email_domain_name` | `str \| None` | `None` | Domain for the generated email of a new wallet user. Without it the email is `<address>@siwe.placeholder.invalid`. |
| `anonymous` | `bool` | `True` | Allow wallet-only accounts; `False` requires an email in the verify body. |
| `ens_lookup` | `callable \| None` | `None` | Resolve ENS name/avatar for new users. |
| `accept_legacy_wallet_fields` | `bool` | `False` | Accept and ignore the `walletAddress`, `address` and `chainId` body fields that 1.0 clients send. |

## Endpoints

| Method | Path |
| --- | --- |
| POST | `/siwe/nonce` |
| POST | `/siwe/get-nonce` (alias) |
| POST | `/siwe/verify` |

`/siwe/nonce` takes an empty body and returns

```json
{
  "nonce": "..."
}
```

The nonce is stored in the `verification` table under `siwe:<nonce>` and
expires after 15 minutes. `get_nonce` must return 8 to 250 letters and
digits, otherwise the endpoint fails with a 500 `SIWE_INVALID_NONCE`.

`/siwe/verify` takes `message`, `signature` and an optional `email`. The
wallet address and chain id are read from the signed message, never from the
body. The nonce in the message is consumed on the first attempt, whether it
succeeds or not. Any other body field is a 400 `INVALID_BODY`, unless
`accept_legacy_wallet_fields=True`.

::: warning Changed in 1.1
In 1.0 the client sent `walletAddress` and `chainId` to `/siwe/nonce` and
`/siwe/verify`. They now come from the signed message, and these fields are
refused unless `accept_legacy_wallet_fields=True`. Nonces issued by 1.0 stop
working after the upgrade. New wallet users get
`<address>@siwe.placeholder.invalid` (was built from the `base_url` origin) unless
`email_domain_name` is set.
See [Upgrade from 1.0](/migrate/from-1-0).
:::

## Schema

| Table | Columns |
| --- | --- |
| `walletAddress` | `userId`, `address`, `chainId`, `isPrimary`, `createdAt` |

## Notes

- The plugin ships its own ERC-4361 message parser (ported verbatim from TS
  `parse-message.ts`). It does not trust `verify_message` for message-body
  validation; your callable only has to check the signature.
- With `anonymous=False`, the email from the verify body is used for a new
  user only if no other user has it. The email is held by a short
  reservation while the user is created, so two wallets cannot claim it at
  once. When it is taken, the user gets the generated email instead, with no
  error, so the endpoint does not reveal which emails exist.
- When `user.validate_user_info` is set, it runs before a new wallet user is
  created, with `source` set to `{"action": "create-user", "method": "siwe"}`.
- Addresses are EIP-55 checksummed via keccak256 (`pycryptodome`); hashlib's
  `sha3_256` is FIPS-202 SHA3 and cannot be used for this.
