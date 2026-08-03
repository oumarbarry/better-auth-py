---
title: SIWE
---

# SIWE

Sign-In with Ethereum (ERC-4361) wallet authentication. You supply nonce
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
        SiwePlugin(domain="example.com", get_nonce=get_nonce, verify_message=verify_message)
    ],
)
```

## Options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `domain` | `str` | required | The domain the SIWE message must be bound to. |
| `get_nonce` | `callable` | required | `() -> str`, generates a nonce. |
| `verify_message` | `callable` | required | `(dict) -> bool`, recovers/checks the secp256k1 signature (bring your own web3 library). |
| `email_domain_name` | `str \| None` | `None` (origin of `base_url`) | Domain for the generated placeholder email. |
| `anonymous` | `bool` | `True` | Allow wallet-only accounts; `False` requires an email in the verify body. |
| `ens_lookup` | `callable \| None` | `None` | Resolve ENS name/avatar for new users. |

## Endpoints

| Method | Path |
| --- | --- |
| POST | `/siwe/nonce` |
| POST | `/siwe/get-nonce` (alias) |
| POST | `/siwe/verify` |

## Schema

| Table | Columns |
| --- | --- |
| `walletAddress` | `userId`, `address`, `chainId`, `isPrimary`, `createdAt` |

## Notes

- The plugin ships its own ERC-4361 message parser (ported verbatim from TS
  `parse-message.ts`) — it does not trust `verify_message` for message-body
  validation; your callable only has to check the signature.
- Addresses are EIP-55 checksummed via keccak256 (`pycryptodome`); hashlib's
  `sha3_256` is FIPS-202 SHA3 and cannot be used for this.
