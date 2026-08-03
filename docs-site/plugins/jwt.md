---
title: JWT
---

# JWT

Issues signed JWTs for the current session and publishes a JWKS so other
services can verify them without calling back. Mirrors the TS `jwt()` plugin.

## Enable

```python
from better_auth import BetterAuth
from better_auth.plugins_ext import JWTPlugin

auth = BetterAuth(
    secret="a-strong-32-character-minimum-secret",
    plugins=[JWTPlugin(expiration_time="15m")],
)
```

## Options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `remote_url` | `str \| None` | `None` | Point `/jwks` consumers at a remote JWKS instead of local keys. |
| `key_pair_config` | `dict \| None` | `None` (`{"alg": "EdDSA", "crv": "Ed25519"}`) | Key algorithm config; the TS `JWKOptions` union: EdDSA/Ed25519, ES256, ES512, PS256, RS256. |
| `disable_private_key_encryption` | `bool` | `False` | Store private keys unencrypted. |
| `rotation_interval` | `int \| None` | `None` | Rotate the signing key every N seconds. |
| `grace_period` | `int` | `2592000` | How long rotated-out keys stay in the JWKS (30 days). |
| `jwks_path` | `str` | `"/jwks"` | Route where the JWKS is published. |
| `issuer` | `str \| None` | `None` (`base_url`) | `iss` claim. |
| `audience` | `str \| list[str] \| None` | `None` (`base_url`) | `aud` claim. |
| `expiration_time` | `int \| float \| datetime \| str` | `"15m"` | Token lifetime (seconds or a duration string). |
| `define_payload` | `callable \| None` | `None` | Custom payload builder from the session. |
| `get_subject` | `callable \| None` | `None` | Custom `sub` claim (defaults to the user id). |
| `sign` | `callable \| None` | `None` | Replace the signing routine entirely. |
| `disable_setting_jwt_header` | `bool` | `False` | Don't attach `set-auth-jwt` on `/get-session` responses. |

## Endpoints

| Method | Path |
| --- | --- |
| GET | `/jwks` (at `jwks_path`) |
| GET | `/token` |

## Schema

| Table | Columns |
| --- | --- |
| `jwks` | `id`, `publicKey`, `privateKey`, `createdAt`, `expiresAt` |

## Notes

- Storage parity: the `privateKey` codec is byte-compatible with TS — a `jwks`
  row written here is readable by a TS app sharing the database and vice versa.
  `alg`/`crv` are not persisted (TS declares no such columns); they are
  reconstructed from `key_pair_config` on read.
- Required by [oauth-provider](./oauth-provider) unless that plugin is
  configured with `disable_jwt_plugin=True`.
