---
title: API Key
---

# API Key

Long-lived API keys backed by the database: create, list, update, delete and
verify, with prefixes, expiry windows, per-key rate limits, refill quotas,
metadata and permissions. Mirrors the TS `@better-auth/api-key` plugin
(database storage mode).

## Enable

```python
from better_auth import BetterAuth
from better_auth.plugins_ext import ApiKeyPlugin

auth = BetterAuth(
    secret="a-strong-32-character-minimum-secret",
    plugins=[
        ApiKeyPlugin(
            {"default_prefix": "sk_", "default_key_length": 64, "enable_metadata": True}
        )
    ],
)
```

## Options

Unlike the other plugins, configuration is a **dict** (or a list of dicts, each
carrying a `config_id`), not kwargs — mirroring the TS multi-config shape.

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `config` | `dict \| list[dict] \| None` | `None` | Snake_case option dict(s) mirroring the TS `apiKey()` options — e.g. `default_prefix`, `default_key_length`, `enable_metadata`, `rate_limit`, `key_expiration`, `permissions`. |
| `schema` | `Schema \| None` | `None` | Override the generated `apikey` table definition. |

## Endpoints

| Method | Path |
| --- | --- |
| POST | `/api-key/create` |
| GET | `/api-key/get` |
| POST | `/api-key/update` |
| POST | `/api-key/delete` |
| GET | `/api-key/list` |

The TS `serverOnly` endpoints are plugin methods, never mounted as HTTP routes
(the [Email OTP](./email-otp) precedent): `verify_api_key(...)` and
`delete_all_expired_api_keys(ctx)`. The HTTP create/update routes always run
the TS "client" path (rejecting server-only props and `userId`); the
`create_api_key` / `update_api_key` methods run the "server" path.

## Schema

| Table | Columns |
| --- | --- |
| `apikey` | `configId`, `name`, `start`, `referenceId`, `prefix`, `key`, `refillInterval`, `refillAmount`, `lastRefillAt`, `enabled`, `rateLimitEnabled`, `rateLimitTimeWindow`, `rateLimitMax`, `requestCount`, `remaining`, `lastRequest`, `expiresAt`, `createdAt`, `updatedAt`, `permissions`, `metadata` |

## Notes

- Cross-runtime storage parity: the `key` column is base64url-nopad SHA-256 of
  `prefix + random`, byte-identical to the TS `defaultKeyHasher` — a row
  written by the TS plugin verifies here and vice versa.
- `storage: "database"` only; `secondary-storage` / `customStorage` raise
  `NotImplementedError` at construction.
- Quota/rate-limit updates use a guarded compare-and-swap against the DB row,
  so exactly one concurrent verify wins a `remaining` decrement.
