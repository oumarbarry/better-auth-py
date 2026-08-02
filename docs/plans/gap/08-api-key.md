# API Key (`@better-auth/api-key`) — Python parity spec

Scope: port the plugin package `@better-auth/api-key` to the Python port. This is a single-table
credential plugin: it mints long-lived API keys, verifies them (with atomic per-key quota + rate
limiting), optionally mocks a session from a key, and exposes CRUD. Source read from
`packages/api-key/` (~4.8k src LOC + ~6k test LOC) at the pinned TS repo (v1.6.23).

Cross-runtime compatibility is a hard requirement: an `apikey` row written by the TS plugin must
verify in the Python port and vice-versa — identical table/column names (camelCase) and, above all,
an **identical key-hash encoding** (base64url-nopad SHA-256 over the full `prefix+random` string).

Conventions:
- Endpoint paths are relative to the auth mount (TS registers under the base path, e.g. `/api-key/create`).
- Schema field names are the **exact camelCase** column names the plugin uses by default.
- "internalAdapter" / "adapter" refer to the Python `InternalAdapter` (`internal_adapter.py`) and
  `BaseAdapter` (`adapters/base.py`) seams — **both already exist**. TS `ctx.context.internalAdapter.*`
  maps to `ctx.internal.*`; TS `ctx.context.adapter.*` to `ctx.adapter.*`.
- TS `file.ts:NN` anchors are into `packages/api-key/src/`.

Unlike the OAuth-provider plugin (gap 07), this plugin uses the port's **standard `APIError`
`{code, message}` envelope everywhere** — the error codes and messages line up 1:1 with the port's
`error_codes` ClassVar. There is exactly one envelope divergence (the `verify` wrapper) plus one
`APIError.details` gap (rate-limit `tryAgainIn`); see the reconciliation section. This makes the port
mostly plugin-local logic on existing seams.

---

## Python current state — foundations that already EXIST (do NOT re-spec as gaps)

Verified present and reusable — the plugin can be built almost entirely on these:

- **Key hasher, byte-exact** (`crypto.py:55`): `default_key_hasher(token)` = `b64url_encode_nopad(SHA-256(utf8(token)))`
  — **byte-for-byte identical** to the plugin's `defaultKeyHasher` (`index.ts:26`:
  `base64Url.encode(SHA-256(TextEncoder().encode(key)), {padding:false})`). This is the cross-runtime
  linchpin: a `key` column written by TS verifies in Python and vice-versa with no adaptation.
- **Random key generator** (`crypto.py:42`): `generate_random_string(size, alphabet)` (charset-parameterized).
  ⚠︎ The plugin generates with `generateRandomString(length, "a-z", "A-Z")` — a **52-char** alphabet
  (lowercase + uppercase, **no digits, no `-_`**), *not* the port's default `_RANDOM_ALPHABET`
  (`crypto.py:35`, which includes `0-9-_`). The port must pass the explicit 52-char alphabet.
  (Charset only affects entropy, not storage compat — the stored value is the hash — but match it for
  parity of `defaultKeyLength` entropy assumptions.)
- **Atomic CAS primitives** (`adapters/base.py`): **`increment_one(model, where, increment, set)`**
  (`base.py:138`) — re-applies `where` (incl. guards) as a compare-and-swap inside a `transaction`,
  returns the updated row or `None` on guard miss. This is exactly TS `incrementOne` and maps the
  remaining-decrement, rate-limit-increment, refill, and window-open CAS operations **directly**.
  `Where(field, value, operator, connector, mode)` with `eq|ne|gt|gte|lt|lte|in|not_in|...`
  (`base.py:19`). `consume_one` exists too (not needed here — keys are decremented, not consumed).
  `find_one`/`find_many` (sort_by/limit/offset)/`create`/`update`/`update_many`/`delete`/`delete_many`/`count`/`transaction`.
- **Role authorization** (`access_control.py:77-114`): `role(statements).authorize(request, connector)` →
  `{success, error?}` — **exactly** TS `role(apiKeyPermissions).authorize(permissions)` used by the
  verify permission gate (`verify-api-key.ts:130`). Handles the `[]`-vs-absent-key subtlety (documented
  in the port).
- **Organization permission check** (`plugins_ext/organization.py:246`): `has_permission(role, permissions,
  options, ac_roles, allow_creator_all_permissions)` + `creator_role` (default `"owner"`). Maps TS
  `checkOrgApiKeyPermission` → `hasPermission({permissions:{apiKey:[action]}, allowCreatorAllPermissions:true})`
  (`org-authorization.ts:120`). Member lookup via `ctx.adapter.find_one("member", …)`.
- **User lookup** (`internal_adapter.py`): `find_user_by_id(id)` — used by the session-mock hook and the
  org create-path (`index.ts` before-hook, `create-api-key.ts:290`).
- **Session from authoritative store** (`admin.py:253` precedent): `get_session(auth, request, disable_cache=True)`
  = TS `getSessionFromCtx(ctx, {disableCookieCache:true})` — create/update use this so a revoked/banned
  session cannot mint or mutate a key inside the cookie-cache window.
- **Session-mocking before-hook precedent** (`plugins_ext/bearer.py`): the exact shape of a matched
  `HookSet(before=[PluginHook(matcher, handler)])` that inspects headers, and (for `/get-session`) the
  pattern of injecting a session. `client_ip` for the mock's `ipAddress` (`types.py:44`).
- **Plugin contract** (`plugins.py`): `Plugin` with `id`, `version`, `schema` (ClassVar), `error_codes`
  (ClassVar → `auth.error_codes`, = TS `$ERROR_CODES`), `init(auth)`, `routes()` → `[(method, path, handler)]`,
  `hooks()` → `HookSet(before=[PluginHook{matcher, handler}], after=[…])`, `rate_limit()` → `[RateLimitRule]`.
  A before handler returning an `AuthResponse` short-circuits (the `/get-session` mock path).
- **Schema `Field`** (`schema.py:38`): `type` includes `string|number|boolean|date|datetime|json|text`;
  `index`, `input`, `returned`, `default`, `default_factory`, `field_name`, `references`, `bigint`,
  **`transform_input`** (TS `transform.input` — used for metadata stringify). ⚠︎ **No `transform_output`**
  (only `transform_input` exists, `schema.py:59`) — so metadata JSON must be parsed in the route handler,
  which is what the TS routes do anyway. `merge_schema` for the `options.schema` override.
- **Secondary storage protocol** (`secondary_storage.py:16`): `SecondaryStorage{get,set,delete}` +
  `MemorySecondaryStorage`. Present but the plugin's secondary-storage *mode* logic (`adapter.ts`, ~800 LOC)
  is not — see Open questions (default: defer, ship `storage:"database"` only).
- **APIError** (`types.py:15`): `APIError(status, code, message)` renders `{code, message}` — matches every
  api-key error throw. ⚠︎ **No `details` field** — the rate-limit deny path's `details:{tryAgainIn}` +
  custom `code:"RATE_LIMITED"` has no home; see reconciliation.

Net: the genuinely new work is the plugin-local logic (schema, config normalization, 7 endpoints, the
atomic verify pipeline, the session-mock hook, the org gate). No new core primitive is required for the
database-mode happy path — `increment_one` already provides every CAS the concurrency tests assert.

---

## Package layout (what maps to what)

| TS file (`src/`) | LOC | Purpose | Python home |
|---|---|---|---|
| `index.ts` | 387 | Plugin factory, config normalization, multi-config validation, `defaultKeyHasher`, `defaultKeyGenerator`, the `/get-session` session-mock before-hook | `plugins_ext/api_key.py` (plugin class + hook) |
| `types.ts` | 386 | `ApiKeyConfigurationOptions` (config surface), `ApiKey` row type | folded into `api_key.py` (dataclass/TypedDict + defaults) |
| `schema.ts` | 204 | The single `apikey` table (21 cols) | `api_key.py` `schema` ClassVar |
| `error-codes.ts` | 47 | `API_KEY_ERROR_CODES` (34 codes) | `api_key.py` `error_codes` ClassVar |
| `rate-limit.ts` | 97 | `evaluateRateLimit` pure decision fn + `RateLimitDecision` | `api_key.py` `_evaluate_rate_limit` |
| `routes/index.ts` | 177 | `resolveConfiguration`, `configIdMatches`, `isDefaultConfigId`, `deleteAllExpiredApiKeys` (10s throttle) | `api_key.py` helpers |
| `routes/create-api-key.ts` | 535 | `POST /api-key/create` | `api_key.py` `_create` |
| `routes/verify-api-key.ts` | 631 | `POST /api-key/verify` (serverOnly) + `validateApiKey` + `claimUsageInDatabase` (the atomic core) | `api_key.py` `_verify`/`_validate_api_key`/`_claim_usage_db` |
| `routes/get-api-key.ts` | 250 | `GET /api-key/get` | `api_key.py` `_get` |
| `routes/update-api-key.ts` | 506 | `POST /api-key/update` | `api_key.py` `_update` |
| `routes/delete-api-key.ts` | 172 | `POST /api-key/delete` | `api_key.py` `_delete` |
| `routes/list-api-keys.ts` | 402 | `GET /api-key/list` (pagination, config grouping) | `api_key.py` `_list` |
| `routes/delete-all-expired-api-keys.ts` | 33 | `POST /api-key/delete-all-expired-api-keys` (serverOnly) | `api_key.py` `_delete_all_expired` |
| `org-authorization.ts` | 145 | `checkOrgApiKeyPermission` (org-owned keys) | `api_key.py` `_check_org_permission` |
| `adapter.ts` | 808 | Secondary-storage / customStorage / fallbackToDatabase / legacy-metadata migration | **deferred** (see Open questions) |
| `client.ts` | 24 | Client-side plugin (pathMethods) | out of server scope |
| `utils.ts` | 14 | `getDate`, `isAPIError` | inline one-liners |

**Recommendation: one module `plugins_ext/api_key.py`.** Justification: it is a single plugin over a
single table; the org path and rate-limit fn are small and share the config/schema/hash core. Splitting
mid-plugin (e.g. verify into its own module) would create a shared-state seam across the config
resolver, the schema, and the hasher for no benefit. Estimated ~1.2–1.5k Python LOC for the
database-mode plugin (the ~800-LOC `adapter.ts` secondary-storage layer is deferred). If secondary
storage is later built, split it into `api_key/adapter.py` behind the `storage` switch.

---

## Area 1 — Endpoints

| method | path | body/query | auth | TS anchor |
|---|---|---|---|---|
| POST | `/api-key/create` | `{configId?, name?, expiresIn?, prefix?, remaining?, metadata?, refillAmount?, refillInterval?, rateLimitTimeWindow?, rateLimitMax?, rateLimitEnabled?, permissions?, userId?, organizationId?}` | session (client) OR `userId`/server | `create-api-key.ts:132` |
| POST | `/api-key/verify` | `{key, configId?, permissions?}` | **serverOnly** | `verify-api-key.ts:426` |
| GET | `/api-key/get` | query `{id, configId?}` | `sessionMiddleware` | `get-api-key.ts:44` |
| POST | `/api-key/update` | `{keyId, configId?, userId?, name?, enabled?, remaining?, refillAmount?, refillInterval?, metadata?, expiresIn?, rateLimitEnabled?, rateLimitTimeWindow?, rateLimitMax?, permissions?}` | session (client) OR `userId`/server | `update-api-key.ts:123` |
| POST | `/api-key/delete` | `{keyId, configId?}` | `sessionMiddleware` | `delete-api-key.ts:39` |
| GET | `/api-key/list` | query `{configId?, organizationId?, limit?, offset?, sortBy?, sortDirection?}` | `sessionMiddleware` | `list-api-keys.ts:81` |
| POST | `/api-key/delete-all-expired-api-keys` | — | **serverOnly** | `delete-all-expired-api-keys.ts:9` |

**serverOnly** = `createAuthEndpoint.serverOnly` — reachable only via `auth.api.*` (no HTTP mount). The
port's convention (see `one_time_token.py` / admin serverOnly notes) is to gate on `ctx.request is None`
(direct API call) vs an HTTP request. `verify` and `delete-all-expired` are server-only; the rest are
HTTP-mounted but distinguish client (`ctx.request`/`ctx.headers` present) from direct API calls.

**Client/server property split** (create + update, `create-api-key.ts:266`, `update-api-key.ts:277`): an
HTTP/client request that sets any **server-only property** — `remaining` (create: `!== null`; update:
`!== undefined`), `refillAmount`, `refillInterval`, `rateLimitMax`, `rateLimitTimeWindow`,
`rateLimitEnabled`, `permissions` — is rejected `BAD_REQUEST SERVER_ONLY_PROPERTY`. A client request
that sets `userId` (create, `ctx.request` present) is rejected `UNAUTHORIZED UNAUTHORIZED_SESSION`.

---

## Area 2 — Schema (`apikey` table, exact camelCase, `schema.ts`)

One table. PK `id` (auto). All fields `input: false` **except `metadata`**. Columns:

| column | type | required | default | index | notes |
|---|---|---|---|---|---|
| `configId` | string | ✓ | `"default"` | ✓ | which config minted the key; `null`/`undefined`/`"default"` all treated equal (`configIdMatches`) |
| `name` | string | — | — | | `input:false` |
| `start` | string | — | — | | first N chars of the full key (plaintext, for UI) |
| `referenceId` | string | ✓ | — | ✓ | owner: `userId` **or** `organizationId` per config's `references` |
| `prefix` | string | — | — | | plaintext prefix |
| `key` | string | ✓ | — | ✓ | **hashed** key (base64url-nopad SHA-256 of `prefix+random`), or plaintext if `disableKeyHashing` |
| `refillInterval` | number | — | — | | ms between refills |
| `refillAmount` | number | — | — | | amount to refill `remaining` to |
| `lastRefillAt` | date | — | — | | last refill timestamp |
| `enabled` | boolean | — | `true` | | disabled keys reject on verify |
| `rateLimitEnabled` | boolean | — | `true` | | per-key rate-limit toggle |
| `rateLimitTimeWindow` | number | — | `defaultTimeWindow` | | ms window (default 86_400_000) |
| `rateLimitMax` | number | — | `defaultRateLimitMax` | | max requests/window (default 10) |
| `requestCount` | number | — | `0` | | requests in current window |
| `remaining` | number | — | — | | remaining uses; `null` = unlimited |
| `lastRequest` | date | — | — | | last verify timestamp |
| `expiresAt` | date | — | — | | key expiry; `null` = never |
| `createdAt` | date | ✓ | — | | |
| `updatedAt` | date | ✓ | — | | |
| `permissions` | string | — | — | | **JSON string** (`{resource:[actions]}`); route stringifies/parses manually |
| `metadata` | string | — | — | | `input:true`, `transform.input`=`JSON.stringify`, `transform.output`=`parseJSON` |

`defaultTimeWindow`/`defaultRateLimitMax` are baked into the schema defaults from the **single** config's
`rateLimit` (or `10` / `86_400_000` when multiple configs, `index.ts:110`).

Cross-runtime notes:
- `permissions` is a plain `string` column holding a JSON object; the TS route does
  `JSON.stringify(permissions)` on write and `safeJSONParse` on read. Port: store the JSON string, parse
  in the handler. (It is **not** a `json`-typed column and has no schema transform.)
- `metadata` uses the schema `transform.input` to stringify on write. Port: `Field(type="string",
  input=True, transform_input=json.dumps)`. On read, parse in the handler (port `Field` has no
  `transform_output`). A `json`-typed column would also work but diverges from the TS storage shape (TS
  stores a stringified JSON in a string column) — **keep it a `string` column with `transform_input` for
  byte-parity of the stored value.**
- Dates are `type:"date"`. The port's `datetime` type maps; the row-level ISO serialization only matters
  for the (deferred) secondary-storage path.

---

## Area 3 — Config surface (`ApiKeyConfigurationOptions`, `types.ts`) with ALL defaults

The plugin factory takes **either** a single config object, **or an array** of configs (multi-config).
Array form: every entry must have a unique `configId`, else `BetterAuthError` at construction
(`index.ts:50-60`). A second `options` arg (or the single object's `schema`) carries the
`schema` override.

Per-config, normalized defaults (`index.ts:69-108`):

| option | default | notes |
|---|---|---|
| `configId` | `"default"` (single) | required+unique in array form |
| `apiKeyHeaders` | `"x-api-key"` | string or string[] — headers scanned for the key in the session hook |
| `disableKeyHashing` | `false` | ⚠︎ plaintext storage; `key` column = the raw key |
| `defaultKeyLength` | `64` | random part length (excludes prefix) |
| `defaultPrefix` | `undefined` | prepended to the key and stored plaintext |
| `maximumPrefixLength` / `minimumPrefixLength` | `32` / `1` | |
| `requireName` / `maximumNameLength` / `minimumNameLength` | `false` / `32` / `1` | |
| `enableMetadata` | `false` | metadata rejected `METADATA_DISABLED` when off |
| `startingCharactersConfig` | `{shouldStore:true, charactersLength:6}` | `start` = first `charactersLength` chars |
| `keyExpiration` | `{defaultExpiresIn:null, disableCustomExpiresTime:false, minExpiresIn:1, maxExpiresIn:365}` | min/max in **days**; `defaultExpiresIn` in **seconds** |
| `rateLimit` | `{enabled:true, timeWindow:86_400_000, maxRequests:10}` | ms window |
| `enableSessionForAPIKeys` | `false` | enables the `/get-session` mock hook |
| `permissions` | `undefined` | `{defaultPermissions: Statements \| (refId, ctx)=>Statements}` |
| `storage` | `"database"` | `"database"` \| `"secondary-storage"` (deferred) |
| `fallbackToDatabase` | `false` | secondary-storage only (deferred) |
| `customStorage` | `undefined` | `{get,set,delete}` (deferred) |
| `deferUpdates` | `false` | needs `advanced.backgroundTasks` (deferred — see Open questions) |
| `references` | `"user"` | `"user"` \| `"organization"` — determines `referenceId` + ownership model |
| `customAPIKeyGetter` / `customAPIKeyValidator` / `customKeyGenerator` | `undefined` | callbacks |
| `schema` | `undefined` | `merge_schema` override |

`resolveConfiguration(ctx, configs, configId)` (`routes/index.ts:44`): returns the config matching
`configId`, else the default config (`configId` unset or `"default"`); throws `BAD_REQUEST
NO_DEFAULT_API_KEY_CONFIGURATION_FOUND` if no default exists. `configIdMatches(keyCfg, expected)` treats
`null`/`undefined`/`"default"` as equal (backward-compat for pre-configId rows). `isDefaultConfigId`
likewise.

---

## Area 4 — Key generation & hashing (cross-runtime, EXACT)

**This is the storage-compat linchpin. Get it byte-exact.**

1. **Generate** (`index.ts:120` `defaultKeyGenerator`): `random = generateRandomString(defaultKeyLength,
   "a-z", "A-Z")` (52-char alphabet, default length 64); `fullKey = f"{prefix or ''}{random}"`. Port:
   `generate_random_string(length, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")` then prepend
   `prefix`. A `customKeyGenerator({length, prefix})` overrides.
2. **Hash for storage** (`create-api-key.ts:409`): `stored_key = disableKeyHashing ? fullKey :
   defaultKeyHasher(fullKey)`. **The prefix is part of the hashed string** — the hash covers
   `prefix+random`, not just the random part. Port: `default_key_hasher(full_key)` =
   `b64url_encode_nopad(sha256(full_key.encode()))`. **Byte-identical to TS.** A TS-written `key` column
   verifies in Python and vice-versa.
3. **`start`** (`create-api-key.ts:414`): if `startingCharactersConfig.shouldStore`, `start =
   fullKey[:charactersLength]` (default 6, **includes** the prefix); else `null`.
4. **Verify lookup** (`verify-api-key.ts:44`): re-hash the presented key the same way, `getApiKey` by the
   hashed `key` column (exact-match `find_one("apikey", [Where("key", hashed)])` in database mode).
5. **Length gate** (session hook, `index.ts:190`): the before-hook rejects a presented key
   `< config.defaultKeyLength` (FORBIDDEN INVALID_API_KEY) **before** any hash/DB hit — a cheap DoS guard.

The full returned key is sent to the caller **only** on create (`create-api-key.ts:490`); every other
endpoint strips `key` from responses (`const {key:_, ...rest} = apiKey`).

---

## Area 5 — Create (`create-api-key.ts`)

Order of operations (`create-api-key.ts:255`):
1. `opts = resolveConfiguration(configId)`; `keyGenerator = opts.customKeyGenerator ?? defaultKeyGenerator`.
2. `session = getSessionFromCtx(ctx, {disableCookieCache:true})` — authoritative store, so a
   revoked/banned session cannot mint a key inside the cookie-cache window (`create-api-key.ts:264`).
3. Server-only-property gate (client + any server-only prop set → `BAD_REQUEST SERVER_ONLY_PROPERTY`);
   client + `userId` (with `ctx.request`) → `UNAUTHORIZED UNAUTHORIZED_SESSION`.
4. **Reference resolution**:
   - `references:"organization"`: require `organizationId` (`BAD_REQUEST ORGANIZATION_ID_REQUIRED`);
     `userId = session.user.id ?? body.userId` (`UNAUTHORIZED` if none); `checkOrgApiKeyPermission(ctx,
     userId, orgId, "create")`; `referenceId = orgId`.
   - `references:"user"` (default): client → `referenceId = session.user.id` (`UNAUTHORIZED` if none);
     server → `referenceId = sessionUserId ?? body.userId` (reject if a session AND a mismatching body
     `userId` are both present, `create-api-key.ts:317`).
5. Validation gates → `BAD_REQUEST` with the exact code:
   - `metadata` set but `enableMetadata:false` → `METADATA_DISABLED`; non-object → `INVALID_METADATA_TYPE`.
   - `refillAmount` xor `refillInterval` → `REFILL_AMOUNT_AND_INTERVAL_REQUIRED` /
     `REFILL_INTERVAL_AND_AMOUNT_REQUIRED`.
   - `expiresIn` (seconds) with `disableCustomExpiresTime:true` → `KEY_DISABLED_EXPIRATION`; else
     `expiresIn/86400` days outside `[minExpiresIn, maxExpiresIn]` → `EXPIRES_IN_IS_TOO_SMALL` / `_LARGE`.
   - `prefix` length outside `[min,max]PrefixLength` → `INVALID_PREFIX_LENGTH`.
   - `name` length outside `[min,max]NameLength` → `INVALID_NAME_LENGTH`; absent + `requireName` →
     `NAME_REQUIRED`.
6. `deleteAllExpiredApiKeys(ctx)` (throttled sweep).
7. Generate + hash (Area 4). Compute `start`. Resolve `permissions` (body → JSON string; else
   `opts.permissions.defaultPermissions` (value or `(refId, ctx)=>Statements`) → JSON string).
8. Build row: `remaining = (body.remaining === null) ? null : (body.remaining ?? refillAmount ?? null)`;
   `expiresAt = expiresIn ? now+expiresIn(s) : (defaultExpiresIn ? now+defaultExpiresIn(s) : null)`;
   `rateLimitMax/TimeWindow/Enabled` from body ?? config; `requestCount=0`; `configId = opts.configId ?? "default"`.
9. `create("apikey", data)`. Return the row **plus the raw `key`**, `metadata` (echoed object),
   `permissions` parsed to object.

---

## Area 6 — Verify (`verify-api-key.ts`) — the atomic core

`POST /api-key/verify` (serverOnly) and the internal `validateApiKey` (also called by the session hook).

### Response envelope (⚠︎ divergent — see reconciliation)
`verify` **never throws to the caller**. It returns HTTP 200:
- success → `{valid:true, error:null, key:{…row without `key`, metadata parsed, permissions parsed}}`.
- failure → `{valid:false, error:{message, code}, key:null}` — the caught `APIError`'s `body.message`/
  `body.code`, or a fallback `{message:INVALID_API_KEY, code:"INVALID_API_KEY"}` (`verify-api-key.ts:540`).
- scoped-config custom-validator fail → `{valid:false, error:{message:INVALID_API_KEY,
  code:"KEY_NOT_FOUND"}, key:null}` (`verify-api-key.ts:470`).

### `validateApiKey` (`verify-api-key.ts:24`)
1. `hashedKey = disableKeyHashing ? key : default_key_hasher(key)`; `apiKey = getApiKey(hashedKey,
   lookupOpts)`. Not found → `UNAUTHORIZED INVALID_API_KEY`.
2. **Config scoping**: if `expectedConfigId` set and `!configIdMatches(apiKey.configId, expectedConfigId)`
   → `UNAUTHORIZED INVALID_API_KEY` (a key can't be verified under the wrong config).
3. **Switch to the key's own config**: `opts = resolveConfiguration(apiKey.configId)` — an unscoped
   verify uses the key's config for storage/hashing/rate-limit, not the lookup config
   (`verify-api-key.ts:63`).
4. `runCustomValidator && opts.customAPIKeyValidator` → invalid → `UNAUTHORIZED KEY_NOT_FOUND`. (Scoped
   calls already ran it against the correct config; unscoped runs it here — **once**, test 1987/4225.)
5. `enabled === false` → `UNAUTHORIZED KEY_DISABLED`.
6. **Expiry**: `expiresAt` in the past → delete the key (storage-appropriate) then `UNAUTHORIZED
   KEY_EXPIRED`.
7. **Permissions** (if `permissions` arg given): parse `apiKey.permissions` JSON; missing →
   `UNAUTHORIZED KEY_NOT_FOUND`; `role(perms).authorize(requested)` fail → `UNAUTHORIZED KEY_NOT_FOUND`.
8. **Exhausted non-refillable**: `remaining === 0 && refillAmount === null` → delete + `TOO_MANY_REQUESTS
   USAGE_EXCEEDED`.
9. **Claim usage** (`claimUsageInDatabase`, database mode): consume quota + a rate-limit slot atomically.

### `claimUsageInDatabase` (`verify-api-key.ts:198`) — maps to `increment_one` CAS
Runs three guarded steps; each `increment_one` guard lives in the `where`, so concurrent verifications
cannot violate the invariants (this is what tests 5102 / 5130 assert):

**(a) `consumeRemaining`** (only if `remaining !== null`, `verify-api-key.ts:245`):
- **Refill (CAS on observed `lastRefillAt`)**: if `refillInterval && refillAmount && now -
  (lastRefillAt ?? createdAt) > refillInterval`:
  `increment_one(where=[id==id, lastRefillAt==observed], increment={}, set={remaining: refillAmount-1,
  lastRefillAt: now})`. Winner returns; loser (another verify already refilled) **falls through**.
- **Decrement (CAS on `remaining>0`)**: `increment_one(where=[id==id, remaining gt 0],
  increment={remaining:-1})`. `None` → `TOO_MANY_REQUESTS USAGE_EXCEEDED`. → guarantees remaining never
  goes negative under concurrency.

**(b) `consumeRateLimit`** (`verify-api-key.ts:290`), driven by `evaluateRateLimit` (below):
- `deny` → raise `TOO_MANY_REQUESTS` with `code:"RATE_LIMITED"`, `details:{tryAgainIn}` (⚠︎ details gap).
- `skip` → if `lastRequest===null` return row unchanged; else `update(set lastRequest)`.
- `increment` → `increment_one(where=[id==id, lastRequest gt windowStart, requestCount lt max],
  increment={requestCount:1}, set={lastRequest: now})`. `None` (window rolled / max hit between read and
  write) → re-`find_one` fresh row and **recurse** `consumeRateLimit`.
- `start`/`reset` → `increment_one(where=[id==id, windowGuard], increment={}, set={requestCount:1,
  lastRequest: now})` where `windowGuard = reset ? (lastRequest lte windowStart) : (lastRequest eq null)`.
  `None` (another verify opened the window) → re-`find_one` fresh and **recurse** (so this request
  consumes an increment slot instead of resetting).

**(c) Final stamp** (`verify-api-key.ts:225`): `update(where=[id==id], set={updatedAt: now})`. `None` (row
deleted concurrently, e.g. revoked mid-verify) → `UNAUTHORIZED INVALID_API_KEY` — **do not** re-cache the
in-memory row (test 5037: "should not recreate a key deleted during verification"; test 4958: "should
not re-enable a key disabled during verification").

### `evaluateRateLimit` (`rate-limit.ts:53`) — pure decision fn, no writes
```
if opts.rateLimit.enabled is False           -> skip(lastRequest=now)
if apiKey.rateLimitEnabled is False           -> skip(lastRequest=now)
if rateLimitTimeWindow is None or rateLimitMax is None -> skip(lastRequest=None)   # no write
if lastRequest is None                        -> start(now)
delta = now - lastRequest
if delta > rateLimitTimeWindow                -> reset(now, windowStart=now-window)
if requestCount >= rateLimitMax               -> deny(msg=RATE_LIMIT_EXCEEDED, tryAgainIn=ceil(window-delta))
else                                          -> increment(now, max, windowStart=now-window)
```

---

## Area 7 — The `/get-session` session-mock hook (`index.ts:165`)

A **before-hook** matched on `findApiKeyAndConfig(ctx)` — scans, per config with
`enableSessionForAPIKeys:true`, the configured `apiKeyHeaders` (or `customAPIKeyGetter`) for a key
(`index.ts:135`). When one is found:

1. Non-string key → `BAD_REQUEST INVALID_API_KEY_GETTER_RETURN_TYPE`.
2. `key.length < config.defaultKeyLength` → `FORBIDDEN INVALID_API_KEY` (pre-DB length gate).
3. `config.customAPIKeyValidator({ctx, key})` falsy → `FORBIDDEN INVALID_API_KEY`.
4. `validateApiKey({key, ctx, lookupOpts:config, expectedConfigId:config.configId, ...})` — the full
   verify pipeline (Area 6), so a request bearing a valid key **consumes quota + a rate-limit slot** and
   can 429 (test 1023). `runCustomValidator` is off here (already ran at step 3, avoiding double-run).
5. `deleteAllExpiredApiKeys` sweep.
6. **User-owned only**: `config.references ?? "user"` must be `"user"`, else `UNAUTHORIZED
   INVALID_REFERENCE_ID_FROM_API_KEY` (test 4705: no session mocking for org keys). Load
   `find_user_by_id(apiKey.referenceId)`; missing → `UNAUTHORIZED INVALID_REFERENCE_ID_FROM_API_KEY`.
7. Build a **mock session** (not persisted):
   ```
   session = {
     user,
     session: {
       id: apiKey.id, token: key, userId: apiKey.referenceId,
       userAgent: request "user-agent" or null,
       ipAddress: getIp(request, options) or null,      # port: request.client_ip
       createdAt: now, updatedAt: now,
       expiresAt: apiKey.expiresAt or now + (options.session.expiresIn or 7d),
     }
   }
   ctx.context.session = session          # port: set on ctx so downstream sees it
   ```
8. If `ctx.path === "/get-session"` → **return the session** (short-circuits the endpoint). Else return
   `{context: ctx}` (continue with the session attached).

Port mapping: a `HookSet(before=[PluginHook(matcher=_has_api_key, handler=_session_hook)])`. Set
`ctx.session` (mirroring `bearer.py`'s cookie injection but here the session object is synthesized
directly). For `/get-session`, return an `AuthResponse(body=session)` to short-circuit. The
`options.session.expiresIn` default is 7 days (`60*60*24*7`).

---

## Area 8 — Get / Update / Delete / List

All resolve `lookupOpts` from `configId`, fetch by id, then **`configIdMatches` gate** (mismatch →
`NOT_FOUND KEY_NOT_FOUND`), then re-resolve `opts` from the key's own `configId`, then **ownership**:
`references:"organization"` → `checkOrgApiKeyPermission(ctx, userId, referenceId, action)`; else
`referenceId !== session.user.id` → `NOT_FOUND KEY_NOT_FOUND`.

- **get** (`get-api-key.ts`): `sessionMiddleware`; action `"read"`; strips `key`; parses `metadata` +
  `permissions`.
- **update** (`update-api-key.ts:277`): `getSessionFromCtx({disableCookieCache:true})` (server-only-prop
  gate as create); action `"update"`. Field-by-field builds `newValues` with the same validation
  (name length, `expiresIn` days range or `null` to clear expiry, metadata object when `enableMetadata`,
  refill pair, rate-limit fields, `permissions` → JSON string). **Empty patch → `BAD_REQUEST
  NO_VALUES_TO_UPDATE`.** `update("apikey", where=[id], newValues)`. Notably update does **not**
  touch `lastRequest`/`requestCount`/`remaining` implicitly (tests 1566/1585) — only what's in the body.
  `remaining` via update has zod `.min(1)` (can't set 0), create allows `.min(0)`.
- **delete** (`delete-api-key.ts:96`): `sessionMiddleware`; **`session.user.banned === true` →
  `UNAUTHORIZED USER_BANNED`** (only delete checks banned); action `"delete"`; `delete("apikey",
  [id])`; returns `{success:true}`.
- **list** (`list-api-keys.ts:334`): `sessionMiddleware`; `organizationId` present →
  `checkOrgApiKeyPermission(read)` and `referenceId = organizationId` (else `session.user.id`). In
  database mode, `listApiKeys` fans out to `find_many` + `count` by `referenceId`. Filters to keys whose
  config `references` matches the expected owner type AND `referenceId` matches; optional `configId`
  filter; **pagination applied after filtering** (`slice(offset)` then `slice(0, limit)`); returns
  `{apiKeys:[…without `key`, metadata/permissions parsed], total, limit, offset}`.

**`deleteAllExpiredApiKeys`** (`routes/index.ts:96`): module-level `lastChecked` timestamp; skips if
`< 10_000ms` since last run (unless bypassed). `delete_many("apikey", [expiresAt lt now, expiresAt ne
null])`. Fired opportunistically (fire-and-forget) by every route. Port: a module-level `datetime` +
`delete_many`. The serverOnly `/api-key/delete-all-expired-api-keys` endpoint calls it with
`bypassLastCheckTime=true` and returns `{success, error}` (catches internally).

---

## Area 9 — Organization-owned keys (`org-authorization.ts`)

`references:"organization"` routes ownership through `checkOrgApiKeyPermission(ctx, userId, orgId,
action)` where `action ∈ create|read|update|delete`:
1. Resolve org options (`ctx.context.orgOptions` or the installed `organization` plugin's options); absent
   → `INTERNAL_SERVER_ERROR ORGANIZATION_PLUGIN_REQUIRED`.
2. `member = adapter.find_one("member", [userId==userId, organizationId==orgId])`; absent → `FORBIDDEN
   USER_NOT_MEMBER_OF_ORGANIZATION`.
3. `hasPermission({role: member.role, options, permissions:{apiKey:[action]}, organizationId,
   allowCreatorAllPermissions:true})` (`org-authorization.ts:120`); falsy → `FORBIDDEN
   INSUFFICIENT_API_KEY_PERMISSIONS`. Org **owners** (config `creatorRole`, default `"owner"`) get full
   access via `allowCreatorAllPermissions`.

Port mapping: `organization.has_permission(role, {"apiKey":[action]}, options, ac_roles,
allow_creator_all_permissions=True)` (`organization.py:246`). ⚠︎ The org's access-control statements must
declare an `apiKey` resource with the four actions — the org-api-key tests add `apiKey:
["create","read","update","delete"]` to the org roles. This is a **caller-configured** statement, not
something the api-key plugin registers.

---

## Error codes (exact strings, `error-codes.ts`)

34 codes surfaced via `$ERROR_CODES` → port `error_codes` ClassVar (code → message). Key ones:
`INVALID_METADATA_TYPE`, `REFILL_AMOUNT_AND_INTERVAL_REQUIRED`, `REFILL_INTERVAL_AND_AMOUNT_REQUIRED`,
`USER_BANNED`, `UNAUTHORIZED_SESSION`, `KEY_NOT_FOUND`, `KEY_DISABLED`, `KEY_EXPIRED`, `USAGE_EXCEEDED`,
`KEY_NOT_RECOVERABLE`, `EXPIRES_IN_IS_TOO_SMALL`, `EXPIRES_IN_IS_TOO_LARGE`, `INVALID_REMAINING`,
`INVALID_PREFIX_LENGTH`, `INVALID_NAME_LENGTH`, `METADATA_DISABLED`, `RATE_LIMIT_EXCEEDED`,
`NO_VALUES_TO_UPDATE`, `KEY_DISABLED_EXPIRATION`, `INVALID_API_KEY`, `INVALID_USER_ID_FROM_API_KEY`,
`INVALID_REFERENCE_ID_FROM_API_KEY`, `INVALID_API_KEY_GETTER_RETURN_TYPE`, `SERVER_ONLY_PROPERTY`,
`FAILED_TO_UPDATE_API_KEY`, `NAME_REQUIRED`, `ORGANIZATION_ID_REQUIRED`,
`USER_NOT_MEMBER_OF_ORGANIZATION`, `INSUFFICIENT_API_KEY_PERMISSIONS`,
`NO_DEFAULT_API_KEY_CONFIGURATION_FOUND`, `ORGANIZATION_PLUGIN_REQUIRED`. Copy the exact messages from
`error-codes.ts` verbatim (cross-runtime message parity for clients that string-match).

---

## Security properties asserted by tests (must-preserve checklist)

1. **Key hashing on by default**: `key` stored as base64url-nopad SHA-256 of the full `prefix+random`
   (test 384/417 for the `disableKeyHashing` escape hatch). Cross-runtime storage-compatible.
2. **Pre-DB length gate**: session hook rejects keys shorter than `defaultKeyLength` before hashing/lookup.
3. **Atomic remaining**: concurrent verifications never drive `remaining` below zero (CAS `remaining>0`,
   test 5102).
4. **Atomic rate limit**: concurrent verifications never exceed `rateLimitMax` in a window (CAS
   `requestCount<max`, test 5130); refill is single-winner (CAS on `lastRefillAt`, test 2492).
5. **No stale write-back**: verify never re-enables a key disabled mid-verify (test 4958/5016) and never
   recreates a key deleted mid-verify (final-update `None` → INVALID_API_KEY, test 5037).
6. **Config scoping**: a key from config A can't verify (test 4154) or session-mock (test 2019) under
   config B; session mocking is user-owned only (test 4705).
7. **Server-only-property gate**: client requests can't set remaining/refill/rateLimit/permissions
   (create test 536/891, update test 277) or `userId` (create test 111).
8. **Ownership isolation**: a user only reads/updates/deletes their own keys (`referenceId ===
   session.user.id`) or via org membership + `apiKey` permission (org tests 110/182/669).
9. **Banned gate**: a banned user can't delete keys (test uses `USER_BANNED`).
10. **Session authoritativeness**: create/update resolve the session with `disableCookieCache:true` so a
    revoked/banned session can't mint/mutate keys in the cookie-cache window.
11. **Custom validator runs once** on the session path (test 1987) and the key's-own validator is used on
    unscoped verify (test 4225/4261).
12. **Expiry/exhaustion cleanup**: expired keys and exhausted non-refillable keys are deleted on verify
    (tests 1115/1091) and swept opportunistically (`deleteAllExpiredApiKeys`).

---

## Error-envelope reconciliation (flag every divergence)

Unlike gap 07, **almost every endpoint uses the port's native `APIError {code, message}`** — the TS
`APIError.from("STATUS", API_KEY_ERROR_CODES.X)` maps directly to the port's `APIError(status, code,
message)` (the code = the ERROR_CODES key, the message = its value). No OAuth-shaped body, no redirects.
Divergences to handle:

1. **`/api-key/verify` wrapped response** (`verify-api-key.ts:508-563`): verify **catches** its internal
   `APIError` and returns **HTTP 200** `{valid:false, error:{message, code}, key:null}` (or `{valid:true,
   error:null, key}`). The port must replicate this wrapper — do **not** let the `APIError` propagate as a
   4xx. The `error.code`/`error.message` come from the caught `APIError`'s body.
2. **Rate-limit deny `details`** (`verify-api-key.ts:302`, `verify-api-key.ts:497`): the deny path raises
   `APIError("TOO_MANY_REQUESTS", {message, code:"RATE_LIMITED", details:{tryAgainIn}})` — a **custom code
   `"RATE_LIMITED"`** (not an ERROR_CODES key) plus a **`details` field the port's `APIError` lacks**
   (`types.py:15` has only status/code/message). Options: (a) extend `APIError` with an optional
   `details`/`body` extra (smallest, benefits future plugins), or (b) surface `tryAgainIn` only inside the
   verify wrapper's `error` object and drop it from the raw before-hook 429 (tests only assert the 429
   status, test 1023, not the body). **Default: (b) for now** — carry `tryAgainIn` in the verify wrapper,
   omit from the bare `APIError`; revisit if a client depends on `Retry-After`.
3. **`/api-key/delete-all-expired-api-keys`** returns `{success, error}` at 200 (catches internally) — not
   an APIError.
4. **`deleteApiKey`/`updateApiKey` storage errors** wrap adapter exceptions in `INTERNAL_SERVER_ERROR`
   with the raw message (`delete-api-key.ts:154`, `update-api-key.ts:...`). Map to
   `APIError(500, "INTERNAL_SERVER_ERROR", str(e))`.

There is no OAuth-error helper needed. The `error_codes` ClassVar carries the full table for
`auth.error_codes` parity.

---

## Gap items — ordered (dependencies first)

Sizing: **S** ≈ hours, **M** ≈ a day, **L** ≈ multi-day. Database mode only; secondary-storage &
friends deferred (items 14–16).

1. **Schema** — `apikey` table (21 cols) via `Field`, incl. `metadata` `transform_input=json.dumps`,
   `configId`/`referenceId`/`key` indexes, dynamic `rateLimit*` defaults from the single config. **S**
2. **Config normalization + multi-config** — accept single-or-array, unique-`configId` validation,
   per-config defaults (Area 3), `resolveConfiguration`/`configIdMatches`/`isDefaultConfigId`. **M**
3. **Key gen + hash wiring** — `generate_random_string(len, 52-char alphabet)` + prefix; `default_key_hasher`
   over the full key; `start` slice; `disableKeyHashing` passthrough. **S** (reuses existing crypto)
4. **`evaluateRateLimit`** — pure decision fn (Area 6). **S**
5. **`deleteAllExpiredApiKeys`** — module-level 10s throttle + `delete_many`; serverOnly endpoint. **S**
6. **Error codes ClassVar** — verbatim 34-code table. **S**
7. **Create endpoint** — full validation matrix, session-from-store, server-only-prop gate, user/org
   reference resolution, permissions default, row build, raw-key return. **L** (deps 1–3)
8. **Verify endpoint + `validateApiKey` + `claimUsageInDatabase`** — the atomic pipeline (remaining CAS,
   rate-limit CAS, refill CAS, final-update null-guard), permission gate via `role().authorize()`,
   wrapped `{valid,error,key}` response. **L** (deps 1–4, hardest item; rests on `increment_one`)
9. **Get / Update / Delete / List** — config scoping, ownership, banned gate (delete), no-values gate
   (update), pagination + filtering (list), metadata/permissions parse. **M** (deps 1–3)
10. **`/get-session` session-mock before-hook** — header scan, length gate, custom validator, verify
    pipeline, user-owned-only gate, synthesized non-persisted session, `/get-session` short-circuit. **M**
    (deps 3, 8)
11. **Org authorization** — `checkOrgApiKeyPermission` via `organization.has_permission` + member lookup.
    **M** (dep: organization plugin installed; used by 7/9)
12. **Error-envelope reconciliation** — verify wrapper, `RATE_LIMITED` `tryAgainIn` handling (default (b)),
    delete-all-expired `{success,error}`. **S** (folded into 8)

**Deferred (default-off, independent bolt-ons):**
13. **Secondary-storage / customStorage / fallbackToDatabase** — `adapter.ts` (~800 LOC): serialize/
    deserialize, ref-list in-process lock, TTL, RMW quota path (explicitly non-atomic per TS FIXME). **L**
14. **`deferUpdates` / backgroundTasks** — port has no background-task runner (grep: none). **S** but
    needs infra. Default: no-op (run synchronously — stricter, correctness-preserving).
15. **Legacy double-stringified metadata migration** — greenfield has no legacy rows. **S**. Default: skip
    the DB heal, keep a defensive parse-on-read.

**Total: 12 build items (database mode) + 3 deferred.**

### Recommended dispatch grouping
**One primary agent** for items 1–12 (the whole database-mode plugin in `plugins_ext/api_key.py`). It is a
single plugin over one table; the config resolver, schema, hasher, and verify pipeline are tightly
coupled and splitting them creates a shared-state seam. ~1.2–1.5k LOC.

**One optional follow-up agent** for items 13–15 (secondary storage + deferUpdates + legacy migration) —
these hang cleanly off the `storage` switch and the (future) background-task runner, and are all
default-off. Don't block the primary port on them.

---

## Open questions (with defaults)

1. **Secondary storage / customStorage — support now or defer?** `adapter.ts` is ~800 LOC and its
   secondary-storage-*only* path is **explicitly non-atomic** (TS FIXMEs `api-key-reflist-durable`,
   `api-key-secondary-atomic`) — the concurrency guarantees the tests assert only hold in `database` mode
   (or `secondary-storage + fallbackToDatabase`, where the DB row is authoritative). **Default: ship
   `storage:"database"` only; raise `NotImplementedError` at plugin init when `storage != "database"` or
   `customStorage` is set**, with a message pointing at the follow-up. The database default covers the
   overwhelming majority of usage.

2. **`deferUpdates` + `backgroundTasks`.** The port has no `runInBackground`/`backgroundTasks` runner
   (grep confirms). **Default: treat `deferUpdates` as a no-op — always run updates synchronously.**
   Synchronous is *stricter* (no eventual-consistency window), so correctness is unaffected; only the
   latency optimization and the two deferral-behavior tests (3462/3550) are skipped. Add real deferral if
   the port later grows a background-task seam.

3. **Legacy double-stringified `metadata` migration.** The `parseDoubleStringifiedMetadata` /
   `migrateDoubleStringifiedMetadata` machinery heals TS rows where `metadata` was accidentally
   double-`JSON.stringify`d. A greenfield Python DB has no such rows. **Default: skip the DB write-back;
   keep a defensive read helper that tolerates `None`/object/string (parse-once) so a mixed TS/Python DB
   still reads.** The migration tests (3737–3955) target legacy healing, not core behavior.

4. **`metadata` column type — `string`+`transform_input` vs `json`.** TS stores a stringified JSON in a
   `string` column (via `transform.input`). The port `Field` has `transform_input` but **no
   `transform_output`** (`schema.py:59`), so reads parse in the route regardless. **Default: keep it a
   `string` column with `transform_input=json.dumps` (byte-parity of the stored value with TS) and parse
   in the handler** — do not switch to a `json` column, which would change the on-disk representation and
   break cross-runtime reads.

5. **`APIError.details` for rate-limit `tryAgainIn` + custom `RATE_LIMITED` code.** The port's `APIError`
   has no `details` slot. **Default: carry `tryAgainIn` inside the verify wrapper's `error` object only;
   emit the bare before-hook 429 without it** (tests assert status, not body). If a `Retry-After`/details
   contract emerges, extend `APIError` with an optional `details`/`body` extra (a small, broadly useful
   core addition).

6. **`references:"organization"` requires the organization plugin AND an `apiKey` access-control
   statement.** The plugin does not register the statement; the caller must add `apiKey:
   ["create","read","update","delete"]` to their org roles (as the tests do). **Default: document this as
   a caller requirement; at the org create/read/update/delete path, surface
   `ORGANIZATION_PLUGIN_REQUIRED` when the org plugin is absent** (matching TS), and rely on
   `organization.has_permission` returning falsy (→ `INSUFFICIENT_API_KEY_PERMISSIONS`) when the statement
   is missing.
