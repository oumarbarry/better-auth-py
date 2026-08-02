# Passkey / WebAuthn (`@better-auth/passkey`) — Python parity spec

Scope: port the server package `@better-auth/passkey` (~1.9k src LOC) to the Python port. This is
the WebAuthn/FIDO2 passkey plugin: it generates registration/authentication ceremony options,
verifies the authenticator responses, persists one `passkey` row per credential, and mints a
session on successful authentication. The TS package is a **thin wrapper over
`@simplewebauthn/server`**; the Python port will wrap **`webauthn` (py_webauthn)** — same author,
same crypto, but a different call surface (bytes vs base64url, pydantic option models). Source read
from `packages/passkey/src/` at the pinned TS repo (v1.6.23).

Cross-runtime compatibility is a **hard requirement**: a `passkey` row written by the TS plugin must
verify under Python and vice-versa. That pins the on-disk encoding of every credential column
(`credentialID`, `publicKey`, `counter`, `transports`, `deviceType`, `backedUp`, `aaguid`) to the
exact bytes the TS verifier writes. The `@simplewebauthn` ↔ `py_webauthn` type mismatch (notably
`credentialDeviceType`) is the single biggest storage hazard and is spelled out below.

Conventions:
- Endpoint paths are relative to the auth mount (`/passkey/...`).
- Schema field names are the **exact camelCase** column names the plugin uses by default.
- `internalAdapter` / `adapter` refer to the Python `InternalAdapter` (`internal_adapter.py`) and
  `BaseAdapter` (`adapters/base.py`). TS `ctx.context.internalAdapter.*` → `ctx.internal.*`; TS
  `ctx.context.adapter.*` → `ctx.adapter.*`.
- TS `file.ts:NN` anchors are into `packages/passkey/src/`.

---

## Python current state — foundations that already EXIST (do NOT re-spec as gaps)

Verified present and reusable (the plugin is small; almost every primitive it needs already exists):

- **Plugin contract** (`plugins.py`): `Plugin` base with `id`, `version`, `schema` (ClassVar),
  `error_codes` (ClassVar → `auth.error_codes`), `init(auth)`, `routes()` → `[(method, path,
  handler)]`, `hooks()`, `rate_limit()`. Endpoint handlers receive `Ctx` and return `AuthResponse`.
- **Ctx / request surface** (`types.py`): `Ctx.body()` (parsed JSON dict), `ctx.request.query`
  (dict), `ctx.request.headers` (lower-cased), `ctx.request.cookies()`, `ctx.get_session()` /
  `ctx.require_session()` → `{"session", "user"}`, `ctx.adapter`, `ctx.internal`, `ctx.auth`.
  `AuthResponse(status, body, headers, redirect_to, media_type)` with `set_cookie(value)`. `APIError(status, code, message)` renders `{"code", "message"}`.
- **Verification store, atomic single-use** (`internal_adapter.py`): `create_verification_value(
  identifier, value, expires_at)`, `find_verification_value(identifier)`,
  **`consume_verification_value(identifier)`** (per-identifier `asyncio.Lock` + adapter transaction,
  delete-all-rows-for-identifier, returns `None` past `expiresAt`). This is the **exact** analogue of
  TS `createVerificationValue` / `consumeVerificationValue` the plugin relies on for challenge
  single-use — the two passkey concurrency tests rest on this.
- **Session/user surface** (`internal_adapter.py` + `session.py`): `create_session(auth, user_id,
  request, ...)` → `(session, cookies)`; `internal.find_user_by_id`; `session.build_cookie` /
  `cookie_name(auth, base)` / `clear_cookie` / `sign_value` / `unsign_value`. The two-factor and
  magic-link plugins already use exactly this pattern (signed cookie carrying a random token that
  indexes a verification row → consume on verify → `create_session` → set session cookie).
- **Crypto** (`crypto.py`): `generate_random_string(size, alphabet)` (default charset
  `a-z0-9A-Z-_`, matches TS `generateRandomString`), `b64url_encode_nopad`/`b64url_decode_nopad`,
  stdlib `base64.b64encode` (standard, padded — used at `crypto.py:100`). Signed-cookie codec
  (`sign_value`/`unsign_value`) is TS `setSignedCookie`/`getSignedCookie` byte-parity.
- **Cookie naming** (`session.py:27`): `cookie_name(auth, base)` = `{cookie_prefix}.{base}` with a
  `__Secure-` prefix over HTTPS — the port's analogue of TS `ctx.context.createAuthCookie(name)`.
- **Schema `Field`** (`schema.py`): `type` (`string`/`number`/`boolean`/`date`/…),
  `references=Reference(model, field)`, `index`, `required`, `input`, `returned`, `field_name`.
  Covers every passkey column (all scalar; no `json`/`string[]` needed).
- **Auth attributes** (`auth.py`): `auth.secret`, `auth.base_url` (rstrip'd), `auth.cookie_prefix`,
  `auth.use_secure_cookies`, `auth.plugins`, `auth.adapter`, `auth.internal`.

Net: the only genuinely new pieces are (a) the **py_webauthn wrapper** (options-gen + verify, with
the encoding translation below), (b) a small **resource-ownership guard** for delete/update (the port
has no `requireResourceOwnership` middleware), and (c) two missing niceties — a **fresh-session**
notion and an **app-name** default for `rpName`. Everything else is plugin-local glue.

---

## Package layout (what maps to what)

| TS file (`src/`) | LOC | Purpose | Python home |
|---|---|---|---|
| `index.ts` | 68 | Plugin factory, option defaults (`origin:null`, `advanced.webAuthnChallengeCookie`), endpoint wiring, `mergeSchema`, `$ERROR_CODES`, `MAX_AGE_IN_SECONDS=300` | `plugins_ext/passkey.py` (`Passkey(Plugin)`) |
| `routes.ts` | 1140 | All 7 endpoints + `resolveRegistrationUser`/`resolveExtensions` helpers | `plugins_ext/passkey.py` (route methods) |
| `schema.ts` | 55 | The single `passkey` table | folded into the plugin `schema` ClassVar |
| `types.ts` | 167 | `PasskeyOptions`, `Passkey`, `WebAuthnChallengeValue`, registration/authentication option interfaces | folded into the plugin (config dataclass) |
| `utils.ts` | 8 | `getRpID(options, baseURL)` | one helper (`_rp_id`) |
| `error-codes.ts` | 21 | `PASSKEY_ERROR_CODES` (14 codes) | `error_codes` ClassVar |
| `authenticator-metadata.ts` | ~70 | `commonAuthenticatorNames` AAGUID→label map + `getAuthenticatorName` | optional module-level dict + helper (display-only, see Open Q4) |
| `client.ts` | — | **Client-side** `passkeyClient()` (browser `navigator.credentials` wrapper) | **out of server scope** — see Open questions |

`@simplewebauthn/server` calls (`generateRegistrationOptions`, `verifyRegistrationResponse`,
`generateAuthenticationOptions`, `verifyAuthenticationResponse`) → `webauthn` (py_webauthn) — full
mapping in its own section below.

---

## Endpoints

| method | path | body / query | auth | notes |
|---|---|---|---|---|
| GET | `/passkey/generate-register-options` | query `{authenticatorAttachment?, name?, context?}` | **freshSession** if `registration.requireSession` (default true); else optional | Mints registration challenge. `routes.ts:123` (factory), impl `routes.ts:274` |
| POST | `/passkey/verify-registration` | `{response: RegistrationResponseJSON, name?}` | **freshSession** if `requireSession`; else `getSessionFromCtx` | Verifies + inserts `passkey` row, returns the row. `routes.ts:536` |
| GET | `/passkey/generate-authenticate-options` | — | optional session (scopes `allowCredentials`) | Mints authentication challenge. `routes.ts:356` |
| POST | `/passkey/verify-authentication` | `{response: AuthenticationResponseJSON}` | none (passkey IS the credential) | Verifies, bumps `counter`, mints session, sets session cookie, returns `{session, user}`. `routes.ts:725` |
| GET | `/passkey/list-user-passkeys` | — | session | `findMany passkey where userId=session.user.id`. `routes.ts:926` |
| POST | `/passkey/delete-passkey` | `{id}` | session **+ owner** | `requireResourceOwnership` middleware then `delete`. Returns `{status:true}`. `routes.ts:993` |
| POST | `/passkey/update-passkey` | `{id, name}` (name trimmed, `min(1)`) | session **+ owner** | Updates `name`, returns `{passkey}`. `routes.ts:1069` |

Server API method names (for `auth.api.*` parity): `generatePasskeyRegistrationOptions`,
`verifyPasskeyRegistration`, `generatePasskeyAuthenticationOptions`, `verifyPasskeyAuthentication`,
`listPasskeys`, `deletePasskey`, `updatePasskey`.

**Ownership guard** (`deletePasskey`/`updatePasskey`, `routes.ts:998`/`1074`): TS uses the shared
`requireResourceOwnership({model:"passkey", idParam:"id", idSource:"body", notFoundError:
PASSKEY_NOT_FOUND, forbiddenStatus:"UNAUTHORIZED"})` middleware — load the row by `id`, 404
(`PASSKEY_NOT_FOUND`) if missing, `UNAUTHORIZED` if `row.userId !== session.user.id`. The port has
**no such middleware** → inline the check in each handler (or add a tiny shared helper). This is the
GHSA-4vcf-q4xf-f48m fix; tests assert cross-user delete/update both reject **and leave the row
intact** (`passkey.test.ts:445`, `:496`).

---

## `passkey` table — exact columns (`schema.ts:3`) + cross-runtime encodings

The table name is `passkey` (camelCase columns). PK `id` is auto (better-auth default id). All
columns are **scalar** — no `json`/array types.

| column | `Field` type | req | index | TS value written (anchor) | cross-runtime encoding (CRITICAL) |
|---|---|---|---|---|---|
| `id` | (auto PK) | — | — | better-auth generated id | opaque; not cross-verified |
| `name` | `string` | no | — | `resolvedName` (trimmed client name → `afterVerification.name` → undefined) `routes.ts:687` | plain UTF-8 string or NULL |
| `publicKey` | `string` | **yes** | — | `base64.encode(credential.publicKey)` `routes.ts:686` | **standard base64, PADDED** of the raw COSE public-key bytes. `@better-auth/utils` `base64.encode` is the non-url-safe, padded alphabet (`+`/`/`/`=`). Python: `base64.b64encode(pub_bytes).decode()`. **NOT base64url.** On auth TS decodes with `base64.decode` (`routes.ts:834`). |
| `userId` | `string` (ref `user.id`) | **yes** | **yes** | resolved target user id `routes.ts:689` | plain id (FK) |
| `credentialID` | `string` | **yes** | **yes** | `credential.id` `routes.ts:690` | **base64url, NO padding** — `@simplewebauthn` v13 `credential.id` is a `Base64URLString`. This is the lookup key on auth (`where credentialID == resp.id`, `routes.ts:811`) and the `excludeCredentials`/`allowCredentials` id. Python (py_webauthn) gets `credential_id: bytes` → must `bytes_to_base64url(...)` to match. |
| `counter` | `number` | **yes** | — | `credential.counter` at register (`0` typical), then `verification.authenticationInfo.newCounter` on each auth `routes.ts:692`/`:866` | plain integer (sign counter). py_webauthn: `sign_count` / `new_sign_count`. |
| `deviceType` | `string` | **yes** | — | `credentialDeviceType` `routes.ts:693` | **`"singleDevice"` \| `"multiDevice"`** (camelCase). ⚠️ py_webauthn returns `"single_device"` / `"multi_device"` (snake). Python **MUST map to camelCase** before storing or a TS-written vs Python-written row will diverge. |
| `backedUp` | `boolean` | **yes** | — | `credentialBackedUp` `routes.ts:695` | plain bool |
| `transports` | `string` | no | — | `resp.response.transports?.join(",") ?? ""` `routes.ts:694` | **comma-joined** transport strings (e.g. `"internal"`, `"usb,nfc"`, or `""`). NOT JSON. Read back via `split(",")` (`routes.ts:305`/`:487`/`:836`). Values are raw WebAuthn transport tokens: `usb`/`nfc`/`ble`/`internal`/`hybrid`/`cable`/`smart-card`. |
| `createdAt` | `date` | no | — | `new Date()` `routes.ts:696` | timestamp |
| `aaguid` | `string` | no | — | `aaguid` `routes.ts:697` | UUID string `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx` (all-zero for privacy-preserving/Apple-`none`). py_webauthn returns the same UUID-string form. |

> There is **no `updatedAt`** column in the schema, yet the `listPasskeys` OpenAPI marks `updatedAt`
> required (`routes.ts:948`) — that is a doc artifact; the table has none. Do not add one (would break
> cross-runtime shape). `name`, `transports`, `createdAt`, `aaguid` are `required:false`.

**Encoding summary (the four that bite):** `publicKey` = **standard base64 padded**; `credentialID`
= **base64url no-pad**; `deviceType` = **camelCase** (translate from py_webauthn snake_case);
`transports` = **comma-joined** raw tokens. Get any of these wrong and cross-runtime verify fails
silently (row present, signature check rejects).

---

## Challenge storage flow (between generate and verify)

The WebAuthn challenge lives in the **verification table**, indexed by a random token carried in a
**signed cookie**. One cookie + one verification row are shared by both ceremonies, disambiguated by a
`type` tag. Entirely single-runtime (mint and consume happen in the same process) — no cross-runtime
concern here, only the `passkey` rows are shared.

**Generate (both `generate-register-options` and `generate-authenticate-options`):**
1. `verificationToken = generateRandomString(32)` (default charset `a-z0-9A-Z-_`) `routes.ts:321`/`:500`.
2. Set a **signed cookie** named `<cookie_prefix>.better-auth-passkey` (TS
   `ctx.context.createAuthCookie(opts.advanced.webAuthnChallengeCookie)`, default cookie base
   `"better-auth-passkey"`), value = `setSignedCookie(verificationToken)`, **`maxAge = 300`** (5 min)
   `routes.ts:322`/`:334`. Port: `build_cookie(auth, sign_value(secret, token), max_age=300)` under
   `cookie_name(auth, "better-auth-passkey")`.
3. `createVerificationValue({identifier: verificationToken` (**RAW, not hashed**)`, value:
   JSON.stringify(StoredChallengeValue), expiresAt: now + 300s})` `routes.ts:335`/`:514`.
   `expiresAt` is computed **per-request** (`Date.now()` at call time, not init) — asserted by the
   `expirationTime per-request` tests (`passkey.test.ts:1303`).

`StoredChallengeValue` JSON (`routes.ts:42`, `types.ts:16`):
- registration: `{"type":"registration", "expectedChallenge": <base64url challenge string>,
  "userData": {"id","name","displayName"}, "context": <string|null>}` `routes.ts:337`.
- authentication: `{"type":"authentication", "expectedChallenge": <base64url challenge>,
  "userData": {"id": <sessionUserId | "">}}` `routes.ts:493`.

**Verify (both verifiers):**
1. Read signed cookie → `getSignedCookie` → `verificationToken`; missing → `CHALLENGE_NOT_FOUND`
   (`routes.ts:578`/`:774`). Port: `unsign_value(secret, cookies[cookie_name])`.
2. **`consumeVerificationValue(verificationToken)`** — atomic delete-and-return, single-use; `None` →
   `CHALLENGE_NOT_FOUND` (`routes.ts:590`/`:786`). This is what makes concurrent verifies mint at most
   one row/session (both race tests). Port: `internal.consume_verification_value(token)`.
3. **Ceremony gate**: parse `value`, read `type`. If `type !== undefined && type !== <thisCeremony>`
   → `CHALLENGE_NOT_FOUND` **before** calling the WebAuthn library or touching the DB
   (`routes.ts:608`/`:801`). A legacy row with no `type` (pre-upgrade) is accepted by either verifier.
   Tests assert the cross-ceremony rejection happens before `verify*Response` is invoked
   (`passkey.test.ts:963`, `:1018`).

---

## Wire JSON shapes of the four ceremony endpoints

These follow `@simplewebauthn`'s `PublicKeyCredentialCreationOptionsJSON` /
`PublicKeyCredentialRequestOptionsJSON`; py_webauthn's `options_to_json` emits the identical shape.
The verifiers accept the browser's `RegistrationResponseJSON` / `AuthenticationResponseJSON`
verbatim (better-auth passes `ctx.body.response` straight through).

**`generate-register-options` → 200** (`generateRegistrationOptions`, `routes.ts:296`):
```
{
  challenge: string(base64url),
  rp: { name: string, id: string },
  user: { id: string(base64url), name: string, displayName: string },
  pubKeyCredParams: [{ type: "public-key", alg: number }],
  timeout: number,                     // 60000 default
  excludeCredentials: [{ id: string(base64url), type: "public-key", transports?: string[] }],
  authenticatorSelection: { authenticatorAttachment?, residentKey, requireResidentKey, userVerification },
  attestation: "none",
  extensions?: object
}
```
- `rpName` = `opts.rpName || ctx.context.appName`; `rpID` = `getRpID` (below); `userID` =
  UTF-8 bytes of `generateRandomString(32,"a-z","0-9")` (fresh per request, base64url'd in `user.id`)
  `routes.ts:289`; `userName` = `query.name || user.name || user.id`; `userDisplayName` =
  `user.displayName || user.name || user.id`; `attestationType:"none"`; `excludeCredentials` = the
  caller's existing passkeys (`{id: credentialID, transports: split(",")}`) `routes.ts:303`;
  `authenticatorSelection` = `{residentKey:"preferred", userVerification:"preferred",
  ...opts.authenticatorSelection, ...(query.authenticatorAttachment ? {authenticatorAttachment} : {})}`
  `routes.ts:309`.

**`generate-authenticate-options` → 200** (`generateAuthenticationOptions`, `routes.ts:478`):
```
{
  challenge: string(base64url),
  timeout: number,
  rpId: string,                        // note: `rpId`, camelCase (test asserts this key)
  allowCredentials?: [{ id: string(base64url), type: "public-key", transports?: string[] }],
  userVerification: "preferred",
  extensions?: object
}
```
- `allowCredentials` present only if a session exists (scoped to that user's passkeys); absent →
  discoverable-credential flow (`passkey.test.ts:319`). `userVerification:"preferred"`.

**`verify-registration` → 200**: the created `passkey` row (the full object above).
**`verify-authentication` → 200**: `{session, user}` + `Set-Cookie` session cookie.

`getRpID(opts, baseURL)` (`utils.ts:3`): `opts.rpID || (baseURL ? new URL(baseURL).hostname :
"localhost")`. Port: `opts.rp_id or (urlsplit(auth.base_url).hostname or "localhost")`.

---

## Config surface (`PasskeyOptions`, `types.ts:99`) with ALL defaults

| option | default | notes |
|---|---|---|
| `rpID` | `hostname(baseURL)` or `"localhost"` | relying-party id (`getRpID`) |
| `rpName` | `ctx.context.appName` (TS default app name `"Better Auth"`) | human-readable RP name. ⚠️ port has no `appName` — supply a default (recommend literal `"Better Auth"`, or reuse `cookie_prefix`). |
| `origin` | **`null`** | expected origin(s) for verify; falls back to the request `origin` header when null. `string \| string[] \| null`. |
| `authenticatorSelection` | `{residentKey:"preferred", userVerification:"preferred"}` (base) | merged over the base on register options; `authenticatorAttachment` from the query overrides. |
| `advanced.webAuthnChallengeCookie` | `"better-auth-passkey"` | challenge cookie base name (`index.ts:38`). |
| `schema` | — | `InferOptionSchema` field/table renames (`mergeSchema`). |
| `registration.requireSession` | **`true`** | when true, register endpoints use `freshSessionMiddleware`; identity = session user. `types.ts:46`. |
| `registration.resolveUser` | — | required when `requireSession:false` and no session → resolves `{id, name, displayName?}` from `query.context`; missing → `RESOLVE_USER_REQUIRED`; invalid result → `RESOLVED_USER_INVALID`. `routes.ts:93`. |
| `registration.afterVerification` | — | post-verify hook `{ctx, verification, user, clientData, context}` → `{userId?, name?} | void`. May re-attribute `userId` (rejected if non-string/empty, or mismatches session user); may supply `name` fallback. `routes.ts:653`. |
| `registration.extensions` | — | WebAuthn extension inputs, static or `({ctx}) => …`. `routes.ts:285`. |
| `authentication.extensions` | — | same, for auth options. `routes.ts:474`. |
| `authentication.afterVerification` | — | `{ctx, verification, clientData} => void` after a verified auth. `routes.ts:849`. |

Constants: `MAX_AGE_IN_SECONDS = 300` (challenge cookie + verification TTL, `index.ts:31`);
`requireUserVerification: false` hard-coded in **both** verifiers (`routes.ts:635`/`:840`);
`attestationType: "none"` hard-coded (`routes.ts:302`).

**No rate-limit rules** are declared by this plugin (unlike oauth-provider) — it inherits the global
limiter only.

---

## Library mapping: `@simplewebauthn/server` → `webauthn` (py_webauthn)

py_webauthn (PyPI `webauthn`, same author as SimpleWebAuthn) is a near-1:1 port but with **bytes at
the boundary** where TS uses base64url strings, and **pydantic option models** instead of plain JSON.
Helpers live in `webauthn.helpers` (`bytes_to_base64url`, `base64url_to_bytes`, `options_to_json`).

| `@simplewebauthn/server` | py_webauthn | signature / format differences (and what Python must do) |
|---|---|---|
| `generateRegistrationOptions({rpName, rpID, userID:Uint8Array, userName, userDisplayName, attestationType:"none", excludeCredentials:[{id:b64url, transports}], authenticatorSelection, extensions})` → `PublicKeyCredentialCreationOptionsJSON` (already JSON) | `generate_registration_options(*, rp_id, rp_name, user_name, user_id: bytes, user_display_name, attestation=AttestationConveyancePreference.NONE, authenticator_selection: AuthenticatorSelectionCriteria, exclude_credentials: list[PublicKeyCredentialDescriptor], supported_pub_key_algs=…)` → `PublicKeyCredentialCreationOptions` (**pydantic model**) | (a) `exclude_credentials[].id` is **bytes** → `base64url_to_bytes(credentialID)`. (b) **No `extensions` param** — py_webauthn cannot inject extensions; see "lacks" below. (c) Serialize with `helpers.options_to_json(options)` (returns a JSON string with the correct camelCase + base64url). (d) `challenge` is bytes on the model → store `bytes_to_base64url(options.challenge)` as `expectedChallenge`. (e) default `supported_pub_key_algs` = `[ES256, RS256]`; `@simplewebauthn` offers `[EdDSA, ES256, RS256]` — pass `[-8,-7,-257]` explicitly to match `pubKeyCredParams`. |
| `verifyRegistrationResponse({response, expectedChallenge, expectedOrigin, expectedRPID, requireUserVerification:false})` → `{verified, registrationInfo:{aaguid, credentialDeviceType, credentialBackedUp, credential:{id:b64url, publicKey:Uint8Array, counter}}}` | `verify_registration_response(*, credential: str|dict, expected_challenge: bytes, expected_origin: str|list[str], expected_rp_id: str, require_user_verification=False)` → `VerifiedRegistration{credential_id: bytes, credential_public_key: bytes, sign_count: int, aaguid: str, credential_device_type: CredentialDeviceType, credential_backed_up: bool, …}` | `expected_challenge` is **bytes** → `base64url_to_bytes(expectedChallenge)`. Returned `credential_id: bytes` → `bytes_to_base64url(...)` for the `credentialID` column. `credential_public_key: bytes` → **standard** `base64.b64encode(...)` (NOT base64url). `sign_count` → `counter`. `credential_device_type` ∈ `{"single_device","multi_device"}` → **map to `"singleDevice"/"multiDevice"`**. `transports` come from the raw request (`response.response.transports`), NOT from py_webauthn. |
| `generateAuthenticationOptions({rpID, userVerification:"preferred", allowCredentials:[{id:b64url, transports}], extensions})` → `PublicKeyCredentialRequestOptionsJSON` | `generate_authentication_options(*, rp_id, user_verification=UserVerificationRequirement.PREFERRED, allow_credentials: list[PublicKeyCredentialDescriptor])` → `PublicKeyCredentialRequestOptions` | `allow_credentials[].id` is **bytes** → `base64url_to_bytes(credentialID)`. No `extensions` param (see lacks). `options_to_json` for the wire body; `bytes_to_base64url(options.challenge)` for storage. |
| `verifyAuthenticationResponse({response, expectedChallenge, expectedOrigin, expectedRPID, credential:{id:b64url, publicKey:Uint8Array, counter, transports}, requireUserVerification:false})` → `{verified, authenticationInfo:{newCounter}}` | `verify_authentication_response(*, credential: str|dict, expected_challenge: bytes, expected_rp_id, expected_origin, credential_public_key: bytes, credential_current_sign_count: int, require_user_verification=False)` → `VerifiedAuthentication{new_sign_count: int, credential_device_type, credential_backed_up, …}` | **Signature shape differs**: py_webauthn takes `credential_public_key` (bytes; `base64.b64decode(stored publicKey)` — **standard**, not base64url) and `credential_current_sign_count` (int) as **flat kwargs**, not a nested `credential` object. `expected_challenge` bytes. Result `new_sign_count` → write to `counter`. |

**Behaviors py_webauthn lacks / differs (with default recommendation):**
1. **WebAuthn extensions passthrough** — py_webauthn's `generate_*_options` do not accept an
   `extensions` argument, so `registration.extensions`/`authentication.extensions` cannot be injected
   through the library. *Default:* serialize with `options_to_json`, `json.loads` it, splice the
   resolved `extensions` dict into the top-level object, re-serialize. (Cheap; keeps option parity.)
   If deferred, document that `extensions` is a no-op in v1.
2. **`options_to_json` vs raw dict** — TS returns a plain JSON object it hands to `ctx.json`;
   py_webauthn returns a pydantic model. Always route through `helpers.options_to_json` (do **not**
   `model_dump()` naively — it would emit enum objects / bytes, not the base64url wire form).
3. **`credentialDeviceType` casing** — the storage hazard above. Add a 2-entry map
   (`single_device→singleDevice`, `multi_device→multiDevice`).
4. **Default offered algs** differ (`[-7,-257]` vs `[-8,-7,-257]`). *Default:* pass
   `supported_pub_key_algs=[-8,-7,-257]` explicitly so the advertised `pubKeyCredParams` match TS.
5. **`credential.id` / `credential_id` type** — bytes vs base64url string; always translate with the
   `helpers`. Never store the raw bytes' `str()`.

---

## Behaviors from tests (`passkey.test.ts`, the behavioral contract)

- **Options generation** sets the `better-auth-passkey` cookie (`:97`) and a verification row; register
  options carry `challenge`/`rp`/`user`/`pubKeyCredParams` (`:79`); auth options carry
  `challenge`/`rpId`/`allowCredentials`/`userVerification` (`:314`), and work **without a session**
  (discoverable) — then no `allowCredentials` (`:319`).
- **`requireSession:false` + `resolveUser`**: options succeed pre-auth (`:104`); missing `resolveUser`
  → `APIError` (`:128`).
- **`afterVerification`**: can override `userId` to link the passkey to another account (`:144`);
  rejects a non-string/empty `userId` → `RESOLVED_USER_INVALID` (`:208`); rejects a `userId` that
  mismatches the current session user → `UNAUTHORIZED` (`:265`); supplies a `name` fallback only when
  the client sent none/whitespace, but always runs (`:1240`–`:1301`).
- **Naming**: client name is **trimmed** and wins (`:1212`); whitespace-only → NULL (`:1221`); the
  server **never** derives a label from the AAGUID but persists the raw AAGUID (`:1230`).
- **Ceremony gating**: a registration challenge cannot be spent on authentication and vice-versa →
  `CHALLENGE_NOT_FOUND`, and the WebAuthn lib is **not** called (`:963`, `:1018`).
- **Empty resolved user id** at persist time → `RESOLVED_USER_INVALID`, no row written (`:1090`).
- **Concurrency**: two verifies of the same registration challenge → **exactly one** `passkey` row
  (`:728`); two verifies of the same auth challenge → **exactly one** session (`:827`). Both rest on
  `consumeVerificationValue` atomicity.
- **Consume returns null** (challenge not consumable) → `CHALLENGE_NOT_FOUND` (`:910`).
- **Auth success** bumps `counter` to `newCounter`, creates a session, sets the session cookie,
  returns `{session, user}` with the right user (`:544`).
- **Ownership (GHSA-4vcf-q4xf-f48m)**: another user's passkey cannot be deleted (`:445`) or updated
  (`:496`); the row is verified to still exist / be unchanged afterward.
- **Error propagation**: a failed registration verify surfaces `BAD_REQUEST` +
  `FAILED_TO_VERIFY_REGISTRATION` (`:621`); a failed auth verify surfaces `UNAUTHORIZED` +
  `AUTHENTICATION_FAILED` (`:654`) — the inner `APIError` is re-thrown unchanged, only unexpected
  errors are wrapped.
- **`expiresAt` is per-request**, computed at call time, not plugin-init (`:1303`).
- **Origin**: verify uses `opts.origin || header("origin") || ""`; empty → `BAD_REQUEST`
  (`FAILED_TO_VERIFY_REGISTRATION` for register `routes.ts:568`; `"origin missing"` for auth
  `routes.ts:766`).

---

## Security checklist (must-preserve)

1. **Challenge single-use under concurrency** — `consumeVerificationValue` atomic delete-and-return;
   N racing verifies → ≤1 passkey row / ≤1 session. (`internal.consume_verification_value` covers it.)
2. **Cross-ceremony isolation** — the stored `type` tag; a registration verifier rejects an
   authentication challenge (and vice-versa) **before** invoking WebAuthn or writing the DB.
3. **Challenge integrity/confidentiality** — token lives in a **signed** cookie (`sign_value`),
   verification row is server-side, 5-minute TTL, single-use.
4. **User binding on registration** — when a session exists, `userData.id` must equal
   `session.user.id` (`routes.ts:618`); an `afterVerification` `userId` override may not cross to a
   different session user (`routes.ts:668`); empty resolved id → reject, no dangling row.
5. **Resource ownership** — delete/update gated on `row.userId === session.user.id` (GHSA fix); on
   failure the row is left intact.
6. **Counter monotonicity** — `counter` advanced to `newCounter` after every auth (clone-detection
   signal the authenticator provides; py_webauthn enforces the comparison in
   `verify_authentication_response`).
7. **`requireUserVerification:false`** — intentional (broad authenticator support); do **not**
   silently flip it (would change verify semantics vs TS).
8. **Origin/RPID pinning** — verify pins `expectedOrigin` (configured or request header) and
   `expectedRPID` (`getRpID`); an empty origin is rejected.

---

## Error responses — envelope reconciliation

Unlike oauth-provider, passkey uses the **plain `APIError`** envelope throughout — no OAuth
`{error, error_description}` shape. Every error is `APIError.from(<STATUS>, PASSKEY_ERROR_CODES.<KEY>)`,
which better-auth renders as `{code: <KEY>, message: <text>}` (tests assert `body.code ===
"FAILED_TO_VERIFY_REGISTRATION"` etc., `passkey.test.ts:649`). This maps **directly** onto the port's
`APIError(status, code, message)` → `{"code","message"}`. No special helper needed.

`PASSKEY_ERROR_CODES` (`error-codes.ts:3`) → surface as the plugin's `error_codes` ClassVar (→
`auth.error_codes`). 14 codes, with their HTTP status at throw sites:
- `CHALLENGE_NOT_FOUND` (400) — missing cookie / unconsumable / wrong-ceremony challenge.
- `SESSION_REQUIRED` (401), `RESOLVE_USER_REQUIRED` (400), `RESOLVED_USER_INVALID` (400).
- `YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY` (401) — user-binding / ownership on update.
- `FAILED_TO_VERIFY_REGISTRATION` (400, or 500 on unexpected inner error).
- `PASSKEY_NOT_FOUND` (401 via ownership guard / auth lookup).
- `AUTHENTICATION_FAILED` (401 on `!verified`, 400 on unexpected inner error).
- `UNABLE_TO_CREATE_SESSION` (500), `FAILED_TO_UPDATE_PASSKEY` (500).
- `PREVIOUSLY_REGISTERED`, `REGISTRATION_CANCELLED`, `AUTH_CANCELLED`, `UNKNOWN_ERROR` — **client-side
  only** codes (used by `client.ts`); server surfaces them for parity but never throws them.

Note the status **asymmetry** in the auth verifier: `!verified` → `UNAUTHORIZED` +
`AUTHENTICATION_FAILED` (`routes.ts:843`), but an **unexpected exception** in the try block →
`BAD_REQUEST` + `AUTHENTICATION_FAILED` (`routes.ts:903`). Registration mirrors this
(`FAILED_TO_VERIFY_REGISTRATION` at 400 for `!verified`, 500 for unexpected). Preserve both — the
tests pin the `!verified` statuses.

---

## Gap items — ordered (dependencies first)

Sizing: **S** ≈ hours, **M** ≈ a day. The whole plugin is roughly **M–L total**; there are no
new shared-core primitives (all exist), only the py_webauthn wrapper and a couple of small helpers.

1. **py_webauthn wrapper module** — thin functions over `generate_registration_options` /
   `verify_registration_response` / `generate_authentication_options` /
   `verify_authentication_response`, encapsulating **all** the encoding translation from the mapping
   table (bytes↔base64url, standard-base64 publicKey, `deviceType` casing, `options_to_json`,
   challenge bytes↔base64url string, `supported_pub_key_algs=[-8,-7,-257]`). Add `webauthn` to
   `pyproject.toml`. **M** — the crux; every other item depends on it.
2. **`passkey` schema** — the 10 columns above via `Field` (indexes on `userId`, `credentialID`;
   FK `userId→user.id`). **S**
3. **Config dataclass + `_rp_id` + origin resolution + app-name default** — `PasskeyOptions`
   analogue, `getRpID` (`opts.rp_id or hostname(base_url) or "localhost"`), origin fallback
   (`opts.origin or header("origin")`), and an `rpName` default (port lacks `appName` → recommend
   `"Better Auth"`). **S**
4. **`generate-register-options`** — resolve registration user (session/`resolveUser`),
   `excludeCredentials` from existing passkeys, extensions resolve, mint challenge → signed cookie +
   verification row (per-request `expiresAt`), return `options_to_json`. **M** (dep 1–3)
5. **`generate-authenticate-options`** — optional-session `allowCredentials`, extensions, mint
   challenge, return. **S** (dep 1–3)
6. **`verify-registration`** — origin check, cookie→consume→ceremony gate, session/user binding,
   `verify_registration_response`, `afterVerification` (userId re-attribution + name fallback, with
   the mismatch/empty guards), insert `passkey` row, return it. **M** (dep 1,2,4)
7. **`verify-authentication`** — origin check, cookie→consume→ceremony gate, lookup passkey by
   `credentialID`, `verify_authentication_response`, `afterVerification`, bump `counter`,
   `create_session` + session cookie, return `{session, user}`. **M** (dep 1,2,5)
8. **Ownership guard + list/delete/update** — inline `requireResourceOwnership` (load by id, 404
   `PASSKEY_NOT_FOUND`, `UNAUTHORIZED` on user mismatch) for delete/update; `list` = findMany by
   userId; `update` trims name (`min(1)`). **S**
9. **`error_codes` ClassVar** (14 codes) + fresh-session handling for register endpoints (see Open
   Q3). **S**
10. *(optional)* **`authenticator-metadata`** — `commonAuthenticatorNames` dict + `getAuthenticatorName`
    (display-only helper; the server never uses it to label rows). **S** — include only if a Python
    consumer wants the label helper (Open Q4).

---

## Open questions (with defaults)

1. **`webauthn` (py_webauthn) as a dependency.** The port currently has no WebAuthn library. py_webauthn
   is the natural choice (same author, same crypto, `cbor2`+`cryptography` under the hood).
   *Default:* add `webauthn>=2` to `pyproject.toml` as a passkey extra (`better-auth[passkey]`), so the
   base install stays lean. Pin a version whose `VerifiedRegistration`/`VerifiedAuthentication` field
   names match the mapping table (v2.x).

2. **Extensions passthrough** (py_webauthn lacks an `extensions` param). *Default:* splice resolved
   `extensions` into the `options_to_json` output (documented above) so `registration.extensions` /
   `authentication.extensions` keep working. If time-boxed, ship v1 with `extensions` a no-op and flag
   it — no test exercises extensions, so it is low-risk to defer.

3. **`freshSessionMiddleware`** — TS gates the register endpoints on a *fresh* session (session
   `createdAt` within `session.freshAge`, better-auth default `60*60*24` = 1 day), not merely a valid
   one. The port has only `require_session`, no freshness notion. *Default:* implement a small
   freshness check (`now - session.createdAt <= freshAge`, default 1 day, config-driven) for the two
   register endpoints; if deferred, use `require_session` and document the (minor) weaker guarantee —
   no passkey test asserts freshness, but it is a real security posture difference.

4. **Client-side `passkeyClient()` (`client.ts`)** — the browser wrapper around
   `navigator.credentials.create/get` + the `PREVIOUSLY_REGISTERED`/`*_CANCELLED` client codes. This is
   not part of the server. *Default:* **exclude** — the Python port targets the server; a JS/TS client
   already exists upstream. Surface the client-only error codes in `error_codes` for parity but do not
   port the browser logic.

5. **`aaguid` display map (`authenticator-metadata.ts`)** — purely cosmetic (labels passkeys in
   management UIs); the server stores the raw AAGUID and never derives a label (a test locks this in).
   *Default:* port the `commonAuthenticatorNames` dict + `getAuthenticatorName` helper as an optional
   exported utility (it is 14 static entries + a lowercase/anonymous-guard lookup), but it is not on
   any request path — safe to skip in a first cut.

6. **`updatedAt` doc artifact** — the `listPasskeys` OpenAPI lists `updatedAt` as required, but the
   schema has no such column (`schema.ts` has only `createdAt`). *Default:* follow the **schema**, not
   the OpenAPI — do **not** add `updatedAt` (adding it would break byte-shape parity with TS-written
   rows). Treat the OpenAPI entry as a known upstream doc bug.
