# Core plugins (hard) — better-auth v1.6.23 → Python parity spec

Scope: `two-factor`, `admin`, `organization` (+ access-control subsystem), `multi-session`,
`jwt`, `generic-oauth`, `device-authorization`. Source read from the pinned TS repo at
`packages/better-auth/src/plugins/`. Cross-runtime compatibility is a hard requirement: a DB
written by the TS library must be readable by the Python port — identical table/column names
(camelCase), identical token/secret encodings, identical crypto.

Conventions used below:
- All endpoint paths are relative to the auth mount (TS registers them under the base path).
- Schema field names are the **exact camelCase** column names better-auth uses by default.
- "internalAdapter" = the higher-level adapter wrapper in TS core (`createVerificationValue`,
  `consumeVerificationValue`, `createSession`, `findUserById`, `deleteSession`, …). The Python
  port currently has only a thin `Adapter` (`create/find_one/find_many/update/delete_many`) —
  see **Python current state**.

---

## Shared crypto primitives (needed by 2FA, JWT; cross-runtime critical)

These live in TS core `src/crypto/index.ts` and `@better-auth/utils`. They are prerequisites for
several plugins, so they are documented once here.

### `symmetricEncrypt` / `symmetricDecrypt` (`src/crypto/index.ts`)
- Cipher: **XChaCha20-Poly1305** (`@noble/ciphers`), `managedNonce` wrapper.
- Key: `SHA-256(secret)` → 32 bytes. `secret` is the app secret string (or a versioned
  `SecretConfig` key).
- Nonce: 24-byte random nonce, **prepended** to the ciphertext by `managedNonce`.
- Output: lowercase **hex** string of `nonce(24) || ciphertext || tag(16)`.
- Versioned envelope (only when `key` is a `SecretConfig`, i.e. key rotation enabled):
  `formatEnvelope(version, hex)` = `"$ba$" + version + "$" + hex`. Prefix constant `ENVELOPE_PREFIX = "$ba$"`.
  A bare-hex payload (no `$ba$` prefix) is the legacy format, decrypted with `key.legacySecret`.
- Python equivalent: libsodium `crypto_aead_xchacha20poly1305_ietf_*` (PyNaCl
  `nacl.bindings.crypto_aead_xchacha20poly1305_ietf_encrypt/decrypt`) uses the same 24-byte nonce +
  16-byte Poly1305 tag layout; prepend the random nonce and hex-encode. **Verify byte-for-byte
  against a TS-produced ciphertext** (see Open questions).

### HMAC helper (`@better-auth/utils/hmac` `createHMAC`)
- `createHMAC("SHA-256", "base64urlnopad").sign(secret, value)` → base64url **without padding**.
  Used by two-factor trust-device tokens.

### Signed cookies (already in Python `crypto.py`)
- `sign_value`/`unsign_value` already match TS `setSignedCookie`/`getSignedCookie`
  (HMAC-SHA256, standard base64 **with** padding, 44 chars, `value.sig`, URL-encoded). Reused by
  every plugin cookie below. Note the two-factor trust token uses a *different* encoding
  (base64url-nopad) **inside** the cookie value, then the whole value is signed with the standard
  cookie signer.

### Random generators (partly in Python `crypto.py`)
- `generateId(size=32)` alphabet `a-zA-Z0-9` (already present as `generate_id`).
- `generateRandomString(size, ...charsets)` — TS `createRandomStringGenerator("a-z","0-9","A-Z","-_")`
  as the default; callers override charset per call, e.g. `generateRandomString(6, "0-9")` for OTP,
  `generateRandomString(len, "a-z","A-Z","0-9")` for device/backup codes. Python `generate_random_string`
  exists but hardcodes one alphabet — **needs a charset-parameterized variant**.

---

## two-factor

- **Purpose:** Second-factor auth via TOTP, emailed/SMS OTP, and backup codes, with a trusted-device
  cookie and per-account lockout.

### Endpoints
All bodies are JSON. Error responses are `{message, code}` with the HTTP status shown.

| method | path | body | success response |
|---|---|---|---|
| POST | `/two-factor/enable` | `{password?, issuer?}` (password required unless `allowPasswordless` and user has no credential account) | `{totpURI, backupCodes: string[]}` |
| POST | `/two-factor/disable` | `{password?}` (sensitive-session middleware) | `{status: true}` |
| POST | `/two-factor/get-totp-uri` | `{password?}` (session) | `{totpURI}` |
| POST | `/two-factor/verify-totp` | `{code, trustDevice?}` | `{token, user}` on sign-in; `{status:true}` on re-verify enrollment |
| POST | `/two-factor/send-otp` | `{trustDevice?}?` | `{status: true}` |
| POST | `/two-factor/verify-otp` | `{code, trustDevice?}` | `{token, user}` |
| POST | `/two-factor/verify-backup-code` | `{code, disableSession?, trustDevice?}` | `{token?, user, session?}` |
| POST | `/two-factor/generate-backup-codes` | `{password?}` (session) | `{status:true, backupCodes: string[]}` |
| POST | `/totp/generate` | `{secret}` | **server-only** `{code}` |
| POST | `/two-factor/view-backup-codes` | `{userId}` | **server-only** `{status:true, backupCodes: string[]}` |

Sign-in vs re-verify: `verifyTwoFactor(ctx)` distinguishes an unauthenticated 2FA challenge (cookie
`two_factor` present, no session) from an already-authenticated re-verification (`session.session`
non-null). Sign-in path mints a session via `valid(ctx)`; re-verify just returns `{token, user}`.

### Schema additions
`user`:
- `twoFactorEnabled` boolean, default `false`, `input:false`.

`twoFactor` (table name configurable via `twoFactorTable`, default `"twoFactor"`):
- `id` string PK
- `secret` string, required, `returned:false`, indexed — **XChaCha20 ciphertext (hex, or `$ba$…` envelope)** of the TOTP secret
- `backupCodes` string, required, `returned:false` — see backup-code storage below
- `userId` string, required, `returned:false`, references `user.id`, indexed
- `verified` boolean, default **`true`** (so pre-migration rows count as verified; `enable` sets new rows to `false`)
- `failedVerificationCount` number, default `0`, `input:false`, `returned:false`
- `lockedUntil` date, nullable, `input:false`, `returned:false`

### Crypto details (exact, for cross-runtime compat)
- **TOTP secret:** `generateRandomString(32)` (charset `a-z0-9A-Z-_`), stored `symmetricEncrypt`-ed.
- **TOTP algorithm:** `@better-auth/utils` `createOTP(secret, {digits, period})`. Defaults `digits=6`,
  `period=30`. `.url(issuer, account)` → `otpauth://totp/…?secret=<base32(secret-utf8-bytes)>…`.
  The HMAC key is the secret's raw UTF-8 bytes; the URI exposes its base32 (RFC 4648, no padding) so
  authenticator apps derive the same key. Hash algorithm is RFC 6238 default **SHA-1** — **VERIFY**
  against `@better-auth/utils` (source not vendored in this checkout; see Open questions).
  `digits` allowed values `6 | 8`.
- **Emailed OTP:** `generateRandomString(digits, "0-9")`, default `digits=6`, validity default
  3 minutes (`period` option, in minutes). Stored per `storeOTP` option: `"plain"` (default),
  `"encrypted"` (symmetricEncrypt), `"hashed"` (`defaultKeyHasher` = base64url-nopad of SHA-256), or
  custom `{hash}` / `{encrypt,decrypt}`. Stored value format in the verification table:
  `"<storedOtp>:<attemptCounter>"`, identifier `2fa-otp-<challengeKey>`.
- **Backup codes:** `generateBackupCodesFn` → `amount` (default 10) codes of `length` (default 10)
  chars from `a-z A-Z 0-9`, each formatted `code.slice(0,5) + "-" + code.slice(5)` (i.e. `XXXXX-XXXXX`).
  Storage (`storeBackupCodes`, default `"encrypted"`): JSON-array string, `symmetricEncrypt`-ed
  when `"encrypted"`; `"plain"` stores the JSON array; custom `{encrypt,decrypt}` supported.
  Verification decodes, checks membership (constant-time is not used for backup codes — plain array
  `includes`), then rewrites the array minus the used code via an **atomic `incrementOne` guarded on
  the old `backupCodes` value** (optimistic concurrency; a lost race → 409 CONFLICT).
- **Trust-device token:** `createHMAC("SHA-256","base64urlnopad").sign(secret, "<userId>!<trustIdentifier>")`.
  Cookie value = `"<token>!<trustIdentifier>"`, then signed with the standard cookie signer.
  `trustIdentifier = "trust-device-" + generateRandomString(32)`. A verification-table row maps
  `identifier=trustIdentifier → value=userId`, `expiresAt = now + trustDeviceMaxAge`.

### Hooks / middleware / cookies / rate-limit
- **after-hook** on `/sign-in/email`, `/sign-in/username`, `/sign-in/phone-number`: if the new
  session's user has `twoFactorEnabled`, either (a) validate & **rotate** the trust-device cookie and
  let sign-in proceed, or (b) delete the just-created session, null out `newSession`, create a
  `two_factor` verification challenge, set the signed `two_factor` cookie, and return
  `{twoFactorRedirect: true, twoFactorMethods: string[]}` (methods = `"totp"` if a verified secret
  exists and TOTP not disabled; `"otp"` if `sendOTP` configured).
- **Cookies set:** `two_factor` (challenge, signed, maxAge `twoFactorCookieMaxAge` default 600s);
  `trust_device` (signed, maxAge `trustDeviceMaxAge` default 2 592 000s / 30d). Names come from
  `constant.ts` (`TWO_FACTOR_COOKIE_NAME="two_factor"`, `TRUST_DEVICE_COOKIE_NAME="trust_device"`).
- **Rate limit:** paths starting `"/two-factor/"` → `window:10s, max:3`.
- **Per-challenge attempt cap:** verification-table row `2fa-attempts-<challengeKey>` initialized to
  `"0"`, consumed/re-armed atomically; `DEFAULT_TWO_FACTOR_ALLOWED_ATTEMPTS = 5`. OTP uses its own
  in-row counter with `allowedAttempts` (default 5).
- **Account lockout** (`accountLockout` option, default enabled): after
  `maxFailedAttempts` (default 10) consecutive failed verifications across factors, sets
  `lockedUntil = now + durationSeconds` (default 900s). `assertTwoFactorNotLocked` fails closed with
  429; lazily clears an expired lock (guarded `incrementOne` on `lockedUntil <= now`).

### Config options + defaults
`issuer?`, `twoFactorTable="twoFactor"`, `totpOptions{digits=6, period=30, disable?, allowPasswordless?}`,
`otpOptions{period=3(min), digits=6, sendOTP, allowedAttempts=5, storeOTP="plain"}`,
`backupCodeOptions{amount=10, length=10, storeBackupCodes="encrypted", customBackupCodesGenerate?, allowPasswordless?}`,
`skipVerificationOnEnable=false`, `allowPasswordless=false`, `twoFactorCookieMaxAge=600`,
`trustDeviceMaxAge=2592000`, `accountLockout{enabled=true, maxFailedAttempts=10, durationSeconds=900}`.

### Error codes (exact strings, `TWO_FACTOR_ERROR_CODES`)
`OTP_NOT_ENABLED`="OTP not enabled", `OTP_HAS_EXPIRED`="OTP has expired", `TOTP_NOT_ENABLED`="TOTP not enabled",
`TWO_FACTOR_NOT_ENABLED`="Two factor isn't enabled", `BACKUP_CODES_NOT_ENABLED`="Backup codes aren't enabled",
`INVALID_BACKUP_CODE`="Invalid backup code", `INVALID_CODE`="Invalid code",
`TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE`="Too many attempts. Please request a new code.",
`ACCOUNT_TEMPORARILY_LOCKED`="Too many failed verification attempts. Your account is temporarily locked. Please try again later.",
`INVALID_TWO_FACTOR_COOKIE`="Invalid two factor cookie". Also ad-hoc: `TOTP_NOT_CONFIGURED`, `OTP_NOT_CONFIGURED`.

### Behaviors & edge cases from tests
- The 2FA challenge is single-use: `valid(ctx)` **consumes** the verification row atomically before
  minting a session (an expired/replayed/concurrent second use returns null → 401 + cookie cleared).
- On `disable`, the trust-device verification row is deleted and the cookie expired.
- Enrollment flow: verifying TOTP when `verified !== true` flips `twoFactorEnabled=true`, rotates the
  session, and marks `verified=true` **only after** session ops succeed (retry-safe).
- `verified === false` rows are rejected during sign-in (abandoned enrollments) but treated as
  verified when the field is null/absent (legacy-safe — use `=== false`, not `!verified`).
- Sensitive `disable` uses a **DB-backed** session (not cookie-cache) to resist replayed cookie-cache payloads.

### Dependencies
Core: sessions, verification-value store with **atomic consume**, `symmetricEncrypt/Decrypt`, HMAC
base64url, password `checkPassword`/`shouldRequirePassword`, `setSessionCookie`/`deleteSessionCookie`/`expireCookie`,
adapter `incrementOne` (guarded/optimistic). No other plugin.

---

## admin

- **Purpose:** Admin user management — roles/permissions, ban, impersonation, session management,
  password/email set, permission checks.

### Endpoints (all under `/admin/…`)
| method | path | body/query | notes |
|---|---|---|---|
| POST | `/admin/set-role` | `{userId, role:string|string[]}` | perm `user:set-role` |
| GET | `/admin/get-user` | query `{id}` | perm `user:get` |
| POST | `/admin/create-user` | `{email, password?, name, role?, data?}` | perm `user:create` (+`set-role` if role, +`ban` if ban fields) |
| POST | `/admin/update-user` | `{userId, data}` | perm `user:update`; role→`set-role`, ban fields→`ban`, email→`set-email`; rejects `password` key |
| GET | `/admin/list-users` | query search/filter/sort/paginate | perm `user:list` |
| POST | `/admin/list-user-sessions` | `{userId}` | perm `session:list` |
| POST | `/admin/ban-user` | `{userId, banReason?, banExpiresIn?}` | perm `user:ban`; revokes sessions; cannot ban self |
| POST | `/admin/unban-user` | `{userId}` | perm `user:ban` |
| POST | `/admin/impersonate-user` | `{userId}` | perm `user:impersonate` (+`impersonate-admins` for admins) |
| POST | `/admin/stop-impersonating` | — | reads `admin_session` cookie |
| POST | `/admin/revoke-user-session` | `{sessionToken}` | perm `session:revoke` |
| POST | `/admin/revoke-user-sessions` | `{userId}` | perm `session:revoke` |
| POST | `/admin/remove-user` | `{userId}` | perm `user:delete`; cannot remove self |
| POST | `/admin/set-user-password` | `{newPassword, userId}` | perm `user:set-password` |
| POST | `/admin/has-permission` | `{userId?, role?, permissions}` (xor `permission`) | returns `{error:null, success:bool}` |

`list-users` query params: `searchValue`, `searchField`(`email|name`), `searchOperator`
(`contains|starts_with|ends_with`), `limit`, `offset`, `sortBy`, `sortDirection`(`asc|desc`),
`filterField`, `filterValue`, `filterOperator`. Response `{users, total, limit?, offset?}` (swallows
adapter errors → empty list).

### Schema additions
`user`: `role` string (nullable, `input:false`), `banned` boolean default `false`, `banReason` string,
`banExpires` date. `session`: `impersonatedBy` string (`input:false`).

### Impersonation details (cookies)
- Creates a fresh session for the target with `impersonatedBy = admin.userId` and
  `expiresAt = now + impersonationSessionDuration` (default **3600s**).
- Sets signed cookie `admin_session` = `"<adminSessionToken>:<dontRememberFlag>"` (attributes of the
  session cookie), then swaps the active session cookie to the impersonation session.
- `stop-impersonating` reads `admin_session`, restores the admin session, deletes the impersonation
  session, expires `admin_session`.

### Ban enforcement
`init()` registers **databaseHooks**: `user.create.before` injects default role; `session.create.before`
throws `FORBIDDEN`/`BANNED_USER` if the user is banned (lazily lifting an expired ban). The
`after`-hook on `/list-sessions` filters out sessions with `impersonatedBy`.

### Permission checking (`has-permission.ts`, **synchronous**)
`hasPermission({userId?, role?, options, permissions})`:
1. `adminUserIds` includes `userId` → `true`.
2. Split `role` (or `defaultRole` or `"user"`) on `,`; for each, look up in `options.roles || defaultRoles`;
   `role.authorize(permissions)` — success on any role → `true`.

### Config options + defaults
`defaultRole="user"`, `adminRoles=["admin"]` (validated against `roles`/`defaultRoles` at init, else throws),
`defaultBanReason?`, `defaultBanExpiresIn?`, `impersonationSessionDuration=3600`, `ac?`, `roles?`,
`adminUserIds?`, `bannedUserMessage="You have been banned from this application. Please contact support if you believe this is an error."`,
`allowImpersonatingAdmins=false` (deprecated → use `impersonate-admins` perm).

### Error codes (exact, `ADMIN_ERROR_CODES`)
`FAILED_TO_CREATE_USER`, `USER_ALREADY_EXISTS`="User already exists.",
`USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL`, `YOU_CANNOT_BAN_YOURSELF`,
`YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE`, `YOU_ARE_NOT_ALLOWED_TO_CREATE_USERS`,
`YOU_ARE_NOT_ALLOWED_TO_LIST_USERS`, `YOU_ARE_NOT_ALLOWED_TO_LIST_USERS_SESSIONS`,
`YOU_ARE_NOT_ALLOWED_TO_BAN_USERS`, `YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS`,
`YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS`, `YOU_ARE_NOT_ALLOWED_TO_DELETE_USERS`,
`YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PASSWORD`, `BANNED_USER`="You have been banned from this application",
`YOU_ARE_NOT_ALLOWED_TO_GET_USER`, `NO_DATA_TO_UPDATE`, `YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS`,
`YOU_CANNOT_REMOVE_YOURSELF`, `YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE`,
`YOU_CANNOT_IMPERSONATE_ADMINS`, `INVALID_ROLE_TYPE`, `YOU_ARE_NOT_ALLOWED_TO_SET_USERS_EMAIL`,
`PASSWORD_CANNOT_BE_UPDATED_VIA_UPDATE_USER`. (Full strings in `admin/error-codes.ts`.)

### Behaviors & edge cases
- `create-user` also authorizes `data.role` (not just top-level `role`) — prevents privilege escalation.
- `update-user` rejects a `password` key (must use `set-user-password`) and validates role against
  the `roles` allow-list; banning via update revokes sessions.
- `create-user`/`has-permission` allow a null-session server call (trusted) when no request/headers.
- Roles stored comma-joined in `user.role`.

### Dependencies
Access-control subsystem (`admin/access` defaults). Core: sessions, databaseHooks, internalAdapter
user/session CRUD + `listUsers`/`countTotalUsers`/`listSessions`, password hash. No other plugin.

---

## organization

- **Purpose:** Organizations with members, invitations, roles/permissions, optional teams, and
  optional dynamic (DB-stored) access control.

### Endpoints (all under `/organization/…` unless noted)
Core:
- POST `/organization/create` `{name, slug, userId?, logo?, metadata?, keepCurrentActiveOrganization?}`
- POST `/organization/update` `{organizationId?, data:{name?,slug?,logo?,metadata?}}`
- POST `/organization/delete` `{organizationId}`
- POST `/organization/set-active` `{organizationId?|organizationSlug?}` (null clears active)
- GET `/organization/get-full-organization` `{organizationId?|organizationSlug?, membersLimit?}`
- GET `/organization/list`
- POST `/organization/check-slug` `{slug}`
- POST `/organization/invite-member` `{email, role, organizationId?, teamId?, resend?}`
- POST `/organization/accept-invitation` `{invitationId}`
- POST `/organization/reject-invitation` `{invitationId}`
- POST `/organization/cancel-invitation` `{invitationId}`
- GET `/organization/get-invitation` `{id}`
- GET `/organization/list-invitations` `{organizationId?}`
- GET `/organization/list-user-invitations` `{email?}` (server may pass email; client uses session email)
- POST `/organization/remove-member` `{memberIdOrEmail, organizationId?}`
- POST `/organization/update-member-role` `{memberId, role, organizationId?}`
- GET `/organization/get-active-member`
- GET `/organization/get-active-member-role`
- GET `/organization/list-members` `{organizationId?, limit?, offset?, sortBy?, sortDirection?, filter…}`
- POST `/organization/leave` `{organizationId}`
- POST `/organization/has-permission` `{organizationId?, permissions}` (xor deprecated `permission`)
- `addMember` — **server-only** (`auth.api.addMember`, no HTTP route, no session/permission check).

Teams (only when `teams.enabled`):
- POST `/organization/create-team` `{name, organizationId?, …}`
- GET `/organization/list-teams`
- POST `/organization/remove-team` `{teamId, organizationId?}`
- POST `/organization/update-team` `{teamId, data}`
- POST `/organization/set-active-team` `{teamId?}`
- GET `/organization/list-user-teams`
- GET `/organization/list-team-members` (POST in source? — path `/organization/list-team-members`, method GET)
- POST `/organization/add-team-member` `{teamId, userId}`
- POST `/organization/remove-team-member` `{teamId, userId}`

Dynamic access control (only when `dynamicAccessControl.enabled`):
- POST `/organization/create-role` `{organizationId?, role, permission:Record<string,string[]>, …additionalFields}`
- POST `/organization/delete-role` `{organizationId?, roleName|roleId}`
- GET `/organization/list-roles` `{organizationId?}`
- GET `/organization/get-role` `{organizationId?, roleName|roleId}`
- POST `/organization/update-role` `{organizationId?, roleName|roleId, data:{permission?, …}}`

### Schema additions (exact camelCase)
`organization`: `name`(string,req,sortable), `slug`(string,req,unique,sortable,indexed),
`logo`(string), `metadata`(string — **JSON-stringified** object), `createdAt`(date,req).
`member`: `organizationId`→org.id (indexed), `userId`→user.id (indexed), `role`(string,req,default `"member"`,sortable),
`createdAt`(date,req).
`invitation`: `organizationId`→org.id, `email`(string,req,sortable,indexed), `role`(string,sortable),
`status`(string,req,default `"pending"`,sortable), `teamId`(string, only when teams enabled),
`expiresAt`(date,req), `createdAt`(date,req,default now), `inviterId`→user.id.
`session` (added): `activeOrganizationId`(string,`input:false`); `activeTeamId`(string,`input:false`, teams only).
`team` (teams only): `name`(string,req), `organizationId`→org.id (indexed), `createdAt`(date,req),
`updatedAt`(date, onUpdate).
`teamMember` (teams only): `teamId`→team.id (indexed), `userId`→user.id (indexed), `createdAt`(date).
`organizationRole` (dynamic AC only): `organizationId`→org.id (indexed), `role`(string,req,indexed),
`permission`(string,req — **JSON-stringified `{resource:[actions]}`**), `createdAt`(date,req,default now),
`updatedAt`(date, onUpdate).

Invitation status enum: `pending | accepted | rejected | canceled`.

### Permission checking (`has-permission.ts` + `permission.ts`, **async**)
`hasPermission(input, ctx)`:
- Base roles = `options.roles || defaultRoles`.
- When `dynamicAccessControl.enabled` and `options.ac` set and not using memory cache: load all
  `organizationRole` rows for the org, `JSON.parse` each `permission`, **merge** into the static role's
  statements (dedup per resource), rebuild via `options.ac.newRole(merged)`.
- `hasPermissionFn`: split `role` on `,`; `creatorRole` (default `"owner"`) with
  `allowCreatorAllPermissions` short-circuits to `true`; else any role's `authorize(permissions)` success → `true`.
- `cacheAllRoles` is a module-level `Map<orgId, roles>` for in-memory reuse (`useMemoryCache`).

### Config options + defaults (`OrganizationOptions`)
`allowUserToCreateOrganization=true` (bool or `(user)=>bool`), `organizationLimit=unlimited`,
`creatorRole="owner"`, `membershipLimit=100`, `ac?`, `roles?`,
`dynamicAccessControl{enabled=false, maximumRolesPerOrganization=Infinite}`,
`teams{enabled, defaultTeam{enabled=true, customCreateDefaultTeam?}, maximumTeams=unlimited,
maximumMembersPerTeam=undefined, allowRemovingAllTeams=false}`,
`invitationExpiresIn=48h`, `invitationLimit=100`, `cancelPendingInvitationsOnReInvite=false`,
`requireEmailVerificationOnInvitation?`, `sendInvitationEmail?`, `schema?`,
`disableOrganizationDeletion=false`, and a large `organizationHooks` object (before/after for
create/update/delete org, add/remove/updateRole member, create/accept/reject/cancel invitation, and
team create/update/delete/add-member/remove-member).

### Error codes (exact, `ORGANIZATION_ERROR_CODES`)
Full set in `organization/error-codes.ts` (96 lines). Key ones: `ORGANIZATION_NOT_FOUND`,
`ORGANIZATION_SLUG_ALREADY_TAKEN`, `USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION`, `MEMBER_NOT_FOUND`,
`ROLE_NOT_FOUND`, `NO_ACTIVE_ORGANIZATION`, `USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION`,
`INVITATION_NOT_FOUND`, `YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION`,
`EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION`,
`ORGANIZATION_MEMBERSHIP_LIMIT_REACHED`, `INVITATION_LIMIT_REACHED`,
`YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER`, and the dynamic-AC set
(`MISSING_AC_INSTANCE`, `TOO_MANY_ROLES`, `INVALID_RESOURCE`, `ROLE_NAME_IS_ALREADY_TAKEN`,
`CANNOT_DELETE_A_PRE_DEFINED_ROLE`, `ROLE_IS_ASSIGNED_TO_MEMBERS`, `INVALID_TEAM_ID`).

### Behaviors & edge cases
- Creating an org makes the creator a member with `creatorRole` and (if `teams.defaultTeam.enabled`)
  a default team.
- `metadata` round-trips as a JSON string column; `organizationSchema` parses string→object on read.
- `set-active` writes `session.activeOrganizationId` (and clears with null).
- Invitations expire (`invitationExpiresIn`); accept requires the session email to match the
  invitation email; `requireEmailVerificationOnInvitation` gates by-ID actions for predictable IDs.
- Dynamic AC: role name uniqueness per org; cannot delete predefined roles or roles assigned to
  members; `maximumRolesPerOrganization` enforced; `permission` validated against `ac` statements
  (`INVALID_RESOURCE`).
- `has-permission` requires the caller to be a member of the (active or specified) org.

### Dependencies
Access-control subsystem (`organization/access` defaults + `createAccessControl`). Core: sessions with
extra session fields, databaseHooks, `getOrgAdapter` (a large plugin-local adapter, `adapter.ts`, 1160
lines, wrapping member/invitation/team/role CRUD), internalAdapter user lookups, email sending hook.
No hard dependency on other plugins.

---

## multi-session

- **Purpose:** Keep several device sessions signed in at once and switch/revoke between them via
  per-session cookies.

### Endpoints
| method | path | body | response |
|---|---|---|---|
| GET | `/multi-session/list-device-sessions` | — (requires headers) | `[{session, user}]` (unique per user, active only) |
| POST | `/multi-session/set-active` | `{sessionToken}` | `{session, user}` |
| POST | `/multi-session/revoke` | `{sessionToken}` | `{status:true}` |

### Schema additions
None.

### Cookies / hooks
- Per-session cookie name: `"<sessionCookieName>_multi-<sessionToken.toLowerCase()>"`, signed, value =
  the session token. Detection helper: name `includes("_multi-")`.
- **after-hook (matcher `()=>true`):** when a `newSession` exists and a session cookie was just set,
  write the multi cookie (unless at `maximumSessions`); also drop stale multi cookies for the same user.
- **after-hook on `/sign-out`:** delete all sessions referenced by multi cookies and expire them
  (with a `__Secure-` prefix-normalization fix).
- On `revoke` of the active session, promotes the next valid multi-session to active (or clears cookies).

### Config options + defaults
`maximumSessions=5`.

### Error codes
`MULTI_SESSION_ERROR_CODES.INVALID_SESSION_TOKEN`="Invalid session token".

### Behaviors & edge cases
- **Security:** `set-active`/`revoke` act on the token proven by the *signed cookie value*, never the
  request-body token (the signature covers the value, not the cookie name) — so a valid cookie can't
  be paired with an arbitrary token.
- `list-device-sessions` filters expired sessions and de-dupes by user id.

### Dependencies
Core: signed cookies, `internalAdapter.findSessions([...], {onlyActiveSessions})` /
`deleteSessions`, cookie parsing helpers (`parseCookies`, `parseSetCookieHeader`, `SECURE_COOKIE_PREFIX`).
No other plugin.

---

## jwt

- **Purpose:** Issue asymmetric-signed JWTs for the session and publish a JWKS for verification.

### Endpoints
| method | path | body | response |
|---|---|---|---|
| GET | `/jwks` (configurable `jwksPath`) | — | `{keys: JWK[]}` (public keys; 404 when `remoteUrl` set) |
| GET | `/token` | — (session) | `{token}` |
| POST | `signJWT` | `{payload, overrideOptions?}` | **server-only** `{token}` |
| POST | `verifyJWT` | `{token, issuer?}` | **server-only** `{payload}` |

### Schema additions
`jwks` table: `id`(string PK), `publicKey`(string,req), `privateKey`(string,req), `createdAt`(date,req),
`expiresAt`(date,nullable). Plus optional `alg`, `crv` on the row object.

### Crypto details (cross-runtime critical)
- Library: `jose` (`generateKeyPair`, `exportJWK`, `importJWK`, `SignJWT`).
- **Default key:** `alg="EdDSA"`, `crv="Ed25519"`. Other supported: `ES256`(P-256), `ES512`(P-521),
  `PS256`(RSA-PSS), `RS256`(RSA), with `modulusLength` for RSA.
- **Storage format (exact):**
  - `publicKey` column = `JSON.stringify(publicWebKey)` (a JWK object).
  - `privateKey` column = `JSON.stringify(symmetricEncrypt({secret, JSON.stringify(privateWebKey)}))`
    when encryption enabled (default), i.e. a **JSON-quoted** string wrapping the `$ba$…`/hex envelope;
    or `JSON.stringify(privateWebKey)` (plain) when `disablePrivateKeyEncryption`.
  - On read: `JSON.parse(privateKey)` → the ciphertext string → `symmetricDecrypt` → `JSON.parse` → JWK.
- **kid** = the JWKS row `id`.
- **JWKS response:** merges `{alg, crv, ...JSON.parse(publicKey), kid: id}`; filters keys whose
  `expiresAt + gracePeriod` is past (default grace 30d).
- **Token claims (`signJWT`/`getJwtToken`):** `iss`/`aud` default to the resolved `baseURL` origin;
  `exp` default from `expirationTime="15m"` (`jose`-style time span, computed via `toExpJWT`);
  `sub` = `getSubject(session)` or `session.user.id`; `iat` = now; payload = `definePayload(session)`
  or `session.user`. Protected header `{alg, kid}`.
- **`set-auth-jwt` header:** an `after`-hook on `/get-session` signs a token and sets response header
  `set-auth-jwt` plus `Access-Control-Expose-Headers` (unless `disableSettingJwtHeader`).

### Config options + defaults
`jwks{remoteUrl?, keyPairConfig={alg:"EdDSA",crv:"Ed25519"}, disablePrivateKeyEncryption=false,
rotationInterval? (disabled), gracePeriod=2592000, jwksPath="/jwks"}`,
`jwt{issuer?, audience?, expirationTime="15m", definePayload?, getSubject?, sign?}`,
`disableSettingJwtHeader=false`, `schema?`, `adapter{getJwks?, createJwk?}`.
Init guards: `jwt.sign` requires `jwks.remoteUrl`; `remoteUrl` requires `keyPairConfig.alg`;
`jwksPath` must start with `/` and not contain `..`.

### Error codes
Uses core `BetterAuthError` (key-decryption failure message) and `APIError("NOT_FOUND")` — no
dedicated `$ERROR_CODES` map.

### Behaviors & edge cases
- First `/jwks` or `/token` call lazily creates a key if none exists.
- Key rotation: when `rotationInterval` set, keys get `expiresAt`; expired latest key triggers a new key.
- Rotation tests (`rotation.test.ts`) confirm old public keys stay published during the grace period.

### Dependencies
`symmetricEncrypt/Decrypt` (private-key encryption), a JOSE-equivalent Python lib (e.g. `PyJWT` +
`cryptography`, or `python-jose`/`authlib`) that can round-trip Ed25519/ES256/ES512/PS256/RS256 JWKs.
Core: sessions, adapter `findMany/create`. No other plugin (but OIDC/MCP build on it).

---

## generic-oauth

- **Purpose:** Add OAuth2/OIDC sign-in for arbitrary providers (discovery, PKCE, custom token/userinfo).

### Endpoints
| method | path | body/query | response |
|---|---|---|---|
| POST | `/sign-in/oauth2` | `{providerId, callbackURL?, errorCallbackURL?, newUserCallbackURL?, disableRedirect?, scopes?, requestSignUp?, additionalData?}` | `{url, redirect:true}` (authorization URL) |
| GET | `/oauth2/callback/:providerId` | query `{code?, error?, error_description?, state?, iss?}` | redirect to callbackURL / sets session |
| POST | `/oauth2/link` | `{providerId, callbackURL, scopes?, errorCallbackURL?}` (session) | `{url, redirect:true}` |

### Schema additions
None (reuses core `account`/`user`/`verification`). OAuth `state` + PKCE `codeVerifier` are stored in
the core `verification` table (as the base social-login flow does).

### Config options + defaults (`GenericOAuthConfig[]`, one per provider)
`providerId` (unique), `discoveryUrl?`, `issuer?`, `requireIssuerValidation=false`, `authorizationUrl?`,
`tokenUrl?`, `userInfoUrl?`, `clientId`, `clientSecret?`, `scopes=[]`, `redirectURI?`,
`responseType="code"`, `responseMode?`, `prompt?`, `pkce=false`, `accessType?`, `accessTokenExpiresIn?`,
`getToken?`, `getUserInfo?`, `mapProfileToUser?`, `authorizationUrlParams?`, `tokenUrlParams?`,
`disableImplicitSignUp?`, `disableSignUp?`, `authentication="post"` (`basic|post`), `discoveryHeaders?`,
`authorizationHeaders?`, `overrideUserInfo=false`. Prebuilt provider presets in `providers/`
(auth0, keycloak, okta, slack, line, hubspot, microsoft-entra-id, yandex, gumroad, patreon).

### Crypto / flow details
- Redirect URI used at the provider: `${baseURL}/oauth2/callback/${providerId}`.
- PKCE (`code_verifier`/`code_challenge` S256) only when `pkce:true`.
- Callback validates `iss` (RFC 9207) when `issuer` set and `requireIssuerValidation`.
- `getUserInfo` resolves a stable id from `mapProfileToUser().id || userInfo.id || userInfo.sub`.
- `init()` registers the configured providers into `context.socialProviders`, so the plugin rides on
  the core social-login machinery (`createAuthorizationURL`, `validateAuthorizationCode`,
  `refreshAccessToken`, `applyDefaultAccessTokenExpiry`).

### Error codes (exact, `GENERIC_OAUTH_ERROR_CODES`)
`INVALID_OAUTH_CONFIGURATION`, `TOKEN_URL_NOT_FOUND`, `PROVIDER_CONFIG_NOT_FOUND`,
`PROVIDER_ID_REQUIRED`, `INVALID_OAUTH_CONFIG`, `SESSION_REQUIRED`, `ISSUER_MISMATCH`, `ISSUER_MISSING`.

### Behaviors & edge cases
- Duplicate `providerId`s warn (console) but don't throw.
- `disableImplicitSignUp` requires `requestSignUp:true` to create a new user.
- Discovery document fetched lazily and cached per-call for auth/token/userinfo endpoints.

### Dependencies
Core OAuth2 primitives (the Python port already has `oauth.py` — a good base), core `account` linking,
sessions, `verification` state store. No other plugin.

---

## device-authorization

- **Purpose:** OAuth 2.0 Device Authorization Grant (RFC 8628) — device+user code, poll for token.

### Endpoints
| method | path | body/query | response |
|---|---|---|---|
| POST | `/device/code` | `{client_id, user_id?, scope?}` | `{device_code, user_code, verification_uri, verification_uri_complete, expires_in, interval}` (Cache-Control: no-store) |
| POST | `/device/token` | `{grant_type:"urn:ietf:params:oauth:grant-type:device_code", device_code, client_id}` | `{access_token, token_type:"Bearer", expires_in, scope}` or OAuth error |
| GET | `/device` | query `{user_code}` | `{user_code, status}` (claims a pending code to the signed-in user) |
| POST | `/device/approve` | `{userCode}` (session) | `{success:true}` |
| POST | `/device/deny` | `{userCode}` (session) | `{success:true}` |

### Schema additions
`deviceCode` table: `deviceCode`(string,req), `userCode`(string,req), `userId`(string,nullable),
`expiresAt`(date,req), `status`(string,req: `pending|approved|denied`), `lastPolledAt`(date,nullable),
`pollingInterval`(number,nullable, ms), `clientId`(string,nullable), `scope`(string,nullable). PK `id`.

### Crypto / code generation
- Device code: `generateRandomString(deviceCodeLength, "a-z","A-Z","0-9")` (default length 40) or
  custom `generateDeviceCode`.
- User code: default charset `"ABCDEFGHJKLMNPQRSTUVWXYZ23456789"` (Crockford-ish, no ambiguous chars),
  length 8, via `crypto.getRandomValues`; or custom `generateUserCode`. Dashes stripped on lookup
  (`user_code.replace(/-/g,"")`).
- `verification_uri` default `/device` (absolute or relative to baseURL); `verification_uri_complete`
  appends `?user_code=`.

### Config options + defaults (parsed by a zod schema, all validated)
`expiresIn="30m"`, `interval="5s"` (time strings), `deviceCodeLength=40`, `userCodeLength=8`,
`generateDeviceCode?`, `generateUserCode?`, `validateClient?`, `onDeviceAuthRequest?`,
`verificationUri?`, `schema?`.

### Error codes
Internal (`DEVICE_AUTHORIZATION_ERROR_CODES`): `INVALID_DEVICE_CODE`, `EXPIRED_DEVICE_CODE`,
`EXPIRED_USER_CODE`, `AUTHORIZATION_PENDING`, `ACCESS_DENIED`, `INVALID_USER_CODE`,
`DEVICE_CODE_ALREADY_PROCESSED`, `DEVICE_CODE_NOT_CLAIMED`, `POLLING_TOO_FREQUENTLY`, `USER_NOT_FOUND`,
`FAILED_TO_CREATE_SESSION`, `INVALID_DEVICE_CODE_STATUS`, `AUTHENTICATION_REQUIRED`.
Wire errors (OAuth `{error, error_description}`): `authorization_pending`, `slow_down`,
`expired_token`, `access_denied`, `invalid_request`, `invalid_grant`, `invalid_client`.

### Behaviors & edge cases
- `/device/token` enforces `pollingInterval` (returns `slow_down` if polled too soon), updates
  `lastPolledAt`, deletes expired/denied rows, returns `authorization_pending` while pending.
- Redemption is **atomic**: `consumeOne` on `(deviceCode, status="approved")` — only one poll wins,
  then a session is created (and cached in secondary storage if configured). Response is OAuth-style
  (`access_token` = session token).
- `/device` claims a pending unbound code to the current user via a guarded `incrementOne`
  (`status="pending" AND userId IS NULL`).
- approve/deny require the claiming user to match `deviceCode.userId`.

### Dependencies
Core: sessions, adapter `consumeOne`/`incrementOne` (guarded), `getSessionFromCtx`, secondary storage
(optional). No other plugin.

---

## Access-control subsystem — full model

Location: `plugins/access/` (shared) + per-plugin `access/statement.ts` defaults.

### Statements
A `Statements` is `Record<resource, readonly string[]>` — resource → allowed action strings.

### `createAccessControl(statements)`
Returns `{ statements, newRole(roleStatements) }`. `roleStatements` must be a subset of the base
statements (typed via `RoleInput`/`Subset`). `newRole` → `role(statements)`.

### `role(statements)` → `{ statements, authorize(request, connector="AND") }`
`authorize(request, connector)`:
- `request` = `{resource: string[] | {actions:string[], connector:"OR"|"AND"}}`.
- Per requested resource: unknown resource → fail (AND) or skip (OR).
- Resource authorized iff (AND) every requested action ∈ allowed, or (OR) some action ∈ allowed;
  empty action list → not authorized.
- Top-level `connector` combines resources: OR short-circuits on first authorized; AND fails on first
  unauthorized. Returns `{success:true}` or `{success:false, error}` with messages:
  `"You are not allowed to access resource: <r>"`, `"unauthorized to access resource "<r>""`,
  `"Not authorized"`.

### Permission-checking API differences
- **admin** `hasPermission` is **synchronous** (static roles only, `adminUserIds` bypass).
- **organization** `hasPermission` is **async** (may load `organizationRole` rows and merge dynamic
  permissions into static roles; `creatorRole` + `allowCreatorAllPermissions` bypass).

### Defaults — admin (`admin/access/statement.ts`)
`defaultStatements = { user: ["create","list","set-role","ban","impersonate","impersonate-admins",
"delete","set-password","set-email","get","update"], session: ["list","revoke","delete"] }`.
Roles: `admin` (all user actions **except** `impersonate-admins`, all session actions);
`user` (empty). `defaultRoles = { admin, user }`.

### Defaults — organization (`organization/access/statement.ts`)
`defaultStatements = { organization:["update","delete"], member:["create","update","delete"],
invitation:["create","cancel"], team:["create","update","delete"], ac:["create","read","update","delete"] }`.
Roles: `owner` (everything), `admin` (everything except `organization:delete`),
`member` (only `ac:["read"]`). `defaultRoles = { admin, owner, member }`.

Python must reproduce these exact statement/action strings and default role tables — they are the
authorization contract and are referenced by permission checks and error branches.

---

## Python current state

The Python port (`src/better_auth/`, ~2 100 LOC total) is **core-only**. None of the seven plugins
exist. What is present and reusable:
- `plugins.py`: a `Plugin` base class with `routes()`, `before(ctx)`, `after(ctx, response)` hooks and
  a `schema` classvar. No endpoint/middleware/rate-limit/`$ERROR_CODES` structure, no `init()`,
  no databaseHooks, no per-path `after` matchers.
- `schema.py`: `Field`/`Schema` + `CORE_SCHEMA` (user/session/account/verification with camelCase
  columns) + `merge_schema`. No `references`-as-object, `index`, `input`, `returned`, `defaultValue`,
  `onUpdate`, or `number`/`date`-vs-`datetime` distinctions the plugins use.
- `crypto.py`: scrypt password hash (TS-compatible), `generate_id`, `generate_random_string`
  (single alphabet only), signed-cookie `sign_value`/`unsign_value` (TS-compatible). **No
  symmetric encryption**, **no base64url HMAC helper**, **no charset-parameterized random**,
  **no TOTP**, **no constant-time compare exposed**.
- `oauth.py`: a basic OAuth2 flow (good base for generic-oauth).
- `session.py` / `auth.py`: `create_session`/`get_session`, cookie read/write, rate-limit + origin
  checks, a `run_hook` mechanism. **No `internalAdapter`** (no verification-value store, no
  `createSession(userId, dontRemember, override, overrideAll)` signature, no `deleteSessions`,
  `findSessions`, `listUsers`, `countTotalUsers`, `updateUser`, `linkAccount`, `updatePassword`).
- `adapters/base.py`: `create`, `find_one`, `find_many`, `update`, `delete_many` only. **Missing**
  the atomic/guarded primitives every hard plugin relies on: single `delete`, `incrementOne`
  (guarded/optimistic, returns updated row), `consumeOne`/`consumeVerificationValue` (atomic
  read-and-delete), `count`, sort/limit/offset, and `where` operators (`contains`, `lte`, `eq null`,
  `starts_with`, `ends_with`).

Net: substantial **core** work is prerequisite before any of these plugins can be ported.

---

## Gap items — ordered (dependencies first)

**Phase 0 — crypto & adapter primitives (block everything):**
1. `symmetric_encrypt`/`symmetric_decrypt` — XChaCha20-Poly1305, `SHA-256(secret)` key, 24-byte
   prepended nonce, hex output, `$ba$<v>$<hex>` envelope + legacy bare-hex. Cross-runtime tested. **M**
2. `create_hmac(..., "base64urlnopad")` helper + charset-parameterized `generate_random_string`
   (and a `constant_time_equal`). **S**
3. Adapter extensions: single `delete`, `count`, sort/limit/offset, `where` operators
   (`contains/starts_with/ends_with/lte/eq-null`), guarded `increment_one` (returns updated row),
   atomic `consume_one` / verification `consume`. **L**
4. `internalAdapter` layer: verification-value store (`create/find/consume/deleteByIdentifier`),
   session helpers (`createSession` with `dontRemember`/override/overrideAll, `findSession(s)`,
   `deleteSession(s)`, `deleteUserSessions`, `listSessions`), user helpers (`findUserById/ByEmail`,
   `createUser`, `updateUser`, `listUsers`, `countTotalUsers`, `linkAccount`, `createAccount`,
   `updatePassword`, `deleteUser`). **L**
5. Plugin framework parity: `init()`, endpoint objects with method/path/body-schema/`use`-middleware,
   `hooks.after` with path matchers, `rateLimit` rules, `$ERROR_CODES`, databaseHooks
   (`user.create.before`, `session.create.before`), server-only endpoints. **L**
6. Schema-system parity: object `references`, `index`, `input`, `returned`, `defaultValue`, `onUpdate`,
   `number`/`date` types, `mergeSchema` with model-name override. **M**
7. Session extra fields plumbing (`impersonatedBy`, `activeOrganizationId`, `activeTeamId`) +
   `setSessionCookie`/`expireCookie`/`deleteSessionCookie` semantics. **M**

**Phase 1 — access-control subsystem (blocks admin & org):**
8. `create_access_control` / `role` / `authorize` with OR/AND connectors + exact error strings. **M**
9. admin default statements/roles; organization default statements/roles (exact strings). **S**

**Phase 2 — plugins (each depends on Phase 0/1):**
10. **jwt** — needs #1, JOSE-equivalent lib, jwks table, exact storage format, `/jwks` + `/token` +
    server-only sign/verify, `set-auth-jwt` hook, rotation/grace. **L**
11. **two-factor** — needs #1–#7, TOTP (#verify algorithm), OTP, backup codes, trust-device cookie,
    attempt cap + account lockout, sign-in after-hook, rate-limit. **L**
12. **multi-session** — needs #3/#4/#7, per-session signed cookies, two after-hooks, sign-out cleanup. **M**
13. **generic-oauth** — extends existing `oauth.py`; provider registry, discovery, PKCE, `iss`
    validation, 3 endpoints, provider presets. **M–L**
14. **device-authorization** — needs #3 (`consume_one`/guarded `increment_one`) + sessions;
    deviceCode table, 5 endpoints, RFC 8628 polling/claim/approve/deny. **M**
15. **admin** — needs #4/#5/#8/#9; 15 endpoints, ban databaseHooks, impersonation cookies,
    list-users query. **L**
16. **organization** — needs #4/#5/#7/#8/#9; the plugin-local org adapter, ~40 endpoints across
    org/member/invitation/team, optional teams + dynamic access control (organizationRole table,
    permission merge), org hooks, email sending. **XL** (largest single item; consider sub-phasing
    core-org → invitations → teams → dynamic-AC).

## Open questions

- **BLOCKED (verify):** `@better-auth/utils` `createOTP` internals are **not vendored** in this
  checkout (no `node_modules`). The spec assumes RFC 6238 HMAC-**SHA1**, base32(no-pad) URI secret,
  HMAC key = secret UTF-8 bytes, default `digits=6`/`period=30`, and a verification window. Confirm
  the exact algorithm, default window, and `.verify()` skew against the published `@better-auth/utils`
  source (or a live TS instance) before implementing — TOTP is cross-runtime and unforgiving.
- **BLOCKED (verify):** `symmetricEncrypt` byte layout — confirm that libsodium
  `crypto_aead_xchacha20poly1305_ietf` (PyNaCl) with a prepended 24-byte nonce reproduces
  `@noble/ciphers` `managedNonce(xchacha20poly1305)` exactly (nonce placement, tag placement, AAD
  empty). Validate by decrypting a TS-produced `twoFactor.secret` and a TS-produced JWKS `privateKey`.
- JOSE library choice for Python that supports EdDSA/Ed25519 **and** ES512/PS256 JWK import-export
  with matching `kid`/JWK field encodings (base64url `n/e/x/y/crv`). Candidates: `authlib`,
  `python-jose`, `PyJWT`+`cryptography`.
- Confirm `/organization/list-team-members` HTTP method (source registers path with `method:"GET"`
  in `crud-team.ts` but the plugin doc comment says POST — treat the source `method` as authoritative).
- `dontRememberToken` cookie + `secretConfig` (versioned keys) plumbing does not exist in the Python
  core yet; several 2FA/impersonation branches read it. Decide whether to support key rotation
  (`SecretConfig`) now or only single-secret (legacy bare-hex) initially.
- Whether to port `test-utils` OTP sink for parity tests, or drive tests against emailed-OTP capture.
