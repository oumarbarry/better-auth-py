# Simple plugins — better-auth v1.6.23 → Python parity spec

Scope: `username`, `anonymous`, `phone-number`, `magic-link`, `email-otp`, `one-time-token`, `bearer`, `last-login-method`, `haveibeenpwned`, `captcha`, `additional-fields`, `custom-session`, `open-api`.

TS source pinned at `v1.6.23`: `packages/better-auth/src/plugins/<name>/`.
Python port: `better-auth-py/src/better_auth/`.

Every claim below is grounded in TS source/tests. All field/table names are the exact camelCase used by TS so a Python app can share a DB with a TS app. Paths in this doc are relative to `base_path` (default `/api/auth`) unless noted.

---

## Cross-cutting: what the Python plugin API is missing

The current Python `Plugin` (`src/better_auth/plugins.py`) offers only: `id`, `schema` (ClassVar), `routes()`, `before(ctx)`, `after(ctx, response)`. Every plugin below needs one or more capabilities the Python core does not yet expose. These are the shared prerequisites; per-plugin gap items depend on them.

1. **`init()` hook** — TS plugins return `{ options: { databaseHooks, emailVerification, … } }` and `{ context: { password: {…} } }` from `init(ctx)`. Used by: `username` (user.create/update.before), `phone-number` (user.update.before), `last-login-method` (user.create.before + session.create.after), `email-otp` (`emailVerification.sendVerificationEmail` override), `haveibeenpwned` (wrap `context.password.hash`). Python has no `init`, no `databaseHooks`, and no context override. **L**
2. **Path-matched hooks with matchers** — TS `hooks.before/after = [{ matcher(ctx), handler }]`. Python `before`/`after` run globally with no matcher and no helper to read the matched path cheaply (path is on `ctx.request.path`). Plugins can self-filter on `ctx.request.path`, but there is no equivalent of `getEndpointResponse` (read+reparse the JSON body of the outgoing response) that `email-otp`/`custom-session` rely on. **M**
3. **`onRequest` hook** — `captcha` uses `onRequest(request, ctx)` which runs before endpoint dispatch and can short-circuit with a `Response`. Python has no onRequest; `before` is the closest but only fires on matched routes (a 404 path never reaches plugins). Acceptable for captcha (it guards existing endpoints). **S** (map to `before`).
4. **Plugin-contributed rate-limit rules** — TS plugins declare `rateLimit: [{ pathMatcher, window, max }]`. Python `RateLimit` only supports exact-path `custom_rules: dict[path,(window,max)]` plus two hardcoded `_SPECIAL_RATE_RULES` in `auth.py`. Needs: collect `plugin.rate_limit` prefix/matcher rules and fold them into `_check_rate_limit`. Used by `phone-number`, `magic-link`, `email-otp`. **M**
5. **Atomic verification-value consume + verification helpers** — TS `internalAdapter.consumeVerificationValue(identifier)` atomically returns-and-deletes a `verification` row (the race gate for every OTP/token single-use guarantee). Also `createVerificationValue`, `findVerificationValue`, `deleteVerificationByIdentifier`, `updateVerificationByIdentifier`. Python adapter (`adapters/base.py`) has generic `create/find_one/find_many/update/delete_many` only — no atomic consume. Required by `magic-link`, `email-otp`, `one-time-token`, `phone-number`. **M**
6. **OTP / token crypto helpers** — `generate_random_string` in `crypto.py` takes only a size (fixed 64-char alphabet); TS uses `generateRandomString(6, "0-9")` for OTPs and `generateRandomString(32, "a-z","A-Z")` for magic-link tokens. Need a charset-parameterized generator. Also `defaultKeyHasher` = base64url-nopad(SHA-256(x)) for `storeToken:"hashed"`, and `symmetricEncrypt/Decrypt` for `email-otp storeOTP:"encrypted"`. **S–M**
7. **`additionalFields` core support** — `parseUserInput`/`parseUserOutput` and the `user.additionalFields` / `session.additionalFields` config. Python `update_user` whitelists only `name`/`image`; sign-up ignores extra body fields; there is no output field stripping (`returned:false`). Needed by `phone-number.signUpOnVerification`, `email-otp` sign-up, and the `additional-fields` plugin. **M**
8. **Response-header plumbing on new sessions** — `set-auth-token` (bearer), `set-ott` (one-time-token), `Access-Control-Expose-Headers` merging, and `ctx.setCookie` with attribute inheritance (last-login-method). Python `AuthResponse` supports `headers`/`set_cookie` append, so `after` can do this; the missing piece is a reliable "a new session was created on this response" signal (`ctx.context.newSession`). **S–M**
9. **Extended schema field attributes** — TS DB fields carry `input:false` (never taken from request body), `defaultValue`, `returned:false`, `sortable`, `unique`, `fieldName`, `transform.input`. Python `schema.Field` has only `type/required/unique/references`. `input:false` and `defaultValue` are load-bearing (`isAnonymous`, `phoneNumberVerified`, `lastLoginMethod`). **M**

---

## username

- **Purpose**: sign in with a username instead of email; enforce uniqueness/format on sign-up and update.
- **Endpoints**:
  - `POST /sign-in/username` — body `{ username:str, password:str, rememberMe?:bool, callbackURL?:str }`. Response `{ redirect:bool, token:str, url:str|null, user }`. Sets `Location` header when `callbackURL` present. Errors: `INVALID_USERNAME_OR_PASSWORD` (401; also for missing fields, user-not-found, no credential account, bad password — password is still hashed on user-not-found to equalize timing), `USERNAME_TOO_SHORT`/`USERNAME_TOO_LONG`/`INVALID_USERNAME` (422), `EMAIL_NOT_VERIFIED` (403 when `emailAndPassword.requireEmailVerification` and unverified; sends verification email if `emailVerification.sendOnSignIn`).
  - `POST /is-username-available` — body `{ username:str }`. Response `{ available:bool }`. Errors: `INVALID_USERNAME`/`USERNAME_TOO_SHORT`/`USERNAME_TOO_LONG` (422).
- **Schema additions** (`user`): `username` string, `required:false`, `unique:true`, `sortable:true`, `returned:true`, `transform.input` = normalizer (default `toLowerCase`). `displayUsername` string, `required:false`, `transform.input` = display normalizer (default identity).
- **Hooks/middleware**: `init().databaseHooks.user.create.before` and `.update.before` — validate + normalize username/displayUsername; skip validation on `/sign-up/email` and `/update-user` (those are validated in the http `before` hooks instead) to avoid double-validation. Three `hooks.before` matchers on `/sign-up/email` (+`/update-user`): (a) if only `displayUsername` given and it passes validation, copy it into `username`; (b) validate username/displayUsername + uniqueness (on update, allow if the existing row is the current session's user); (c) default `displayUsername = username` when username set but display omitted.
- **Rate-limit**: none plugin-specific.
- **Config + defaults**: `minUsernameLength=3`, `maxUsernameLength=30`, `usernameValidator=/^[a-zA-Z0-9_.]+$/`, `displayUsernameValidator=undefined` (no validation), `usernameNormalization=toLowerCase` (or `false` to disable, or custom fn), `displayUsernameNormalization=false`, `validationOrder={username:"pre-normalization", displayUsername:"pre-normalization"}`, `schema` override.
- **$ERROR_CODES** (exact strings): `INVALID_USERNAME_OR_PASSWORD:"Invalid username or password"`, `EMAIL_NOT_VERIFIED:"Email not verified"`, `UNEXPECTED_ERROR:"Unexpected error"`, `USERNAME_IS_ALREADY_TAKEN:"Username is already taken. Please try another."`, `USERNAME_TOO_SHORT:"Username is too short"`, `USERNAME_TOO_LONG:"Username is too long"`, `INVALID_USERNAME:"Username is invalid"`, `INVALID_DISPLAY_USERNAME:"Display username is invalid"`.
- **Behaviors/edge cases (tests)**: duplicate username fails on sign-up; on update fails only if row belongs to a different user; duplicate check is case-insensitive via normalization; both `username`+`displayUsername` preserved on update; `displayUsername` NOT normalized by default; a display-only value that fails username validation is NOT stored as username; an explicit empty username is not overwritten by displayUsername; sign-in normalizes username before lookup; no info leak — wrong password returns `INVALID_USERNAME_OR_PASSWORD` even when email unverified, `EMAIL_NOT_VERIFIED` only after correct password; `validationOrder:"post-normalization"` validates the normalized value.
- **Dependencies**: `init()`+`databaseHooks`, path-matched `hooks.before`, `additionalFields`/`transform.input` on schema, credential sign-in, email-verification token issuance (`sendOnSignIn`).

---

## anonymous

- **Purpose**: create a throwaway anonymous user + session; auto-link/cleanup when they later sign in with a real credential.
- **Endpoints**:
  - `POST /sign-in/anonymous` — no body. Response `{ token, user }`. Rejects with `ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY` (400) if the current session is already an anonymous user (checked with `disableRefresh:true`). Creates user `{ email:<temp>, emailVerified:false, isAnonymous:true, name }` then a session and sets the cookie.
  - `POST /delete-anonymous-user` — uses `sensitiveSessionMiddleware`. Response `{ success:true }`. Errors: `DELETE_ANONYMOUS_USER_DISABLED` (400 if `disableDeleteAnonymousUser`), `USER_IS_NOT_ANONYMOUS` (403), `FAILED_TO_DELETE_ANONYMOUS_USER_SESSIONS`/`FAILED_TO_DELETE_ANONYMOUS_USER` (500). Clears the session cookie.
- **Schema additions** (`user`): `isAnonymous` boolean, `required:false`, `input:false`, `defaultValue:false`.
- **Hooks/middleware**: one `hooks.after` matcher on paths starting `/sign-in`, `/sign-up`, `/callback`, `/oauth2/callback`, `/magic-link/verify`, `/email-otp/verify-email`, `/one-tap/callback`, `/passkey/verify-authentication`, `/phone-number/verify`, `/verify-email`. If the response set a session cookie AND the pre-existing session was anonymous AND a `newSession` was created: call `onLinkAccount({anonymousUser, newUser, ctx})`, then (unless `disableDeleteAnonymousUser`, or same user, or the new session is itself anonymous) delete the old anonymous user + sessions. On `/sign-in/anonymous` with no `newSession` it re-throws `ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY`.
- **Rate-limit**: none.
- **Config + defaults**: `emailDomainName` (temp email `temp-<id>@<domain>`, else `temp@<id>.com`), `onLinkAccount`, `disableDeleteAnonymousUser`, `generateName(ctx)` (default `"Anonymous"`), `generateRandomEmail()` (validated as email; else `INVALID_EMAIL_FORMAT` 400), `schema`.
- **$ERROR_CODES**: `INVALID_EMAIL_FORMAT:"Email was not generated in a valid format"`, `FAILED_TO_CREATE_USER:"Failed to create user"`, `COULD_NOT_CREATE_SESSION:"Could not create session"`, `ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY:"Anonymous users cannot sign in again anonymously"`, `FAILED_TO_DELETE_ANONYMOUS_USER:"Failed to delete anonymous user"`, `FAILED_TO_DELETE_ANONYMOUS_USER_SESSIONS:"Failed to delete anonymous user sessions"`, `USER_IS_NOT_ANONYMOUS:"User is not anonymous"`, `DELETE_ANONYMOUS_USER_DISABLED:"Deleting anonymous users is disabled"`.
- **Behaviors/edge cases (tests)**: sign in anonymously; link on email + social sign-in; `onLinkAccount` fires on email verification of the anon user; `generateName`/`generateRandomEmail` (sync+async) honored; invalid generated email throws; first anon sign-in allowed, subsequent rejected once signed in; cleanup safeguards — does not delete when the new session is still anonymous; deletes previous anon user when linking a new account.
- **Dependencies**: schema `input:false`+`defaultValue`, path-matched `hooks.after`, `ctx.context.newSession` signal, `getSessionFromCtx(disableRefresh)`, `sensitiveSessionMiddleware`, `parseUserOutput`.

---

## phone-number

- **Purpose**: SMS-OTP-based sign-in, verification, and password reset via phone number.
- **Endpoints** (all under `/phone-number/*` except sign-in):
  - `POST /sign-in/phone-number` — body `{ phoneNumber, password, rememberMe? }`. Response `{ token, user }`. Errors: `INVALID_PHONE_NUMBER` (400 if validator fails), `INVALID_PHONE_NUMBER_OR_PASSWORD` (401 user/credential/password), `PHONE_NUMBER_NOT_VERIFIED` (401 when `requireVerification` and unverified — also sends a fresh OTP), `UNEXPECTED_ERROR`.
  - `POST /phone-number/send-otp` — body `{ phoneNumber }`. Response `{ message:"code sent" }`. Stores `verification` `{ value:"<code>:0", identifier:phoneNumber, expiresAt }`. Errors: `SEND_OTP_NOT_IMPLEMENTED` (501), `INVALID_PHONE_NUMBER` (400).
  - `POST /phone-number/verify` — body `{ phoneNumber, code, disableSession?, updatePhoneNumber?, ...additionalFields }`. Response `{ status:true, token:str|null, user }`. If `updatePhoneNumber` → requires session, rejects if number already exists (`PHONE_NUMBER_EXIST`), updates current user. Else marks/creates user (`signUpOnVerification` → create with temp email/name + additional fields) and (unless `disableSession`) creates a session. Uses atomic OTP verify. Errors: `OTP_NOT_FOUND`/`OTP_EXPIRED`/`INVALID_OTP` (400), `TOO_MANY_ATTEMPTS` (403), `PHONE_NUMBER_EXIST` (400).
  - `POST /phone-number/request-password-reset` — body `{ phoneNumber }`. Response `{ status:true }` (constant; stores OTP under identifier `<phoneNumber>-request-password-reset`; sends only if user exists, no enumeration).
  - `POST /phone-number/reset-password` — body `{ otp, phoneNumber, newPassword }`. Response `{ status:true }`. Verifies OTP under the reset identifier, validates password length (`PASSWORD_TOO_SHORT`/`PASSWORD_TOO_LONG`), upserts credential account, fires `onPasswordReset`, revokes sessions if `revokeSessionsOnPasswordReset`.
- **Schema additions** (`user`): `phoneNumber` string, `required:false`, `unique:true`, `sortable:true`, `returned:true`. `phoneNumberVerified` boolean, `required:false`, `returned:true`, `input:false`.
- **Hooks/middleware**: `init().databaseHooks.user.update.before` — when `phoneNumber` set to `null`, atomically also set `phoneNumberVerified:false`. `hooks.before` on `/update-user` — block any `phoneNumber` change that is not disassociation (non-null) with `PHONE_NUMBER_CANNOT_BE_UPDATED` (400).
- **Rate-limit**: `[{ pathMatcher: startsWith("/phone-number"), window:60, max:10 }]`.
- **Config + defaults**: `otpLength=6`, `expiresIn=300`, `allowedAttempts=3`, `sendOTP` (required), `verifyOTP` (custom; bypasses internal store), `sendPasswordResetOTP`, `phoneNumberValidator`, `requireVerification=false`, `callbackOnVerification`, `signUpOnVerification:{getTempEmail, getTempName?}`, `schema`.
- **$ERROR_CODES**: `INVALID_PHONE_NUMBER:"Invalid phone number"`, `PHONE_NUMBER_EXIST:"Phone number already exists"`, `PHONE_NUMBER_NOT_EXIST:"phone number isn't registered"`, `INVALID_PHONE_NUMBER_OR_PASSWORD:"Invalid phone number or password"`, `UNEXPECTED_ERROR:"Unexpected error"`, `OTP_NOT_FOUND:"OTP not found"`, `OTP_EXPIRED:"OTP expired"`, `INVALID_OTP:"Invalid OTP"`, `PHONE_NUMBER_NOT_VERIFIED:"Phone number not verified"`, `PHONE_NUMBER_CANNOT_BE_UPDATED:"Phone number cannot be updated"`, `SEND_OTP_NOT_IMPLEMENTED:"sendOTP not implemented"`, `TOO_MANY_ATTEMPTS:"Too many attempts"`.
- **Behaviors/edge cases (tests)**: OTP value is stored as `"<code>:<attempts>"`; wrong code recreates the row with `attempts+1` (same value/expiry) until `allowedAttempts`, then a further attempt is `TOO_MANY_ATTEMPTS` and the row is not recreated; the code cannot be reused after success (atomic consume is the race gate — exactly one success under concurrent verify of the same code); expired code deletes the row and returns `OTP_EXPIRED`; full send→verify→signUp→sign-in flow; disassociation nulls the number and resets verified flag atomically, then another user can claim the released number; `callbackOnVerification` fires on `updatePhoneNumber`; `signUpOnVerification` copies additional fields from body; custom `verifyOTP` is used instead of the internal store and still cleans up the row; background-task `sendOTP` failures do not fail the request.
- **Dependencies**: consume/verification helpers, plugin rate-limit, `init()`+databaseHooks, path-matched hooks, `additionalFields`, digit OTP generator, `onPasswordReset`, `revokeSessionsOnPasswordReset`.

---

## magic-link

- **Purpose**: passwordless sign-in/sign-up via an emailed one-time link.
- **Endpoints**:
  - `POST /sign-in/magic-link` — `requireHeaders:true`. Body `{ email, name?, callbackURL?, newUserCallbackURL?, errorCallbackURL?, metadata? }`. Response `{ status:true }`. Stores `verification` `{ identifier:<storedToken>, value:JSON({email,name}), expiresAt }`; builds `<baseURL><basePath>/magic-link/verify?token=<rawToken>&callbackURL=…[&newUserCallbackURL][&errorCallbackURL]`; calls `sendMagicLink({email,url,token,metadata})`.
  - `GET /magic-link/verify` — `requireHeaders:true`. Query `{ token, callbackURL?, errorCallbackURL?, newUserCallbackURL? }`; each callback URL guarded by `originCheck`. Atomically consumes the token. On invalid/missing → redirect to `errorCallbackURL?error=INVALID_TOKEN` (or 400 if no callback). Creates the user if not found (`emailVerified:true`, unless `disableSignUp` → error `new_user_signup_disabled`); if the existing user is unverified, revokes unproven account access then marks verified; creates a session + cookie. If no `callbackURL` → returns `{ token, user, session }` JSON; new user → redirect `newUserCallbackURL`; else redirect `callbackURL`.
- **Schema additions**: none (uses core `verification`).
- **Hooks/middleware**: none. `originCheck` middleware on the three callback URLs.
- **Rate-limit**: `[{ pathMatcher: startsWith("/sign-in/magic-link") || startsWith("/magic-link/verify"), window: rateLimit.window||60, max: rateLimit.max||5 }]`.
- **Config + defaults**: `expiresIn=300`, `allowedAttempts=1` (deprecated — any value ≠1 is ignored and logs a `console.warn`; token is single-use regardless), `sendMagicLink` (required), `disableSignUp=false`, `rateLimit={window:60,max:5}`, `generateToken(email)` (default `generateRandomString(32,"a-z","A-Z")`), `storeToken="plain"|"hashed"|{type:"custom-hasher",hash}`.
- **$ERROR_CODES**: none exported (`redirectWithError` uses string codes `INVALID_TOKEN`, `new_user_signup_disabled`, `failed_to_create_user`, `failed_to_create_session`).
- **Behaviors/edge cases (tests)**: token is single-use — second verify rejected even with `allowedAttempts:3` or `Infinity`; mints at most one session under concurrent verification; expired token rejected; redirect to `errorCallbackURL` on error; sign-up path; existing unverified user becomes verified and its unverified account password is cleared on adopt; `generateToken` custom; `storeToken` hashed / custom-hasher stores a transformed token in DB but the sent token is the raw one; additional fields returned; untrusted callbackURL rejected on verify.
- **Dependencies**: consume/verification helpers, plugin rate-limit, `originCheck`/trusted-URL (Python has `ensure_trusted_url`), `defaultKeyHasher`, `revokeUnprovenAccountAccess`, charset token generator.

---

## email-otp

- **Purpose**: email one-time-code sign-in, email verification, password reset, and email change.
- **Endpoints** (identifier scheme: `<type>-otp-<email>`, value `"<storedOTP>:<attempts>"`):
  - `POST /email-otp/send-verification-otp` — body `{ email, type:"sign-in"|"email-verification"|"forget-password" }` (`change-email` rejected here). Response `{ success:true }`. `INVALID_EMAIL` (400). No enumeration: for non-sign-in types with no user, deletes the row and returns success without sending.
  - `POST /email-otp/create-verification-otp` — **server-only**. Body `{ email, type }`. Returns the OTP string (creates row).
  - `GET /email-otp/get-verification-otp` — **server-only**. Query `{ email, type }`. Response `{ otp:str|null }` (null if missing/expired; 400 if `storeOTP` is hashed/custom-hash — cannot recover).
  - `POST /email-otp/check-verification-otp` — body `{ email, type, otp }`. Response `{ success:true }`. Non-consuming check: increments attempts on wrong code (`updateVerificationByIdentifier`); `INVALID_OTP`/`OTP_EXPIRED` (400), `TOO_MANY_ATTEMPTS` (403), `USER_NOT_FOUND` (400).
  - `POST /email-otp/verify-email` — body `{ email, otp }`. Atomic verify against `email-verification` identifier; marks user `emailVerified:true`; `autoSignInAfterVerification` → session; else updates cookie cache if it's the current user. Response `{ status:true, token:str|null, user }`.
  - `POST /sign-in/email-otp` — body `{ email, otp, name?, image?, ...additionalFields }`. Atomic verify against `sign-in` identifier. Creates user if not found (unless `disableSignUp` → `INVALID_OTP`); if existing unverified, revokes unproven access + marks verified; creates session. Response `{ token, user }`.
  - `POST /email-otp/request-password-reset` — body `{ email }`. `{ success:true }` (no enumeration).
  - `POST /forget-password/email-otp` — **deprecated** alias of request-password-reset (logs deprecation).
  - `POST /email-otp/reset-password` — body `{ email, otp, password }`. Atomic verify against `forget-password` identifier; length checks; upsert credential account; `onPasswordReset`; mark verified; `revokeSessionsOnPasswordReset`. `{ success:true }`.
  - `POST /email-otp/request-email-change` — `sensitiveSessionMiddleware`. Body `{ newEmail, otp? }`. Requires `changeEmail.enabled`; if `verifyCurrentEmail`, requires + atomic-verifies an `email-verification` OTP for the current email; stores a `change-email` OTP under `<currentEmail>-<newEmail>`; no enumeration if newEmail taken. `{ success:true }`.
  - `POST /email-otp/change-email` — `sensitiveSessionMiddleware`. Body `{ newEmail, otp }`. Atomic verify against the change-email identifier; rejects same email / email-already-in-use; updates user email + `emailVerified:true`; before/after email-verification callbacks; resets session cookie. `{ success:true }`.
- **Schema additions**: none (core `verification`).
- **Hooks/middleware**: `init()` — if `overrideDefaultEmailVerification`, replaces `emailVerification.sendVerificationEmail` to send an OTP instead. `hooks.after` on `/sign-up*` — when `sendVerificationOnSignUp` and not overriding, generate+store+send an `email-verification` OTP (reads response via `getEndpointResponse`).
- **Rate-limit**: nine rules, each `window:rateLimit.window||60, max:rateLimit.max||3`, for exact paths: `/email-otp/send-verification-otp`, `/email-otp/check-verification-otp`, `/email-otp/verify-email`, `/sign-in/email-otp`, `/email-otp/request-password-reset`, `/email-otp/reset-password`, `/forget-password/email-otp`, `/email-otp/request-email-change`, `/email-otp/change-email`.
- **Config + defaults**: `sendVerificationOTP` (required), `otpLength=6`, `expiresIn=300`, `generateOTP` (default digits), `sendVerificationOnSignUp=false`, `disableSignUp=false`, `allowedAttempts=3`, `storeOTP="plain"|"hashed"|"encrypted"|{hash}|{encrypt,decrypt}`, `resendStrategy="rotate"|"reuse"` (reuse resends same OTP + extends expiry, only when recoverable; falls back to rotate for hashed), `changeEmail={enabled:false,verifyCurrentEmail:false}`, `overrideDefaultEmailVerification=false`, `rateLimit={window:60,max:3}`.
- **$ERROR_CODES**: `OTP_EXPIRED:"OTP expired"`, `INVALID_OTP:"Invalid OTP"`, `TOO_MANY_ATTEMPTS:"Too many attempts"` (plus core `INVALID_EMAIL`, `USER_NOT_FOUND`, `PASSWORD_TOO_SHORT`/`LONG`).
- **Behaviors/edge cases (tests)**: emails lowercased; atomic consume = one success under concurrent verify (sign-in and email-verification); wrong code increments attempts without burning a valid OTP; consumed code cannot be replayed; budget-exhausted identifier locks out (not recreated), but a fresh OTP after exhaustion works; expired OTP → `OTP_EXPIRED` and row deleted; `resendStrategy:"reuse"` returns same OTP for plain/encrypted, rotates for hashed/custom-hash; `storeOTP` plain/hashed/encrypted/custom variants (get-verification-otp blocked for hashed); `overrideDefaultEmailVerification` sends OTP once and fires after-verification hook; sign-up with additional fields (`input:false` fields ignored, defaults applied); verify-email cookie-cache isolation — verifying a different user's email does not mark the current session's user verified; enumeration prevention when `disableSignUp`.
- **Dependencies**: consume/verification helpers, plugin rate-limit, `init()` context/emailVerification override, `hooks.after`+`getEndpointResponse`, digit OTP generator + `defaultKeyHasher` + symmetric encrypt/decrypt, `additionalFields`, `sensitiveSessionMiddleware`, cookie-cache, server-only endpoints.

---

## one-time-token

- **Purpose**: mint a short-lived single-use token from a session, then exchange it for that session (e.g. cross-domain handoff).
- **Endpoints**:
  - `GET /one-time-token/generate` — `sessionMiddleware`. Response `{ token }`. Stores `verification` `{ identifier:"one-time-token:<storedToken>", value:<session.token>, expiresAt=now+expiresIn*60s }`. Rejects client requests (`c.request` present) with 400 `"Client requests are disabled"` if `disableClientRequest`.
  - `POST /one-time-token/verify` — body `{ token }`. Atomically consumes the record; looks up the session by stored value; sets session cookie (unless `disableSetSessionCookie`); rejects expired session. Response = the session `{ session, user }`. Errors: 400 `"Invalid token"`, `"Session not found"`, `"Session expired"`.
- **Schema additions**: none (core `verification`).
- **Hooks/middleware**: `hooks.after` (matcher `true`) — on a new session, if `setOttHeaderOnNewSession`, generate a token and set header `set-ott` + add it to `Access-Control-Expose-Headers`.
- **Rate-limit**: none.
- **Config + defaults**: `expiresIn=3` (minutes), `disableClientRequest`, `generateToken(session,ctx)` (default `generateRandomString(32)`), `disableSetSessionCookie`, `storeToken="plain"|"hashed"|{type:"custom-hasher",hash}`, `setOttHeaderOnNewSession`.
- **$ERROR_CODES**: none exported (plain messages above).
- **Behaviors/edge cases (tests)**: token redeemable exactly once under concurrent verify (atomic consume); expires after `expiresIn`; rejects when the underlying session has expired; `disableClientRequest` blocks client (request-bearing) calls but allows server calls; `disableSetSessionCookie` suppresses the cookie; `setOttHeaderOnNewSession` sets `set-ott` on new sessions and on sign-in.
- **Dependencies**: consume/verification helpers, `sessionMiddleware`, `ctx.context.newSession` signal + expose-headers plumbing, `defaultKeyHasher`.

---

## bearer

- **Purpose**: accept `Authorization: Bearer <token>` and convert it to a session cookie for the request; expose the session token via `set-auth-token` on responses.
- **Endpoints**: none.
- **Schema additions**: none.
- **Hooks/middleware**:
  - `hooks.before` (matcher: request has an `authorization` header) — parse the bearer token (case-insensitive `"bearer "` scheme). If the token contains `.` it is treated as a signed value (URI-decoded when it contains `%`); otherwise, unless `requireSignature`, it is signed with the secret (`serializeSignedCookie`). Verify the HMAC-SHA-256 signature (`base64urlnopad`); on success, inject it as the session-token cookie into the request headers so downstream session loading finds it. Invalid signature → no-op (fall through).
  - `hooks.after` (matcher `true`) — if the response set a session cookie with a non-zero max-age, set header `set-auth-token: <cookie value>` and add `set-auth-token` to `Access-Control-Expose-Headers`.
- **Rate-limit**: none.
- **Config + defaults**: `requireSignature=false` (when true, only signed `.`-bearing tokens are accepted).
- **$ERROR_CODES**: none.
- **Behaviors/edge cases (tests)**: get/list session via bearer header; works on server actions and with `asResponse`; a valid cookie wins even if the authorization header is invalid.
- **Python note**: bearer is **built into core** (`session.read_token` in `session.py`) — it already reads `Authorization: Bearer`, accepting the signed value or the raw session token. Differences from TS: (1) no `set-auth-token` response header, (2) no `Access-Control-Expose-Headers` merge, (3) no `requireSignature` option, (4) Python accepts the raw unsigned session token directly rather than re-signing+verifying. Parity gap is the response-side header emission + `requireSignature`, not the request-side read.

---

## last-login-method

- **Purpose**: record the auth method used on the most recent successful login, in a cookie and optionally in the DB.
- **Endpoints**: none.
- **Schema additions** (only when `storeInDatabase:true`) (`user`): `lastLoginMethod` string, `input:false`, `required:false`, `fieldName` = `schema.user.lastLoginMethod || "lastLoginMethod"`.
- **Hooks/middleware**:
  - `init().databaseHooks.user.create.before` — when `storeInDatabase`, set `lastLoginMethod` from the resolver at user creation.
  - `init().databaseHooks.session.create.after` — when `storeInDatabase`, `updateUser(session.userId, {lastLoginMethod})`.
  - `hooks.after` (matcher `true`) — resolve the method; if the response set a session-token cookie, set a **non-httpOnly** cookie `cookieName=<method>` inheriting the session cookie's attributes but with `maxAge` overridden.
  - Default resolver: `/callback/:id` or `/oauth2/callback/:providerId` → provider id (params or last path segment); `/sign-in/email`|`/sign-up/email` → `"email"`; path includes `siwe` → `"siwe"`; `/passkey/verify-authentication` → `"passkey"`; `/magic-link/verify` → `"magic-link"`; else `null`.
- **Rate-limit**: none.
- **Config + defaults**: `cookieName="better-auth.last_used_login_method"`, `maxAge=2592000` (30d), `customResolveMethod(ctx)`, `storeInDatabase=false`, `schema`.
- **$ERROR_CODES**: none.
- **Behaviors/edge cases (tests)**: sets cookie for email/siwe/magic-link/OAuth; does NOT set the cookie on failed auth (no session cookie in response) or failed OAuth callback; DB storage on create + updates on subsequent logins (email and OAuth); handles missing `ctx.path` gracefully (normalizes to `""`); respects custom cookie prefix; cross-subdomain/cross-origin cookie attributes; multiple `set-cookie` headers handled; generic OAuth `/oauth2/callback/:providerId`.
- **Dependencies**: `init()`+databaseHooks, `hooks.after`, cookie-attribute inheritance + `ctx.setCookie`, schema `input:false`+`fieldName`.

---

## haveibeenpwned

- **Purpose**: reject passwords found in the Have I Been Pwned breach corpus (k-anonymity range query).
- **Endpoints**: none.
- **Schema additions**: none.
- **Hooks/middleware**: `init()` wraps `context.password.hash` — on the configured paths, SHA-1 the password (hex, uppercased), query `https://api.pwnedpasswords.com/range/<first5>` with headers `Add-Padding: true`, `User-Agent: BetterAuth Password Checker`, and if the suffix appears, throw `PASSWORD_COMPROMISED` (400). Non-path calls or `enabled:false` hash normally. Uses `getCurrentAuthContext()` for the active path.
- **Rate-limit**: none.
- **Config + defaults**: `customPasswordCompromisedMessage`, `enabled=true`, `paths=["/sign-up/email","/change-password","/reset-password","/email-otp/reset-password","/phone-number/reset-password","/admin/create-user","/admin/set-user-password"]`.
- **$ERROR_CODES**: `PASSWORD_COMPROMISED:"The password you entered has been compromised. Please choose a different password."` Fetch failures → 500 `"Failed to check password. Please try again later."`
- **Behaviors/edge cases (tests)**: blocks compromised password on sign-up and change-password; allows strong password; `enabled:false` allows compromised; enforced on `/email-otp/reset-password`, `/phone-number/reset-password`, `/admin/create-user`, `/admin/set-user-password`.
- **Dependencies**: `init()` context override of `password.hash` (or, since Python has no such seam, a hook invoked wherever `hash_password` is called on those paths), an async HTTP client (`auth.http` exists), path awareness. **Note**: Python's `hash_password` is a sync module function called directly in `endpoints.py`; to gate it per-path the call sites must route through a context-held async hasher.

---

## captcha

- **Purpose**: verify a CAPTCHA token (`x-captcha-response` header) against a provider before protected endpoints run.
- **Endpoints**: none.
- **Schema additions**: none.
- **Hooks/middleware**: `onRequest(request, ctx)` — strip `basePath`, normalize the pathname; if it matches a protected endpoint (default `["/sign-up/email","/sign-in/email","/request-password-reset"]`, or `options.endpoints`) and is not an exempt path (`/sign-in/email-otp`, unless explicitly opted in): require `x-captcha-response` (else 400 `MISSING_RESPONSE`); require `secretKey` (else internal `MISSING_SECRET_KEY`, surfaced as 500); dispatch to the provider handler; on failure return 403 `VERIFICATION_FAILED`; on unexpected error 500 `UNKNOWN_ERROR`. Runs **after** rate limiting (test-verified).
- **Rate-limit**: none (relies on core; verified that core rate limits apply before captcha verification).
- **Config + defaults**: `provider` (`"cloudflare-turnstile"|"google-recaptcha"|"hcaptcha"|"captchafox"`), `secretKey` (required), `endpoints`, `siteVerifyURLOverride`; provider-specific: `minScore=0.5` + `expectedAction` + `allowedHostnames` (recaptcha), `expectedAction` + `allowedHostnames` (turnstile), `siteKey` (hcaptcha, captchafox). Per-request verify timeout `CAPTCHA_VERIFY_TIMEOUT_MS=10000`. `siteVerifyMap`: turnstile→`challenges.cloudflare.com/turnstile/v0/siteverify`, recaptcha→`www.google.com/recaptcha/api/siteverify`, hcaptcha→`api.hcaptcha.com/siteverify`, captchafox→`api.captchafox.com/siteverify`.
- **$ERROR_CODES** (external): `VERIFICATION_FAILED:"Captcha verification failed"`, `MISSING_RESPONSE:"Missing CAPTCHA response"`, `UNKNOWN_ERROR:"Something went wrong"`. Internal (logs only): `MISSING_SECRET_KEY:"Missing secret key"`, `SERVICE_UNAVAILABLE:"CAPTCHA service unavailable"`.
- **Verify semantics**: POST to siteVerify with `{secret, response, remoteip?}` (turnstile JSON, others form-encoded; hcaptcha/captchafox also send `sitekey`; captchafox uses `remoteIp`). Fail closed on non-2xx/`SERVICE_UNAVAILABLE`. Fail if `success:false`; recaptcha v3 also fails if `score < minScore`; turnstile/recaptcha also fail on `expectedAction` mismatch or hostname not in `allowedHostnames`.
- **Behaviors/edge cases (tests)**: ignores non-protected endpoints; 500 on missing secret; 400 on missing token; rate limits apply before verification; 500 on siteverify failure; 403 on validation failure; recaptcha low-score 403; `/sign-in/email-otp` exempt by default but enforced when opted in; action/hostname binding rejections.
- **Dependencies**: `onRequest` (→ Python `before`, filtering on `ctx.request.path` and `x-captcha-response`), async HTTP client with timeout, `getIp`.

---

## additional-fields

- **Purpose**: **client-only** type-inference plugin (`inferAdditionalFields`) so the client sees extra `user`/`session` fields declared on the server (or passed a manual schema). Server id `additional-fields-client`; no server endpoints, hooks, or schema.
- **Underlying feature (core, not a server plugin)**: extra fields are declared via `user.additionalFields` / `session.additionalFields` in the main config. Sign-up/update accept and validate them (`parseUserInput`); outputs strip `returned:false` (`parseUserOutput`); `input:false` fields are ignored from the body and `defaultValue` applied.
- **Behaviors/edge cases (tests)**: extends fields; requires additional fields on sign-up when `required`; infers on update/sign-in; applies default values (incl. runtime default-value functions and with secondary storage); works alongside other plugins; client inference works with and without direct import.
- **Dependencies**: this is a Python **core** gap, not a plugin port — `additionalFields` config + `parseUserInput`/`parseUserOutput` in `endpoints.py`/`session.py`. The client-side `inferAdditionalFields` has no Python-server equivalent (no Python client in this port).

---

## custom-session

- **Purpose**: wrap `/get-session` so integrators can shape/augment the returned session object.
- **Endpoints**: overrides `GET /get-session` (metadata `CUSTOM_SESSION:true`, `requireHeaders:true`, query `getSessionQuerySchema`). Calls core `getSession`, then `fn(session, ctx)`; returns `null` when no session. Forwards the core handler's `set-cookie` (re-emitted individually via `ctx.setCookie`, not comma-joined) and other headers.
- **Schema additions**: none. Exposes `$Infer.Session` (type only).
- **Hooks/middleware**: `hooks.after` on `/multi-session/list-device-sessions` (only when `shouldMutateListDeviceSessionsEndpoint`) — maps `fn` over each device session.
- **Rate-limit**: none.
- **Config + defaults**: `fn(session, ctx)` (required, async), `options` (BetterAuthOptions, type inference only), `pluginOptions.shouldMutateListDeviceSessionsEndpoint=false`.
- **$ERROR_CODES**: none.
- **Behaviors/edge cases (tests)**: returns the transformed session; `set-cookie` emitted as separate entries (never comma-joined); no double-encoding of the session cookie on refresh; preserves per-cookie `Max-Age` when `cookieCache` enabled; preserves partitioned cookie attributes on refresh; accepts `disableRefresh` as a query string without validation error; multi-session mutation; type inference (omitting user/session narrows client types; composes with `inferAdditionalFields`).
- **Dependencies**: ability to **override** a core route (`/get-session`) from a plugin — Python builds routes as `[*ROUTES, *plugin.routes()]`, so a plugin route with the same `(method, path)` would be a duplicate, and `_match` returns the **first** match (core wins). Needs route-override precedence (plugin routes shadow core) or a hook that rewrites the `/get-session` response. Also needs faithful multi-set-cookie forwarding (already supported by `AuthResponse.set_cookie` appending).

---

## open-api

- **Purpose**: generate an OpenAPI 3.1 schema for all mounted endpoints and serve a Scalar reference UI.
- **Endpoints**:
  - `GET /open-api/generate-schema` — returns the generated OpenAPI JSON.
  - `GET <path>` (default `/reference`) — returns the Scalar HTML reference (404 if `disableDefaultReference`). Metadata `HIDE_METADATA`.
- **Schema additions**: none.
- **Hooks/middleware**: none.
- **Rate-limit**: none.
- **Config + defaults**: `path="/reference"`, `disableDefaultReference=false`, `theme="default"` (Scalar themes), `nonce` (CSP). HTML loads Scalar from `cdn.jsdelivr.net` (external script).
- **$ERROR_CODES**: none.
- **Generator behaviors (tests)**: model `id` fields required + read-only; includes `additionalFields` in the User schema; omits runtime-generated defaults; nested request-body objects; optional primitives stay non-nullable; OpenAPI 3.1 nullable format for get-session; unique `operationId`s across multi-method endpoints; path parameters inferred for dynamic segments; no shared parameter/response objects across methods; serializable without circular refs; unwraps `ZodDefault`; request bodies for all email-OTP POST endpoints; merges object+record intersections; default-wrapped bodies marked optional; string-length constraints preserved; required computed through Zod wrappers.
- **Dependencies**: an endpoint/metadata registry to walk. Python routes are bare `(method, path, handler)` tuples in `endpoints.py`/`plugin.routes()` with **no body/query schema metadata, no openapi metadata, no operationId**. A faithful generator would require attaching per-endpoint schema metadata across the whole port first. This is the largest and lowest-value item; a Python-idiomatic alternative is to derive a minimal schema from the route table + hand-written metadata, or defer entirely.

---

## Python current state (what exists — file:line)

- **Plugin API**: `src/better_auth/plugins.py:15` — `Plugin` base with `id`, `schema` (ClassVar), `routes()` (`:22`), `before(ctx)` (`:25`), `after(ctx, response)` (`:29`). No `init`, no matchers, no `onRequest`, no plugin rate-limit, no `$ERROR_CODES` convention.
- **Plugin wiring**: `src/better_auth/auth.py:94` merges plugin schemas; `:101–105` appends `plugin.routes()` after core `ROUTES` (core wins on collision via `_match` first-match, `:191`); `:177–180` runs every `plugin.before` (global, no matcher); `:185–188` runs every `plugin.after`. Rate limit `:216–239` supports exact-path `custom_rules` + two hardcoded special rules (`:26–38`); no plugin-contributed prefix rules. Origin/CSRF check `:206`.
- **No plugin is implemented.** None of the 13 exist in the Python port.
- **bearer**: built into core at `src/better_auth/session.py:46` (`read_token` reads `Authorization: Bearer`). Missing TS bearer response-side (`set-auth-token`, expose-headers) and `requireSignature`.
- **Schema**: `src/better_auth/schema.py:12` `Field(type, required, unique, references)` — no `input:false`, `defaultValue`, `returned`, `sortable`, `fieldName`, `transform`. `merge_schema` `:68` supports adding models/fields (used for plugin schema).
- **Adapter**: `src/better_auth/adapters/base.py:25` — `create/find_one/find_many/update/delete_many` + `Where` (ops eq/ne/in/contains/gt/gte/lt/lte). **No atomic `consume`**, no verification-specific helpers.
- **Crypto**: `src/better_auth/crypto.py` — `generate_id`, `generate_random_string(size)` (fixed alphabet, no charset arg), `hash_password`/`verify_password` (scrypt), `dummy_verify`, `sign_value`/`unsign_value` (HMAC-SHA-256, base64 w/ padding). **No** digit-OTP generator, **no** `defaultKeyHasher` (base64url-nopad SHA-256), **no** symmetric encrypt/decrypt.
- **Config**: `src/better_auth/config.py` — `EmailAndPassword`, `EmailVerification`, `SessionOptions`, `RateLimit`. Has `revoke_sessions_on_password_reset` (`:25`) but **no** `on_password_reset` callback, no `additionalFields`.
- **Verification usage**: `endpoints.py` uses the `verification` table directly with string identifiers (`reset-password:<token>`, `email-verification:<token>`) — a viable pattern for OTP identifiers, but non-atomic (`find_one` then `delete_many`).
- **HTTP client**: `auth.py:109` `auth.http` (httpx) — usable by `haveibeenpwned`/`captcha`.

---

## Gap items — ordered by implementation order (dependencies first)

**Foundation (shared infra — build before any plugin):**

1. **Plugin `init()` hook + context/config override + `databaseHooks`** — add `Plugin.init(auth) -> dict|None` merged at construction, supporting: `databaseHooks.{user,session}.{create,update}.{before,after}`, `emailVerification.send_verification_email` override, and a mutable `context.password.hash` seam. Requires threading databaseHooks into `create_session`/user create/update paths in `endpoints.py`. **L**
2. **Path-matched hooks** — extend `before`/`after` to `list[{matcher, handler}]` (or document the self-filter pattern on `ctx.request.path`) and add a `get_endpoint_response(response)` helper (parse outgoing JSON). **M**
3. **Adapter atomic consume + verification helpers** — add `consume_verification_value(identifier)` (atomic find+delete) to `BaseAdapter`/`MemoryAdapter`/`SQLAlchemyAdapter`, plus thin `create/find/delete/update` verification helpers. Single race gate for OTP/token single-use. **M**
4. **Crypto: OTP + hashing helpers** — charset-parameterized `generate_random_string(size, *charsets)` (or a `generate_otp(length)` digits helper + `generate_token(size, alpha)`), `default_key_hasher` (base64url-nopad SHA-256), `symmetric_encrypt/decrypt`. **S–M**
5. **Schema field attributes** — add `input`, `default_value`, `returned`, `sortable`, `field_name`, `transform_input` to `Field`; honor `input:false`/`default_value` in user create/update, `returned:false` in output, `transform_input` on write. **M**
6. **`additionalFields` core support** — `user.additional_fields`/`session.additional_fields` config + `parse_user_input`/`parse_user_output`; wire into sign-up/update/output. Unblocks `additional-fields`, `email-otp`, `phone-number.signUpOnVerification`. **M**
7. **Plugin-contributed rate-limit rules** — collect `plugin.rate_limit` (prefix/matcher, window, max) and fold into `_check_rate_limit`. **M**
8. **New-session signal + response-header plumbing** — expose "a session was created on this response" to `after` hooks; helpers to append `set-auth-token`/`set-ott` and merge `Access-Control-Expose-Headers`. **S–M**
9. **Route-override precedence** — let a plugin route shadow a core route of the same `(method, path)` (needed by `custom-session` `/get-session`), or provide an after-hook rewrite path. **S**
10. **`onPasswordReset` callback + config** — add to `EmailAndPassword` (used by phone-number/email-otp reset). **S**

**Plugins (after foundation; independent plugins can proceed in parallel):**

11. **bearer response-side parity** — emit `set-auth-token` + expose-headers on new sessions; add `require_signature`. (Request-side already in core.) **S**
12. **haveibeenpwned** — needs (1) context `password.hash` seam + async hasher call sites, and `auth.http`. **S–M**
13. **last-login-method** — needs (1) databaseHooks, (2) after-hook cookie emission, (5) `input:false`/`field_name`. **M**
14. **username** — needs (1) databaseHooks, (2) path hooks, (5) `transform_input`/`unique`, credential sign-in reuse, verification-token issuance. **M–L**
15. **anonymous** — needs (5) `input:false`+`default_value`, (2) after-hook + new-session signal, `parse_user_output`, sensitive-session guard. **M**
16. **one-time-token** — needs (3) consume, (8) `set-ott`, (4) `default_key_hasher`, session middleware. **M**
17. **magic-link** — needs (3) consume, (7) rate-limit, trusted-URL (`ensure_trusted_url` exists), (4) token gen/hasher, unproven-account revoke. **M**
18. **phone-number** — needs (3) consume, (7) rate-limit, (1) databaseHooks, (2) path hooks, (6) additional fields, (4) digit OTP, (10) onPasswordReset. **L**
19. **email-otp** — needs (3) consume, (7) rate-limit, (1) init override, (2) after-hook + `get_endpoint_response`, (4) OTP + hasher + symmetric crypto, (6) additional fields, (10) onPasswordReset, sensitive-session, cookie-cache. **L**
20. **captcha** — needs `before`/`onRequest` path filtering + async HTTP with per-request timeout + `get_ip`. Largely self-contained. **M**
21. **custom-session** — needs (9) route override + faithful multi-set-cookie forwarding. **M**
22. **additional-fields** — server side is just (6); the client `inferAdditionalFields` has no Python-server counterpart. **S** (or N/A).
23. **open-api** — needs a full endpoint-metadata registry (body/query/response schema + operationId + openapi metadata) across the port before a faithful generator is possible. Largest, lowest value. **L** (recommend defer).

---

## Open questions

1. **BLOCKED: `init()` context override for `password.hash` (haveibeenpwned).** Python `hash_password` is a sync module function called directly in `endpoints.py` (sign-up, change/reset/set-password). Options: (a) route all hashing through an async, context-held `ctx.password.hash` so plugins can wrap it (matches TS, larger refactor); (b) add a dedicated `password_check` hook list invoked on the configured paths before hashing (smaller, less general). **Default: (b)** — a `before`-style password-compromise hook keyed by path, since Python has no context-override seam and `hash_password` is synchronous.
2. **BLOCKED: open-api generator source of truth.** TS derives the schema from rich per-endpoint Zod + openapi metadata that the Python port does not carry. Options: (a) add metadata to every route and port the generator; (b) hand-maintain an OpenAPI document; (c) defer. **Default: (c) defer** — recommend excluding open-api from the first plugin milestone; revisit once route metadata exists.
3. **`overrideDefaultEmailVerification` (email-otp) vs core verify-email.** TS replaces `emailVerification.sendVerificationEmail` via `init()`. Confirm the Python core will call a plugin-provided sender the same way `_send_verification_email` (`endpoints.py:66`) currently calls `cfg.send_verification_email`. **Default: route the core sender through a possibly-plugin-overridden callable set during init.**
4. **`custom-session` route override.** Should a plugin route shadow the same-path core route (precedence), or should custom-session be modeled as an `after` hook that rewrites the `/get-session` body? Precedence is cleaner but changes `_match` semantics (currently first-match = core wins). **Default: plugin routes shadow core** (append plugins first, or a dedicated override table), but flag the semantic change for review.
5. **`last-login-method` non-httpOnly cookie + attribute inheritance.** Python `build_cookie` (`session.py:31`) always sets `HttpOnly` and fixed attributes. The plugin needs a non-httpOnly cookie inheriting session-cookie attributes (SameSite/Domain/Secure) with a custom Max-Age. Needs a more configurable cookie builder. **Default: generalize `build_cookie` to accept attribute overrides.**
6. **`getSessionFromCtx(disableRefresh)` semantics.** anonymous/phone-number read the session without sliding its expiry. Python `ctx.get_session()`/`load_session` always runs the refresh path (`session.py:127`). Need a `disable_refresh` option to avoid mutating expiry during hook checks. **Default: add `disable_refresh` param to `get_session`.**
7. **`storeToken`/`storeOTP` custom async hashers.** These are user-supplied async callables — confirm the config surface accepts async callables in the Python dataclasses (it can). No blocker; noted for API design.
8. **`sensitiveSessionMiddleware` / `sessionMiddleware`.** Several endpoints require "freshly re-authenticated" vs "any valid session". Python only has `require_session`. Confirm whether the port needs the sensitive (recently-created session) variant or can treat both as `require_session` initially. **Default: alias sensitive→`require_session` initially, revisit for the sensitive freshness check.**
