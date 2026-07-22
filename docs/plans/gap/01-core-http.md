# Core HTTP — better-auth v1.6.23 → Python parity spec

Scope: the core HTTP/API layer only (router assembly, request lifecycle, core
route handlers, cookies, rate limiting, CSRF/origin, the plugin contract, and the
`BetterAuthOptions` tree). OAuth provider internals, DB adapters, and client SDK
are out of scope except where they cross the request boundary.

Prime directive: wire/storage fidelity. Same route paths, same JSON field names
(camelCase preserved), same error-code strings, same cookie names/formats, same
camelCase DB columns. Every claim below is grounded in the TS source at tag
v1.6.23 (`packages/better-auth/src`, `packages/core/src`) and the Python port at
`src/better_auth`. Line references use `file:line`.

---

## TS inventory (authoritative)

### Router assembly & request lifecycle

Entry: `api/index.ts` `router()` (line 273) → `createRouter(api, {...})` from the
`better-call` library. Assembly steps:

1. `getEndpoints(ctx, options)` (`api/index.ts:173`) builds `baseEndpoints`
   (line 230) + `pluginEndpoints` + `ok` + `error`, then wraps each with
   `toAuthEndpoints` (`api/to-auth-endpoints.ts:73`) so every call runs through
   the hook pipeline in `dispatchAuthEndpoint` (`api/dispatch.ts:321`).
2. Router config (`api/index.ts:280`): `basePath = new URL(ctx.baseURL).pathname`,
   `routerMiddleware = [{path:"/**", middleware: originCheckMiddleware}, ...pluginMiddlewares]`,
   `allowedMediaTypes: ["application/json"]`,
   `skipTrailingSlashes: options.advanced?.skipTrailingSlashes ?? false`.
3. `onRequest(req)` (line 295): (a) reject `options.disabledPaths` with 404;
   (b) `onRequestRateLimit(req, ctx)` — atomic rate-limit check, returns 429 or
   nothing; (c) run each `plugin.onRequest` in order (may replace request or
   short-circuit with a response).
4. Route match → per-request before-hooks (user `hooks.before`, then plugin
   `hooks.before[]` with matchers) → endpoint `use:[]` middlewares → handler →
   after-hooks (user `hooks.after`, plugin `hooks.after[]`).
5. `onResponse(res, req)` (line 331): run each `plugin.onResponse` in order.
6. `onError(e)` (line 350): if `APIError` with status `FOUND` (redirect) swallow;
   else honour `options.onAPIError.throw` / `.onError`; else log per
   `options.logger.level` unless `logger.disabled`.

Dispatch details (`api/dispatch.ts`): before-hooks may return a short-circuit
response or a `{context}` patch merged via `defu`; APIErrors thrown in
handler/after are caught, their `kAPIErrorHeaderSymbol` + `e.headers` merged
(`mergeAPIErrorHeaders`, line 114), and re-thrown to `auth.api.*` callers or
serialized to a `Response` for HTTP callers. `set-cookie` headers accumulate;
all other headers replace.

### Endpoints

Legend: **Auth** = session requirement (via middleware `use:[]`). `sessionMiddleware`
= any valid session (cookie cache allowed). `sensitiveSessionMiddleware` =
authoritative read (bypasses cookie cache on stateful deploys). `freshSessionMiddleware`
= valid + fresh (`createdAt` within `session.freshAge`). Error codes are the
`BASE_ERROR_CODES` **keys** (the string sent is `code`; `message` is the mapped
English text, see error-codes list).

| Route | Method | Auth | Key request fields | Response JSON (exact fields) | Notable error codes | Cookies |
|---|---|---|---|---|---|---|
| `/ok` | GET | none | — | `{ok:true}` | — | — |
| `/error` | GET | none | `?error`,`?error_description` | HTML page (or 302 to `errorURL`/`/` in prod) | — | — |
| `/sign-up/email` | POST | none (`formCsrfMiddleware`) | `name,email,password,image?,callbackURL?,rememberMe?`+additional | `{token: string\|null, user}` | `EMAIL_PASSWORD_SIGN_UP_DISABLED`, `INVALID_EMAIL`, `INVALID_PASSWORD`, `PASSWORD_TOO_SHORT/LONG`, `USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL`, `FAILED_TO_CREATE_USER`, `FAILED_TO_CREATE_SESSION` | sets session cookies unless verify-required/`autoSignIn:false` |
| `/sign-in/email` | POST | none (`formCsrfMiddleware`) | `email,password,callbackURL?,rememberMe?=true` | `{redirect:boolean, token:string, url?:string, user}` | `EMAIL_PASSWORD_DISABLED`, `INVALID_EMAIL`, `INVALID_EMAIL_OR_PASSWORD`, `EMAIL_NOT_VERIFIED`, `FAILED_TO_CREATE_SESSION` | sets session cookies; `Location` header if callbackURL |
| `/sign-in/social` | POST | none | `provider,callbackURL?,newUserCallbackURL?,errorCallbackURL?,disableRedirect?,idToken?,scopes?,requestSignUp?,loginHint?,additionalData?` | redirect branch `{url, redirect}` or idToken branch `{redirect:false, token, url:undefined, user}` | `PROVIDER_NOT_FOUND`, `ID_TOKEN_NOT_SUPPORTED`, `INVALID_TOKEN`, `FAILED_TO_GET_USER_INFO`, `USER_EMAIL_NOT_FOUND`, `OAUTH_LINK_ERROR` | idToken branch sets session; state stored per `storeStateStrategy` |
| `/callback/:id` | GET,POST | none | query/body `code,error,error_description,device_id,state,user` | 302 redirect (to callbackURL / newUserURL / errorURL) | redirects with `?error=<code>` | sets session cookie; POST re-redirects to GET |
| `/get-session` | GET,POST | none | `?disableCookieCache,?disableRefresh` | `{session, user}` or `null`; `+needsRefresh` if `deferSessionRefresh` GET | `METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED` (POST w/o deferSessionRefresh), `FAILED_TO_GET_SESSION` | may refresh/clear session + session_data cookies |
| `/sign-out` | POST | requireHeaders | — | `{success:true}` | — | clears session cookie |
| `/list-sessions` | GET | fresh + requireHeaders | — | `Session[]` (active only) | `SESSION_NOT_FRESH`, `INTERNAL_SERVER_ERROR` | — |
| `/revoke-session` | POST | sensitive + requireHeaders | `token` | `{status:true}` | — (no error if token unknown/foreign) | — |
| `/revoke-sessions` | POST | sensitive + requireHeaders | — | `{status:true}` | `INTERNAL_SERVER_ERROR` | — |
| `/revoke-other-sessions` | POST | sensitive + requireHeaders | — | `{status:true}` | `UNAUTHORIZED` | — |
| `/update-user` | POST | session | `name?,image?`+additional (no `email`) | `{status:true}` | `BODY_MUST_BE_AN_OBJECT`, `EMAIL_CAN_NOT_BE_UPDATED`, `"No fields to update"` | refreshes session cookie w/ new user |
| `/change-password` | POST | sensitive | `newPassword,currentPassword,revokeOtherSessions?` | `{token: string\|null, user}` | `PASSWORD_TOO_SHORT/LONG`, `CREDENTIAL_ACCOUNT_NOT_FOUND`, `INVALID_PASSWORD`, `FAILED_TO_GET_SESSION` | on revokeOther: revokes ALL, mints NEW session cookie |
| `/set-password` | POST | **serverOnly** + sensitive | `newPassword` | `{status:true}` | `PASSWORD_TOO_SHORT/LONG`, `PASSWORD_ALREADY_SET` | — (not exposed over HTTP router) |
| `/verify-password` | POST | **scope:"server"** + sensitive | `password` | `{status:true}` (throws on invalid) | `INVALID_PASSWORD` | — |
| `/request-password-reset` | POST | none (`originCheck(redirectTo)`) | `email,redirectTo?` | `{status:true, message:"If this email exists…"}` | `RESET_PASSWORD_DISABLED`, `INVALID_REDIRECT_URL` | — |
| `/forget-password` | POST | (alias, TS: same as request-password-reset via client) | as above | as above | as above | — |
| `/reset-password/:token` | GET | none (`originCheck(callbackURL)`) | path `token`, `?callbackURL` (required) | 302 redirect to `callbackURL?token=` or `?error=INVALID_TOKEN` | — | — |
| `/reset-password` | POST | none | `newPassword`, `token?` (body or `?token`) | `{status:true}` | `INVALID_TOKEN`, `PASSWORD_TOO_SHORT/LONG` | — |
| `/send-verification-email` | POST | optional session | `email,callbackURL?` | `{status:true}` | `VERIFICATION_EMAIL_NOT_ENABLED`, `EMAIL_MISMATCH`, `EMAIL_ALREADY_VERIFIED` | — |
| `/verify-email` | GET | none (`originCheck(callbackURL)`) | `?token` (JWT), `?callbackURL` | `{status:true, user: null}` (or `{status,user}` on change-email) or 302 | `TOKEN_EXPIRED`, `INVALID_TOKEN`, `USER_NOT_FOUND`, `INVALID_USER` (redirects on error if callbackURL) | may set session cookie (autoSignIn) |
| `/change-email` | POST | sensitive | `newEmail,callbackURL?` | `{status:true, message?}` | `CHANGE_EMAIL_DISABLED`, `"Email is the same"`, `"Verification email isn't enabled"` | may refresh session cookie |
| `/delete-user` | POST | sensitive | `password?,token?,callbackURL?` | `{success:true, message:"User deleted"\|"Verification email sent"}` | 404 (disabled), `CREDENTIAL_ACCOUNT_NOT_FOUND`, `INVALID_PASSWORD`, `SESSION_EXPIRED` | clears session cookie on delete |
| `/delete-user/callback` | GET | session (bypass cache if stateful) | `?token,?callbackURL` | `{success:true, message:"User deleted"}` or 302 | 404, `INVALID_TOKEN`, `FAILED_TO_GET_USER_INFO` | clears session cookie |
| `/link-social` | POST | session + requireHeaders | `provider,callbackURL?,idToken?,requestSignUp?,scopes?,errorCallbackURL?,disableRedirect?,additionalData?` | `{url, redirect}` or `{url:"", status:true, redirect:false}` | `PROVIDER_NOT_FOUND`, `ID_TOKEN_NOT_SUPPORTED`, `INVALID_TOKEN`, `FAILED_TO_GET_USER_INFO`, `USER_EMAIL_NOT_FOUND`, `LINKING_NOT_ALLOWED`, `LINKING_DIFFERENT_EMAILS_NOT_ALLOWED`, `LINKING_FAILED` | — |
| `/list-accounts` | GET | session | — | `Account[]` with `{id,providerId,createdAt,updatedAt,accountId,userId,scopes:string[]}` (scope→scopes, tokens stripped) | — | — |
| `/unlink-account` | POST | fresh | `providerId,accountId?` | `{status:true}` | `FAILED_TO_UNLINK_LAST_ACCOUNT`, `ACCOUNT_NOT_FOUND` | — |
| `/refresh-token` | POST | resolveUserId | `providerId,accountId?,userId?` | `{accessToken,refreshToken,accessTokenExpiresAt,refreshTokenExpiresAt,scope,idToken,providerId,accountId}` | `PROVIDER_NOT_SUPPORTED`, `TOKEN_REFRESH_NOT_SUPPORTED`, `ACCOUNT_NOT_FOUND`, `REFRESH_TOKEN_NOT_FOUND`, `FAILED_TO_REFRESH_ACCESS_TOKEN`, `USER_ID_OR_SESSION_REQUIRED` | — |
| `/get-access-token` | POST | resolveUserId | `providerId,accountId?,userId?` | `{accessToken,accessTokenExpiresAt,scopes,idToken}` | `PROVIDER_NOT_SUPPORTED`, `ACCOUNT_NOT_FOUND`, `FAILED_TO_GET_ACCESS_TOKEN` | — |
| `/account-info` | GET | resolveUserId | `?accountId,?providerId,?userId` | provider `getUserInfo` shape `{user, data}` | `ACCOUNT_NOT_FOUND`, `AMBIGUOUS_ACCOUNT`, `PROVIDER_NOT_CONFIGURED`, `ACCESS_TOKEN_NOT_FOUND` | — |
| `/update-session` | POST | session | additional session fields | `{session}` | `BODY_MUST_BE_AN_OBJECT`, `"No fields to update"`, `FAILED_TO_GET_SESSION` | refreshes session cookie |

Response `user` / `session` objects are always passed through `parseUserOutput` /
`parseSessionOutput` (`db/schema`), i.e. only schema-declared + configured
additional fields are emitted (sensitive/unknown fields dropped).

### Plugin interface contract

`BetterAuthPlugin` (`packages/core/src/types/plugin.ts:39`). Every field and when
core invokes it:

- `id: string` (required) — namespace for hooks/logs; used in endpoint-conflict
  detection (`api/index.ts:58`).
- `version?: string`.
- `init?(ctx) => {context?, options?} | void` — called once at context creation;
  may deep-merge into `AuthContext` and patch `options`.
- `endpoints?: { [key]: Endpoint }` — merged into the router (`getEndpoints`
  line 177) and into `auth.api`. Each endpoint carries `path`, `options.method`,
  `body`/`query` zod schemas, `use:[]` middlewares, `metadata` (operationId,
  openapi, `scope:"server"`, `allowedMediaTypes`).
- `middlewares?: {path, middleware}[]` — registered as router middleware
  (`api/index.ts:197`), wrapped with a span; run for matching paths.
- `onRequest?(request, ctx) => {response} | {request} | void` — in `onRequest`
  phase (line 310); can short-circuit or rewrite the request.
- `onResponse?(response, ctx) => {response} | void` — in `onResponse` phase.
- `hooks?.before?: {matcher, handler}[]` / `hooks?.after?: {matcher, handler}[]` —
  before/after the endpoint (`dispatch.ts:287`); `matcher(ctx)` gates each; handler
  is an `AuthMiddleware`. Plugin hooks run AFTER user `options.hooks.before/after`.
- `schema?: BetterAuthPluginDBSchema` — merged into DB schema, drives migrations;
  fields have `type`, `required`, `unique`, `references`, `defaultValue`,
  `fieldName`, `input`, `returned`.
- `migrations?`, `options?`, `$Infer?` — types/config passthrough.
- `rateLimit?: {window, max, pathMatcher}[]` — consulted per-request in
  `resolveRateLimitConfig` (`rate-limiter/index.ts:403`); first matching rule wins,
  overrides default/special rules.
- `adapter?: {[key]: fn}` — override DB operations.
- `$ERROR_CODES?: Record<string, RawError>` — plugin error-code table, surfaced on
  the built instance for typed client errors.

### Config options — `BetterAuthOptions` (`packages/core/src/types/init-options.ts:429`)

Full tree with defaults (only non-obvious defaults noted):

- `appName?` (default `"Better Auth"`; also the cookie-prefix source).
- `baseURL?: string | {allowedHosts, fallback?, protocol?}` (dynamic multi-domain).
- `basePath?` (default `"/api/auth"`).
- `secret?` / `secrets?: {version,value}[]` (rotation via envelope encryption).
- `database?` (Kysely/pool/adapter/D1/bun/node-sqlite variants; `casing:"camel"`).
- `secondaryStorage?: {get,set,delete,increment?}` (sessions + rate limit).
- `emailVerification?`: `sendVerificationEmail(data,request?)`, `sendOnSignUp?`,
  `sendOnSignIn?` (default false), `autoSignInAfterVerification?`, `expiresIn?`
  (default 3600), `beforeEmailVerification?`, `afterEmailVerification?`.
- `emailAndPassword?`: `enabled` (default false), `disableSignUp?`,
  `requireEmailVerification?`, `maxPasswordLength?` (128), `minPasswordLength?` (8),
  `sendResetPassword(data,request?)`, `resetPasswordTokenExpiresIn?` (3600),
  `onPasswordReset?`, `password?: {hash?, verify?}`, `autoSignIn?` (default true),
  `revokeSessionsOnPasswordReset?` (false), `onExistingUserSignUp?`,
  `customSyntheticUser?`.
- `socialProviders?`.
- `plugins?: BetterAuthPlugin[]`.
- `user?`: `modelName?`, `fields?` (column remap), `additionalFields?`,
  `changeEmail?: {enabled, sendChangeEmailConfirmation?, updateEmailWithoutVerification?}`,
  `deleteUser?: {enabled?, sendDeleteAccountVerification?, beforeDelete?, afterDelete?, deleteTokenExpiresIn? (86400)}`.
- `session?`: `modelName/fields/additionalFields`, `expiresIn?` (604800),
  `updateAge?` (86400), `disableSessionRefresh?`, `deferSessionRefresh?`,
  `storeSessionInDatabase?`, `preserveSessionInDatabase?`,
  `cookieCache?: {maxAge? (300), enabled? (false), strategy? ("compact"|"jwt"|"jwe"), refreshCache?, version? ("1")}`,
  `freshAge?` (86400).
- `account?`: `modelName/fields/additionalFields`, `updateAccountOnSignIn?` (true),
  `accountLinking?: {enabled? (true), disableImplicitLinking?, requireLocalEmailVerified? (true), trustedProviders?, allowDifferentEmails? (false), allowUnlinkingAll? (false), updateUserInfoOnLink? (false)}`,
  `encryptOAuthTokens?` (false), `skipStateCookieCheck?` (false),
  `storeStateStrategy? ("database"|"cookie")`, `storeAccountCookie?` (false).
- `verification?`: `modelName/fields`, `disableCleanup?`, `storeIdentifier?`
  (`"plain"|"hashed"|{hash}`), `storeInDatabase?`.
- `trustedOrigins?: string[] | (request?) => (string|null|undefined)[]` (wildcards).
- `rateLimit?`: `window?` (10), `max?` (100), `enabled?` (prod-only default),
  `customRules?: {[path]: rule | false | fn}`, `storage? ("memory"|"database"|"secondary-storage")`,
  `customStorage?`, `modelName/fields`.
- `advanced?`: `ipAddress?: {ipAddressHeaders?, disableIpTracking?, ipv6Subnet? (64), trustedProxies?}`,
  `useSecureCookies?` (false override), `disableCSRFCheck?`, `disableOriginCheck?`,
  `crossSubDomainCookies?: {enabled, additionalCookies?, domain?}`,
  `cookies?: {[key]: {name?, attributes?}}`, `defaultCookieAttributes?`,
  `cookiePrefix?`, `database?: {defaultFindManyLimit? (100), generateId?}`,
  `trustedProxyHeaders?`, `backgroundTasks?: {handler}`, `skipTrailingSlashes?` (false).
- `logger?: {level, disabled?, log?}`.
- `databaseHooks?`: `user|session|account|verification` × `create|update|delete` ×
  `before|after`. `before` may return `false` (abort) or `{data}` (replace).
- `onAPIError?`: `throw?`, `onError(error,ctx)?`, `errorURL?`,
  `customizeDefaultErrorPage?` (colors/size/font/toggles).
- `hooks?`: `before?: AuthMiddleware`, `after?: AuthMiddleware` (global, matcher
  `() => true`).
- `disabledPaths?: string[]`.
- `telemetry?: {enabled? (false), debug?}`.
- `experimental?: {joins?}`.

### Cookies (`cookies/index.ts`, `cookies/cookie-utils.ts`)

- Names via `createCookieGetter` (line 40). Pattern:
  `${securePrefix}${cookiePrefix}.${cookieKey}` where `cookiePrefix` =
  `advanced.cookiePrefix || "better-auth"`, `securePrefix` = `"__Secure-"` when
  secure (see below). Per-cookie override via `advanced.cookies[key].name`.
- Cookie keys: `session_token`, `session_data`, `dont_remember`, `account_data`
  (+ plugin cookies).
- **Secure resolution** (line 61): `advanced.useSecureCookies` if set; else dynamic
  `protocol:"https"→true/"http"→false`; else static `baseURL.startsWith("https://")`;
  else `isProduction` (`NODE_ENV==="production"`). `__Host-`/`__Secure-` prefix
  constant in `cookie-utils.ts` (`SECURE_COOKIE_PREFIX`).
- Attributes: `{secure, sameSite:"lax", path:"/", httpOnly:true, [domain if crossSub],
  ...defaultCookieAttributes, ...overrides, ...per-cookie attributes}`.
- **Cross-subdomain** (line 72): when `crossSubDomainCookies.enabled`, sets
  `domain = config.domain || new URL(baseURL).hostname`; throws if no domain and
  static baseURL. `additionalCookies` widened to the shared domain.
- **session_token signing**: `${token}.${makeSignature(token, secret)}` where
  `makeSignature` (`crypto/index.ts:112`) = **standard base64 (with padding, 44 chars,
  ends with `=`)** of HMAC-SHA256. `dont_remember` = signed `"true"`.
- **session_data cookie cache** (`setCookieCache` line 152): payload
  `{session, user, updatedAt, version}`; encoded by strategy — `compact`
  (base64url + HMAC-SHA256 **base64urlnopad** signature, `{session,expiresAt,signature}`),
  `jwt` (HS256 JWT), or `jwe` (A256CBC-HS512). maxAge = `cookieCache.maxAge` (300)
  unless dontRememberMe (session cookie). Chunked if oversized.
- Session refresh formula (`session.ts:421`):
  `dueDate = expiresAt - expiresIn*1000 + updateAge*1000`; refresh when `dueDate <= now`
  and not dontRemember and not disabled and not skip-flagged.

### Rate limiting (`api/rate-limiter/index.ts`)

- Default rule `{window:10, max:100}`; `enabled` defaults true only in production.
- Storage: `memory` (default), `database` (`rateLimit` table), `secondary-storage`,
  or `customStorage`. Atomic `consume(key, rule)` primitive; memory backend uses
  a rolling window keyed on `lastRequest` with prune + 100k cap; DB backend uses
  guarded `incrementOne`; secondary uses fixed-TTL `increment`.
- Key: `createRateLimitKey(ip, normalizedPath)`; IP from `getIp` honouring
  `ipAddressHeaders`/`trustedProxies`/`ipv6Subnet`; fail-closed shared bucket
  `"no-trusted-ip"` when no IP; skip entirely only if `disableIpTracking` and no IP.
- Special rules (`getDefaultSpecialRules` line 513):
  - `{window:10, max:3}` for paths starting `/sign-in`, `/sign-up`,
    `/change-password`, `/change-email`.
  - `{window:60, max:3}` for `/request-password-reset`, `/send-verification-email`,
    paths starting `/forget-password`, plus `/email-otp/send-verification-otp`,
    `/email-otp/request-password-reset` (plugin paths).
- Precedence: default → special rule → **plugin `rateLimit[]`** (first match) →
  `customRules` (exact or `*` wildcard; may be a function or `false` to skip).
- 429 body `{message:"Too many requests. Please try again later."}`, header
  `X-Retry-After: <seconds>`.

### CSRF / origin (`api/middlewares/origin-check.ts`)

- `originCheckMiddleware` (router `/**`, line 66): skips GET/OPTIONS/HEAD; else
  `validateOrigin` then per-URL validation of `callbackURL`, `redirectTo`,
  `errorCallbackURL`, `newUserCallbackURL` against `isTrustedOrigin` with distinct
  error codes. Non-string URL → 400.
- `validateOrigin` (line 220): reads `origin` || `referer`; validates when cookies
  present (or forced). No/`"null"` origin with cookies → `MISSING_OR_NULL_ORIGIN`.
  Trusted-origin match via `matchesOriginPattern` (wildcards + dynamic function form).
  Skips on `skipCSRFCheck` / backward-compat `disableOriginCheck`.
- `formCsrfMiddleware` (line 283, on sign-in/sign-up): if cookies present →
  `validateOrigin`; else use Fetch Metadata — block `Sec-Fetch-Site: cross-site` +
  `Sec-Fetch-Mode: navigate` → `CROSS_SITE_NAVIGATION_LOGIN_BLOCKED`; else if any
  origin/referer present force-validate; else pass (non-browser clients).

### Error codes (`packages/core/src/error/codes.ts` — `BASE_ERROR_CODES`)

Full key set (the string in `code`): `USER_NOT_FOUND, FAILED_TO_CREATE_USER,
FAILED_TO_CREATE_SESSION, FAILED_TO_UPDATE_USER, FAILED_TO_GET_SESSION,
INVALID_PASSWORD, INVALID_EMAIL, INVALID_EMAIL_OR_PASSWORD, INVALID_USER,
SOCIAL_ACCOUNT_ALREADY_LINKED, PROVIDER_NOT_FOUND, INVALID_TOKEN, TOKEN_EXPIRED,
ID_TOKEN_NOT_SUPPORTED, FAILED_TO_GET_USER_INFO, USER_EMAIL_NOT_FOUND,
EMAIL_NOT_VERIFIED, PASSWORD_TOO_SHORT, PASSWORD_TOO_LONG, USER_ALREADY_EXISTS,
USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL, EMAIL_CAN_NOT_BE_UPDATED,
CHANGE_EMAIL_DISABLED, CREDENTIAL_ACCOUNT_NOT_FOUND, SESSION_EXPIRED,
FAILED_TO_UNLINK_LAST_ACCOUNT, ACCOUNT_NOT_FOUND, USER_ALREADY_HAS_PASSWORD,
CROSS_SITE_NAVIGATION_LOGIN_BLOCKED, VERIFICATION_EMAIL_NOT_ENABLED,
EMAIL_ALREADY_VERIFIED, EMAIL_MISMATCH, SESSION_NOT_FRESH,
LINKED_ACCOUNT_ALREADY_EXISTS, INVALID_ORIGIN, INVALID_CALLBACK_URL,
INVALID_REDIRECT_URL, INVALID_ERROR_CALLBACK_URL, INVALID_NEW_USER_CALLBACK_URL,
MISSING_OR_NULL_ORIGIN, CALLBACK_URL_REQUIRED, FAILED_TO_CREATE_VERIFICATION,
FIELD_NOT_ALLOWED, ASYNC_VALIDATION_NOT_SUPPORTED, VALIDATION_ERROR, MISSING_FIELD,
METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED, BODY_MUST_BE_AN_OBJECT,
PASSWORD_ALREADY_SET`.

Error body shape: `{code, message}` (+HTTP status). `APIError.from("STATUS", {code,message})`.
Route-local codes not in the base set: `EMAIL_PASSWORD_DISABLED`,
`EMAIL_PASSWORD_SIGN_UP_DISABLED`, `RESET_PASSWORD_DISABLED`, `OAUTH_LINK_ERROR`,
`LINKING_NOT_ALLOWED`, `LINKING_DIFFERENT_EMAILS_NOT_ALLOWED`, `LINKING_FAILED`,
`USER_ID_OR_SESSION_REQUIRED`, `PROVIDER_NOT_SUPPORTED`, `TOKEN_REFRESH_NOT_SUPPORTED`,
`REFRESH_TOKEN_NOT_FOUND`, `FAILED_TO_REFRESH_ACCESS_TOKEN`, `FAILED_TO_GET_ACCESS_TOKEN`,
`ACCESS_TOKEN_NOT_FOUND`, `AMBIGUOUS_ACCOUNT`, `PROVIDER_NOT_CONFIGURED`.

### Behaviors & edge cases (from route code + tests)

- **Email-verification token is a JWT** (`email-verification.ts:15,303`): signed
  HS256 with payload `{email, updateTo?, requestType?}`, verified via `jose.jwtVerify`.
  There is NO `verification` DB row for email verification. Change-email uses the
  same JWT with `requestType: "change-email-confirmation" | "change-email-verification"`.
- **verify-email returns `user: null`** on plain verification success (line 484,540);
  only change-email verification returns the parsed user.
- **Sign-up enumeration protection** (`sign-up.ts:235`): when
  `requireEmailVerification` OR `autoSignIn:false`, an existing email returns a
  fabricated `{token:null, user: syntheticUser}` (200) instead of a 422; otherwise
  throws `USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL` (422). Password is still hashed to
  equalize timing.
- **sign-in timing**: password hashed even when user/credential/hash missing
  (`sign-in.ts:494,506,515`).
- **revoke-session never errors** on unknown/foreign token — returns `{status:true}`
  (`session.ts:812`).
- **change-password revokeOtherSessions** deletes ALL sessions incl. current, mints
  a brand-new session/cookie, returns the new token (`update-user.ts:291`).
- **list-sessions requires a fresh session** (`freshSessionMiddleware`).
- **unlink-account** blocks removing the only account unless `allowUnlinkingAll`;
  removes exactly one matching account (`account.ts:417`).
- **send-verification-email** enforces a 500ms constant-time floor for
  unauthenticated callers (`email-verification.ts:180`).
- **request-password-reset** always returns the same `{status:true, message}` (no
  enumeration), simulating token gen + lookup for unknown users (`password.ts:104`).
- **reset-password / delete-user token** are single-use via
  `consumeVerificationValue` (atomic) to defeat concurrent racers.
- **get-session cookie cache**: cached session honoured unless
  `?disableCookieCache`, version-checked, refreshed before expiry when
  `refreshCache` set; falls through to DB on miss/expiry.
- **POST /callback** redirects to GET `/callback/:id?<params>` to ensure cookies.
- **set-password & verify-password are server-scoped** (not reachable via HTTP
  router); `verify-password` returns `{status:true}` and throws `INVALID_PASSWORD`
  when wrong (never `{valid:false}`).

---

## Python current state — what exists, what differs

Files: `auth.py` (router/dispatch/rate-limit/origin), `endpoints.py` (handlers +
`ROUTES`), `session.py` (cookies + session lifecycle), `oauth.py` (social),
`crypto.py`, `schema.py`, `config.py`, `plugins.py`, `types.py`,
`integrations/fastapi.py`. ~2.1k lines total.

### What matches (parity WINS — do not regress)

- Core DB schema camelCase columns are identical (`schema.py:22`): user/session/
  account/verification with the same field names/types. `account` includes
  `accessToken/refreshToken/idToken/accessTokenExpiresAt/refreshTokenExpiresAt/scope/password`.
- Password hashing = better-auth scrypt (`crypto.py:38`): N=16384, r=16, p=1,
  dkLen=64, salt = hex-string bytes, format `${saltHex}:${keyHex}`, NFKC normalize.
  Byte-for-byte compatible.
- **session_token cookie signature matches**: `crypto.py:74` uses standard base64
  WITH padding (44 chars ending `=`), same as TS `makeSignature`. `sign_value`
  = `quote(f"{token}.{sig}")`. Compatible on the wire.
- Cookie name pattern `${prefix}.${base}` with `__Secure-` prefix over HTTPS
  (`session.py:26`). Default prefix `"better-auth"`, `SameSite=Lax`, `HttpOnly`,
  `Path=/`, `Secure` over HTTPS. `dont_remember` cookie present.
- Session refresh formula matches (`session.py:122`):
  `expiresAt - expiresIn + updateAge <= now`, skipped when `dont_remember`.
- Rate-limit special rules mirror TS (`auth.py:26`): `(10,3)` for sign-in/sign-up/
  change-password/change-email; `(60,3)` for request-password-reset/
  send-verification-email/forget-password.
- Error body shape `{code, message}` (`auth.py:153`) and 429 body/header
  (`x-retry-after`) match.
- `INVALID_EMAIL_OR_PASSWORD` timing equalization via `dummy_verify` (`endpoints.py:157`).
- `reset-password` single-use: deletes the verification row before checking expiry
  (`endpoints.py:401`) — close to TS `consumeVerificationValue`.

### What differs / is missing (per handler)

- **Endpoints absent entirely**: `/change-email`, `/delete-user`,
  `/delete-user/callback`, `/link-social`, `/refresh-token`, `/get-access-token`,
  `/account-info`, `/update-session`. (`endpoints.py:555` ROUTES list.)
- **`/verify-password` wire mismatch** (`endpoints.py:322`): returns
  `{"valid": bool}`; TS returns `{status:true}` and throws `INVALID_PASSWORD`.
  Also TS is server-scoped (not HTTP-exposed).
- **`/set-password`** (`endpoints.py:297`) is exposed as a public HTTP POST; TS is
  `serverOnly`. Error on existing password: Python `USER_ALREADY_HAS_PASSWORD`; TS
  `PASSWORD_ALREADY_SET`.
- **Email verification uses random string + DB row** (`endpoints.py:66`,
  identifier `email-verification:{token}`), NOT a JWT. Cross-runtime tokens are
  not interoperable, and `/verify-email` looks up a DB row instead of decoding a
  JWT. `verify-email` returns `{"status":True,"user":user}` (`endpoints.py:489`);
  TS returns `user: null`.
- **`/sign-up/email`** (`endpoints.py:94`): no `disableSignUp`; disabled path uses
  `EMAIL_PASSWORD_DISABLED` not `EMAIL_PASSWORD_SIGN_UP_DISABLED`; always throws
  422 on existing email (no synthetic-user enumeration protection); returns the raw
  user dict (not `parseUserOutput`); no `databaseHooks`.
- **`/change-password`** (`endpoints.py:269`): on `revokeOtherSessions` it keeps
  the current session and returns the current token; TS revokes ALL and mints a new
  session. Returns raw `user` not parsed.
- **`/update-user`** (`endpoints.py:259`): silently ignores `email` (TS →
  `EMAIL_CAN_NOT_BE_UPDATED`); no `BODY_MUST_BE_AN_OBJECT`; no "No fields to update"
  error; does NOT refresh the session cookie with the new user.
- **`/list-accounts`** (`endpoints.py:502`): returns accounts minus a fixed
  sensitive set but keeps `scope` (string); TS drops `scope` and emits
  `scopes: string[]`. Shape mismatch.
- **`/list-sessions`** uses `require_session` not fresh (`endpoints.py:218`).
- **`/revoke-session`** (`endpoints.py:227`) throws `SESSION_NOT_FOUND` (400) on
  unknown/foreign token; TS returns `{status:true}` silently.
- **`/unlink-account`** (`endpoints.py:512`) uses `require_session` (TS: fresh);
  deletes ALL matching accounts (TS: exactly one); last-account guard computed
  differently and no `allowUnlinkingAll` option.
- **`/get-session` POST** always 405 (`endpoints.py:203`); TS allows POST when
  `deferSessionRefresh`. No cookie-cache, no `disableCookieCache`/`disableRefresh`
  query support, no `needsRefresh`.
- **`/send-verification-email`** (`endpoints.py:436`): requires `email`, throws
  `USER_NOT_FOUND` (400) when absent — leaks existence; TS uses the 500ms floor +
  session-aware `EMAIL_MISMATCH`/`EMAIL_ALREADY_VERIFIED`.
- **CSRF/origin** (`auth.py:206`): only checks the `Origin` header on non-GET when
  present, against `scheme://netloc` of base+trusted origins. Missing: `Referer`
  fallback, `MISSING_OR_NULL_ORIGIN` when cookies present, Fetch-Metadata /
  `CROSS_SITE_NAVIGATION_LOGIN_BLOCKED`, wildcard/function trusted origins, per-URL
  validation with distinct codes (`INVALID_CALLBACK_URL` etc.), `disableCSRFCheck`/
  `disableOriginCheck`. Python's `ensure_trusted_url` (`auth.py:137`) does a simpler
  relative-or-allowed-origin check inline in handlers.
- **Rate limiter** (`auth.py:216`): in-memory only, `enabled` default False (TS:
  prod-default true), fixed-window reset (TS: rolling `lastRequest`), key on raw
  path (TS normalizes). Missing: `database`/`secondary-storage`/`customStorage`,
  plugin `rateLimit[]` rules, wildcard/function `customRules`, IP header/proxy/ipv6
  resolution (Python takes `client_ip` from `X-Forwarded-For` first hop in the
  FastAPI adapter only).
- **Plugin contract** (`plugins.py:15`): `id`, `schema`, `routes()`,
  `before(ctx)->AuthResponse|None`, `after(ctx,response)->AuthResponse|None`.
  Missing vs TS: `init`, `middlewares` (path-scoped), `onRequest`/`onResponse`
  (distinct from before/after), hook `matcher`s + arrays, `rateLimit[]`,
  `$ERROR_CODES`, endpoint metadata/method/schema, `adapter` overrides,
  `version`/`options`/`$Infer`. Python `before`/`after` are global (no matcher) and
  run for every route.
- **Hooks** (`auth.py:115`): only a flat `hooks` dict invoked by name; only
  `user_created_before`/`user_created_after` are called (sign-up + oauth). No
  `databaseHooks` (user/session/account/verification × create/update/delete ×
  before/after with abort/replace), no `options.hooks.before/after` middleware.
- **onAPIError**: unsupported. `handle()` (`auth.py:148`) catches `APIError` →
  `{code,message}`, everything else → 500 `{message:"Internal Server Error"}` (no
  `code`). No `throw`/`onError`/`errorURL`/`customizeDefaultErrorPage`.
- **`/error` page** (`endpoints.py:550`) is a minimal hardcoded HTML; TS is the
  styled page with `customizeDefaultErrorPage`, `errorURL` redirect, and prod-mode
  redirect to `/`.
- **`disabledPaths`**, **`skipTrailingSlashes`**, **cookie cache
  (`session_data`)**, **cross-subdomain cookies**, **`account_data` cookie**,
  **secondaryStorage**, **telemetry**, **`logger` config**, **`secrets` rotation**,
  **dynamic `baseURL`**, **`user.additionalFields`/`fields` remap**,
  **`parseUserOutput`/`parseSessionOutput` field filtering** — all unsupported.
- **Config coverage** (`config.py`): `EmailAndPassword` lacks `disable_sign_up`,
  `password` override, `on_password_reset`, `on_existing_user_sign_up`,
  `custom_synthetic_user`. `EmailVerification` lacks `send_on_sign_in`,
  `before/after_email_verification`. `SessionOptions` lacks `disable_session_refresh`,
  `defer_session_refresh`, `cookie_cache`, `fresh_age`, `store_session_in_database`.
  No `user`, `account`, `verification`, `advanced`, `databaseHooks`, `onAPIError`
  option groups.

---

## Gap items (ordered; S/M/L effort)

Ordered by wire-compat impact then structural need. Each names the exact
route/JSON/error-code requirement.

1. **`/verify-password` response shape + scope** — S. Return `{status:true}`,
   throw `INVALID_PASSWORD` (400) when wrong (drop `{valid}`). Decide whether to
   mark server-only. Wire-breaking for any TS client. No deps.

2. **`/list-accounts` shape** — S. Drop `scope`, emit `scopes: string[]`
   (`account.scope?.split(",") ?? []`), keep `{id,providerId,createdAt,updatedAt,accountId,userId,scopes}`.
   Wire-breaking. No deps.

3. **`/revoke-session` silent success** — S. Return `{status:true}` when token
   unknown/foreign instead of `SESSION_NOT_FOUND`. Matches TS anti-enumeration.
   No deps.

4. **`/update-user` contract** — S. Throw `EMAIL_CAN_NOT_BE_UPDATED` when `email`
   present, `BODY_MUST_BE_AN_OBJECT` on non-object, `"No fields to update"` (400)
   when empty; refresh the session cookie with the merged user. No deps.

5. **`/sign-up/email` fidelity** — M. Add `disableSignUp` →
   `EMAIL_PASSWORD_SIGN_UP_DISABLED`; add synthetic-user enumeration protection
   (return `{token:null, user: <synthetic>}` when `requireEmailVerification` or
   `autoSignIn:false`); route disabled case through `EMAIL_PASSWORD_SIGN_UP_DISABLED`
   vs the sign-in `EMAIL_PASSWORD_DISABLED`. Depends on #12 (field filtering) for
   a faithful synthetic user.

6. **Email-verification token = JWT (HS256)** — M. Replace the random-string + DB
   row scheme with a `jose`-equivalent HS256 JWT `{email, updateTo?, requestType?}`;
   `/verify-email` decodes the JWT (codes `TOKEN_EXPIRED`, `INVALID_TOKEN`,
   `USER_NOT_FOUND`, `INVALID_USER`), returns `{status:true, user:null}` on plain
   success, redirects with `?error=<code>` when `callbackURL` present. Required for
   cross-runtime token interop and correct wire shape. Depends on a JWT helper.

7. **`/change-password` revokeOtherSessions semantics** — M. Match TS: delete ALL
   sessions, create a NEW session, set its cookie, return the new token; return
   `parseUserOutput(user)`. Wire/behavioral. Depends on #12.

8. **Missing account/session endpoints** — L. Add `/change-email`, `/delete-user`,
   `/delete-user/callback`, `/link-social`, `/update-session`, and (OAuth-token)
   `/refresh-token`, `/get-access-token`, `/account-info` with exact paths,
   request/response fields, and error codes from the tables above. Depends on
   config groups (`user.changeEmail`, `user.deleteUser`, `account.*`), databaseHooks,
   and token encryption for the token endpoints.

9. **CSRF / origin parity** — L. Add `Referer` fallback, `MISSING_OR_NULL_ORIGIN`
   (cookies present, no origin), Fetch-Metadata handling +
   `CROSS_SITE_NAVIGATION_LOGIN_BLOCKED`, wildcard + function `trustedOrigins`,
   per-URL validation of `callbackURL`/`redirectTo`/`errorCallbackURL`/
   `newUserCallbackURL` with codes `INVALID_CALLBACK_URL`/`INVALID_REDIRECT_URL`/
   `INVALID_ERROR_CALLBACK_URL`/`INVALID_NEW_USER_CALLBACK_URL`/`INVALID_ORIGIN`,
   and `advanced.disableCSRFCheck`/`disableOriginCheck`. Depends on a trusted-origin
   matcher.

10. **Session freshness middleware** — M. Implement `freshAge` + a fresh-session
    gate; apply to `/list-sessions` and `/unlink-account`; add
    `sensitiveSessionMiddleware` semantics (authoritative read) to
    revoke-*/change-password/set-password/verify-password. Error `SESSION_NOT_FRESH`
    (403). Depends on `session.freshAge` config.

11. **Plugin contract expansion** — L. Extend `Plugin` with `init`,
    `middlewares` (path-scoped), `onRequest`/`onResponse`, `hooks.before/after`
    with `matcher`, `rate_limit` rules, `$ERROR_CODES`, and per-endpoint
    method/schema/metadata. Wire the dispatch loop (`auth.py:159`) to run them in
    TS order (user hooks before plugin hooks; middlewares by path; rate-limit rule
    precedence default→special→plugin→customRules). Structural; enables the plugin
    ecosystem. Depends on #12 and #13.

12. **Output field filtering (`parseUserOutput`/`parseSessionOutput`)** — M. Emit
    only schema + configured `additionalFields`; drop unknown/sensitive fields. Add
    `user.additionalFields`/`fields` column remap. Needed for faithful responses in
    #5/#7/#8 and multi-field plugins.

13. **databaseHooks + options.hooks** — M. Add `databaseHooks` (user/session/
    account/verification × create/update/delete × before/after with abort/`{data}`
    replace) invoked inside adapter operations, and global `hooks.before/after`
    middleware. Replace the ad-hoc `user_created_before/after` string hooks. Depends
    on the middleware/hook context shape from #11.

14. **Rate-limiter storage + rules** — M. Add `database` and `secondary-storage`
    backends + `customStorage`, plugin `rateLimit[]` precedence, wildcard/function
    `customRules`, IP resolution via `ipAddressHeaders`/`trustedProxies`/`ipv6Subnet`,
    and rolling-window (`lastRequest`) semantics. Default `enabled` in production.
    Depends on #11 (plugin rules) and secondaryStorage.

15. **Cookie cache (`session_data`) + cross-subdomain + `account_data`** — L.
    Implement `session.cookieCache` (`compact`/`jwt`/`jwe` strategies, version,
    refreshCache), `advanced.crossSubDomainCookies` (domain widening), and the
    `account_data` cookie for `storeAccountCookie`. `get-session` must honour the
    cache + `disableCookieCache`/`disableRefresh`/`deferSessionRefresh`. Depends on
    a JWT/JWE + base64url-HMAC helper. Large; low interop urgency (cache is an
    optimization) but required for stateless deployments.

16. **onAPIError + error page** — M. Support `throw`/`onError`/`errorURL`/
    `customizeDefaultErrorPage`; port the styled `/error` page + prod redirect;
    include a `code` on 500s where TS does. Depends on nothing structural.

17. **`disabledPaths`, `skipTrailingSlashes`, dynamic `baseURL`, `secrets`
    rotation, telemetry, logger config** — M (spread). Lower interop priority;
    schedule after the wire-critical items.

---

## Open questions

- BLOCKED: Exact `parseUserOutput`/`parseSessionOutput` field-selection rules
  (which fields are `returned:false`, how `additionalFields.returned` is honoured)
  — not fully read (`db/schema.ts` out of the sampled set). / Options: (a) read
  `packages/better-auth/src/db/schema.ts` before implementing #12; (b) approximate
  with schema-declared fields only. / Default: (b) for now, refine in #12.

- BLOCKED: `/forget-password` in TS — Python aliases it to
  `request-password-reset` (`endpoints.py:575`), but the TS core `baseEndpoints`
  has no `/forget-password` route (it is a client-side alias / plugin path; only
  the rate-limit special rule references `/forget-password*`). / Options: (a) keep
  the Python alias (harmless superset); (b) drop it to match core exactly. /
  Default: (a) keep — it does not break wire compat and matches the client alias.

- BLOCKED: Whether `set-password`/`verify-password` should be reachable over HTTP
  at all. TS marks them server-only, so a wire-faithful port would 404 them on the
  router. / Options: (a) keep them HTTP-exposed (Python currently does) as a
  documented superset; (b) gate them to server-side `auth.api`-style calls only. /
  Default: (a) but return the TS response shape (#1); revisit if strict parity is
  required.

- BLOCKED: OAuth `state`/PKCE wire fidelity (`storeStateStrategy`, `generateState`,
  state cookie vs DB) is only partially in scope here and differs structurally
  (Python always uses a DB row + signed `state` cookie; TS switches on
  `storeStateStrategy`). / Options: (a) treat OAuth in a separate gap doc; (b) fold
  the state-storage strategy into this one. / Default: (a) — covered by the OAuth
  gap spec, not core-http.

- BLOCKED: `generateId` alphabet/length equivalence between Python
  (`crypto.py:26` custom alphabets) and TS `@better-auth/utils` — the Python file
  claims byte-for-byte match but the TS `generateId`/`generateRandomString` source
  was not read in this pass. / Options: (a) verify against
  `packages/utils` before relying on token interop; (b) trust the existing claim. /
  Default: (a) verify in the crypto gap spec; IDs are opaque so it does not affect
  route wire compat, only cross-runtime token reuse.
