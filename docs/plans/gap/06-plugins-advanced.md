# Advanced plugins + ecosystem — better-auth v1.6.23 → Python parity spec

Reference (read-only, tag `v1.6.23`): `packages/better-auth/src/plugins/` (core) and `packages/` (ecosystem).
Python port: `src/better_auth/` — no plugin system exists yet (`plugins.py` is a 31-line stub: a single empty `Plugin` base class).

Scope note: **oidc-provider and mcp are both marked `@deprecated` in v1.6.23** — the successor is the standalone `@better-auth/oauth-provider` package (see Part 2). They are still shipped, still tested, and mcp still depends on oidc-provider internals, so they are specced in full here, but any Python port should target `oauth-provider` semantics for new work and treat these two as the compatibility floor.

---

## Part 1: full specs

Conventions used below: paths are relative to the auth base path (default `/api/auth`). Bodies are the zod-validated request schemas. "camelCase" schema fields are the exact DB column names better-auth generates.

Shared crypto/runtime primitives these plugins lean on (must exist in the Python port before the plugins can):
- **`generateRandomString(len, ...charsets)`** — token/code/secret generation. Charsets passed as `"a-z"`, `"A-Z"`, `"0-9"`. Python has `generate_random_string(size)` but **not** the charset-restricted variant.
- **`symmetricEncrypt`/`symmetricDecrypt({key, data})`** — AES-GCM under the auth secret (or a `SecretConfig`). Used by oauth-proxy for state/profile packages and by oidc-provider `storeClientSecret: "encrypted"`. **Python has none** (only HMAC `sign_value`/`unsign_value`).
- **`constantTimeEqual(a, b)`** — client-secret comparison. Python has `hmac.compare_digest`.
- **`createHash("SHA-256", "base64urlnopad").digest(x)`** — PKCE S256 challenge. Python: `hashlib` + urlsafe b64 no-pad.
- **JWT (jose `SignJWT`/`jwtVerify`)** — HS256 for id_tokens, RS256/EdDSA when the jwt plugin is present. **Python has no JWT machinery.**
- **Signed cookies** (`setSignedCookie`/`getSignedCookie`) — Python has the HMAC signing but not the cookie helper wiring.

---

### 1. oidc-provider  (`plugins/oidc-provider/`, ~5.5k LOC incl. tests; ~2.3k source)

Full OIDC authorization-code provider: authorize, token, userinfo, jwks (delegated to jwt plugin), consent, dynamic client registration, RP-initiated logout. **Deprecated** in favor of `@better-auth/oauth-provider`.

**Dependencies:** `jose` (SignJWT / jwtVerify), the **jwt plugin** (only when `useJWTPlugin: true`, for RS256/EdDSA id_tokens and `/jwks`; without it id_tokens are HS256 signed with the client secret), symmetric encrypt/decrypt (only for `storeClientSecret: "encrypted"`), PKCE S256 hashing, signed cookies.

#### Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/.well-known/openid-configuration` | none | Discovery metadata (see below). Hidden from OpenAPI. |
| GET | `/oauth2/authorize` | session (redirects to `loginPage` if none) | Start auth-code flow. Query is free-form (`z.record`); parsed as `AuthorizationQuery`. |
| POST | `/oauth2/consent` | session | Accept/deny consent. Body `{ accept: boolean, consent_code?: string }`. Returns `{ redirectURI }`. |
| POST | `/oauth2/token` | client creds | Token exchange. Accepts `application/x-www-form-urlencoded` **or** `application/json`. Body free-form record. |
| GET | `/oauth2/userinfo` | Bearer access token | Returns claims filtered by granted scopes. |
| POST | `/oauth2/register` | session unless `allowDynamicClientRegistration` | RFC 7591 dynamic client registration. Returns 201. |
| GET | `/oauth2/client/:id` | session | Public client info `{ clientId, name, icon }`. |
| GET/POST | `/oauth2/endsession` | session/id_token_hint | RP-initiated logout. |

**`/oauth2/authorize` behavior** (from `authorize.ts` + tests):
- No session → if `prompt=none`: must return `login_required` error redirect to a **registered** redirect_uri (400 `invalid_request` if redirect_uri missing; `invalid_client` if client_id missing/unknown; 400 if redirect_uri not registered — never redirect to an unregistered URI). Otherwise stores full query in signed cookie `oidc_login_prompt` (maxAge 600, path `/`, sameSite lax) and redirects to `{loginPage}?{originalQueryString}`.
- Browser-`fetch` requests (detected via `isBrowserFetchRequest` on headers, i.e. Sec-Fetch-*) get `{ redirect: true, url }` JSON instead of a 302 throw. Non-fetch gets a real redirect.
- Validates: `client_id` present, `response_type === "code"` (only code flow; `token`/implicit rejected `unsupported_response_type`), redirect_uri exactly matches a registered `redirectUrls` entry, client not `disabled`.
- Scope: request scope defaults to `defaultScope` ("openid"); every requested scope must be in the configured `scopes` allowlist else `invalid_scope`.
- **PKCE gate:** if `requirePKCE` (default **true**) and missing `code_challenge`/`code_challenge_method` → `invalid_request` "pkce is required". `code_challenge_method` without `code_challenge` → error. When `code_challenge` present: allowed methods are `["s256"]` unless `allowPlainCodeChallengeMethod` (default false) which adds `plain`. Method lowercased and persisted normalized. Missing method defaults to `plain` **only** when the plain opt-in is on (legacy back-compat, flagged for removal).
- Consent decision: `requireConsent = !client.skipConsent && (!hasAlreadyConsented || prompt includes "consent")`. `hasAlreadyConsented` = an `oauthConsent` row with `consentGiven` covering every requested scope.
- `prompt=none` + consent needed → `consent_required` error redirect.
- `max_age`: if session age (now − `session.createdAt`) in seconds > max_age, force re-login (equivalent to `prompt=login`). Invalid max_age ignored.
- Auth code = `generateRandomString(32, a-z, A-Z, 0-9)`, stored as a **verification value** (identifier = code) with JSON `CodeVerificationValue` `{ clientId, redirectURI, scope[], userId, authTime, requireConsent, state, codeChallenge, codeChallengeMethod, nonce }`, expires in `codeExpiresIn` (600s).
- `requireLogin` → sets both `oidc_login_prompt` and `oidc_consent_prompt` (=code) cookies, redirects to loginPage with `client_id, code, state`.
- No consent → redirect to redirect_uri with `code` + `state`.
- Consent required → redirect to `consentPage` (with `consent_code, client_id, scope` query + `oidc_consent_prompt` cookie) OR render `getConsentHTML(...)` inline (text/html). If neither configured → 500 "No consent page provided".
- **Post-login continuation:** an `after` hook (matcher: always) fires when `oidc_login_prompt` cookie + a fresh session-token Set-Cookie are both present. It restores the query from the cookie, strips `login` from the prompt set, sets the session, and re-invokes `authorize()`. Fixes issue #4594 (must not re-redirect to the OIDC client on later normal logins — gated on the login-prompt cookie).

**`/oauth2/consent`:** consent_code from body or `oidc_consent_prompt` signed cookie. Looks up verification value; 401 if missing/expired. Expires cookie. If `!value.requireConsent` → 401 "Consent not required". `accept:false` → deletes verification, returns redirectURI with `error=access_denied`. `accept:true` → generates new code, updates verification (identifier→new code, `requireConsent:false`), creates `oauthConsent` row (`consentGiven:true`, scopes space-joined), returns redirectURI with `code`(+`state`).

**`/oauth2/token`:**
- Client auth: `client_id`/`client_secret` from body, or `Authorization: Basic base64(urlenc(id):urlenc(secret))` (split on first colon, percent-decode each half per RFC 6749 §2.3.1; body client_id must match header else `invalid_client`).
- **grant_type=refresh_token:** find token by `refreshToken`; validate clientId match, not expired, client exists+enabled; confidential clients must present a valid secret (`verifyStoredClientSecret`, constant-time). Issues new access+refresh tokens (both `generateRandomString(32, a-z, A-Z)`). Returns `{ access_token, token_type:"Bearer", expires_in, refresh_token, scope }`.
- **grant_type=authorization_code:** `requirePKCE` → code_verifier required. **Atomic single-use redemption:** `consumeVerificationValue(code)` — first caller wins, racers get null → `invalid_grant` (tested: "rejects concurrent redemption"). Validates grant_type is exactly `authorization_code`, redirect_uri present, client exists+enabled, `value.clientId`/`value.redirectURI` match. Public clients (`type:"public"`) validate PKCE not secret; confidential validate secret. PKCE: challenge = code_verifier (plain) or SHA-256 base64url-nopad; must equal stored `codeChallenge`.
- Access token `generateRandomString(32, a-z, A-Z)`, refresh token `generateRandomString(32, A-Z, a-z)`. Stored in `oauthAccessToken`.
- **id_token** built from claims `{ sub, aud, iat, auth_time, nonce, acr:"urn:mace:incommon:iap:silver", ...profile-if-scope, ...email-if-scope, ...getAdditionalUserInfoClaim }`. `profile` scope → `{given_name, family_name, name, profile, updated_at}`; `email` scope → `{email, email_verified}`. Signing: `useJWTPlugin` → delegates to jwt plugin's `getJwtToken` (RS256/EdDSA, real jwks). Else **HS256 signed with the client secret** as the key. id_token only returned if `openid` in scopes; refresh_token only if `offline_access` in scopes.
- Response headers `Cache-Control: no-store`, `Pragma: no-cache`.
- **Security (tested): discovery metadata must never advertise `alg=none`.**

**`/oauth2/userinfo`:** Bearer token → look up `oauthAccessToken`, reject if expired (`invalid_token`). Claims: `sub` always; `email`/`email_verified` if email scope; `name`/`picture`/`given_name`/`family_name` if profile scope. `getAdditionalUserInfoClaim` overrides base claims if configured.

**`/oauth2/register`:** RFC 7591. Body validated by `registerOAuthApplicationBodySchema` (redirect_uris **must pass `isSafeUrlScheme`** — rejects `javascript:`/`data:`/`vbscript:`; https + loopback-http allowed). Requires session unless `allowDynamicClientRegistration`. redirect_uris required for authorization_code/implicit grants. grant/response-type correlation enforced. Generates `clientId`/`clientSecret` (`generateRandomString(32, a-z, A-Z)` or custom generators). Secret stored per `storeClientSecret` mode. Creates `oauthApplication` (type `"web"`). Returns 201 RFC-7591 body with plaintext `client_secret` (`client_secret_expires_at: 0`).

**`/oauth2/endsession`** (RP-initiated logout, GET+POST): validates `id_token_hint` (via jwt plugin JWKS if `useJWTPlugin`, else HS256 with client secret), `client_id`, `post_logout_redirect_uri` (must be registered). **Cross-site protection (tested):** if request + (validated user or session), require same-site (`Sec-Fetch-Site` same-origin/same-site/none, or trusted Origin/Referer) OR an id_token_hint matching the current session — else 403. Deletes all `oauthAccessToken` for the user, deletes session, expires cookie. Redirects to `post_logout_redirect_uri`(+state) or returns `{success, message}`.

#### Discovery metadata (`getMetadata`)
`issuer` = jwt plugin issuer or baseURL. `id_token_signing_alg_values_supported` = `["RS256","EdDSA"]` if `useJWTPlugin` else `["HS256"]`. Endpoints: authorize `/oauth2/authorize`, token `/oauth2/token`, userinfo `/oauth2/userinfo`, jwks `/jwks`, registration `/oauth2/register`, end_session `/oauth2/endsession`. `response_types_supported:["code"]`, `grant_types_supported:["authorization_code","refresh_token"]`, `code_challenge_methods_supported:["S256"]`, `subject_types_supported:["public"]`, `token_endpoint_auth_methods_supported:["client_secret_basic","client_secret_post","none"]`.

#### Schema additions (exact camelCase)
- **`oauthApplication`**: `name`, `icon?`, `metadata?`(string JSON), `clientId`(unique), `clientSecret?`, `redirectUrls`(string, comma-joined), `type`(enum web/native/user-agent-based/public), `disabled?`(default false), `userId?`(→user.id cascade, indexed), `createdAt`, `updatedAt`.
- **`oauthAccessToken`**: `accessToken`(unique), `refreshToken`(unique), `accessTokenExpiresAt`, `refreshTokenExpiresAt`, `clientId`(→oauthApplication.clientId cascade, indexed), `userId?`(→user.id cascade, indexed), `scopes`(space-joined string), `createdAt`, `updatedAt`.
- **`oauthConsent`**: `clientId`(→oauthApplication.clientId cascade, indexed), `userId`(→user.id cascade, indexed), `scopes`(space-joined), `createdAt`, `updatedAt`, `consentGiven`(boolean).

#### Config options (`OIDCOptions`) + defaults
`loginPage` (required), `accessTokenExpiresIn`=3600, `refreshTokenExpiresIn`=604800, `codeExpiresIn`=600, `scopes` (defaults `["openid","profile","email","offline_access"]`, user scopes appended), `defaultScope`="openid", `consentPage?`, `getConsentHTML?`, `requirePKCE`=**true**, `allowPlainCodeChallengeMethod`=false, `generateClientId?`, `generateClientSecret?`, `getAdditionalUserInfoClaim?`, `trustedClients?` (bypass DB, optional `skipConsent`), `storeClientSecret`="plain" (also "hashed" SHA-256 base64url-nopad / "encrypted" AES-GCM / `{hash}` / `{encrypt,decrypt}`), `useJWTPlugin`=false, `allowDynamicClientRegistration?`, `metadata?`, `schema?`.

---

### 2. mcp  (`plugins/mcp/`, ~3.7k LOC incl. tests)

Model Context Protocol OAuth server. **A thin wrapper over oidc-provider** with MCP-specific discovery endpoints and its own token/register/authorize handlers (uses oidc-provider's `schema`, `parsePrompt`, types, and `oAuthConsent` endpoint directly). **Deprecated** → `@better-auth/oauth-provider`.

**Dependencies:** oidc-provider (schema, authorize logic, consent endpoint), `jose` SignJWT (id_token — note: **HS256 with an ephemeral randomly-generated HMAC key**, not the client secret), PKCE hashing, base64.

#### Endpoints
| Method | Path | Purpose |
|---|---|---|
| GET | `/.well-known/oauth-authorization-server` | MCP provider metadata (`getMCPProviderMetadata`). |
| GET | `/.well-known/oauth-protected-resource` | Resource metadata (`getMCPProtectedResourceMetadata`). |
| GET | `/mcp/authorize` | `authorizeMCPOAuth` — same flow as oidc authorize (session→redirect to `loginPage`, consent, code issuance). Sets permissive CORS (`*`). |
| POST | `/mcp/token` | Token exchange (auth-code + refresh_token). Basic-auth parsing same as oidc. |
| POST | `/mcp/register` | Dynamic client registration; sets CORS. `token_endpoint_auth_method:"none"`→public client. Returns 201. |
| GET | `/mcp/get-session` | Bearer access-token introspection → returns `oauthAccessToken` row or null (401 + `WWW-Authenticate: Bearer` header). Rejects expired tokens. |
| POST | `/oauth2/consent` | reuses oidc-provider's consent endpoint. |

**Discovery metadata differences from oidc:** endpoints under `/mcp/*` (authorize/token/userinfo/jwks/register). `scopes_supported` includes `offline_access`. `id_token_signing_alg_values_supported:["RS256"]`. Protected-resource metadata: `resource` (option or origin), `authorization_servers:[origin]`, `bearer_methods_supported:["header"]`, `resource_signing_alg_values_supported:["RS256"]`.

**Token endpoint specifics (tested):**
- Public client + PKCE only (no secret); rejects public client without `code_verifier`.
- Confidential client secret compared **constant-time** (`constantTimeEqual` — note: mcp uses plain compare, not `verifyStoredClientSecret`).
- refresh_token grant **requires the original grant to include `offline_access`** else `invalid_grant` (tested "rejects a refresh_token grant whose original scopes lack offline_access").
- Atomic `consumeVerificationValue(code)` single-use.
- id_token signed HS256 with an **ephemeral WebCrypto HMAC key** (generated per request) — effectively unverifiable by clients; a known quirk of the deprecated plugin.
- `no-store`/`no-cache` headers.

**Helper exports:** `withMcpAuth(auth, handler)` — wraps a request handler, returns JSON-RPC 401 `{jsonrpc:"2.0", error:{code:-32000,...}, id:null}` with `WWW-Authenticate: Bearer resource_metadata="..."` + `Access-Control-Expose-Headers` when unauthenticated. `oAuthDiscoveryMetadata(auth)` / `oAuthProtectedResourceMetadata(auth)` — CORS-wrapped metadata handlers. `getMCPProviderMetadata` throws `invalid_issuer` if baseURL unset.

**Config (`MCPOptions`):** `loginPage` (required), `resource?`, `oidcConfig?` (full `OIDCOptions`). Defaults merged: `codeExpiresIn:600, defaultScope:"openid", accessTokenExpiresIn:3600, refreshTokenExpiresIn:604800, allowPlainCodeChallengeMethod:false`, scopes forced to include openid/profile/email/offline_access.

**Schema:** reuses oidc-provider's schema (`oauthApplication`/`oauthAccessToken`/`oauthConsent`), plus `mcp/register` writes `authenticationScheme` + `type` (web/public).

**Post-login hook:** identical pattern to oidc — after any request, if `oidc_login_prompt` cookie + fresh session cookie, restore query, strip `login` prompt, re-run `authorizeMCPOAuth`. Test "should redirect back to client after login, not to /api/auth/error".

---

### 3. siwe — Sign-In with Ethereum  (`plugins/siwe/`, ~1.8k LOC incl. tests)

ERC-4361 wallet authentication. **Self-contained ERC-4361 message parser** (`parse-message.ts`) — does not trust the caller's `verifyMessage` for message-body validation.

**Dependencies:** `toChecksumAddress` (EIP-55 checksum — keccak256-based; **Python needs a keccak/eth-utils dependency or a hand-rolled EIP-55**), caller-supplied `getNonce` + `verifyMessage` (signature recovery, e.g. viem — Python would need `eth-account`/`eth-keys` or delegate to the app). No JWT.

#### Endpoints
| Method | Path | Body | Response |
|---|---|---|---|
| POST | `/siwe/nonce` (alias `/siwe/get-nonce`) | `{ walletAddress? , address?, chainId?=1 }` (one of walletAddress/address required; regex `^0x[a-fA-F0-9]{40}$`, length 42) | `{ nonce }` |
| POST | `/siwe/verify` | `{ message, signature, walletAddress, chainId?=1, email? }` (`requireRequest:true`; email required when `anonymous===false`) | `{ token, success, user:{ id, walletAddress, chainId } }` + session cookie |

**Nonce:** address checksummed, `getNonce()` called, stored as verification value identifier `siwe:{checksumAddress}:{chainId}`, expires **15 min**.

**Verify flow (tested extensively):**
- Address checksummed. `isAnon = options.anonymous ?? true`; non-anon requires email.
- **Atomic single-use nonce:** `consumeVerificationValue("siwe:{addr}:{chainId}")` before any signature work — first concurrent request wins (tested "mint exactly one session when the same nonce is verified concurrently"); consumes on failure too; applies expiry gate. Missing → 401 `UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE`.
- **Message binding** (parse ERC-4361, all must match server state): `nonce`==stored, `address`(lowercased)==wallet, `chainId`==, `domain` normalized==`options.domain` normalized → else 401 `UNAUTHORIZED_SIWE_MESSAGE_MISMATCH`. Honors signed `expirationTime` (401 `UNAUTHORIZED_SIWE_MESSAGE_EXPIRED`) and `notBefore` (401 `UNAUTHORIZED_SIWE_MESSAGE_NOT_YET_VALID`). Tested: rejects arbitrary non-SIWE message, mismatched nonce/domain/chain, reused unrelated signature.
- Then calls `options.verifyMessage({message, signature, address, chainId, cacao})` (CAIP-122 cacao built with domain/nonce/version). False → 401.
- **User resolution:** find `walletAddress` row by (address, chainId); else by address on any chain (same user); else create user. New-user email = `{address}@{emailDomainName || origin}` unless non-anon email given **and not already claimed** (case-insensitive; silent fallback to avoid enumeration). `ensLookup?` provides name/avatar. Creates `walletAddress` row (`isPrimary` true for first), `account` (providerId `"siwe"`, accountId `{address}:{chainId}`). Creates session, sets cookie.

#### Schema (exact camelCase)
- **`walletAddress`**: `userId`(→user.id, required, indexed), `address`(string, required), `chainId`(number, required), `isPrimary`(boolean, default false), `createdAt`(date, required).

#### Config (`SIWEPluginOptions`)
`domain` (required), `emailDomainName?`, `anonymous?`(default true), `getNonce` (required async), `verifyMessage` (required async), `ensLookup?`, `schema?`.

---

### 4. one-tap — Google One Tap  (`plugins/one-tap/`, ~1.3k LOC incl. tests)

Verifies a Google One Tap ID token and signs the user in via the shared OAuth account-linking path.

**Dependencies:** `verifyGoogleIdToken` + `isGoogleHostedDomainAllowed` (from core social-providers — jose-based Google JWKS verification; **Python needs Google id_token verification** via `google-auth` or manual JWKS+RS256), `handleOAuthUserInfo` (shared linking logic).

#### Endpoint
| Method | Path | Body | Response |
|---|---|---|---|
| POST | `/one-tap/callback` | `{ idToken, callbackURL? }` | `{ token, user }` + session cookie; 400 on invalid token |

**Behavior (tested):**
- **Audience required (fail closed):** resolves `options.clientId || socialProviders.google.clientId`; if none → 400 (a token minted for a different Google client would otherwise pass). Verifies via `verifyGoogleIdToken({token, audience})`.
- **Hosted domain (`hd`):** enforced via `isGoogleHostedDomainAllowed(configuredHd, payload.hd)` — matches redirect sign-in behavior; wildcard accepts any Workspace hd but rejects missing hd; no config → ignored.
- Requires `payload.sub`; `email` lowercased; missing email → `{error:"Email not available in token"}`.
- **Identity via `handleOAuthUserInfo`** (providerId `"google"`, accountId=sub): the account owning the Google `sub` wins, not an email-matched local user. Honors `accountLinking` verification gates (`requireLocalEmailVerified`, `disableImplicitLinking`) — tested. `disableSignup` option blocks new-user creation.
- **callbackURL** validated by the global origin check against `trustedOrigins` (prevents open redirect); relative URLs pass.

**Config (`OneTapOptions`):** `disableSignup?`(default false), `clientId?`. No schema additions.

---

### 5. oauth-popup  (`plugins/oauth-popup/`, ~1.2k LOC incl. tests)

Popup-based social OAuth: popup navigates to a first-party start endpoint; on callback the plugin swaps the redirect for an HTML page that `postMessage`s the session token (or error) back to the opener. **Pair with the `bearer` plugin** (token is handed back for cross-site use).

**Dependencies:** OAuth state machinery (`setOAuthState`, `generateGenericState`, `StateData`), signed cookies, `generateRandomString(128)` for PKCE code verifier, the social/generic-oauth providers. No JWT.

#### Endpoint
| Method | Path | Query |
|---|---|---|
| GET | `/oauth-popup/start` | `{ provider, popupOrigin, popupNonce?, callbackURL?, errorCallbackURL?, newUserCallbackURL?, scopes?, requestSignUp?, additionalData? }` (hidden from OpenAPI) |

**Start behavior:** `popupOrigin` must be a **trusted origin** (no relative paths) else 403 `INVALID_ORIGIN`. Redirect URLs mirror the origin check (GET skips global middleware) and relay failures to the opener as a completion page. Resolves provider (built-in + generic-oauth). Builds `StateData` (callbackURL, codeVerifier, errorURL, newUserURL, requestSignUp, expiresAt now+10min; strips `INTERNAL_STATE_KEYS` from `additionalData`), stores it, sets a **signed marker cookie `oauth_popup`** (`{popupOrigin, popupNonce}`, maxAge 600) so the callback can post to the opener. Redirects to the provider authorization URL.

**Callback hook** (`after`, matches `/callback/*` and `/oauth2/callback/*`): reads the `oauth_popup` signed cookie; if absent → keep redirect (not a popup flow). Expires marker. Extracts the session token from the response Set-Cookie; renders the completion page with `{nonce, token, redirectTo}` — or, if no token, relays `error`/`error_description` from the redirect. Swaps `ctx.context.returned` for the HTML Response.

**Completion page crypto/format (exact, cross-runtime):**
- postMessage type: `"better-auth:oauth-popup"`. Data element id: `"better-auth-oauth-popup"`. localStorage key: `"better-auth.popup_token"`.
- Posts `{type, nonce, token, redirectTo, error}` to `window.opener||window.parent` at `payload.targetOrigin` (=validated popupOrigin), then `window.close()`.
- **CSP-pinned script:** the completion `<script>` is a fixed string; its **sha256 is pinned** as `sha256-tIo2K8VBC9SnhvdZ+9GsGkQoZm+jm/JcxL+d+i8b8KQ=` in the response CSP `script-src`. Any port must reproduce the script byte-for-byte or recompute the hash (tested: "pins the script's sha256 in the response CSP hash"). Response headers: `content-type: text/html; charset=utf-8`, `content-security-policy: default-src 'none'; script-src '<hash>'; base-uri 'none'`, `cache-control: no-store`, `pragma: no-cache`. JSON is escaped for `<`, U+2028, U+2029.

**Error codes:** `POPUP_SIGN_IN_FAILED`, `POPUP_BLOCKED`, `POPUP_CLOSED`, `POPUP_TIMEOUT`. **Config:** none (`oauthPopup()` takes no options). No schema additions.

---

### 6. oauth-proxy  (`plugins/oauth-proxy/`, ~2.7k LOC incl. tests)

Lets preview/branch deployments complete social OAuth against a production server: production runs the actual code exchange, then encrypts the profile and replays it to the preview's callback. Cross-environment secret-sharing is the whole point.

**Dependencies:** `symmetricEncrypt`/`symmetricDecrypt` (AES-GCM — **critical, Python lacks it**), OAuth state machinery (`parseGenericState`, `StateData`), `handleOAuthUserInfo`, cookie parsing, `defu` merge. No JWT.

#### Endpoint
| Method | Path | Query |
|---|---|---|
| GET | `/oauth-proxy-callback` | `{ callbackURL (required), profile? (encrypted) }` (origin-checked against callbackURL) |

**Callback behavior:** requires `profile`; decrypts (AES-GCM under proxy key = `opts.secret ?? ctx.context.secretConfig`) → `PassthroughPayload` `{userInfo, account, state, callbackURL, newUserURL?, errorURL?, disableSignUp?, timestamp}`. Validates required fields. **Replay window:** age `(now - timestamp)/1000` must be ≤ `maxAge` (default 60s) and ≥ −10 (clock skew); else `payload_expired`. Consumes the OAuth state (`parseGenericState` with `skipStateCookieCheck`) — missing → `state_mismatch`. `handleOAuthUserInfo` creates/links user+session, sets session cookie, redirects to `newUserURL||callbackURL` (register) or `callbackURL`. All failures redirect to an error URL with a coded reason (`missing_profile`, `invalid_profile`, `invalid_payload`, etc.).

**Hooks (the real machinery):**
- `before` on `/sign-in/social`|`/sign-in/oauth2`: if not skipping (same-origin or `x-skip-oauth-proxy` header), rewrites `callbackURL` to `{currentOrigin}/api/auth/oauth-proxy-callback?callbackURL={original}`; if `productionURL` set, overrides `baseURL` to production so the provider's redirect_uri points at production.
- `before` on `/callback/:id` (runs **on production**): decrypts the `state` as an `OAuthProxyStatePackage` `{state, stateCookie, isOAuthProxy}`; if it decrypts and `isOAuthProxy`, does the full code→token→userInfo exchange itself, builds the encrypted `PassthroughPayload`, and redirects to the preview's `oauth-proxy-callback?profile=...`. If it can't decrypt (different secrets / regular state) → falls through to normal callback.
- `after` on sign-in: recovers the plaintext OAuth state (cookie strategy: decrypt `oauth_state` cookie with env secret; DB strategy: read verification value), **re-encrypts it under the proxy/shared secret**, wraps it in the `OAuthProxyStatePackage`, and replaces the `state` param in the provider URL so production can read it back.
- `after` on `/callback/:id`: unwraps same-origin proxy redirects back to the original destination.

**Config (`OAuthProxyOptions`):** `currentURL?` (trusted as-is; else request origin **only if trusted**, else vendor env `VERCEL_URL`/`NETLIFY_URL`/`RENDER_URL`/... , else baseURL), `productionURL?` (default `BETTER_AUTH_URL`), `maxAge?`=60, `secret?` (string|SecretConfig — dedicated proxy secret, **must be shared across all environments**). **Security tested:** untrusted request origin is never used as the replay receiver; different secrets between preview/production → `state_mismatch` (fail closed). No schema additions.

---

## Part 2: ecosystem package inventory + IN/OUT recommendations

LOC = source only (test files excluded).

### `packages/api-key` (~4.8k LOC)
Server-generated API keys with hashing, prefixes, expiry, rate-limiting, refill/quota (`remaining`/`refillInterval`/`refillAmount`), per-key metadata & permissions, and optional org scoping. Endpoints: `/api-key/create`, `/get`, `/update`, `/delete`, `/list`, `/delete-all-expired-api-keys`, plus a `verifyApiKey` server method and a `/get-session` hook that resolves a key to a session. One table: **`apikey`** (fields: `key` hashed, `start`, `prefix`, `userId`, `refillInterval`, `refillAmount`, `lastRefillAt`, `enabled`, `rateLimit*`, `requestCount`, `remaining`, `lastRequest`, `expiresAt`, `permissions`, `metadata`, timestamps). Pure stdlib crypto (hashing + HMAC), no exotic deps.
**Recommendation: IN.** Common, self-contained, no crypto the Python port can't already do — high-value parity for programmatic/service auth.

### `packages/passkey` (~1.9k LOC)
WebAuthn/FIDO2 passkeys. Endpoints: `/passkey/generate-register-options`, `/verify-registration`, `/generate-authenticate-options`, `/verify-authentication`, `/list-user-passkeys`, `/delete-passkey`, `/update-passkey`. One table: **`passkey`** (`credentialID`, `publicKey`, `userId`, `counter`, `deviceType`, `backedUp`, `transports`, `aaguid`, `name`, `createdAt`). Wraps `@simplewebauthn/server` for challenge generation, attestation, and assertion verification; ships bundled authenticator (AAGUID) metadata.
**Recommendation: IN (medium priority).** Python has the mature `webauthn` (py_webauthn, same author as SimpleWebAuthn) library, so the crypto is covered; the work is porting the option/verify plumbing and the passkey table. Worth it — passkeys are a headline feature.

### `packages/sso` (~7.5k LOC)
Enterprise SSO: **both OIDC and SAML 2.0** identity-provider federation, org auto-provisioning/role assignment, and domain verification. Endpoints (~20): `/sign-in/sso`, `/sso/register`, `/sso/callback`, `/sso/providers` + get/update/delete, `/sso/request-domain-verification` + `/verify-domain`, and a full SAML surface (`/sso/saml2/sp/acs`, `/sp/metadata`, `/sp/slo`, `/idp/*`, plus SAML response parsing, XML-dsig signature verification, assertion/timestamp validation). One table: **`ssoProvider`** (`oidcConfig`, `samlConfig` JSON, `domain`, `organizationId`, ...). Depends on `samlify` + XML crypto — the SAML half is heavy (XML canonicalization, signature validation).
**Recommendation: PARTIAL / mostly OUT.** The OIDC-federation half is tractable and valuable; the SAML half (XML-dsig, samlify) is a large, security-sensitive lift with weaker Python ecosystem support. Do OIDC-SSO if demanded; defer SAML.

### `packages/scim` (~2.9k LOC)
SCIM 2.0 provisioning server so IdPs (Okta/Entra) can CRUD users/groups. Endpoints: SCIM resource routes (`/Users`, `/Groups` with filter/patch semantics) plus management `/scim/generate-token`, `/scim/get-provider-connection`, `/list-provider-connections`, `/delete-provider-connection`. Includes SCIM filter parsing, PATCH operation semantics, attribute mapping, bearer-token auth. Rides on the sso provider connection (no standalone user table — maps to core `user`).
**Recommendation: OUT (initially).** Niche enterprise feature that only pays off once SSO exists; depends conceptually on sso. Revisit after sso lands.

### `packages/stripe` (~4.1k LOC)
Stripe subscriptions/billing: checkout, customer creation, plan upgrade/cancel/restore, billing portal, seat-based plans, trials, and webhook handling. Endpoints: `/subscription/upgrade`, `/cancel`, `/restore`, `/list`, `/billing-portal`, `/subscription/success`, `/stripe/webhook`. Table: **`subscription`** (`plan`, `stripeCustomerId`, `stripeSubscriptionId`, `status`, `periodStart/End`, `trial*`, `seats`, `cancelAtPeriodEnd`, `billingInterval`, ...) + `stripeCustomerId` on `user`. Hard-wired to the Stripe SDK/webhook signatures.
**Recommendation: OUT.** Payment-ecosystem-specific, not authentication; tightly coupled to Stripe's SDK. Belongs in a separate optional package if ever, not "auth parity."

### `packages/oauth-provider` (~9.8k LOC)
**The successor to oidc-provider + mcp** (both are deprecated in favor of this). Full-featured OAuth 2.1 / OIDC authorization server: authorize, token, userinfo, jwks, dynamic + admin client management (create/update/delete/rotate-secret), consent management (get/update/delete consents), token introspection (RFC 7662) and revocation (RFC 7009), RP-initiated logout by sid, MCP integration (`/mcp`, protected-resource metadata), account/organization selection, signed-query flows, and a hardened `SafeUrlSchema` (https-or-loopback redirect policy). Tables: **`oauthClient`**, **`oauthAccessToken`**, **`oauthConsent`** (richer than the oidc-provider trio). Depends on jose/JWT, PKCE, symmetric crypto.
**Recommendation: IN — but this is the strategic target, not oidc-provider/mcp.** If the Python port builds an OAuth server at all, build *this* one (or a subset) rather than porting the two deprecated plugins. Large (L+); phase it.

### `packages/core` (~16.5k LOC)
Not a plugin — the shared foundation: `@better-auth/core` types, the `createAuthEndpoint`/`createAuthMiddleware` API layer, db schema primitives (`BetterAuthPluginDBSchema`), env/logger, oauth2 helpers, social-provider registry, error codes, JSON/URL/fetch-metadata utils. Every plugin imports from it. Two tables referenced (`user`, `verificationRecord`) but it defines the schema *contract*, not app tables.
**Recommendation: IN (implicitly, already partially ported).** The Python port's `endpoints.py`/`schema.ts`-equivalents already cover pieces of this; the plugin work above requires filling core gaps (endpoint/middleware abstraction, plugin registry, verification-value adapter methods like `consumeVerificationValue`). Not a standalone deliverable — it's the substrate every Part-1 plugin needs.

**Auto-OUT (platform-specific, per task):** `expo`, `electron`, `cli` — client/platform tooling, not auth logic.

---

## Python current state

**None of these plugins exist.** `src/better_auth/plugins.py` is a 31-line stub containing only an empty `Plugin` base class — there is no plugin registry, no endpoint/middleware abstraction for plugins, and no per-plugin schema merging.

Crypto/runtime gaps that block the plugins (from `src/better_auth/crypto.py`, deps in `pyproject.toml`):
- **Have:** `generate_id`, `generate_random_string(size)`, scrypt password hash/verify, HMAC cookie `sign_value`/`unsign_value`, `hmac.compare_digest`.
- **Missing (blocking):** charset-restricted `generate_random_string(len, *charsets)`; AES-GCM `symmetric_encrypt`/`symmetric_decrypt` (needed by oauth-proxy always, oidc encrypted-secret mode); **all JWT machinery** (HS256 id_tokens, RS256/EdDSA jwks — no `jwt`/`jose`/`cryptography` dep declared, only `httpx`); PKCE S256 base64url-nopad hashing; base64url helpers; the verification-adapter methods (`createVerificationValue`, `consumeVerificationValue` atomic single-use, `findVerificationValue`, `updateVerificationByIdentifier`); signed-cookie endpoint helpers; `handleOAuthUserInfo` account-linking path; social-provider registry with Google id_token verification; `isTrustedOrigin`/origin-check middleware; `toChecksumAddress` (EIP-55).
- **Only dependency today is `httpx`** — every plugin here needs at least one new crypto dependency (`cryptography` for AES-GCM + JWT, plus `webauthn` for passkey, plus an eth/keccak lib for siwe checksums).

---

## Gap items — ordered, sized, dependencies noted

Sizing: S ≈ ≤1 day, M ≈ 2–4 days, L ≈ 1–2 weeks. "Runtime" = shared primitives; do these first.

1. **[Runtime, M] Plugin system** — plugin registry, `create_auth_endpoint`/`create_auth_middleware` equivalents, before/after hooks, per-plugin schema merge (`mergeSchema`), `$ERROR_CODES`. Blocks everything. *Dep: core endpoint layer.*
2. **[Runtime, M] Verification-value adapter methods** — `create/find/update/deleteByIdentifier` + **atomic `consumeVerificationValue`** (single-use, expiry-gated). Blocks oidc, mcp, siwe. *Must be genuinely atomic (SELECT…FOR UPDATE / conditional delete), not find-then-delete — tests assert concurrent single-use.*
3. **[Runtime, S–M] Crypto primitives** — add `cryptography` dep: AES-GCM `symmetric_encrypt/decrypt`, PKCE S256 (base64url-nopad SHA-256), base64url helpers, charset `generate_random_string`, constant-time compare wrapper. Blocks oauth-proxy, oidc, mcp, oauth-popup.
4. **[Runtime, M] JWT machinery** — HS256 sign/verify (via `cryptography` or PyJWT); RS256/EdDSA + a `jwt` plugin (jwks) as a prerequisite for oidc `useJWTPlugin`/id_token verification and mcp/oauth-provider. **oidc-provider and mcp depend on this.** *Dep: a Python `jwt` plugin (separate gap, not covered here).*
5. **[Runtime, S] Signed cookies + origin check** — `set/get_signed_cookie`, `isTrustedOrigin(origin, {allowRelativePaths})`, `originCheck` middleware, `isBrowserFetchRequest`. Blocks oidc, oauth-popup, one-tap, siwe.
6. **[M] oauth-popup** — least dependency surface (no JWT). Needs plugin system, signed cookies, origin check, OAuth state machinery, `bearer` plugin. **Reproduce the completion script byte-for-byte** (or recompute the CSP sha256). *Deps: 1, 3, 5, OAuth state.*
7. **[M] siwe** — needs plugin system, verification adapter, EIP-55 checksum (new keccak dep or hand-rolled), the ERC-4361 parser (port `parse-message.ts` verbatim), delegated `getNonce`/`verifyMessage`. *Deps: 1, 2, 5.* Signature verification itself is caller-supplied (or add `eth-account`).
8. **[M] one-tap** — needs Google id_token verification (RS256 + Google JWKS, or `google-auth`), `handleOAuthUserInfo` linking, hosted-domain check, origin check. *Deps: 1, 4, 5, account-linking path.*
9. **[L] oauth-proxy** — needs AES-GCM crypto, full OAuth state re-encryption dance, `handleOAuthUserInfo`, social-provider registry, vendor-env resolution, trusted-origin logic. Complex cross-environment flow; port the hook machinery carefully. *Deps: 1, 3, 5, social providers.*
10. **[L] oidc-provider** — full OIDC server. Needs everything above + JWT + client-secret storage modes + consent flow + endsession cross-site protection. **Consider skipping in favor of item 12.** *Deps: 1, 2, 3, 4, 5.*
11. **[M, on top of 10] mcp** — thin wrapper over oidc-provider; only worth doing after 10. *Deps: 10.*
12. **[XL] oauth-provider (successor)** — the strategic target that replaces 10+11. If an OAuth server is in scope at all, build a subset of this instead of the deprecated pair. *Deps: 1–5 + jwt plugin.*

Suggested order: runtime (1–5) → oauth-popup → siwe → one-tap → api-key (from Part 2) → passkey → then decide oidc-provider(10) vs oauth-provider(12) → oauth-proxy.

---

## Open questions

- **BLOCKED: deprecated-vs-successor strategy.** oidc-provider + mcp are deprecated in v1.6.23; `@better-auth/oauth-provider` is the replacement. *Options:* (a) port the deprecated pair for exact v1.6.23 parity; (b) skip them and port `oauth-provider` only; (c) both. *Default (recommend):* **(b)** — build `oauth-provider` (subset), skip oidc-provider/mcp, since porting soon-to-be-removed plugins is throwaway work. Revisit if strict "1.6.23 endpoint parity" is a hard requirement.
- **BLOCKED: siwe signature/checksum dependency.** EIP-55 checksum needs keccak256; signature recovery needs secp256k1. *Options:* add `eth-utils`/`eth-account`; hand-roll keccak; or keep `verifyMessage` fully caller-supplied (as TS does) and only port the parser + checksum. *Default:* caller-supplied `verify_message` + add a small keccak dep for EIP-55 only.
- **BLOCKED: mcp id_token quirk.** mcp signs id_tokens with an ephemeral per-request HMAC key (unverifiable by clients). *Options:* replicate the quirk for byte-parity, or fix it (use jwks). *Default:* replicate only if item 11 is done at all; otherwise moot (prefer oauth-provider).
- **jwt plugin is an unlisted prerequisite** for oidc `useJWTPlugin`, mcp, and oauth-provider. It was not part of this task's plugin list — confirm it's specced elsewhere (likely a separate gap doc) before scheduling items 10/12.
- **oauth-proxy secret-sharing model** assumes multiple deployments share a secret and one is "production." Confirm the Python port's deployment story needs this at all before committing the L-sized item 9 — it may be YAGNI for single-deployment users.
- **Consent-page rendering** (oidc `getConsentHTML`/`consentPage`) and the oauth-popup HTML completion page are server-rendered HTML. Confirm the Python port's integration layer (FastAPI) has a sanctioned way to return raw HTML responses from a plugin endpoint.
