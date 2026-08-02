# Social providers — better-auth v1.6.23 → Python parity spec

Reference (TS, read-only, pinned `v1.6.23` / commit `9dfceee14`):
- `packages/core/src/oauth2/` — shared OAuth2 primitives (moved out of `packages/better-auth` in this version; `packages/better-auth/src/oauth2/index.ts` just re-exports `@better-auth/core/oauth2`)
- `packages/better-auth/src/oauth2/` — state, link-account, token-encryption utils, error helpers (server-specific, not portable primitives)
- `packages/core/src/social-providers/` — all 35 provider factories + `index.ts` registry
- `packages/better-auth/src/api/routes/sign-in.ts`, `account.ts`, `callback.ts` — the endpoints that drive the flow
- `packages/better-auth/src/state.ts` — state payload schema + cookie/DB storage strategies

Python port: `better-auth-py/src/better_auth/oauth.py` (384 lines), wired from
`auth.py` and `endpoints.py`.

**Provider count: TS has 35 social providers. Python has 3 (github, google, discord).**

---

## OAuth2 shared machinery

### `packages/core/src/oauth2/create-authorization-url.ts` — `createAuthorizationURL()`

Builds the `/authorize` redirect URL. Signature takes `{ id, options, authorizationEndpoint, state, codeVerifier?, scopes?, claims?, redirectURI, duration?, prompt?, accessType?, responseType?, display?, loginHint?, hd?, responseMode?, additionalParams?, scopeJoiner? }`.

Behavior:
- `options` may be sync or async (`AwaitableFunction<ProviderOptions>`) — resolved with `await` before use. This lets a provider's client id/secret be fetched from a secret manager per request.
- `options.authorizationEndpoint` overrides the provider's hardcoded endpoint (per-provider config escape hatch, e.g. sandbox/self-hosted OAuth servers).
- `client_id` is always the **primary** client id: `Array.isArray(clientId) ? clientId[0] : clientId` (see `getPrimaryClientId`). Multi-value `clientId: string[]` exists so id-token audience checks can accept several app ids (iOS/Android/web) while authorization still uses one.
- `scope` joined with `scopeJoiner` (default `" "`); optional per-provider (none currently use a non-space joiner, but the hook exists).
- `redirect_uri` = `options.redirectURI || redirectURI` (per-provider override wins).
- Optional params (`duration`, `display`, `login_hint`, `prompt`, `hd`, `access_type`, `response_mode`) are set only when truthy — i.e., omitted entirely rather than sent empty.
- PKCE: if `codeVerifier` is passed, `code_challenge_method=S256` + `code_challenge=SHA256(codeVerifier)` (base64url, no padding) are added. Whether PKCE is used at all is a **per-provider decision** — some providers pass `codeVerifier` through to this function, some don't (see per-provider notes below); it is not a single global flag.
- `claims`: builds an OIDC `claims` JSON param (`{"id_token": {email: null, email_verified: null, ...claims}}`) — used by Twitch to request extra id-token claims.
- `additionalParams`: raw key/value passthrough, applied last (can't be overridden by named params above since it's set separately, but in practice never collides).

### `packages/core/src/oauth2/validate-authorization-code.ts`

- `authorizationCodeRequest()` / `createAuthorizationCodeRequest()` (sync, `@deprecated`, kept for direct use by providers with nonstandard token exchange, e.g. GitHub calls the sync builder then does its own fetch): builds the `POST` body (`grant_type=authorization_code`, `code`, `code_verifier?`, `client_key?` (TikTok), `device_id?` (VK), `redirect_uri`, `resource?` (RFC 8707 resource indicators, repeatable)).
- Client auth: `authentication: "basic"` → `Authorization: Basic base64(clientId:clientSecret)` header (standard base64, RFC 7617 — a comment in the code notes this fixes compatibility with Notion/Twitter which reject base64url). `authentication: "post"` (default) → `client_id`/`client_secret` in the body.
- `additionalParams` merged in without overwriting keys already set (`if (!body.has(key))`).
- `validateAuthorizationCode()`: async wrapper — calls `authorizationCodeRequest`, POSTs to `tokenEndpoint` via `fetchRefusingRedirects` (SSRF hardening, see below), converts the response with `getOAuth2Tokens()`.
- `validateToken()`: generic remote JWT verification helper (JWKS by URL, `jwtVerify` with `audience`/`issuer`) — not used directly by social providers (they have their own JWKS-fetch-and-cache flows per provider), used by other subsystems.

### `packages/core/src/oauth2/refresh-access-token.ts` — `refreshAccessToken()`

Mirrors `validateAuthorizationCode`'s shape for `grant_type=refresh_token`: same basic/post auth switch, `resource`/`extraParams` passthrough, converts `expires_in`/`refresh_token_expires_in` to absolute `Date`s. Every built-in provider wires `refreshAccessToken: options.refreshAccessToken ?? (token => refreshAccessToken({...}))` — i.e. a user-supplied override always wins, else the shared helper hits the provider's token endpoint. **This function has no Python equivalent at all** — no provider exposes `refresh_access_token`, and there's no `/refresh-token` or `/get-access-token` endpoint.

### `packages/core/src/oauth2/client-credentials-token.ts` — `clientCredentialsToken()`

RFC 6749 §4.4 client-credentials grant (app-only auth, e.g. for calling a provider's API without a user). Same body/auth shape. Not used by any social sign-in provider directly; exists for plugins that need app-level tokens. Out of Python-port critical path but should live in the same module if/when ported.

### `packages/core/src/oauth2/utils.ts`

- `getOAuth2Tokens(data)`: normalizes a raw token-endpoint JSON response into `OAuth2Tokens` (camelCase, `Date` expiry fields, `scope` string→array split on space). **Crucially preserves the raw response under `tokens.raw`** — providers can read provider-specific fields (e.g. VK's extra fields) without redefining the whole token shape.
- `applyDefaultAccessTokenExpiry()`: back-fills `accessTokenExpiresAt` from a provider-configured `accessTokenExpiresIn` when the token response omitted `expires_in` (some providers don't return it).
- `getPrimaryClientId(clientId)`: `Array.isArray(clientId) ? clientId[0] : clientId`, returns `undefined` for empty/non-string.
- `generateCodeChallenge(codeVerifier)`: SHA-256 → base64url no-padding. PKCE S256 only, no `plain` method support (correct — `plain` is a downgrade attack surface).

### `packages/core/src/oauth2/reject-redirects.ts` — SSRF hardening (not ported at all)

- `fetchRefusingRedirects()`: wraps `betterFetch` with `redirect: "manual"` and throws `BetterAuthError` if the response *would have been* a redirect (handles both Node/undici's real 3xx status and spec-compliant runtimes' opaque-redirect filtered response, `status: 0, type: "opaqueredirect"`).
- Applied to **every** outbound OAuth fetch: token exchange, JWKS fetch (`createRemoteJWKSet` gets a `customFetch` that checks `assertResponseNotRedirect`), userinfo calls that use `fetchRefusingRedirects` directly (introspection).
- Threat model (per the code comments): a malicious or compromised OAuth endpoint (self-hosted/sandbox endpoints are user-configurable via `authorizationEndpoint`/`issuer`/`loginUrl` overrides on several providers) could redirect a server-side fetch to an internal address (SSRF). Refusing redirects server-side closes that off.
- **Python's `httpx.AsyncClient` calls in `oauth.py` use default redirect-following behavior** (httpx defaults to `follow_redirects=False` per-request unless the client was constructed with `follow_redirects=True` — `auth.py`'s `http` property constructs `httpx.AsyncClient(timeout=10)` with no explicit `follow_redirects`, so httpx's default `False` currently happens to hold, but this is incidental, not asserted/tested, and any config change or per-call `follow_redirects=True` would silently reopen the hole).

### `packages/core/src/oauth2/verify.ts` — JWKS/JWT verification infra (not ported at all)

- `verifyJwsAccessToken()` / `verifyAccessToken()`: local (JWKS) or remote (RFC 7662 introspection) access-token verification for **protecting your own API**, with a JWKS response cache (5 min TTL, `Map` for URL sources + `WeakMap` for function sources keyed by a caller-supplied stable object), plus a "no-`kid`-cache-miss" retry cooldown (30s) so a JWKS rotation without `kid` headers doesn't hammer the JWKS endpoint on every failed verify.
- This is the machinery several social providers reuse (via `decodeProtectedHeader`/`importJWK`/`jwtVerify` from `jose`, not through this exact cache) for **id-token verification**: Google, Apple, Microsoft, Cognito, PayPal, Facebook (limited-login JWT via `createRemoteJWKSet`) all fetch the provider's JWKS by `kid`, verify signature/issuer/audience/`maxTokenAge`, and (where applicable) check `nonce`.
- Python has **no JWT library, no JWKS fetch/cache, and no id-token signature verification anywhere**. This blocks: the id-token direct sign-in flow (below), and any provider whose primary user-info source is the id token itself (Google, Apple, Microsoft, Cognito, TikTok*, Paybin — providers that `decodeJwt` the id token in `getUserInfo` without a network call).

### `packages/better-auth/src/oauth2/state.ts` (server layer, thin wrapper) + `packages/better-auth/src/state.ts` (the actual state engine)

`generateState()` / `parseState()` build the `StateData` payload:
```
{ callbackURL, codeVerifier, errorURL?, newUserURL?, link?: {email, userId}, expiresAt, requestSignUp?, oauthState?, ...additionalData }
```
- `codeVerifier` is **always generated** (`generateRandomString(128)`), regardless of whether the target provider uses PKCE — cheap, and lets a provider's PKCE-ness change without touching the state layer.
- `additionalData` (arbitrary object from the request body) is merged flat into the state payload and threaded back out at the callback — lets an app pass app-specific context through the redirect round-trip. **Not present in Python** (`sign_in_social` builds a fixed 5-key payload).
- `link` (`{email, userId}`) is set only by `/link-social` (account.ts) — its presence is what tells `callback.ts` "this is a linking flow, not a sign-in flow". **Python's callback has no linking branch at all**, so there is no Python equivalent of this field.
- Two storage strategies, chosen by `account.storeStateStrategy` (`"database"` default when DB/secondary-storage configured, else `"cookie"`):
  - **`"database"`**: state written to the `verification` table (`identifier = state`, `value = JSON.stringify(stateData)`, 10 min TTL) *and* a **separately signed** cookie holding the same `state` string (5 min TTL) is set as CSRF binding — the callback must find both the DB row *and* a matching signed cookie (`skipStateCookieCheck` can disable the cookie check, used by the oauth-proxy plugin and SAML relay where the IdP POST is cross-origin and `SameSite=Lax` cookies aren't sent). Verification row is looked up then **deleted** on parse (single use).
  - **`"cookie"`**: the entire `StateData` payload (plus a generated `oauthState`) is AES-encrypted (`symmetricEncrypt`, `secretConfig` key) directly into a 10-min cookie — no DB record at all (fully stateless flow, for DB-less deployments). Callback decrypts the cookie and separately checks `parsedData.oauthState === query.state` (double-submit style, since the state itself never left the round-trip except embedded in the encrypted cookie and the URL param).
  - **Python only implements the `"database"` strategy's shape** (verification-table row + signed cookie), with `skip_state_cookie_check` as a single global auth-instance flag (not tied to the per-call `settings.skipStateCookieCheck` override); there is no `"cookie"`/stateless strategy.
- Expiry check (`parsedData.expiresAt < Date.now()`) happens **after** both storage-specific checks; Python mirrors this ordering correctly (`row["expiresAt"] <= utcnow()` checked first actually — order differs slightly but not security-relevant since both checks must pass).

### `packages/better-auth/src/oauth2/link-account.ts` — `handleOAuthUserInfo()` (the sign-in/register/link decision core)

This is the single function every non-linking OAuth callback (`callback.ts`) and the id-token sign-in path (`sign-in.ts`) route through. Decision tree:
1. Look up the user via `internalAdapter.findOAuthUser(email.toLowerCase(), accountId, providerId)` — a combined "find by linked account OR by matching email" query.
2. **No existing user at all** → register: build `accountData` (tokens + provider/account id), create user via `createOAuthUser` (single adapter call, atomic user+account creation), optionally send the verification email if `emailVerification.sendOnSignUp` is configured and the provider didn't report `emailVerified`. Honors `disableSignUp` (returns `{error: "signup disabled"}` without touching the DB — this is how `provider.disableImplicitSignUp && !requestSignUp` is enforced upstream).
3. **User exists, account already linked** (matching `(providerId, accountId)` row found) → treat as ordinary re-sign-in: refresh stored tokens if `account.updateAccountOnSignIn !== false` (default true), optionally mirror the fresh tokens into a signed "account cookie" (`account.storeAccountCookie`), and **promote `emailVerified: true`** on the local user row if the provider's email is verified and matches (self-healing an unverified local row once IdP proves the email).
4. **User exists, account NOT yet linked** (implicit linking path) → gated by:
   - `isTrustedProvider = opts.isTrustedProvider || (opts.trustProviderByName !== false && ctx.trustedProviders.includes(providerId))` — `trustedProviders` is `account.accountLinking.trustedProviders`, a static array or async `(request) => string[]` function, resolved once at context-init time and again per-request (must tolerate `request: undefined`).
   - Linking is refused (returns `{error: "account not linked"}`, no DB writes) if: `(!isTrustedProvider && !userInfo.emailVerified)` **or** `(requireLocalEmailVerified && !dbUser.user.emailVerified)` **or** `accountLinking.enabled === false` **or** `accountLinking.disableImplicitLinking === true`. `requireLocalEmailVerified` defaults `true` and is `@deprecated` (slated to become unconditional) — its purpose: even a *verified* IdP email shouldn't auto-link into a *pre-existing local row whose own email was never verified*, because an attacker could have pre-registered that email locally to catch the eventual OAuth signup (account pre-emption / takeover).
   - On success: `linkAccount()` (new account row), then if the just-proven IdP email is verified and equals the local email, promote `emailVerified` on the user row too, then apply `updateUserInfoOnLink` (see below).
5. `overrideUserInfo` (= `provider.options?.overrideUserInfoOnSignIn`, default `false`): when true, **every** sign-in (not just first-link) overwrites `name`/`image`/additional-fields/`email`/`emailVerified` on the local user from the fresh provider profile — `emailVerified` logic: if the provider's email differs from the stored one, trust the provider's `emailVerified` outright; if it's the same email, OR the two verified flags (never *downgrades* a verified local email to unverified).
6. Creates the session at the end via `internalAdapter.createSession(user.id)`.

`applyUpdateUserInfoOnLink()` (separate, also called directly by `callback.ts`'s **linking** branch and `account.ts`'s idToken-linking branch): gated by `account.accountLinking.updateUserInfoOnLink` (default `false`); when on, copies `name`/`image`/`mapProfileToUser` extra fields from the freshly-linked provider profile onto the user row — **never** touches `email`/`emailVerified` (so a link can't rebind identity). Swallows update failures (logs a warning, doesn't fail the link).

**Python's `_resolve_user()` implements a small subset of step 2/3/4 only**: create-if-absent, refresh-tokens-if-linked-already, and a single unconditional guard `if user is not None and not info.email_verified: raise account_not_linked`. There is no `isTrustedProvider`, no `requireLocalEmailVerified` (Python doesn't check the *local* row's verification at all — it only inspects the *incoming* `email_verified`), no `accountLinking.enabled`/`disableImplicitLinking` toggles, no `overrideUserInfoOnSignIn`, no `updateUserInfoOnLink`, no `disableSignUp`/`requestSignUp` distinction, no account-cookie mirroring, no `updateAccountOnSignIn` toggle (tokens are always refreshed on re-sign-in — that part matches the TS default).

### `packages/better-auth/src/oauth2/utils.ts` — `setTokenUtil()`/`decryptOAuthToken()`

Transparent AES-256-GCM encrypt-on-write / decrypt-on-read for `account.accessToken`/`refreshToken`, gated by `account.encryptOAuthTokens` (default `false`). `decryptOAuthToken` has a heuristic (`isLikelyEncrypted`) to accept already-plaintext tokens stored before the setting was turned on, so flipping the flag doesn't break existing rows. **No Python equivalent** — `crypto.py` has no `symmetric_encrypt`/`symmetric_decrypt`, and `schema.py`'s `account` table stores tokens as plain `Field("text")`.

### `packages/better-auth/src/oauth2/errors.ts`

- `redirectOnError(ctx, errorURL, error, description?)`: the single choke point every failure path in `sign-in.ts`/`callback.ts`/`account.ts` routes through — always the same `?error=<code>&error_description=<...>` query shape. Python's `_error_redirect()` only ever sets `error=`, never `error_description` (minor fidelity gap — some error paths in TS pass a human-readable description, e.g. the raw `APIError.body.message` from a failed `handleOAuthUserInfo` call).
- `missingEmailLogMessage()`: shared copy for the "provider didn't return an email" log line, pointing at the docs. Cosmetic; not required for parity.

### The two callback-facing routes

**`sign-in.ts` (`POST /sign-in/social`)**:
- Body: `provider`, `callbackURL?`, `newUserCallbackURL?`, `errorCallbackURL?`, `disableRedirect?`, `idToken?: {token, nonce?, accessToken?, refreshToken?, expiresAt?, user?}`, `scopes?` (overrides, doesn't merge with provider defaults — the merge happens *inside* each provider's `createAuthorizationURL`), `requestSignUp?`, `loginHint?`, `additionalData?`.
- **`idToken` branch** (client already has a provider id-token, e.g. from Google Identity Services / Sign in with Apple JS, and wants to skip the redirect round-trip entirely): requires `provider.verifyIdToken` to exist (else `404 ID_TOKEN_NOT_SUPPORTED`); verifies the token, then calls `provider.getUserInfo({idToken, accessToken?, refreshToken?, user?})` (note: **not** a token exchange — `getUserInfo` is called directly with the client-supplied id token), requires a non-empty email (else `401 USER_EMAIL_NOT_FOUND`), then routes through `handleOAuthUserInfo` exactly like the redirect flow, and returns a session token directly (`{redirect: false, token, user}`) instead of a redirect URL. **Entirely missing in Python** — no `verify_id_token`/`get_user_info`-from-raw-token capability exists on `OAuthProvider`, and `sign_in_social` has no `idToken` branch.
- **Redirect branch**: `generateState(ctx, undefined, additionalData)` → `provider.createAuthorizationURL({state, codeVerifier, redirectURI: base+'/callback/'+id, scopes, loginHint})` → sets `Location` header unless `disableRedirect`, returns `{url, redirect}`.

**`account.ts` (`POST /link-social`)** — **entirely missing from Python** (no route, no handler). For an *already-authenticated* user to attach an additional provider:
- Same `idToken` vs redirect branching as sign-in, but the redirect branch's `generateState` is called **with** `link: {userId: session.user.id, email: session.user.email}`, which is what makes `callback.ts` take its linking branch instead of its sign-in branch.
- The `idToken` branch does its own inline linking logic (not `handleOAuthUserInfo`): checks for an already-linked-and-identical account (idempotent success), checks `isTrustedProvider`/`accountLinking.enabled` the same way as `link-account.ts`, checks `allowDifferentEmails` against **the session user's email** (not a stored `link.email`), creates the account row directly, then `applyUpdateUserInfoOnLink`.

**`callback.ts` (`GET|POST /callback/:id`)**:
- POST requests are immediately 302-redirected to the equivalent GET with the same params folded into the query string ("Handle POST requests by redirecting to GET to ensure cookies are sent" — some browsers don't attach cookies to a cross-site POST the way they do a top-level GET navigation). This matters for **Apple**, whose `response_mode: "form_post"` means the provider POSTs `code`/`state`/`user` to the callback URL. **Python's callback route accepts POST (`("POST", "/callback/{provider}", oauth_callback)`) but `oauth_callback()` only ever reads `ctx.request.query.get(...)` — it never parses the POST body**, so an Apple-style form-post callback would silently see no `code`/`state` and fail as `no_code`/`state_not_found` rather than working. This is a live bug blocking any `response_mode: form_post` provider (currently just Apple), independent of Apple itself being unported.
- `link` branch (state has `link: {email, userId}`): checks `isTrustedProvider`/`accountLinking.enabled`, checks `userInfo.email !== link.email` against `allowDifferentEmails`, checks for an existing account row already linked to a **different** user (`account_already_linked_to_different_user`), then creates/updates the account row directly and calls `applyUpdateUserInfoOnLink`, then redirects to `callbackURL` — note this path does **not** call `handleOAuthUserInfo` and does **not** create a new session (the user is already signed in).
- Non-link branch: requires `userInfo.email` (else `email_not_found`), calls `handleOAuthUserInfo`, sets the session cookie, redirects to `newUserURL || callbackURL` on register or `callbackURL` on existing-user sign-in.
- Python's `oauth_callback()` covers only the non-link branch, and even that is a simplified reimplementation rather than calling a shared `handle_oauth_user_info`-equivalent (the trusted-provider/requireLocalEmailVerified/disableImplicitLinking logic described above simply doesn't exist).

---

## Provider inventory

All endpoints below are current as of `v1.6.23`. "PKCE" = whether the provider forwards `codeVerifier` into `createAuthorizationURL`/`validateAuthorizationCode` (S256 only). "Client auth" = how the token endpoint receives client credentials (`post` = body params, `basic` = `Authorization: Basic` header). Default scopes are additive: `disableDefaultScope: true` empties them before `options.scope`/per-call `scopes` are appended (this override pattern is identical across every provider and not restated per-row).

| Provider (`id`) | Authorization endpoint | Token endpoint | Userinfo source | Default scopes | PKCE | Client auth |
|---|---|---|---|---|---|---|
| `google` | `accounts.google.com/o/oauth2/v2/auth` | `oauth2.googleapis.com/token` | decode `id_token` (no network call) | `email profile openid` | yes | post |
| `github` | `github.com/login/oauth/authorize` | `github.com/login/oauth/access_token` | `api.github.com/user` + `/user/emails` | `read:user user:email` | no | post |
| `apple` | `appleid.apple.com/auth/authorize` | `appleid.apple.com/auth/token` | decode `id_token` | `email name` | no (uses `response_type=code id_token`, `response_mode=form_post`) | post |
| `discord` | `discord.com/api/oauth2/authorize` (hand-built URL) | `discord.com/api/oauth2/token` | `discord.com/api/users/@me` | `identify email` | no | post |
| `facebook` | `www.facebook.com/v24.0/dialog/oauth` | `graph.facebook.com/v24.0/oauth/access_token` | decode limited-login JWT **or** `graph.facebook.com/me` (opaque token, app-bound via `debug_token`) | `email public_profile` | no | post |
| `microsoft` | `{authority}/{tenant}/oauth2/v2.0/authorize` | `{authority}/{tenant}/oauth2/v2.0/token` | decode `id_token` + `graph.microsoft.com/v1.0/me/photos/...` for avatar | `openid profile email User.Read offline_access` | yes | post (no secret required — public-client/PKCE-only supported) |
| `spotify` | `accounts.spotify.com/authorize` | `accounts.spotify.com/api/token` | `api.spotify.com/v1/me` | `user-read-email` | yes | post |
| `twitch` | `id.twitch.tv/oauth2/authorize` | `id.twitch.tv/oauth2/token` | decode `id_token` | `user:read:email openid` (+ `claims` param requesting `email,email_verified,preferred_username,picture`) | no | post |
| `twitter` (`x`) | `x.com/i/oauth2/authorize` | `api.x.com/2/oauth2/token` | `api.x.com/2/users/me` (2 calls: profile + `confirmed_email` field) | `users.read tweet.read offline.access users.email` | yes | **basic** |
| `dropbox` | `www.dropbox.com/oauth2/authorize` | `api.dropboxapi.com/oauth2/token` | `POST api.dropboxapi.com/2/users/get_current_account` | `account_info.read` | yes | post |
| `kick` | `id.kick.com/oauth/authorize` | `id.kick.com/oauth/token` | `api.kick.com/public/v1/users` (array, take `[0]`) | `user:read` | yes | post |
| `linear` | `linear.app/oauth/authorize` | `api.linear.app/oauth/token` | `POST api.linear.app/graphql` (GraphQL `viewer` query) | `read` | no | post |
| `linkedin` | `www.linkedin.com/oauth/v2/authorization` | `www.linkedin.com/oauth/v2/accessToken` | `api.linkedin.com/v2/userinfo` | `profile email openid` | no | post |
| `gitlab` | `{issuer}/oauth/authorize` (default `gitlab.com`) | `{issuer}/oauth/token` | `{issuer}/api/v4/user` (rejects `state !== "active"` or `locked`) | `read_user` | yes | post |
| `tiktok` | `www.tiktok.com/v2/auth/authorize` (hand-built, uses `client_key` not `client_id`) | `open.tiktokapis.com/v2/oauth/token/` | `open.tiktokapis.com/v2/user/info/` | `user.info.profile` | no | post (refresh uses `authentication: "post"` + `client_key` in `extraParams`) |
| `reddit` | `www.reddit.com/api/v1/authorize` | `www.reddit.com/api/v1/access_token` (custom fetch, not `validateAuthorizationCode`) | `oauth.reddit.com/api/v1/me` | `identity` (+ optional `duration`) | no | **basic** (+ mandatory `User-Agent` header) |
| `roblox` | `apis.roblox.com/oauth/v1/authorize` (hand-built) | `apis.roblox.com/oauth/v1/token` | `apis.roblox.com/oauth/v1/userinfo` | `openid profile` | no | post (`authentication: "post"` explicit) |
| `salesforce` | `{loginUrl or login/test.salesforce.com}/services/oauth2/authorize` | `.../services/oauth2/token` | `.../services/oauth2/userinfo` | `openid email profile` | yes | post |
| `vk` | `id.vk.com/authorize` | `id.vk.com/oauth2/auth` | `POST id.vk.com/oauth2/user_info` (form body, not bearer header) | `email phone` | yes | post |
| `zoom` | `zoom.us/oauth/authorize` | `zoom.us/oauth/token` | `api.zoom.us/v2/users/me` | (none — no `disableDefaultScope` list) | optional, manual (`options.pkce`, default `true`, built by hand not via `createAuthorizationURL`) | post |
| `notion` | `api.notion.com/v1/oauth/authorize` (+ `owner=user` param) | `api.notion.com/v1/oauth/token` | `api.notion.com/v1/users/me` (nested `bot.owner.user`) | (none) | no | **basic** |
| `kakao` | `kauth.kakao.com/oauth/authorize` | `kauth.kakao.com/oauth/token` | `kapi.kakao.com/v2/user/me` | `account_email profile_image profile_nickname` | no | post |
| `naver` | `nid.naver.com/oauth2.0/authorize` | `nid.naver.com/oauth2.0/token` | `openapi.naver.com/v1/nid/me` (checks `resultcode === "00"`) | `profile email` | no | post |
| `line` | `access.line.me/oauth2/v2.1/authorize` | `api.line.me/oauth2/v2.1/token` | decode `id_token`, else `api.line.me/oauth2/v2.1/userinfo` | `openid profile email` | yes | post |
| `paybin` | `{issuer}/oauth2/authorize` (default `idp.paybin.io`) | `{issuer}/oauth2/token` | decode `id_token` | `openid email profile` | yes | post |
| `paypal` | `{sandbox or live}.paypal.com/signin/authorize` | `api-m.{sandbox.}paypal.com/v1/oauth2/token` (custom fetch, not `validateAuthorizationCode`) | `api-m.{sandbox.}paypal.com/v1/identity/oauth2/userinfo` | (none — permissions configured in PayPal dashboard, not OAuth scopes) | yes | **basic** (custom fetch) |
| `polar` | `polar.sh/oauth2/authorize` | `api.polar.sh/v1/oauth2/token` | `api.polar.sh/v1/oauth2/userinfo` | `openid profile email` | yes | post |
| `railway` | `backboard.railway.com/oauth/auth` | `backboard.railway.com/oauth/token` | `backboard.railway.com/oauth/me` | `openid email profile` | yes | **basic** |
| `vercel` | `vercel.com/oauth/authorize` | `api.vercel.com/login/oauth/token` | `api.vercel.com/login/oauth/userinfo` | (none by default — `scopes` only sent if explicitly configured) | yes (required — throws if missing) | post |
| `wechat` | `open.weixin.qq.com/connect/qrconnect` (hand-built, `appid` not `client_id`, `#wechat_redirect` hash) | `GET api.weixin.qq.com/sns/oauth2/access_token` (query params, not POST body) | `GET api.weixin.qq.com/sns/userinfo` (needs `openid` returned alongside the access token) | `snsapi_login` | no | n/a (`appid`/`secret` query params) |
| `atlassian` | `auth.atlassian.com/authorize` (+ `audience=api.atlassian.com`) | `auth.atlassian.com/oauth/token` | `api.atlassian.com/me` | `read:jira-user offline_access` | yes | post |
| `cognito` | `{domain}/oauth2/authorize` | `{domain}/oauth2/token` | decode `id_token`, else `{domain}/oauth2/userinfo` | `openid profile email` | yes | post (secret optional unless `requireClientSecret`) |
| `huggingface` | `huggingface.co/oauth/authorize` | `huggingface.co/oauth/token` | `huggingface.co/oauth/userinfo` | `openid profile email` | yes | post |
| `figma` | `www.figma.com/oauth` | `api.figma.com/v1/oauth/token` | `api.figma.com/v1/me` | `current_user:read` | yes | **basic** |
| `slack` | `slack.com/openid/connect/authorize` (hand-built) | `slack.com/api/openid.connect.token` | `slack.com/api/openid.connect.userInfo` | `openid profile email` | no | post |

### Profile → user field mapping (all providers, uniform pattern)

Every provider's `getUserInfo(token)` follows the same shape:
```
if options.getUserInfo: return options.getUserInfo(token)   // full override, skips everything below
profile = <fetch or decode>
userMap = await options.mapProfileToUser?.(profile)          // partial override, spread last
return { user: { id, name, email, image, emailVerified, ...userMap }, data: profile }
```
`data: profile` (the raw provider profile) is returned alongside `user` and is what a plugin's `mapProfileToUser`/custom fields pipeline (`parseAdditionalUserInputFromProviderProfile`) reads to populate app-defined extra user columns. Python currently discards the raw profile entirely (`_resolve_user` only reads the four `OAuthUserInfo` fields) — there is no additional-fields pipeline to feed anyway (out of scope for this doc; see the plugins/core gap spec), but porting `data` alongside `user` is a prerequisite for that pipeline later.

### Notable per-provider quirks (beyond the endpoint table)

- **Apple**: `AppleNonConformUser` — on the **first-ever** consent only, Apple includes a `user` JSON query/body param with `{name: {firstName, lastName}, email}` that never appears again on subsequent logins; the client must capture and forward it (`c.body.idToken.user` / `c.body.user` in the callback). `verifyIdToken` accepts the nonce either as a raw match or as `sha256(nonce)` (`nonceMatches`) since Apple's SDKs sometimes hash it client-side before embedding. `getUserInfo` masks a missing name to `""` (comment flags this as TODO removal once the field is optional).
- **Google**: `hd` (hosted domain) restriction — `hd: "*"` accepts any Workspace domain, a specific string requires an exact match; enforced **both** at `verifyIdToken` (id-token flow) and at `getUserInfo` (redirect flow, since the authorization-time `hd` param is "only a UI hint"). `accessType`/`display` are Google-specific authorize params.
- **Microsoft**: multi-tenant issuer validation is hand-rolled because `common`/`organizations`/`consumers` endpoints can't have a single expected `iss` — the code cross-checks the token's own `tid` claim against `iss` and enforces the `tenant === "organizations"` (must not be the fixed consumer tenant id) / `tenant === "consumers"` (must be it) rules explicitly. Profile photo is fetched and base64-inlined as a `data:` URI into `picture` (best-effort, swallows fetch errors).
- **Facebook**: two totally different `getUserInfo` paths depending on whether the presented token is a 3-segment JWT (`limited login`, verified via Facebook's separate `limited.facebook.com` JWKS) or an opaque access token (verified via `debug_token` app-binding check — Facebook access tokens aren't audience-bound at `/me` by default, so an unrelated app's token would otherwise be accepted).
- **PayPal**: dual-algorithm id-token verification — `RS256` via JWKS, `HS256` via the raw `clientSecret` as the HMAC key; token exchange and refresh are hand-rolled (bypass `validateAuthorizationCode`/`refreshAccessToken` entirely) because PayPal doesn't send OAuth2 scopes (permissions live in the PayPal dashboard) and needs custom header casing. `getUserInfo` cross-checks the userinfo response's `sub`/`user_id` against the id token's `sub` when both are present (OIDC UserInfo-to-IDToken binding).
- **Cognito**: requires `domain`/`region`/`userPoolId` at construction (throws `BetterAuthError` immediately if missing — not deferred to first call). AWS's OAuth endpoint wants scopes space-delimited but %-encoded as `%20` rather than `+`; the code manually rewrites the URL's `scope` param after `createAuthorizationURL` builds it, because `URLSearchParams` encodes spaces as `+`.
- **TikTok**: uses `clientKey`/`clientSecret`, never `clientId` (`clientId?: never`) — the type system enforces this at the config level. Scopes are comma-joined in the hand-built authorize URL (not space-joined). Refresh sends `client_key` via `extraParams` since the shared refresh helper's client-id slot isn't used.
- **WeChat**: the most non-standard provider — `appid`/`secret` instead of `client_id`/`client_secret` everywhere, `GET` (not `POST`) for both token exchange and refresh (query string, not body), and the userinfo endpoint requires the `openid` value returned *alongside* the access token (not derivable from the token alone) — `getUserInfo` reads `token.openid` off an extended `OAuth2Tokens & {openid?}` shape. No email is ever returned; a stable `.invalid`-TLD placeholder (`{unionid|openid}@wechat.invalid`) is synthesized so the (email-required) callback flow doesn't reject the sign-in outright.
- **Reddit**: also synthesizes a `.invalid` placeholder email (`{id}@reddit.invalid`) since the `identity` scope never returns one; requires a `User-Agent` header on every call (Reddit rate-limits/blocks default HTTP client user agents) and uses hand-rolled Basic auth with `accept: text/plain` rather than the shared token-exchange helper.
- **VK**: `getUserInfo` **rejects** the sign-in (`return null`) if neither the provider profile nor `mapProfileToUser` supplies an email — the only provider that hard-fails rather than synthesizing a placeholder.
- **Twitch**: the only provider using the `claims` OIDC parameter to explicitly request extra id-token claims (`email`, `email_verified`, `preferred_username`, `picture`) — configurable via `options.claims`.
- **Salesforce/Atlassian/GitLab/PayPal/Cognito/Paybin**: all support a **configurable base host** (`loginUrl`/`environment`, `issuer`, `domain`, sandbox vs. live) for self-hosted or per-org OAuth servers — this is the same "attacker-configurable endpoint" surface that motivates the SSRF redirect-rejection hardening above.
- **Zoom**: the only provider with an *optional* PKCE toggle (`options.pkce`, default `true`) rather than PKCE being an unconditional per-provider fact.
- **Discord/Roblox/TikTok/WeChat/Slack**: build the authorize URL by hand (`new URL(...)` string interpolation) instead of calling the shared `createAuthorizationURL()` — each has some param the shared builder doesn't model (Discord's `permissions`+`bot` scope combo, Roblox's `prompt` default, TikTok's `client_key`, WeChat's `#wechat_redirect` fragment + `appid`, Slack's manual `URLSearchParams`). A Python port can still centralize the *token exchange* side for all of these; only the authorize-URL construction needs a per-provider escape hatch.

---

## Provider option surface shared by all (`ProviderOptions<Profile>`, `packages/core/src/oauth2/oauth-provider.ts`)

Every provider's options type `extends ProviderOptions<TheirProfile>`. Fields, and Python's current coverage:

| Option | Purpose | Python (`OAuthProvider` dataclass in `oauth.py`) |
|---|---|---|
| `clientId` (`unknown` — usually `string \| string[]`) | app identity; array form = multiple accepted audiences | `client_id: str` — no array/multi-audience form |
| `clientSecret` | app secret | `client_secret: str` — present |
| `clientKey` | TikTok's `clientId` replacement | absent |
| `scope: string[]` | additive extra scopes | `scopes: list[str]` used as the *entire* default list, no separate "extra" concept |
| `disableDefaultScope` | wipe the provider's baked-in defaults before adding `scope`/per-call `scopes` | absent (no way to drop defaults without subclassing and overwriting `scopes`) |
| `redirectURI` | per-provider override of the computed `{baseURL}/callback/{id}` | present (`redirect_uri`) |
| `authorizationEndpoint` | override the hardcoded authorize URL | absent |
| `disableIdTokenSignIn` | provider supports id-token verify but this instance opts out | absent (moot — no provider has id-token verify yet) |
| `verifyIdToken` | full override of id-token verification | absent |
| `getUserInfo` | full override of profile fetch — skips network call entirely | absent |
| `refreshAccessToken` | full override of the refresh flow | absent (no refresh flow at all) |
| `mapProfileToUser` | partial override merged over the default mapping | absent |
| `disableImplicitSignUp` | require `requestSignUp: true` on sign-in to create a new user via this provider | absent |
| `disableSignUp` | hard-disable sign-up via this provider entirely (even with `requestSignUp`) | absent |
| `prompt` | `select_account \| consent \| login \| none \| "select_account consent"` | absent |
| `responseMode` | `query \| form_post` (Apple) | absent |
| `overrideUserInfoOnSignIn` | re-sync user profile from provider on every sign-in, not just first link | absent |

Plus per-request/per-call knobs threaded through `createAuthorizationURL`'s `data` param (not provider-config, request-time): `loginHint`, `display` (Google), and provider-config-only extras seen above (`accessType`/`hd` on Google, `permissions`/`prompt` on Discord, `duration` on Reddit, `pkce` on Zoom, `configId` on Facebook, `accessType` on Dropbox, `fields` on Facebook/TikTok, `profilePhotoSize`/`disableProfilePhoto`/`tenantId`/`authority` on Microsoft, `environment`/`loginUrl` on Salesforce, `environment`/`requestShippingAddress` on PayPal, `region`/`userPoolId`/`requireClientSecret` on Cognito, `issuer` on GitLab/Paybin, `scheme` on VK, `lang` on WeChat).

---

## Python current state (file:line)

- `src/better_auth/oauth.py` — the entire OAuth2 module (384 lines):
  - `OAuthTokens` (30-35), `OAuthUserInfo` (38-44), `OAuthProvider` base dataclass (47-78, generic OIDC-shaped `fetch_user`), `GitHub` (81-114, custom `fetch_user` for email lookup), `Google` (117-124, PKCE on, otherwise pure defaults — no `hd`/`accessType`/`verifyIdToken`), `Discord` (127-150, custom `fetch_user` for avatar CDN URL).
  - `sign_in_social()` (165-224): hand-builds the authorize URL (`urlencode(params)`), no `createAuthorizationURL`-equivalent shared helper — every future provider needs its own URL-building code or must fit the one fixed param set this function supports (`client_id`, `response_type=code`, `redirect_uri`, `state`, `scope`, `code_challenge*`, plus `provider.authorize_params` passthrough — this last one is the *only* generalization point, roughly analogous to TS's `additionalParams`).
  - `_exchange_code()` (227-256): single fixed shape — `grant_type=authorization_code`, `client_id`+`client_secret` **always in the body** (no basic-auth mode), single `POST`. No `resource`, no per-provider header shape, no basic-auth switch — this alone blocks correctly porting `twitter`, `figma`, `notion`, `railway`, `paypal`, `reddit` as specified.
  - `oauth_callback()` (271-322): reads `code`/`state`/`error` from **query string only** (`ctx.request.query`) — no POST-body parsing, so `response_mode: form_post` (Apple) cannot work even after Apple itself is ported.
  - `_resolve_user()` (329-384): the `handleOAuthUserInfo` analog — see "OAuth2 shared machinery" above for the itemized gap vs. `link-account.ts`.
  - No `refresh_access_token()`, no `verify_id_token`/JWKS infra, no `client_credentials_token()`, no `fetchRefusingRedirects`-equivalent SSRF guard (see `reject-redirects.ts` note above).
- `src/better_auth/auth.py`:
  - `social_providers: Mapping[str, OAuthProvider]` constructor param (line 54), stored at `self.social_providers` (line 89), with a small normalization loop that back-fills `provider.provider_id` from the dict key if unset (90-92) — this is the closest Python analog to TS's `socialProviderList`/registry, but it's caller-supplied, not a built-in `{google, github, ...}` dict the way TS's `packages/core/src/social-providers/index.ts` exports one.
  - No `trustedProviders`, no `accountLinking` sub-config at all, no `encryptOAuthTokens`, no `storeAccountCookie`, no `storeStateStrategy` choice (always the DB-table shape), `skip_state_cookie_check: bool` exists as a single global flag (line 63) — TS's per-call `settings.skipStateCookieCheck` override (used by oauth-proxy/SAML) has no Python equivalent since there's no plugin system feeding it yet.
- `src/better_auth/endpoints.py`:
  - `ROUTES` (555-582): registers `sign-in/social` (560), `callback/{provider}` GET+POST (561-562), `list-accounts` (580), `unlink-account` (581). **No `link-social` route at all.**
  - `unlink_account()` (512-529): does exist and roughly matches TS's `allowUnlinkingAll`-off default behavior (refuses to unlink the last account) — this part has no gap worth flagging here (out of this doc's OAuth2-machinery scope; the account-route gaps live in the core-http/db-layer specs).
- `src/better_auth/crypto.py`: `generate_random_string()` (34-35, alphabet-and-length-compatible with TS's `generateRandomString`), `sign_value`/`unsign_value` (74-91, matches TS's signed-cookie HMAC format) — both reusable as-is for the state-cookie CSRF binding. No `symmetric_encrypt`/`symmetric_decrypt` (needed for `encryptOAuthTokens`).
- `src/better_auth/schema.py`: `account` table (42-56) already has every column the shared machinery needs (`accessToken`, `refreshToken`, `idToken`, `accessTokenExpiresAt`, `refreshTokenExpiresAt`, `scope`) — no schema changes required to port the remaining machinery, only handler logic.

---

## Gap items

Sized S (≤ half day), M (~1-2 days), L (multi-day / needs design decisions first). Ordered so earlier items unblock later ones.

### Machinery (must land before/alongside provider fan-out)

1. **[L] Generalize `createAuthorizationURL`-equivalent.** Replace `sign_in_social`'s hand-built `urlencode(params)` with a shared builder taking the same knob set TS has (`prompt`, `accessType`, `display`, `loginHint`, `hd`, `responseMode`, `additionalParams`, `scopeJoiner`, `claims`, optional PKCE), while still letting a handful of providers (Discord, Roblox, TikTok, WeChat, Slack) opt out and build their own URL. Also generalize `getPrimaryClientId`/array-`clientId` support since several id-token-verifying providers need it. Blocks nearly every provider below.
2. **[M] Generalize token exchange (`_exchange_code`).** Add `authentication: "basic" | "post"` switch, `resource`/`additionalParams` passthrough, and stop hardcoding `grant_type=authorization_code` fields inline so providers with non-standard exchanges (Reddit's custom headers, PayPal/WeChat's fully custom fetch) can still reuse the shared body/header builder for the parts that are standard. Blocks: twitter, figma, notion, railway, reddit (partial), paypal (partial).
3. **[M] Port `refresh_access_token()`** as a shared function (mirrors item 2's auth-mode switch) plus a `POST /refresh-token` (or `get-access-token`) endpoint. Every provider factory needs a `refresh_access_token` slot exposed the same way `fetch_user`/`get_user_info` is today, defaulting to the shared helper. Currently **zero** refresh support exists.
4. **[L] JWT/JWKS id-token verification infra.** Add a JWT library dependency (e.g. `pyjwt` or `authlib`'s jose) + JWKS fetch/cache (mirrors `verify.ts`'s TTL + no-`kid` retry cooldown, or a simpler `functools.lru_cache`-with-TTL if that ceiling is acceptable — flag as an open question below). This is the single biggest unlock: without it, Google/Apple/Microsoft/Cognito/PayPal/Facebook/TikTok/Paybin/Twitch(claims)/Line can't be ported faithfully, and the id-token direct sign-in flow (item 6) can't exist at all.
5. **[M] Account-linking policy surface.** Add `account_linking` config (`enabled`, `disable_implicit_linking`, `require_local_email_verified`, `trusted_providers` static-or-callable, `allow_different_emails`, `allow_unlinking_all`, `update_user_info_on_link`) and `update_account_on_sign_in`, and rewrite `_resolve_user`'s single `if unverified: reject` guard into the full decision tree from `link-account.ts` (trusted-provider bypass, local-row verification gate, implicit-linking toggle, profile-sync-on-link). This is a **behavior change to existing sign-in**, not purely additive — needs a test-first pass per `superpowers:test-driven-development` given the security sensitivity (account-takeover guard).
6. **[L] `POST /link-social` endpoint + callback linking branch.** New endpoint (idToken sub-flow + redirect sub-flow per `account.ts`), plus teach `oauth_callback()` to recognize a `link` field in the state payload and take the non-session-creating linking path instead of `_resolve_user`. Depends on item 5 (shares the trusted-provider/allow-different-emails checks) and item 1 (needs `createAuthorizationURL` to accept the same `state`/`codeVerifier` shape from a second call site).
7. **[L] id-token direct sign-in** (`sign_in_social`'s `idToken` body branch + the `link-social` idToken branch). Depends on item 4 (verification) and item 5/6 (shares `handleOAuthUserInfo`-equivalent linking logic). Needs `verify_id_token(token, nonce)` and `get_user_info(token=..., id_token=..., access_token=..., user=...)` call shapes added to the provider interface.
8. **[S] SSRF hardening on outbound OAuth fetches.** Explicitly pass `follow_redirects=False` (or manually reject 3xx) on every token-exchange/userinfo/JWKS `httpx` call, matching `reject-redirects.ts`'s threat model — cheap, high-value, currently only accidentally safe via httpx's default.
9. **[S] `error_description` on error redirects** + **fix POST-callback body parsing** (`oauth_callback` must read `code`/`state`/`error` from the POST body when the request is a POST, not just query — currently silently broken for any `form_post` provider). Two small, unrelated-but-adjacent fixes to `_error_redirect`/`oauth_callback`.
10. **[M] OAuth token encryption at rest** (`encrypt_oauth_tokens` option + `symmetric_encrypt`/`symmetric_decrypt` in `crypto.py`, applied at the same two call sites TS uses: writing `account.accessToken`/`refreshToken` in `_resolve_user`, reading them back wherever a plugin needs the live token). Independent of the other items; can land any time. Flagged in the `better-auth-security-best-practices` skill as a recommended hardening step.
11. **[S] `additionalData` passthrough** in the state payload (`sign_in_social`'s body → state → callback round-trip) — small, unblocks apps that need to thread app-specific context through OAuth without a session already existing.
12. **[S] `mapProfileToUser` / `getUserInfo` / `refreshAccessToken` full-override hooks** on `OAuthProvider` (the `options.xxx ?? default` pattern every TS provider uses) — mechanical, but touches every provider's construction, so worth doing once, early, rather than retrofitting per-provider later.
13. **[S] `disable_default_scope` / additive `scope` vs. request-time `scopes` distinction** on the base `OAuthProvider` — currently `scopes` is a single list serving both roles.
14. **[S] `disable_sign_up` / `disable_implicit_sign_up` / `request_sign_up`** enforcement in `_resolve_user`/`sign_in_social` (currently sign-up is always implicit, unconditionally).
15. **[XS, optional] `"cookie"` stateless state-storage strategy.** Lower priority than the above — see Open Questions; Python already assumes a DB adapter exists (unlike TS, which supports secondary-storage-only or fully DB-less deployments), so the value of a stateless mode is smaller here.
16. **[XS, optional] `storeAccountCookie` DB-less account storage** — same reasoning as item 15, likely not worth porting unless a concrete DB-less Python deployment target shows up.

### Mechanical per-provider ports (32 missing; grouped by size, using the endpoint/quirk table above as the spec for each)

All depend on item 1 (URL builder) at minimum; the ones marked "needs JWKS" additionally depend on item 4.

**S — standard OIDC-shaped, no unusual verification or endpoint quirks** (bearer-token GET userinfo, straightforward JSON mapping): `atlassian`, `figma`, `huggingface`, `kakao`, `kick`, `linear`, `linkedin`, `naver`, `notion`, `paybin` (needs JWKS), `polar`, `slack`, `spotify`, `vercel`.

**M — one non-trivial quirk each** (custom auth mode, custom URL construction, multi-endpoint composition, or environment/host configurability): `cognito` (needs JWKS + region config + scope-encoding fix), `gitlab` (self-hosted issuer + account-state check), `line` (id-token-or-userinfo fallback + LINE's own verify-endpoint call instead of JWKS), `reddit` (custom headers/auth + placeholder email), `roblox` (hand-built URL + `authentication: post` explicit), `salesforce` (sandbox/production/loginUrl resolution), `tiktok` (`clientKey` everywhere + comma-scopes + hand-built URL), `twitch` (needs JWKS + `claims` param), `twitter` (basic auth + 2-call profile+email), `vk` (POST-body userinfo + hard email requirement), `zoom` (optional manual PKCE toggle).

**L — multiple compounding quirks, needs careful test coverage**: `apple` (needs JWKS + nonce-hash fallback + `response_mode=form_post` + first-consent-only user payload — depends on item 9's POST-body fix), `facebook` (needs JWKS for limited-login path + opaque-token `debug_token` app-binding verification — two entirely different `getUserInfo` code paths), `microsoft` (needs JWKS + multi-tenant issuer validation + profile-photo fetch-and-inline), `paypal` (needs JWKS, dual-algorithm RS256/HS256 + fully custom token exchange/refresh + sub-binding check), `wechat` (fully non-standard token/refresh/userinfo shapes, GET not POST, `appid` not `client_id`).

**Vendor/self-referential, confirm demand before investing** (see Open Questions): `polar`, `railway`, `vercel`, `paybin` — these are better-auth's own vendor/dev-tool integrations (Polar payments, Railway, Vercel, a payments IdP called Paybin), not general-purpose identity providers; sized above as if in-scope, but worth a priority check against whether the Python port's target audience needs them at all.

**Already ported but incomplete vs. TS** (not counted in the 32, but flagged): `google` — missing `hd` domain restriction, `accessType`/`display`, and (once item 4 lands) `verifyIdToken`; `discord` — missing default-avatar-CDN fallback for users with no custom avatar (`profile.avatar === null` branch — TS computes a numeric default-avatar index from the Discord snowflake/discriminator), missing `prompt`/`permissions` config; `github` — reasonably faithful already, missing only the generic per-provider hooks from item 12.

---

## Open questions

- **JWKS caching strategy for item 4**: mirror TS's exact TTL/no-`kid`-retry-cooldown cache (`verify.ts`), or is a simpler `cachetools.TTLCache`-based cache an acceptable ceiling for a first pass? Affects how much of `verify.ts`'s ~280 lines need a faithful port vs. a simplified equivalent.
- **State storage strategy (item 15)**: Python's `BetterAuth` currently always assumes a DB adapter (`MemoryAdapter` default, never "no adapter"). Does the stateless `"cookie"` strategy from TS have a real use case here, or is it TS-specific to deployments that skip the DB entirely? Recommend confirming before spending time on it.
- **`storeAccountCookie` (item 16)**: same question as above — depends on whether "DB-less Python deployment" is an actual target.
- **Vendor providers (`polar`, `railway`, `vercel`, `paybin`)**: `ACTIVE.md`'s parked questions already flag "ecosystem packages (api-key, passkey, sso, scim, stripe, oauth-provider) — confirm IN/OUT". These four social providers are a smaller, adjacent version of the same question — worth batching into the same confirmation rather than deciding unilaterally here.
- **Region-specific providers (`wechat`, `vk`, `naver`, `kakao`, `line`)**: no indication in the Python repo of a target user base needing these; sized/spec'd above for completeness (task required reading every provider file), but likely low priority relative to the global-audience providers (`microsoft`, `facebook`, `apple`, `twitter`, `linkedin`, etc.).
- **Relationship to `ACTIVE.md`'s Phase 1 wave-1 line item** ("missing account routes (change-email, delete-user, **link/unlink-social**, refresh-token, get-access-token, full options surface")): that line already names several of this doc's machinery gaps (items 3, 6). Whoever plans Phase 1+ should merge rather than duplicate — this doc is the detailed spec for those bullet points, not a competing plan.
- Not blocked on anything: full read access to both repos throughout; no `BLOCKED` items to report.
