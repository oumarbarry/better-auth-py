# OAuth2/OIDC Provider (`@better-auth/oauth-provider`) — Python parity spec

Scope: port the **server** package `@better-auth/oauth-provider` (successor of the deprecated
`oidc-provider`/`mcp` plugins) to the Python port. This is the authorization-server side: it
issues authorization codes, access/refresh tokens, and id tokens; hosts discovery/JWKS/userinfo;
registers and manages OAuth clients and consents. Source read from
`packages/oauth-provider/` (~9.8k src LOC + ~14k test LOC) at the pinned TS repo.

Cross-runtime compatibility is a hard requirement: a DB written by the TS provider must be
readable by the Python port — identical table/column names (camelCase), identical token/secret
encodings (SHA-256 base64url-nopad hashing, XChaCha20 secret encryption), identical JWT/JWKS
crypto (the JWKS keys are shared with the `jwt` plugin).

Conventions:
- Endpoint paths are relative to the auth mount (TS registers under the base path).
- Schema field names are the **exact camelCase** column names the provider uses by default.
- "internalAdapter" / "adapter" refer to the Python `InternalAdapter` (`internal_adapter.py`) and
  `BaseAdapter` (`adapters/base.py`) seams — **both already exist** in the port (see *Python current
  state*). TS `ctx.context.internalAdapter.*` maps to `ctx.internal.*`; TS `ctx.context.adapter.*`
  to `ctx.adapter.*`.
- TS `file.ts:NN` anchors are into `packages/oauth-provider/src/`.

The provider is JWT-first: by default access tokens with an audience and all id tokens are signed
via the **`jwt` plugin**'s keys (Ed25519 JWKS). It hard-depends on the `jwt` plugin unless
`disableJwtPlugin: true`.

---

## Python current state — foundations that already EXIST (do NOT re-spec as gaps)

The Python port is far past the "core-only" state the earlier gap docs (04/05) describe. Verified
present and reusable:

- **Plugin contract** (`plugins.py`): `Plugin` base with `id`, `version`, `schema` (ClassVar),
  `error_codes` (ClassVar → `auth.error_codes`), `init(auth)`, `routes()` → `[(method, path,
  handler)]`, `middlewares()` (`PluginMiddleware{path, handler}`, prefix `/**`), `hooks()` →
  `HookSet(before=[PluginHook{matcher, handler}], after=[…])`, `rate_limit()` → `[RateLimitRule{window,
  max, path_matcher}]`, `on_request`/`on_response`, `before`/`after`. `add_expose_headers(resp, *names)`
  helper. Every TS plugin hook point has a Python analogue.
- **Verification store, atomic** (`internal_adapter.py`): `create_verification_value`,
  `find_verification_value`, `consume_verification_value` (per-identifier `asyncio.Lock` + adapter
  transaction, delete-all-rows-for-identifier, returns `None` past `expiresAt` — the code single-use
  gate), `delete_verification_by_identifier`, `update_verification_by_identifier`.
- **Session/user surface** (`internal_adapter.py`): `create_session(user_id, dont_remember_me,
  override, …)`, `find_session(token)` → `{session, user}`, `update_session`, `delete_session`,
  `delete_sessions([tokens])`, `delete_user_sessions`, `list_sessions`; `create_user`, `update_user`,
  `delete_user`, `list_users`, `count_total_users`; `create_account`, `update_password`; databaseHooks
  (`_run_before`/`_queue_after`).
- **Adapter primitives** (`adapters/base.py`): `create` / `find_one` / `find_many` (sort_by / limit /
  offset / select) / `update` / `update_many` / `delete` / `delete_many` / `count` / `transaction`;
  **`consume_one`** (atomic delete-and-return, = TS `consumeOne`); **`increment_one`** (guarded
  compare-and-swap that re-applies `where` as the CAS guard and returns the updated row, = TS
  `incrementOne`). `Where(field, value, operator, connector, mode)` with operators
  `eq|ne|in|not_in|contains|starts_with|ends_with|gt|gte|lt|lte`, `AND`/`OR`, sensitive/insensitive.
  → The refresh-rotation CAS on `revoked = null`, the `deleteMany` on `refreshId in [...]`, and the
  code single-use gate all map directly.
- **Crypto** (`crypto.py`): `symmetric_encrypt`/`symmetric_decrypt` (XChaCha20-Poly1305,
  `SHA-256(secret)` key, 24-byte prepended nonce, hex, `$ba$<v>$<hex>` envelope, TS byte-parity);
  **`default_key_hasher`** = base64url-nopad of SHA-256 (**exactly** the provider's `defaultHasher` /
  `storeToken: "hashed"` / `storeClientSecret: "hashed"`); `generate_random_string(size, alphabet)`
  (charset-parameterized), `generate_id`; `sign_value`/`unsign_value` (signed cookies);
  `sign_hmac_b64url`, `b64url_encode_nopad`/`b64url_decode_nopad`; TOTP/`otpauth_url`; Ed25519 JWK pair,
  `encode_jwk_private_key`/`decode_jwk_private_key`. The private `_signature(secret, value)` =
  **standard base64 (padded) HMAC-SHA256** — this is exactly TS `makeSignature` (crypto/index.ts:112,
  `btoa(...)`); the signed-cookie path already uses it.
- **PKCE S256** (`oauth/machinery.py:52`): `code_challenge(verifier)` = base64url(SHA-256(verifier))
  no-pad = the provider's `generateCodeChallenge`.
- **`jwt` plugin** (`plugins_ext/jwt.py`): `jwks` table storage (TS-verified `publicKey`/`privateKey`
  codec), `sign_jwt(payload, override_options)` (= server-only `signJWT`; `_sign` **respects
  payload-provided `iss`/`aud`/`exp`/`iat`/`sub`** so the provider can stamp its own claims),
  `verify_jwt(token, issuer)` (server-only `verifyJWT`), `_get_jwt_token`, `_jwks_body()` (= `getJwks`
  response body), `to_exp_jwt`. **EdDSA/Ed25519 only** (raises `NotImplementedError` for
  ES256/ES512/PS256/RS256).
- **OAuth-error-shape precedent** (`plugins_ext/device_authorization.py`): the exact pattern the
  provider needs — a per-plugin `_oauth_error(status, error, description)` returning
  `AuthResponse(status, body={"error", "error_description"})` because the port's `APIError` renders
  `{"code", "message"}`, which is **incompatible** with OAuth's `{error, error_description}`. Also the
  reference for `routes()`, `rate_limit()`, `consume_one`/`increment_one` usage, and
  `ctx.internal.create_session`.
- **Schema `Field`** (`schema.py`): `type` includes `json`, `string[]`, `number[]`, `datetime`;
  `references=Reference(model, field, on_delete)`, `index`, `input`, `returned`, `default`,
  `default_factory`, `on_update`, `sortable`, `field_name`, `bigint`; `merge_schema`. Covers every
  provider column (`string[]` for redirectUris/scopes/contacts, `json` for metadata, FK refs with
  `on_delete="set null"`).
- **generic-oauth + full client `oauth/` machinery** (`oauth/`, `plugins_ext/generic_oauth.py`):
  provider registry, discovery, PKCE, `oauth/verify.py` JWKS fetch/cache + RS256/ES256 id-token verify
  (client-side). Trusted-origin checks (`origin.py`), signed cookies, `access_control.py` (**not used**
  by this plugin — it authorizes clients via a `clientPrivileges` callback, not roles/statements).

Net: the plugin can be built almost entirely on existing seams. The genuinely new core-ish pieces are
small (OAuth-error helper, jwt-plugin lookup, signed-query codec, a server-side JWT-access-token
verify helper, `SafeUrl` scheme policy). Everything else is plugin-local logic.

---

## Package layout (what maps to what)

| TS file (`src/`) | LOC | Purpose | Python home |
|---|---|---|---|
| `oauth.ts` | 1555 | Plugin factory, endpoint registration, `onRequest` metadata router, before/after hooks, rate limits, `init` guards | `plugins_ext/oauth_provider/__init__.py` (plugin class) |
| `authorize.ts` | 676 | `/oauth2/authorize`: redirect_uri match, PKCE gate, prompt/consent, code minting, signed-query resume | `authorize.py` |
| `token.ts` | 1128 | `/oauth2/token`: 3 grants, JWT+opaque access tokens, id_token, refresh rotation/family invalidation | `token.py` |
| `introspect.ts` | 522 | `/oauth2/introspect` (RFC 7662) | `introspect.py` (+ shared verify helper) |
| `revoke.ts` | 355 | `/oauth2/revoke` (RFC 7009) | `revoke.py` |
| `userinfo.ts` | 100 | `/oauth2/userinfo` (OIDC) + shared `userNormalClaims` | `userinfo.py` |
| `register.ts` | 500 | `/oauth2/register` (RFC 7591 DCR) + shared client-create chokepoint + `oauthToSchema`/`schemaToOAuth` | `register.py` |
| `metadata.ts` | 186 | RFC 8414 auth-server + OIDC discovery documents | `metadata.py` |
| `consent.ts` | 167 | `/oauth2/consent` | `consent.py` |
| `continue.ts` | 101 | `/oauth2/continue` (selected/created/postLogin resume) | `continue.py` |
| `logout.ts` | 193 | `/oauth2/end-session` (OIDC RP-Initiated Logout) | `logout.py` |
| `signed-query.ts` | 71 | Signed-query canonicalization + declared-param-names codec | `signed_query.py` |
| `utils/index.ts` | 684 | `getClient`, store/verify client secret, `storeToken`, PKCE-required, pairwise sub, basic-auth, prompt parse | `utils.py` |
| `oauthClient/` | ~660 | Client CRUD endpoints (10) + `assertClientPrivileges` | `client_crud.py` |
| `oauthConsent/` | ~250 | Consent CRUD endpoints (4) | `consent_crud.py` |
| `schema.ts` | 319 | 4 tables | `schema.py` |
| `types/` | ~1490 | Options, oauth types, zod runtime schemas | folded into the above |
| `mcp.ts`, `client.ts`, `client-resource.ts` | ~450 | **Client-side** helpers (`mcpHandler`, resource-server verify, signin plugin) | out of server scope — see Open questions |

---

## Area 1 — Client registration & storage

### Endpoints

| method | path | body/query | auth | notes |
|---|---|---|---|---|
| POST | `/oauth2/register` | RFC 7591 client metadata (`redirect_uris`, `scope`, `client_name`, `token_endpoint_auth_method`, `grant_types`, `response_types`, `type`, `subject_type`, …) | session OR anonymous (gated) | Dynamic Client Registration. `oauth.ts:1273`, impl `register.ts:31` |
| POST | `/oauth2/create-client` | client metadata (no `skip_consent`/`enable_end_session`/`require_pkce`) | session | `oauthClient/index.ts:228` |
| POST | `/admin/oauth2/create-client` | client metadata **+ SERVER_ONLY fields** (`client_secret_expires_at`, `skip_consent`, `enable_end_session`, `require_pkce`, `subject_type`, `metadata`) | **server-only** | `oauthClient/index.ts:16` |
| GET | `/oauth2/get-client` | `{client_id}` | session (owner) | strips `client_secret`. `oauthClient/index.ts:424` |
| GET | `/oauth2/public-client` | `{client_id}` | session | public UI fields only (name/uri/icon/contacts/tos/policy). `oauthClient/index.ts:444` |
| POST | `/oauth2/public-client-prelogin` | `{client_id, oauth_query?}` | `publicSessionMiddleware` (requires `allowPublicClientPrelogin` + valid signed `oauth_query`) | pre-login public fields. `oauthClient/index.ts:465` |
| GET | `/oauth2/get-clients` | — | session | lists caller's clients (by `userId` or `referenceId`). `oauthClient/index.ts:487` |
| POST | `/oauth2/update-client` | `{client_id, update:{…}}` | session (owner) | `token_endpoint_auth_method` **immutable**. `oauthClient/index.ts:558` |
| PATCH | `/admin/oauth2/update-client` | `{client_id, update:{… + SERVER_ONLY}}` | **server-only** | `oauthClient/index.ts:505` |
| POST | `/oauth2/client/rotate-secret` | `{client_id}` | session (owner) | confidential clients only. `oauthClient/index.ts:604` |
| POST | `/oauth2/delete-client` | `{client_id}` | session (owner) | `oauthClient/index.ts:624` |

**Ownership check** (`oauthClient/endpoints.ts:26-33`, repeated in get/update/delete/rotate): if
`client.userId` set → must equal `session.user.id`; else if `client.referenceId` + `opts.clientReference`
→ must equal `await clientReference(session)`; else → `UNAUTHORIZED`. `cachedTrustedClients` are
**immutable via CRUD** (update/delete/rotate throw `INTERNAL_SERVER_ERROR` "trusted clients must be
updated manually", `endpoints.ts:131/181/257`).

**Authorization gate** (`oauthClient/privileges.ts:16`): `assertClientPrivileges(ctx, session, opts,
action)` — throws `UNAUTHORIZED` if no session, `BAD_REQUEST` if no headers, else calls
`opts.clientPrivileges({headers, action, session, user})` and throws `UNAUTHORIZED` on falsy. Action ∈
`create|read|update|delete|list|rotate`. Every client mutation routes through this. `create` is enforced
at the single creation chokepoint `createOAuthClientEndpoint` (`register.ts:216-222`): DCR may be
anonymous (public clients only) when `allowUnauthenticatedClientRegistration`, otherwise a session +
gate is required.

### Client secret storage modes (`types/index.ts:417`, `utils/index.ts:237-338`)

- Default `storeClientSecret` = `disableJwtPlugin ? "encrypted" : "hashed"`.
- `"hashed"`: `defaultHasher` = base64url-nopad SHA-256 (**= port `default_key_hasher`**); verify via
  `constantTimeEqual(hash(input), stored)`.
- `"encrypted"`: `symmetricEncrypt({key: ctx.context.secretConfig, data})` / `symmetricDecrypt`; verify by
  decrypt + constant-time compare. **Only allowed with `disableJwtPlugin: true`** (init guard
  `oauth.ts:157-178`: hashed secrets are rejected when JWT is disabled because id tokens are HS256-signed
  with the secret; encryption is rejected when JWT is enabled).
- Custom `{hash, verify?}` or `{encrypt, decrypt}` objects.
- Client secret sent to the client carries `opts.prefix?.clientSecret` (not stored); verify strips it
  first (`utils/index.ts:246`).

### Client id/secret generation

- `clientId` = `opts.generateClientId?.()` or `generateRandomString(32, "A-Z", "a-z")`
  (`register.ts:232`) → port `generate_random_string(32, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")`.
- `clientSecret` = `opts.generateClientSecret?.()` or `generateRandomString(32, "A-Z", "a-z")`; only for
  confidential (`isPublic = token_endpoint_auth_method === "none"`).
- `client_secret_expires_at`: `0` (never) unless DCR + `clientRegistrationClientSecretExpiration` →
  `toExpJWT(...)`.

### DCR validation (`register.ts:77` `checkOAuthClient`)

- `type` must match `isPublic` (`native`/`user-agent-based` for public; `web` for confidential).
- `authorization_code`/implicit grants require `redirect_uris` non-empty.
- `authorization_code` grant ⇒ `response_types` must include `code`.
- `subject_type` ∈ `public|pairwise`; `pairwise` requires server `pairwiseSecret`; pairwise + multiple
  redirect_uri hosts is rejected (sector_identifier_uri unsupported).
- Requested scopes must be within `clientRegistrationAllowedScopes ?? scopes` (register) or `scopes`
  (create).
- DCR: `require_pkce === false` is rejected ("pkce is required for registered clients"); `skip_consent`
  is a `z.never()` (rejected).
- Unauthenticated DCR (`resolveUnauthenticatedAuth`, `register.ts:15`): forces
  `token_endpoint_auth_method: "none"`, clears `type: "web"`, rejects `client_credentials` grant.

### `oauthToSchema` / `schemaToOAuth` (`register.ts:302`/`407`)

Bidirectional map between RFC 7591 snake_case wire shape and the DB camelCase `SchemaClient`. Unknown
wire keys collapse into the `metadata` JSON column; `metadata` is JSON-stringified on write and
`parseClientMetadata`-parsed on read (tolerates adapters that auto-parse JSON). `client_secret` is
`@internal` — **never** returned by get/update/rotate/list (explicitly nulled).

### Schema — `oauthClient` (exact camelCase, `schema.ts:4`)

`clientId`(string, unique, req), `clientSecret`(string), `disabled`(boolean, default `false`),
`skipConsent`(boolean), `enableEndSession`(boolean), `subjectType`(string), `scopes`(**string[]**),
`userId`(string, ref `user.id`, **index**), `createdAt`(date), `updatedAt`(date), `name`(string),
`uri`(string), `icon`(string), `contacts`(**string[]**), `tos`(string), `policy`(string),
`softwareId`/`softwareVersion`/`softwareStatement`(string), `redirectUris`(**string[]**, **req**),
`postLogoutRedirectUris`(**string[]**), `tokenEndpointAuthMethod`(string), `grantTypes`(**string[]**),
`responseTypes`(**string[]**), `public`(boolean), `type`(string), `requirePKCE`(boolean),
`referenceId`(string), `metadata`(**json**). PK `id` auto.

### Behaviors from tests (`register.test.ts`, `oauthClient/endpoints*.test.ts`)

- Confidential-registration preserves method/type; unauthenticated DCR overrides
  `client_secret_post`/`_basic` → `none` and clears `type`; anonymous `client_credentials` rejected.
- Metadata field round-trips; extra non-schema fields are stripped into `metadata`.
- `endpoints-privileges.test.ts` asserts the `clientPrivileges` gate on **every** action
  (create/read/list/update/delete/rotate/admin-create/register) for allowed vs forbidden users, plus
  "unauthenticated public registration without invoking the gate".
- `update` cannot flip a client public or change `client_secret`; `rotate` returns a new prefixed secret
  and never rotates public clients.

---

## Area 2 — Discovery metadata + JWKS

### Documents (`metadata.ts`)

- **`authServerMetadata`** (RFC 8414): `issuer` (jwt-plugin issuer ?? baseURL, `validateIssuerUrl`-ed),
  `authorization_endpoint`, `token_endpoint`, `jwks_uri` (`remoteUrl ?? ${baseURL}${jwksPath}`; omitted
  when `disableJwtPlugin`), `registration_endpoint` (only if DCR enabled), `introspection_endpoint`,
  `revocation_endpoint`, `response_types_supported` (`["code"]` or `[]` if no auth_code grant),
  `response_modes_supported: ["query"]`, `grant_types_supported`, `token_endpoint_auth_methods_supported`
  (`["none"?, "client_secret_basic", "client_secret_post"]`), `code_challenge_methods_supported:
  ["S256"]`, `authorization_response_iss_parameter_supported: true`.
- **`oidcServerMetadata`** extends it with `userinfo_endpoint`, `subject_types_supported`
  (`["public"]` or `["public","pairwise"]`), `id_token_signing_alg_values_supported`
  (keyPairConfig.alg → `["EdDSA"]` default, or `["HS256"]` when `disableJwtPlugin`),
  `end_session_endpoint`, `acr_values_supported: ["urn:mace:incommon:iap:bronze"]`, `claims_supported`,
  `prompt_values_supported: ["login","consent","create","select_account","none"]`.
- Cache header (`metadataResponse`): `Cache-Control: public, max-age=15,
  stale-while-revalidate=15, stale-if-error=86400`, `Content-Type: application/json`.

### Serving (`oauth.ts:180` `onRequest` + `oauth.ts:584/621` SERVER_ONLY endpoints)

Discovery must be served at **issuer-path-relative** well-known URLs, which the auth router's base path
may not cover. The TS plugin uses `onRequest` (port `on_request`) to intercept both:
- `/.well-known/oauth-authorization-server${issuerPath}` **and** `${issuerPath}/.well-known/oauth-authorization-server`
  (RFC 8414 path-insertion + issuer-append aliases),
- `${issuerPath}/.well-known/openid-configuration` (only when `openid` scope present).
Returns OIDC metadata when `openid` is a scope, else auth-server metadata. `GET`/`HEAD` only (405 with
`Allow: GET, HEAD`); `HEAD` returns empty body. `skipTrailingSlashes` normalization honored. Two
SERVER_ONLY endpoints (`getOAuthServerConfig`, `getOpenIdConfig`) expose the same bodies for manual
mounting (`oauthProviderAuthServerMetadata`/`oauthProviderOpenIdConfigMetadata` helpers,
`metadata.ts:142/169`).

### JWKS

Not a new endpoint — the provider **reuses the `jwt` plugin's `/jwks`**. `jwks_uri` in discovery points
at `${baseURL}${jwksPath}` (or `remoteUrl`). Port: read the `jwt` plugin's `jwks_path`/`remote_url` from
its instance.

### Behaviors from tests (`metadata.test.ts`)

- Metadata served at both the issuer-appended and RFC 8414 path-insertion URLs; restricted to GET/HEAD.
- `advertisedMetadata.scopes_supported`/`claims_supported` overrides; invalid advertised scope throws at
  init. `disableJwtPlugin` → `HS256` alg, no `jwks_uri`. `remoteUrl` reflected.
- No `openid-configuration` when `openid` not in scopes.

---

## Area 3 — Authorization endpoint + consent

### Endpoints

| method | path | query/body | auth | notes |
|---|---|---|---|---|
| GET | `/oauth2/authorize` | `{response_type?, client_id, redirect_uri?, scope?, state?, request_uri?, code_challenge?, code_challenge_method?, nonce?, prompt?}` | optional session | `oauth.ts:268`, impl `authorize.ts:162` |
| POST | `/oauth2/consent` | `{accept:bool, scope?, oauth_query?}` | session | `oauth.ts:638`, impl `consent.ts:14` |
| POST | `/oauth2/continue` | `{selected?, created?, postLogin?, oauth_query?}` | session | `oauth.ts:686`, impl `continue.ts:17` |

### Authorization flow (`authorize.ts`)

1. Grant-gate: 404 if `authorization_code` not in `grantTypes`.
2. **PAR** (`request_uri`): resolve via `opts.requestUriResolver`; only `client_id` carried from URL, all
   other params from the stored request (RFC 9126 §4). Missing resolver / bad URI → error page.
3. Validate `client_id`, `response_type === "code"`, prompt set. `select_account` prompt without a
   `selectAccount.page` → `unsupported_prompt_select_account`.
4. Load client (`getClient` — trusted-cache-then-DB); `disabled` → `client_disabled`; client must allow
   `authorization_code` grant → else `unauthorized_client`.
5. **`redirect_uri` matching** (`authorize.ts:283`): exact string match, OR RFC 8252 §7.3 loopback-IP
   match — for IP-literal hosts (`127.0.0.0/8`, `::1`; **not** DNS "localhost") match on
   scheme+host+path+query **ignoring port**. No match → `invalid_redirect`.
6. **Scope validation**: requested scopes ⊆ `client.scopes ?? opts.scopes`; invalid → `invalid_scope`
   redirect. Unset → default to client/opts scopes.
7. **PKCE enforcement** (`isPKCERequired`, `utils/index.ts:658`): required for public clients, for
   `offline_access` scope, or `client.requirePKCE ?? true`. If required and `code_challenge`/`_method`
   absent → `invalid_request` with the reason string. If challenge present, method must be `S256`.
8. **Session/prompt gates** (redirect to signed login/select/signup/postLogin/consent pages, or
   `prompt=none` → OIDC error redirect `login_required`/`consent_required`/`account_selection_required`/
   `interaction_required`): no session or `prompt=login`/`create` → login/create page; `select_account`
   prompt or `selectAccount.shouldRedirect` → select page; `signup.shouldRedirect` → signup page;
   `postLogin.shouldRedirect` → post-login page; `prompt=consent` → consent page.
9. **Consent**: `client.skipConsent` → straight to code. Else look up `oauthConsent` by
   (clientId, userId, referenceId?); if missing or requested scopes ⊄ stored scopes → consent page (or
   `consent_required` when `prompt=none`).
10. **Code minting** (`redirectWithAuthorizationCode`, `authorize.ts:569`): `code =
    generateRandomString(32, "a-z","A-Z","0-9")`; store a `verification` row with
    `identifier = storeToken(storeTokens, code, "authorization_code")` (hashed), `expiresAt = now +
    codeExpiresIn` (default 600s), `value = JSON.stringify(VerificationValue{type, query, userId,
    sessionId, referenceId, authTime})`. Redirect to `redirect_uri?code&state&iss`.

`VerificationValue` (`types/index.ts:853`): `{type:"authorization_code", query:OAuthAuthorizationQuery,
sessionId, userId, referenceId?, authTime?}` — the full authorization request is stashed in the JSON
`value`, validated on read by `verificationValueSchema` (zod passthrough, `types/zod.ts:33`).

### Signed-query resume machinery (`signed-query.ts`, `oauth.ts:481` hooks, `authorize.ts:648` `signParams`)

The provider redirects the user-agent to app-hosted login/consent pages carrying the authorization query
**signed** so it can be trusted on return, without cookies (native-app friendly). Mechanics:
- `signParams`: append `exp`, `ba_iat` (issued-at ms), optional `ba_pl` (post-login-cleared session
  marker); declare the signed param names via `ba_param` (`setSignedOAuthQueryParameterNames`); sign the
  **canonicalized** query (`canonicalizeOAuthQueryParams`: sort by key then value) with
  `makeSignature(canonical, ctx.context.secret)`; append `sig`.
- **before-hook** (matcher `ctx.body?.oauth_query`, `oauth.ts:483`): verify the signature
  (`verifyOAuthQueryParams` — exactly one `sig`, constant-time compare, `exp` not past), strip
  `sig`/`exp`/`ba_iat`/`ba_pl`, stash into request state (`oAuthState`). On `/sign-in/social` and
  `/sign-in/oauth2` also injects `additionalData.query`.
- **after-hook** (matcher: session cookie was set, `oauth.ts:527`): after a login completes, re-drive
  `/oauth2/authorize` with the stashed query (login prompt removed) via `dispatchAuthEndpoint`.
- `consent.ts`/`continue.ts` re-enter `/oauth2/authorize` through the same dispatcher so hooks run.
  `login` prompt is only considered satisfied if `session.createdAt >= ba_iat` (`consent.ts:159`), and the
  `postLogin` "cleared" flag is trusted only from the server-minted, session-bound `ba_pl` marker
  (`continue.ts:87`) — never the client-submitted `postLogin: true` alone.

### Consent endpoint (`consent.ts:14`)

Reads the stashed `oauth_query`; requested scopes must be ⊆ originally requested. `accept !== true`
(strict) → `access_denied` redirect. On accept: re-check the `login` prompt against `ba_iat`; upsert
`oauthConsent` (create or update scopes+updatedAt); re-enter authorize with `consent` (and satisfied
`login`) prompt removed and the `ba_pl` marker propagated.

### Consent storage — `oauthConsent` (`schema.ts:282`)

`clientId`(string, req, ref `oauthClient.clientId`, index), `userId`(string, ref `user.id`, index),
`referenceId`(string), `scopes`(**string[]**, req), `createdAt`(date), `updatedAt`(date). PK `id`.

### Behaviors from tests (`authorize.test.ts`, `pkce-optional.test.ts`, `signed-query.test.ts`)

- `validateIssuerUrl`: HTTP→HTTPS for non-loopback, strip query/fragment/trailing-slash, preserve path.
- Signed params verify under param reordering and repeated-value reordering; **reject tampered params**;
  **reject duplicate `sig`**; preserve custom signed params; drop reserved `ba_pl` markers from resolved
  PAR params; discard front-channel params not in the stored PAR request.
- `iss` (RFC 9207) included in success **and error** redirects and matches metadata issuer.
- **PKCE downgrade matrix** (`pkce-optional.test.ts`): public-without-PKCE fails always;
  confidential-without-PKCE fails by default (`requirePKCE` defaults true), succeeds only with explicit
  `requirePKCE:false`; `offline_access`-without-PKCE fails **even with** `requirePKCE:false`;
  PKCE-in-auth-but-not-token fails; PKCE-in-token-but-not-auth fails; mismatched challenge fails.
- `prompt=none` returns the right OIDC error per gate (`login_required`/`consent_required`).

---

## Area 4 — Token endpoint (grants)

### Endpoint

`POST /oauth2/token` (`oauth.ts:737`), `allowedMediaTypes: ["application/x-www-form-urlencoded"]`, impl
`token.ts:38`. Body `{grant_type, client_id?, client_secret?, code?, code_verifier?, redirect_uri?,
refresh_token?, resource?, scope?}`. HTTP Basic auth header → `basicToClientCredentials` (`utils/index.ts:391`).
Response: `{access_token, token_type:"Bearer", expires_in, expires_at, refresh_token?, scope, id_token?, …customFields}`
with `Cache-Control: no-store`, `Pragma: no-cache`.

### `grant_type: authorization_code` (`token.ts:701`)

1. Require `client_id`, `code`, `redirect_uri`; require either `client_secret` or `code_verifier`.
2. **Single-use redemption** (`checkVerificationValue`, `token.ts:638`):
   `internalAdapter.consumeVerificationValue(storeToken(code))` — atomic; concurrent racers get `null` →
   `invalid_grant`. Parse+validate `value`; `query.client_id` must match; stored `redirect_uri` must match
   requested.
3. `validateClientCredentials` (secret verify, disabled check, scope subset, grant allowed).
4. **PKCE consistency** (`token.ts:809`): if PKCE required → `code_verifier` mandatory. If PKCE used in
   auth XOR token → `invalid_request` (downgrade protection). Both → verify
   `generateCodeChallenge(code_verifier) === stored code_challenge` (S256).
5. Load user (`findUserById`) and session (must exist and be unexpired). `authTime` from
   `verificationValue.authTime` or session `createdAt`.
6. Mint tokens (`createUserTokens`).

### `grant_type: client_credentials` (`token.ts:906`)

M2M, no user. Require `client_id` + `client_secret`. OIDC scopes (`openid`/`profile`/`email`/
`offline_access`) are **not requestable** → `invalid_scope`. Default scopes:
`client.scopes ?? clientCredentialGrantDefaultScopes ?? opts.scopes`. No refresh, no id_token.

### `grant_type: refresh_token` (`token.ts:993`)

1. Decode (`decodeRefreshToken` — strip prefix, `formatRefreshToken.decrypt?`). Find
   `oauthRefreshToken` by `storeToken(token)`.
2. Guards: exists, `clientId` matches, not expired. **`revoked` set → replay** → tear down the whole
   `(client, user)` refresh family (`invalidateRefreshFamily`, RFC 9700 §4.14) + `invalid_grant`.
3. Scope narrowing: requested scopes must be ⊆ the refresh token's scopes (never widen).
4. `validateClientCredentials` (secret optional for public clients, required for confidential).
5. Mint (`createUserTokens`) with `refreshToken` = the existing row (triggers rotation).

### Token minting (`createUserTokens`, `token.ts:474`)

- **Access token**: JWT when a `resource`/audience is present **and** not `disableJwtPlugin`
  (`createJwtAccessToken`, `token.ts:73`: claims `sub, aud, azp=clientId, scope, sid, iss, iat, exp` +
  `customAccessTokenClaims`, signed via `signJWT` on the jwt plugin's keys); else **opaque**
  (`createOpaqueAccessToken`, `token.ts:239`: `generateRandomString(32,"A-Z","a-z")`, stored hashed in
  `oauthAccessToken` with scopes/expiry/refreshId).
- **Refresh token**: minted only when `user` + client allows `refresh_token` grant + `offline_access`
  scope present. Initial issuance = single insert; **rotation** = atomic CAS on the parent row
  (`incrementOne where id=parent AND revoked=null set revoked=now`, `token.ts:385`) — loser →
  `invalid_grant`; then insert the new row. Prefix + `formatRefreshToken.encrypt?` applied to the returned
  value only.
- **id_token** (`createIdToken`, `token.ts:127`): only when `user` + `openid` scope. Claims: normal user
  claims (per scope) + `auth_time`, `acr: "urn:mace:incommon:iap:bronze"`, `customIdTokenClaims`, then
  **pinned** `iss, sub` (pairwise-resolved), `aud: clientId`, `nonce`, `iat`, `exp` (default
  `idTokenExpiresIn` 36000s), `sid` (only if `enableEndSession`). Signed via jwt plugin (EdDSA) **or**
  HS256 with the client secret when `disableJwtPlugin` (public clients without a secret get no id_token).
- **Expiry**: access default `accessTokenExpiresIn` (3600s) / `m2mAccessTokenExpiresIn` (3600s);
  `scopeExpirations` picks the **earliest** matching scope expiry. `resource`/audience validated against
  `validAudiences ?? [baseURL]` (+ `${baseURL}/oauth2/userinfo` for openid) → `checkResource`,
  `token.ts:421`.
- `customTokenResponseFields` merges into the JSON envelope (cannot override standard fields).

### Schema — `oauthRefreshToken` (`schema.ts:144`) & `oauthAccessToken` (`schema.ts:218`)

`oauthRefreshToken`: `token`(string, req, unique), `clientId`(string, req, ref `oauthClient.clientId`,
index), `sessionId`(string, ref `session.id`, **onDelete set null**, index), `userId`(string, req, ref
`user.id`, index), `referenceId`(string), `expiresAt`(date), `createdAt`(date), `revoked`(**date**),
`authTime`(**date**), `scopes`(**string[]**, req). PK `id`.
`oauthAccessToken`: `token`(string, unique), `clientId`(string, req, ref, index), `sessionId`(string, ref
`session.id`, onDelete set null, index), `userId`(string, ref `user.id`, index), `referenceId`(string),
`refreshId`(string, ref `oauthRefreshToken.id`, index), `expiresAt`(date), `createdAt`(date),
`scopes`(**string[]**, req). PK `id`. (Comment `schema.ts:206`: access tokens are created at
issuance, destroyed at revoke, read at introspection — **never updated**.)

### Behaviors from tests (`token.test.ts`, 3099 LOC)

- Scope → token-shape matrix (openid → id_token; +offline_access → opaque access + refresh;
  +offline_access+resource → **JWT** access + id_token + refresh).
- **Concurrency**: "rejects concurrent redemption of the same authorization code"; "rejects concurrent
  rotation of the same refresh token" (exactly one winner); "concurrent revoke + rotate: exactly one
  wins" — all rest on `consume_one`/`increment_one` CAS.
- Replay: revoked-refresh reuse → family teardown + reject.
- Refresh preserves `auth_time` (OIDC 12.2), allows same-or-lesser scopes, never more; still issues
  refresh after dropping offline_access scope from the request; can't widen.
- `customIdTokenClaims` can override `acr`/`auth_time` but **cannot** override pinned security claims
  (`iss`/`sub`/`aud`/`iat`/`exp`); custom fields can't override standard OAuth response fields.
- Loopback redirect: `127.0.0.1`/`[::1]` different ports succeed, different path rejected, non-loopback
  different ports rejected.
- Grant gating: `client_credentials` rejected for an auth-code-only client; auth-code client with
  `offline_access` still gets refresh; `/authorize` rejected for a client not registered for auth_code.

---

## Area 5 — Introspection (RFC 7662)

`POST /oauth2/introspect` (`oauth.ts:886`, impl `introspect.ts:407`), form-encoded. Requires `client_id`
**and** `client_secret` (Basic or body). Validates client credentials, then tries the token as (in order,
honoring `token_type_hint`): **JWT access** → **opaque access** → **refresh**. Returns RFC 7662 shape
(`{active, scope, client_id, sub, sid, exp, iat, iss, …}`) or `{active:false}`.

Security gates:
- **JWT access** (`validateJwtAccessToken`, `introspect.ts:38`): verify signature/issuer/audience against
  the jwt-plugin JWKS. **Require `azp`** and a matching, enabled client — a plain session JWT from the
  jwt plugin's `/token` (same keys/issuer/audience) must **not** be reported active (test: "rejects a JWT
  plugin session token presented as an access token"). `JWTExpired`/`JWTInvalid` → `active:false`.
- **Opaque access** (`validateOpaqueAccessToken`): find by hashed token; expired/disabled-client/
  client-mismatch → `active:false`; attach custom claims + session liveness.
- **Refresh** (`validateRefreshToken`): client match, unexpired, not revoked.
- `sid` cleared if the session no longer exists / is expired. Pairwise `sub` resolved at the presentation
  layer (`resolveIntrospectionSub`, `introspect.ts:391`). "reads the signing keys once across repeated
  jwt introspections" (JWKS cache keyed on the plugin instance).

---

## Area 6 — Revocation (RFC 7009)

`POST /oauth2/revoke` (`oauth.ts:1027`, impl `revoke.ts:248`), form-encoded. Requires `client_id`
(secret via `validateClientCredentials`). Tries JWT access (no-op — nothing stored) → opaque access
(**delete** the row, `revoke.ts:127`) → refresh. Refresh revoke (`revoke.ts:141`): if already `revoked`
→ family teardown; else atomic CAS `set revoked=now where revoked=null`, loser → family teardown; then
`deleteMany` access tokens with that `refreshId`. Returns empty/`null` on success (BAD_REQUEST swallowed
to `null` per RFC 7009 — revoke is idempotent).

---

## Area 7 — UserInfo (OIDC)

`GET|POST /oauth2/userinfo` (`oauth.ts:1112`, impl `userinfo.ts:36`). Bearer token in `Authorization`
header → `validateAccessToken` (shared with introspect). Requires `openid` scope (else `invalid_scope`)
and a `sub`. `userNormalClaims` (`userinfo.ts:13`): `sub` + (profile → `name`, `picture`(=user.image),
`given_name`, `family_name` split from `user.name`) + (email → `email`, `email_verified`). Pairwise `sub`
resolved when `pairwiseSecret` + client configured. `customUserInfoClaims` merged. Tests assert
consistent `sub` between id_token and userinfo, scoped claim subsets, POST-with-bearer, and header-only
`auth.api` calls.

---

## Area 8 — RP-Initiated Logout + pairwise + consent CRUD

### `/oauth2/end-session` (OIDC RP-Initiated Logout, `logout.ts:17`)

`GET`, query `{id_token_hint (required), client_id?, post_logout_redirect_uri?, state?}`. Resolve client
from `client_id` or `id_token_hint.aud`; client must exist, be enabled, and have `enableEndSession`.
Verify the id_token (jose JWKS, or HS256 client-secret when `disableJwtPlugin`); check `iss` and `aud`.
Delete the session named by the id_token's `sid` (`internalAdapter.deleteSession`). Redirect to
`post_logout_redirect_uri` (must be exact-match a registered `postLogoutRedirectUris`) with `state`.
Tests: rejects clients without `enable_end_session`; DCR cannot self-register `enable_end_session`.

### Pairwise subject identifiers (`utils/index.ts:564-609`)

`subject_type:"pairwise"` + `pairwiseSecret` (≥32 chars, init guard) → `sub =
makeSignature("${sectorHost}.${userId}", pairwiseSecret)` where sector = host of the first redirect_uri.
Public clients / no secret → real `user.id`. Applied consistently across id_token, userinfo, introspection
sub; **JWT access-token `sub` stays real `user.id`** (`pairwise.test.ts`). Determinism per client,
unlinkability across clients on different hosts.

### Consent CRUD (`oauthConsent/`)

| method | path | body/query | notes |
|---|---|---|---|
| GET | `/oauth2/get-consent` | `{id}` | owner-only (`consent.userId === session.user.id`) |
| GET | `/oauth2/get-consents` | — | all for the session user |
| POST | `/oauth2/update-consent` | `{id, update:{scopes:[]}}` | scopes must be ⊆ client's allowed scopes |
| POST | `/oauth2/delete-consent` | `{id}` | owner-only |

All `sessionMiddleware`. Tests: reject updates to scopes not granted to the client; reject cross-user
consent access.

---

## Config surface (`OAuthOptions`, `types/index.ts:36`) with defaults

- **Scopes/audience**: `scopes=["openid","profile","email","offline_access"]`, `validAudiences=[baseURL]`,
  `advertisedMetadata{scopes_supported?, claims_supported?}`.
- **Expiries (s)**: `codeExpiresIn=600`, `accessTokenExpiresIn=3600`, `m2mAccessTokenExpiresIn=3600`,
  `idTokenExpiresIn=36000`, `refreshTokenExpiresIn=2592000`, `scopeExpirations?` (per-scope earliest).
- **Registration**: `allowDynamicClientRegistration=false`, `allowUnauthenticatedClientRegistration=false`,
  `clientRegistrationDefaultScopes?`, `clientRegistrationAllowedScopes?`,
  `clientRegistrationClientSecretExpiration?`.
- **Grants**: `grantTypes=["authorization_code","client_credentials","refresh_token"]` (init guard:
  refresh_token requires authorization_code, `oauth.ts:147`), `clientCredentialGrantDefaultScopes?`.
- **Pages (required)**: `loginPage`, `consentPage`; optional `signup{page?, shouldRedirect?}`,
  `selectAccount{page?, shouldRedirect}`, `postLogin{page, consentReferenceId, shouldRedirect}`.
- **Storage**: `storeClientSecret` (default hashed/encrypted per JWT), `storeTokens="hashed"`,
  `formatRefreshToken{encrypt,decrypt}?`, `prefix{opaqueAccessToken?, refreshToken?, clientSecret?}`,
  `generateClientId?/generateClientSecret?/generateOpaqueAccessToken?/generateRefreshToken?`.
- **Claims/fields**: `customUserInfoClaims?`, `customIdTokenClaims?`, `customAccessTokenClaims?`,
  `customTokenResponseFields?`.
- **Ownership/RBAC**: `clientReference?(context)→referenceId`, `clientPrivileges?(context)→bool`,
  `cachedTrustedClients?: Set<string>`.
- **OIDC extras**: `pairwiseSecret?` (≥32), `requestUriResolver?` (PAR), `allowPublicClientPrelogin?`,
  `disableJwtPlugin=false`, `silenceWarnings{oauthAuthServerConfig?, openidConfig?}`, `schema?`.
- **Rate limits** (`rateLimit?`, each `{window,max}|false`): `token{60,20}`, `authorize{60,30}`,
  `introspect{60,100}`, `revoke{60,30}`, `register{60,5}`, `userinfo{60,60}` — all **path-exact**
  matchers (`oauth.ts:1492`). Port: `RateLimitRule(window, max, path_matcher=lambda p: p=="/oauth2/…")`.

### Init guards (`oauth.ts:71-178`, `425`)

- `clientRegistrationAllowedScopes`/`advertisedMetadata.scopes_supported` must be within `scopes`.
- `pairwiseSecret` ≥32 chars. `refresh_token` grant requires `authorization_code`.
- `disableJwtPlugin` + hashed secret → throw; JWT-enabled + encrypted secret → throw.
- `secondaryStorage` requires `session.storeSessionInDatabase: true` (`oauth.ts:428`).
- JWT-enabled: warns (unless silenced) to ensure the well-known endpoints exist at the issuer path.

---

## Error responses — envelope reconciliation (flag every spot)

The provider emits **OAuth-shaped** `{error, error_description}` (sometimes `+error_uri`, `+state`), NOT
the port's `APIError` `{code, message}` envelope. This affects **every** endpoint:

- **Token / introspect / revoke / register / userinfo**: TS `throw new APIError("BAD_REQUEST", {error,
  error_description})` where the 2nd arg **is the JSON body**. The port's `APIError(status, code, message)`
  cannot carry this. → Use the **device-authorization precedent**: a per-plugin `_oauth_error(status,
  error, description, *, error_uri=None, headers=None)` returning `AuthResponse(status, body={"error",
  "error_description"[, "error_uri"]})`. Error codes are OAuth literals: `invalid_request`,
  `invalid_client`, `invalid_grant`, `invalid_scope`, `unauthorized_client`, `unsupported_grant_type`,
  `access_denied`, `invalid_token`, `server_error`.
- **Authorize**: errors are **redirects**, not JSON. `formatErrorURL(url, error, description, state?,
  iss?)` (`authorize.ts:45`) builds `redirect_uri?error&error_description&state&iss`; pre-redirect-URI-
  validation errors go to `${baseURL}/error` (or `onAPIError.errorURL`). OIDC prompt errors use
  `login_required`/`consent_required`/`account_selection_required`/`interaction_required`. `handleRedirect`
  (`authorize.ts:61`) returns `{redirect:true, url}` for fetch/JSON requests (port `AuthResponse(body=…)`)
  or throws a real redirect (port `AuthResponse(redirect_to=…)`).
- **UserInfo / MCP 401**: `WWW-Authenticate: Bearer …` header on 401 (`mcp.ts:57`). → `_oauth_error` must
  accept extra headers.
- **Consent/continue/consent-CRUD/client-CRUD**: `access_denied` (consent deny) and `not_found`/
  `invalid_client` errors use the same OAuth body; ownership failures are bare `UNAUTHORIZED` (these can
  stay port-`APIError` since they carry no OAuth `error` field — but check each: `getClientEndpoint`
  throws bare `APIError("UNAUTHORIZED")`, while `NOT_FOUND` carries `{error:"not_found",
  error_description}`).

**Internal `error_codes` table**: the plugin has no `$ERROR_CODES` export analogous to admin/2FA — the
OAuth wire codes above are the contract. Surface a small `error_codes` ClassVar only if desired for
`auth.error_codes` parity (optional).

---

## Security properties asserted by tests (must-preserve checklist)

1. **redirect_uri exact-match** + RFC 8252 loopback-IP port-agnostic match (IP literals only, not DNS
   localhost); different path always rejected. (`authorize.test.ts`, `token.test.ts`)
2. **PKCE downgrade protection**: PKCE-in-auth-XOR-token both rejected; required-for-public /
   offline_access / requirePKCE-default-true; mismatched challenge rejected. (`pkce-optional.test.ts`)
3. **Authorization code single-use under concurrency**: `consumeVerificationValue` atomic; concurrent
   redemption → one winner. (`token.test.ts`)
4. **Refresh rotation single-use + replay family teardown** (RFC 9700 §4.14): CAS on `revoked=null`;
   revoked reuse tears down the whole `(client,user)` family; concurrent rotate/revoke → one winner.
5. **Consent CSRF / integrity**: authorization query is signed (`makeSignature`), canonicalized, tamper-
   and duplicate-`sig`-rejected; `login` prompt satisfied only when `session.createdAt >= ba_iat`;
   `postLogin` cleared only via server-minted session-bound `ba_pl` marker (never client-asserted).
6. **Scope narrowing**: consent/refresh can only equal-or-narrow, never widen; client_credentials cannot
   request OIDC scopes.
7. **Token-type confusion**: introspect requires `azp` + matching enabled client (a jwt-plugin session
   token is not an OAuth access token); wrong `token_type_hint` → correct rejection.
8. **Pairwise unlinkability**: distinct `sub` per RP host, deterministic per client, real id kept in JWT
   access `sub`; pairwise rejected without a ≥32-char secret; multi-host redirect_uris rejected.
9. **Client-secret storage**: hashed by default, constant-time verify, prefix-stripped; encrypted only
   when JWT disabled; `client_secret` never returned by any CRUD.
10. **clientPrivileges gate** on every client mutation (create/read/list/update/delete/rotate); trusted
    clients immutable via CRUD; DCR public-only when unauthenticated.
11. **RP logout**: `enable_end_session` required and not DCR-registerable; `post_logout_redirect_uri`
    exact-match; id_token iss/aud verified.

---

## Gap items — ordered (dependencies first)

Sizing: **S** ≈ hours, **M** ≈ a day, **L** ≈ multi-day. Most core primitives already exist (see *Python
current state*), so items 1–6 are small enabling helpers; the bulk is plugin-local logic (7–20).

**Enabling helpers (small, shared):**
1. **OAuth-error helper** — per-plugin `_oauth_error(status, error, description, *, error_uri?, headers?)`
   → `AuthResponse` + `format_error_url(url, error, desc, state?, iss?)` + `handle_redirect(ctx, uri)`
   (fetch/JSON vs real redirect). Precedent: `device_authorization._oauth_error`. **S**
2. **jwt-plugin lookup** — `get_jwt_plugin(auth)` = `next((p for p in auth.plugins if p.id=="jwt"),
   None)`; raise if absent and not `disableJwtPlugin`. One-liner. **S**
3. **`make_signature(value, secret)`** — public wrapper over the existing padded-base64 HMAC (`crypto._signature`,
   arg-order flip) + **signed-query codec** (`canonicalize`, `set/get_signed_param_names` with
   `ba_param`/`ba_iat`/`ba_pl`, `build_signed_oauth_query`, `verify_oauth_query_params`). **S–M**
4. **`SafeUrl` scheme policy** — port TS `@better-auth/core/utils/redirect-uri` `SafeUrlSchema` (reject
   `javascript:`/`data:` etc. on redirect/post_logout URIs). Check if `origin.py`/`oauth/machinery.py`
   already has an equivalent; likely a small addition. **S**
5. **Server-side JWT-access-token verify** — `verify_jws_access_token(token, jwks, {audience, issuer})`
   returning payload with OAuth semantics (expired→inactive, `azp` required, client match), distinct from
   `jwt.verify_jwt` (too strict: requires sub+aud, single iss) and `oauth/verify.py` (remote/client-side).
   Reuse PyJWT + the jwt plugin's `_jwks_body()`/local keys; add a small instance-keyed cache. **M**
6. **`constant_time_equal`** public export (have `hmac.compare_digest` + private `_constant_time_equal`)
   + `basic_to_client_credentials` (base64 `id:secret` decode). **S**

**Plugin areas (Phase-grouped below):**
7. **Client schema + `oauthToSchema`/`schemaToOAuth`** (4 tables via `Field`; wire↔DB mapping, metadata
   JSON collapse). **M**
8. **Client secret storage** (hashed via `default_key_hasher`, encrypted via `symmetric_encrypt`, custom
   objects, prefix, constant-time verify) + `generate_client_id/secret`. **M**
9. **Client CRUD + DCR** — 10 CRUD endpoints + `/oauth2/register`, `assertClientPrivileges` gate,
   `checkOAuthClient` validation, ownership checks, trusted-client immutability, `clientReference`. **L**
10. **Discovery metadata** — `authServerMetadata`/`oidcServerMetadata`, `metadataResponse` cache headers,
    `on_request` well-known router (issuer-path + RFC 8414 aliases, GET/HEAD), 2 SERVER_ONLY endpoints,
    `jwks_uri` wired to the jwt plugin. **M**
11. **Authorization endpoint** — redirect_uri match (+loopback), scope validation, PKCE gate,
    prompt/select/signup/postLogin gates, consent lookup, code minting into the verification store, PAR
    resolver. **L**
12. **Signed-query resume** — before-hook (verify+stash `oauth_query`), after-hook (re-drive authorize on
    login), consent/continue re-entry, `login`/`postLogin` marker checks. **M** (depends on #3)
13. **Consent + continue endpoints** + `oauthConsent` upsert + consent CRUD (4 endpoints). **M**
14. **Token endpoint — authorization_code grant** — single-use redemption, client validation, PKCE
    consistency, user/session load, `createUserTokens`. **L**
15. **Token minting** — JWT vs opaque access token, id_token (EdDSA via jwt plugin; HS256 via secret when
    JWT disabled), scope/resource/audience, scopeExpirations, custom claims/fields. **L** (depends on #5)
16. **Refresh grant + rotation** — decode, guards, scope narrowing, CAS rotation, `invalidateRefreshFamily`.
    **M** (depends on #14)
17. **client_credentials grant** — M2M, OIDC-scope rejection, default scopes. **S** (depends on #14)
18. **Introspection** — JWT/opaque/refresh validation, azp gate, session liveness, pairwise sub, token-type
    confusion protection. **M** (depends on #5, #15)
19. **Revocation** — opaque delete, refresh CAS-revoke + family teardown, idempotent. **S** (depends on #16)
20. **UserInfo + RP-logout + pairwise** — bearer verify, normal claims, custom claims; end-session
    (id_token verify, session delete, post-logout redirect); pairwise sub resolver. **M** (depends on #5, #15)

**Total: 20 gap items** (6 enabling helpers + 14 plugin-area items). Client-side `mcp.ts`/`client.ts`/
`client-resource.ts` are excluded (see Open questions).

---

## Recommended sub-phasing (like organization's 4 phases)

**Phase A — Foundations: clients + discovery + JWKS wiring.** Items 1–4, 6, 7–10.
Delivers the schema, client storage/CRUD/DCR, the `clientPrivileges` gate, discovery documents, and the
jwt-plugin lookup. Independently testable (register a client → fetch it → read discovery/JWKS). Depends
only on existing core seams.
*Deps:* `jwt` plugin installed (for `jwks_uri`/alg advertising); adapter `string[]`/`json` columns
(present); `default_key_hasher`/`symmetric_encrypt` (present).

**Phase B — Authorization + consent.** Items 5(partial), 11–13.
The `/oauth2/authorize` flow, signed-query resume, consent/continue, consent storage + CRUD. Mints
authorization codes into the verification store.
*Deps:* Phase A (client lookup, issuer/discovery); `consume_verification_value` (present); signed-query
codec (#3); `code_challenge` S256 (present).

**Phase C — Token grants + introspection.** Items 5, 14–18.
The three grants, JWT/opaque access tokens, id_token minting, refresh rotation/family invalidation, and
introspection. This is the crypto- and concurrency-heavy core.
*Deps:* Phase B (authorization codes to redeem); server-side JWT verify helper (#5); jwt plugin
`sign_jwt` (present, respects payload claims); `increment_one` CAS (present).

**Phase D — UserInfo + revocation + RP-logout + extras.** Items 19–20.
Userinfo, revocation, end-session logout, pairwise sub finalization. Mostly reuses Phase C's verify/mint
helpers.
*Deps:* Phase C (shared access-token verify + token models).

Rationale for this order (vs a naive endpoint order): A front-loads the DB schema + client model that
literally everything references; B's authorization codes are C's input; introspection (C) and userinfo/
revoke (D) share one JWT-access-token verify helper (#5), so building it once in C and reusing it in D
avoids duplication. Pairwise touches id_token (C), userinfo, and introspection — land the resolver in C,
finalize consistency tests in D.

---

## Open questions (with defaults)

1. **`disableJwtPlugin` / non-EdDSA algs — support now or defer?** The provider's JWT-disabled path signs
   id tokens with **HS256 using the client secret** (`token.ts:180`) and stores client secrets
   **encrypted** (needs `symmetric_encrypt` with a versioned `secretConfig`, which the port lacks). The
   JWT-enabled path is **EdDSA-only** in the port's jwt plugin (ES256/ES512/PS256/RS256 raise
   `NotImplementedError`). **Default: ship EdDSA-only, JWT-enabled path first** (the documented default);
   HS256/`disableJwtPlugin` and non-EdDSA JWKS become a follow-up. Flag `disableJwtPlugin=true` and
   `keyPairConfig.alg != "EdDSA"` as unsupported at plugin init with a clear error.

2. **Versioned-secret (`secretConfig`) client-secret encryption.** TS `storeClientSecret: "encrypted"`
   uses `ctx.context.secretConfig` (key rotation). The port's `symmetric_encrypt` has only the plain-
   string-secret path (bare hex, no `$ba$` version envelope minting). Since encrypted storage is only the
   default when `disableJwtPlugin` (deferred per Q1), and the common path is `"hashed"` (fully supported
   via `default_key_hasher`), **default: support `"hashed"` + custom `{hash,verify}` now; treat
   `"encrypted"`/`secretConfig` as blocked on the same key-rotation work the jwt plugin already defers.**

3. **Client-side helpers (`mcpHandler`, `oauthProviderResourceClient`, `oauthProviderClient`) — in scope?**
   `mcp.ts`/`client.ts`/`client-resource.ts` are **client/resource-server** utilities (WWW-Authenticate
   challenge, remote/local access-token verify for protecting *your* APIs, a fetch plugin that appends
   the page query). They are not part of the authorization server proper. **Default: exclude from this
   port** (the Python port targets the server side; resource-server token verification is already covered
   by `oauth/verify.py` + the new server-side verify helper #5). Revisit if a Python MCP resource-server
   story is requested — `mcpHandler`'s WWW-Authenticate `resource_metadata` logic (`mcp.ts:57`) would be
   the one piece worth porting.

*(Secondary, lower-stakes items also worth confirming during build: (a) `requestUriResolver`/PAR is an
opt-in callback — port the plumbing but no built-in store; (b) `formatRefreshToken`/token `prefix` are
pass-through hooks, cheap to include; (c) the `on_request` well-known router must run before the auth
router's own 404 — verify the port's `on_request` phase fires early enough, matching TS `onRequest`.)*
