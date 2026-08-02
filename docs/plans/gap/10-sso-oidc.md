# SSO — OIDC federation half (`@better-auth/sso`) — Python parity spec

Scope: port the **OIDC federation half** of the `@better-auth/sso` package (pinned TS v1.6.23,
`packages/sso/`, ~12.4k src+test LOC). This is the *client/relying-party* side of SSO: an admin
registers an external OIDC identity provider (per-domain / per-organization), and users
`sign-in/sso` → get redirected to the IdP → return through `/sso/callback` → the plugin exchanges
the code, resolves the profile, and runs the shared find/register/link decision core to create a
session. Plus provider registration & CRUD, and DNS-TXT domain verification.

This is **not** the authorization-server side (that is `@better-auth/oauth-provider`, spec 07). SSO
here is a *federation client* and is the closest cousin of the already-ported `generic-oauth` plugin
(`plugins_ext/generic_oauth.py`) — the same authorize→callback→handleUserInfo shape, but with
DB-persisted providers, strict OIDC discovery with SSRF guards, per-provider field mapping, domain
verification, and organization auto-membership.

**SCOPE RULING (user-confirmed, not re-litigated): the SAML half is OUT.** Every `/sso/saml2/*`
endpoint, the samlify/XML-dsig machinery, and all SAML-only files are excluded — see the explicit
**"Excluded — SAML"** subsection below, which enumerates every excluded file/endpoint so the boundary
is auditable, and flags each SAML-only branch inside shared code that must be skipped.

Conventions:
- Endpoint paths are relative to the auth mount.
- Schema field names are the **exact camelCase** column names the plugin uses by default.
- TS `file.ts:NN` anchors are into `packages/sso/src/`.
- "port `X`" refers to an existing Python symbol in `better-auth-py/src/better_auth/`.

Cross-runtime DB compatibility is a hard requirement: a `ssoProvider` row written by the TS plugin
must be readable/usable by the Python port and vice-versa — identical table/column names (camelCase),
and **identical `oidcConfig` JSON shape with `clientSecret` stored in plaintext** (see Area 1).

---

## Python current state — foundations that already EXIST (do NOT re-spec as gaps)

The port already has a **full client-side OAuth/OIDC machinery** and a `generic-oauth` plugin that is
sso-OIDC's nearest relative. Verified present and reusable:

- **`generic-oauth` plugin** (`plugins_ext/generic_oauth.py`, 891 LOC): the reference implementation
  for exactly this shape — `POST /sign-in/oauth2` builds the authorize URL + CSRF state; `GET|POST
  /oauth2/callback/{id}` consumes state (verification row + signed cookie), exchanges the code,
  validates `iss` (RFC 9207), resolves the profile (id-token decode or bearer userinfo), then runs the
  shared decision core; state-carried `link` branch; `_redirect_error` (302 `?error=&error_description=`
  with `?`/`&` separator); `_with_state_cleared`. **The SSO callback is a near-clone of this file.**
- **Client `oauth/` package** (`oauth/`): `oauth/machinery.py` — `build_authorization_url(...,
  login_hint, code_verifier, scopes, response_type, additional_params)` (= TS `createAuthorizationURL`),
  `exchange_code(..., authentication="basic"|"post")` (= `validateAuthorizationCode`),
  `refresh_access_token`, `code_challenge` (PKCE S256), `oauth_fetch`/`OAuthFetchError`,
  `get_oauth2_tokens`. `oauth/verify.py` — `verify_id_token(http, token, jwks_uri, audience, issuers,
  ...)` with a module-level JWKS cache (= TS `validateToken`). `oauth/providers.py` — `ProviderConfig`
  (carries `provider_id`, `override_user_info_on_sign_in`, `disable_sign_up`,
  `disable_implicit_sign_up`, `authentication`).
- **The find/register/link decision core** (`oauth/flow.py`): `handle_oauth_user_info(ctx, provider,
  info, tokens, *, disable_sign_up)` → `(user_id, is_register)`, raising `OAuthLinkError`
  (`account_not_linked`/`signup_disabled`) on refusal — the exact tree TS calls `handleOAuthUserInfo`.
  Plus `_create_state(ctx, *, callback_url, error_url, new_user_url, link?, additional_data?, nonce?)`
  (writes verification row), `_state_cookie` (signed CSRF cookie), `_create_account`, `_token_fields`,
  `_resolve_trusted_providers`, `_apply_update_user_info_on_link`, `_override_user_info`. **NOTE the
  signature gap** below (trust flags) — this is the one shared-core change SSO needs.
- **Session/adapter** (`session.py`, `internal_adapter.py`, `adapters/base.py`): `create_session(auth,
  user_id, request, ctx=)` → `(session, cookies)`; `InternalAdapter.create_verification_value` /
  `find_verification_value` / `delete_verification_by_identifier`; `BaseAdapter.find_one` / `find_many`
  / `create` / `update` / `delete_many` / `transaction` with `Where(field, value, operator)`
  (`in`/`eq`); `ctx.internal.*` / `ctx.adapter.*`.
- **Plugin contract** (`plugins.py`): `Plugin` with `id`, `schema` (ClassVar via `schema.py` `Field`),
  `error_codes`, `init(auth)`, `routes()` → `[(method, path, handler)]`, `hooks()` (before/after with
  `matcher`/`handler`). `schema.py` `Field(type, required, unique, references, field_name, default)` —
  covers `string`/`boolean`/`json`; `Reference(model, field, on_delete)`.
- **Crypto** (`crypto.py`): `generate_random_string(size=32, alphabet=None)` whose **default alphabet
  is byte-identical to TS** (`a-z 0-9 A-Z -_`), so TS `generateRandomString(24)` → `generate_random_string(24)`
  directly (domain-verification token). `generate_id`.
- **Origin/trust** (`origin.py`): `is_trusted_origin(auth, request, url, *, allow_relative)` (async) and
  `auth.is_trusted_url(url)` (sync) — the port's `isTrustedOrigin` analogue for discovery/endpoint checks.
- **`organization` plugin, complete** (`plugins_ext/organization.py`, id `"organization"`): `member`
  model with fields `{organizationId, userId, role (default "member", comma-joined via `parse_roles`),
  createdAt}`; default roles `owner`/`admin`/`member`. SSO writes `member` rows **directly through the
  adapter** (exactly as TS does), no org-API call needed. Seams named precisely in Area 4.
- **`APIError`** (`types.py`): `APIError(status: int, code: str, message=None)` → renders `{code,
  message}`. SSO uses **HTTP-status-name strings** (`"BAD_REQUEST"`, `"CONFLICT"`, …); map to numeric.

Net: SSO-OIDC is ~70% assembling existing seams (generic-oauth callback shape + machinery + flow core
+ org member writes). The genuinely **new** pieces are: (1) the strict OIDC **discovery pipeline with
SSRF/private-host guards** (no port equivalent — hardest item), (2) **DNS-TXT domain verification** (no
DNS resolver in the port), (3) provider **schema + CRUD + sanitization**, (4) a small **`handle_oauth_user_info`
signature extension** for SSO's trust flags, and (5) a `has_plugin` helper.

---

## Package layout (what maps to what)

| TS file (`src/`) | LOC | OIDC-relevant purpose | Python home |
|---|---|---|---|
| `index.ts` | 311 | `sso()` factory, endpoint registration, `init` (skipOriginCheck — SAML-only, skip), before-hook `/sign-out` (SAML SLO, **skip**), after-hook `/callback/*` (org-by-domain, **keep**), `ssoProvider` schema | `plugins_ext/sso/__init__.py` (plugin class) |
| `routes/sso.ts` | 2452 | `signInSSO`, `handleOIDCCallback`, `callbackSSO`, `callbackSSOShared` (OIDC — **keep**); `spMetadata`/`callbackSSOSAML`/`acsEndpoint`/`sloEndpoint`/`initiateSLO`/SAML branches (**skip**) | `sso/routes.py` |
| `routes/providers.ts` | 707 | `listSSOProviders`, `getSSOProvider`, `updateSSOProvider`, `deleteSSOProvider`, `checkProviderAccess`, `sanitizeProvider`, `hasOrgAdminRole`, merge/identity-boundary | `sso/providers.py` |
| `routes/domain-verification.ts` | 230 | `requestDomainVerification`, `verifyDomain`, `getVerificationIdentifier` (DNS TXT) | `sso/domain_verification.py` |
| `routes/schemas.ts` | 97 | zod bodies for update (OIDC + SAML — port OIDC only) | folded into routes |
| `oidc/discovery.ts` | 702 | Strict discovery pipeline + SSRF/private-host guards + normalization | `sso/discovery.py` (**new core-ish**) |
| `oidc/types.ts` | 222 | `OIDCDiscoveryDocument`, `HydratedOIDCConfig`, `DiscoveryError`, `REQUIRED_DISCOVERY_FIELDS` | `sso/discovery.py` |
| `oidc/errors.ts` | 101 | `mapDiscoveryErrorToAPIError` (code→status) | `sso/discovery.py` |
| `linking/org-assignment.ts` | 177 | `assignOrganizationFromProvider`, `assignOrganizationByDomain` | `sso/org_assignment.py` |
| `linking/types.ts` | 11 | `NormalizedSSOProfile` | folded |
| `utils.ts` | 143 | `safeJsonParse`, `domainMatches`, `parseProviderEmailVerified`, `validateEmailDomain`, `parseProviderDomains`, `maskClientId` (+`parseCertificate`/`normalizePem` — SAML, skip) | `sso/utils.py` |
| `types.ts` | 437 | `OIDCConfig`, `OIDCMapping`, `SSOOptions` (+ SAML types, skip) | folded |
| `client.ts` | 31 | **client-side** helper — out of server scope | — |
| `constants.ts`, `saml*.ts`, `routes/saml-pipeline.ts`, `routes/helpers.ts`, `samlify.ts`, `saml-state.ts` | ~7.5k | **SAML — excluded** | — |

---

## Endpoints (OIDC — all IN)

| method | path | body/query | auth | notes |
|---|---|---|---|---|
| POST | `/sign-in/sso` | `{email?, organizationSlug?, providerId?, domain?, callbackURL(req), errorCallbackURL?, newUserCallbackURL?, scopes?, loginHint?, requestSignUp?, providerType?}` | none | resolve provider → build authorize URL → `{url, redirect:true}`. `sso.ts:1002` |
| GET | `/sso/callback/:providerId` | `{code?, state, error?, error_description?}` | none | per-provider OIDC callback. `sso.ts:1835` → `handleOIDCCallback` `sso.ts:1449` |
| GET | `/sso/callback` | same, `providerId` read from `state.ssoProviderId` | none | **shared** callback (used when `options.redirectURI` set). `sso.ts:1850` |
| POST | `/sso/register` | `ssoProviderBodySchema` (see below) | **session** | register an OIDC provider (runs discovery, persists). `sso.ts:402` |
| GET | `/sso/providers` | — | **session** | list caller-accessible providers (sanitized). `providers.ts:249` |
| GET | `/sso/get-provider` | `{providerId}` | **session** | one provider, sanitized (masked clientId, no secret). `providers.ts:374` |
| POST | `/sso/update-provider` | `{providerId, issuer?, domain?, oidcConfig?, samlConfig?}` | **session** | partial update; identity-boundary guard; domain change resets `domainVerified`. `providers.ts:481` |
| POST | `/sso/delete-provider` | `{providerId}` | **session** | tx: delete linked `account` rows + provider. `providers.ts:658` |
| POST | `/sso/request-domain-verification` | `{providerId}` | **session** | only registered when `domainVerification.enabled`. Returns active-or-new token, 201. `domain-verification.ts:28` |
| POST | `/sso/verify-domain` | `{providerId}` | **session** | only when `domainVerification.enabled`. DNS-TXT check → set `domainVerified`, 204. `domain-verification.ts:96` |

`/sign-in/sso` register-body OIDC shape (`ssoProviderBodySchema`, `sso.ts:194`): `providerId`,
`issuer` (must be a valid URL), `domain` (comma-separated multi-domain allowed), `overrideUserInfo?`
(default false), `organizationId?`, and `oidcConfig{ clientId, clientSecret, authorizationEndpoint?,
tokenEndpoint?, userInfoEndpoint?, tokenEndpointAuthentication? ("client_secret_post"|"client_secret_basic"),
jwksEndpoint?, discoveryEndpoint?, skipDiscovery?, scopes?, pkce? (default true), mapping? }`.

### Excluded — SAML (auditable boundary)

**Endpoints NOT ported** (all under `/sso/saml2/*`, plus SAML-only helpers):
- `GET /sso/saml2/sp/metadata` — `spMetadata` (`sso.ts:111`)
- `GET|POST /sso/saml2/callback/:providerId` — `callbackSSOSAML` (`sso.ts:1893`)
- `POST /sso/saml2/sp/acs/:providerId` — `acsEndpoint` (`sso.ts:1984`)
- `GET|POST /sso/saml2/sp/slo/:providerId` — `sloEndpoint` (`sso.ts:2075`)
- `initiateSLO` (SP-initiated Single Logout, tail of `sso.ts`)

**Files NOT ported:** `saml/` (algorithms, assertions, error-codes, index, parser, response-binding,
timestamp), `saml-state.ts`, `samlify.ts`, `routes/saml-pipeline.ts`, `routes/helpers.ts` (SAML SP/IdP
builders `createIdP`/`createSP`/`createSAMLPostForm`/`findSAMLProvider`), `constants.ts` (all constants
are SAML: `*_KEY_PREFIX`, `*_TTL_MS`, size limits, status codes). `utils.ts`
`parseCertificate`/`normalizePem` (SAML cert/PEM) — skip; keep the rest of `utils.ts`.

**SAML-only branches inside shared code — must be SKIPPED, but keep the surrounding OIDC path:**
- `index.ts` `sso()`: registers both OIDC + SAML endpoints — register OIDC only.
- `index.ts` `init()` (`:193`): appends `SAML_SKIP_ORIGIN_CHECK_PATHS` to `skipOriginCheck` — **skip entirely** (OIDC callbacks are same-origin redirects, no IdP POST).
- `index.ts` before-hook on `/sign-out` (`:207`): SAML SLO session cleanup — **skip**.
- `index.ts` after-hook on `/callback/*` (`:236`): `assignOrganizationByDomain` — **KEEP** (org-by-domain for non-SSO logins, OIDC-relevant).
- `index.ts` schema `ssoProvider.samlConfig` column (`:274`) and `fields.samlConfig` — **KEEP the nullable column** for cross-runtime DB compat, but never write or read it in the OIDC port.
- `registerSSOProvider` (`sso.ts:402`): the `body.samlConfig` validation/build branch (`:820-884`) — skip; keep the `oidcConfig` branch + reserved-id/SCIM/dupe guards. `providerType:"saml"` → reject with a "SAML not supported in this build" `BAD_REQUEST` (or 404) rather than silently branch.
- `signInSSO` (`sso.ts:1002`): the `provider.samlConfig` branch (`:1292-1426`) — skip; keep the `oidcConfig` branch (`:1242-1291`).
- `updateSSOProvider` (`providers.ts:481`): `mergeSAMLConfig`/`samlConfig` branch + `samlIdentityBoundaryChanged` — skip; keep `oidcConfig` merge + `oidcIdentityBoundaryChanged` + issuer/domain updates + identity-boundary guard.
- `sanitizeProvider` (`providers.ts:177`): the `samlConfig`/`spMetadataUrl`/cert branch — skip (return `type:"oidc"`, `oidcConfig` sanitized only).

---

## Schema — `ssoProvider` (exact camelCase, `index.ts:260`)

`modelName` default `"ssoProvider"` (override via `options.modelName`); every field name overridable via
`options.fields.*`.

| column | type | required | notes |
|---|---|---|---|
| `id` | string | auto | PK |
| `issuer` | string | **yes** | IdP issuer URL |
| `oidcConfig` | string (JSON) | no | serialized `OIDCConfig` — see shape below |
| `samlConfig` | string (JSON) | no | **keep nullable for DB compat; never used in OIDC port** |
| `userId` | string | no | ref `user.id` (the registrant) |
| `providerId` | string | **yes, unique** | the account-linking provider slug |
| `organizationId` | string | no | links provider to an org |
| `domain` | string | **yes** | one or comma-separated email domains |
| `domainVerified` | boolean | no | **only added to schema when `domainVerification.enabled`** (`index.ts:303`) |

No `createdAt`/`updatedAt` are declared by the plugin schema (adapter-managed if present).

### `oidcConfig` JSON shape — field-by-field (`buildOIDCConfig`, `sso.ts:769`)

Persisted as `JSON.stringify(...)` into the `oidcConfig` TEXT column. **This exact shape and encoding
is a cross-runtime contract** — the port must write/read identically.

```jsonc
{
  "issuer":                       "https://idp.example.com",      // = body.issuer (or hydrated issuer)
  "clientId":                     "abc123",
  "clientSecret":                 "s3cr3t",     // ⚠️ STORED IN PLAINTEXT — see below
  "authorizationEndpoint":        "https://.../authorize",        // hydrated by discovery, or body (skipDiscovery)
  "tokenEndpoint":                "https://.../token",
  "tokenEndpointAuthentication":  "client_secret_basic",          // skipDiscovery default "client_secret_basic"
  "jwksEndpoint":                 "https://.../jwks",
  "pkce":                         true,                           // = body.oidcConfig.pkce (default true)
  "discoveryEndpoint":            "https://.../.well-known/openid-configuration",
  "mapping":                      { "id": "sub", "email": "email", "name": "name", ... },  // optional
  "scopes":                       ["openid","email","profile","offline_access"],           // optional
  "userInfoEndpoint":             "https://.../userinfo",         // optional
  "overrideUserInfo":             false     // = body.overrideUserInfo || options.defaultOverrideUserInfo || false
}
```

**`clientSecret` is stored as PLAINTEXT inside this JSON — not encrypted, not hashed** (`sso.ts:776`,
`:801`). This is deliberate in TS: the secret is needed in cleartext at every token exchange, and the
plugin never has a symmetric key envelope for it. It is only ever *masked on read*: `sanitizeProvider`
returns `clientIdLastFour = maskClientId(clientId)` (last 4, `utils.ts:138`) and **omits `clientSecret`
entirely** (`providers.ts:213`). → The Python port must store `clientSecret` the same way (plaintext in
the JSON) so a TS-written row is usable and a Python-written row is usable by TS. Do **not** add
encryption here (it would break cross-runtime read). Flag prominently in the port docstring.

When `skipDiscovery:true`, the stored config uses the body's endpoints verbatim +
`discoveryEndpoint = body.discoveryEndpoint || `${issuer}/.well-known/openid-configuration``. When
discovery ran, the hydrated endpoints are stored (existing body values still take precedence per
`discoverOIDCConfig`). Legacy/partial rows are lazily re-hydrated at runtime via `ensureRuntimeDiscovery`
(`discovery.ts:678`) — if `tokenEndpoint`/`jwksEndpoint`/`authorizationEndpoint` are missing, discovery
runs again on sign-in/callback.

---

## Provider resolution — exact precedence

### On `/sign-in/sso` (`sso.ts:1090`)

`domain = body.domain || email.split("@")[1]`; `orgId` resolved from `organizationSlug` via
`organization.slug → organization.id` lookup. Guard: at least one of `email` / `organizationSlug` /
`domain` / `providerId` must be present (unless `defaultSSO` configured); then also require
`providerId || orgId || domain`.

Resolution order (first match wins):
1. **`options.defaultSSO[]` first** (in-memory, takes precedence over DB, `sso.ts:1125`): if `providerId`
   given → match `defaultProvider.providerId === providerId`; else match
   `domainMatches(domain, defaultProvider.domain)`.
2. **DB by `providerId` XOR `organizationId`** (`sso.ts:1177`): `findOne where field = (providerId ?
   "providerId" : "organizationId"), value = providerId || orgId`. → **`providerId` beats `orgId`.**
3. **DB by `domain`** (only if neither providerId nor orgId, `sso.ts:1190`): exact `findOne where domain
   = domain` (fast path); on miss, `findMany` all providers + `domainMatches(domain, p.domain)`
   (comma-separated multi-domain scan).

**Net precedence: `defaultSSO` > `providerId` > `organizationId (from slug)` > `domain` (exact) >
`domain` (comma-scan).**

### On callback (`handleOIDCCallback`, `sso.ts:1449`)

`providerId` comes from the URL path (`/sso/callback/:providerId`) OR from `state.ssoProviderId` (shared
`/sso/callback`). Resolve: `defaultSSO` by `providerId` first (`:1474`), else DB `findOne where providerId`
(`:1490`). No domain/org fallback here — the callback always knows its `providerId`.

`domainMatches(searchDomain, domainList)` (`utils.ts:38`): domain matches if it `=== domain` or
`endsWith("." + domain)` for any comma-listed, `parseProviderDomains`-normalized entry (hostname-parsed
via `tldts`, lowercased).

---

## The OIDC callback — decision tree vs the port's existing oauth path

`handleOIDCCallback` (`sso.ts:1449`) is structurally the port's `generic_oauth._callback`. Steps, with
reuse vs plugin-local called out:

1. **Parse state / errors** — `parseState(ctx)` (state row + signed cookie). No state → redirect
   `${errorURL||baseURL/error}?error=invalid_state`. `code` missing or `error` set → redirect
   `${errorURL||callbackURL}?error=&error_description=`. → **Reuse** the port's state-consume block from
   `oauth/flow.oauth_callback` / `generic_oauth._callback` (verification row + `unsign_value` cookie
   check + `skip_state_cookie_check`). Shared callback reads `providerId = stateData.ssoProviderId`
   (`sso.ts:1875`) — the port stores it via `_create_state(additional_data={"ssoProviderId": id})`, so
   read it back from `data["additionalData"]["ssoProviderId"]` (or hoist to top-level for symmetry).
2. **Resolve provider** (defaultSSO → DB, above) — **plugin-local**.
3. **Domain-verification gate** (`sso.ts:1518`): if `domainVerification.enabled` and provider not
   `domainVerified` → `APIError("UNAUTHORIZED", "Provider domain has not been verified")`. **plugin-local**.
4. **Runtime discovery** (`ensureRuntimeDiscovery`, `sso.ts:1537`): hydrate missing endpoints; on
   `DiscoveryError` → redirect `?error=discovery_failed&error_description=`. Default scopes
   `["openid","email","profile","offline_access"]` if unset. Require `tokenEndpoint`. → **plugin-local**
   (uses the new discovery pipeline). Distinct from generic-oauth's loose `_discover`.
5. **Token exchange** (`validateAuthorizationCode`, `sso.ts:1570`): `code`, `codeVerifier` (only if
   `config.pkce`), `redirectURI = getOIDCRedirectURI(...)`, `clientId`/`clientSecret`, `tokenEndpoint`,
   `authentication = tokenEndpointAuthentication === "client_secret_post" ? "post" : "basic"`. →
   **Reuse `oauth/machinery.exchange_code`** verbatim (same params). Failure → redirect
   `?error=invalid_provider&error_description=...`.
6. **Resolve profile** (`sso.ts:1605`):
   - If `config.userInfoEndpoint`: bearer-fetch it; map raw claims through `config.mapping` with
     defaults `id←sub`, `email←email`, `emailVerified←email_verified`, `name←name`, `image←picture`,
     plus `mapping.extraFields`.
   - Else if `tokenResponse.idToken`: require `jwksEndpoint`; **verify** the id-token via
     `validateToken(idToken, jwksEndpoint, {audience: clientId, issuer: provider.issuer})`. → **Reuse
     `oauth/verify.verify_id_token`** (same audience/issuer semantics). Then map `idToken` claims via
     `config.mapping`. (Note: the userinfo path does *not* verify a signature — the token came over TLS;
     the id-token path *does* verify against JWKS. Mirror both exactly.)
   - Else → redirect `user_info_endpoint_not_found`.
   - `emailVerified` is `parseProviderEmailVerified(...)` **only when `options.trustEmailVerified`**, else
     forced `false` (`sso.ts:1642`). Require `userInfo.email && userInfo.id`.
   → **plugin-local** (mapping is per-provider; generic-oauth uses a fixed mapping).
7. **Compute `isTrustedProvider`** (`sso.ts:1716`): `provider.domainVerified === true &&
   validateEmailDomain(userInfo.email, provider.domain)`. → **plugin-local**.
8. **Find/register/link** (`handleOAuthUserInfo`, `sso.ts:1723`): passes
   `disableSignUp = disableImplicitSignUp && !requestSignUp`, `overrideUserInfo = config.overrideUserInfo`,
   `isTrustedProvider`, and **`trustProviderByName: false`** (SSO NEVER inherits the global
   `trustedProviders` list by name — trust is domain-ownership only). → **Reuse the port's
   `handle_oauth_user_info`, but it needs a signature extension** (see gap #4): the port's helper today
   takes only `disable_sign_up=` and consults `provider.override_user_info_on_sign_in` +
   `_resolve_trusted_providers(ctx)`. SSO needs call-time `is_trusted_provider: bool | None`,
   `trust_provider_by_name: bool = True`, `override_user_info: bool = <provider flag>`. Extend the shared
   helper (defaults preserve generic-oauth/social behavior) rather than fork. On `OAuthLinkError`/`APIError`
   → redirect with the code (same pattern as `generic_oauth._callback`). **Divergence to remember:** TS
   `handleOAuthUserInfo` *creates the session itself* (returns `{session,user}`); the port's helper returns
   `(user_id, is_register)` and the caller calls `create_session` — follow the port convention.
9. **`provisionUser`** (`sso.ts:1771`): if `options.provisionUser` and `(isRegister ||
   provisionUserOnEveryLogin)` → call with `{user, userInfo, token, provider}`. → **plugin-local hook.**
10. **`assignOrganizationFromProvider`** (`sso.ts:1783`) — org auto-membership (Area 4). **plugin-local.**
11. **Session + redirect** (`sso.ts:1798`): `create_session` → set cookies; redirect to
    `isRegister ? (newUserURL||callbackURL) : callbackURL`. → **Reuse `create_session`.**

---

## Discovery pipeline (the hard new piece) — `oidc/discovery.ts`

Not present in the port (generic-oauth's `_discover` is a loose best-effort fetch with no SSRF/issuer
validation). Port faithfully:

- `discoverOIDCConfig({issuer, existingConfig, discoveryEndpoint?, timeout=10000, isTrustedOrigin})`
  (`discovery.ts:44`): compute URL (`computeDiscoveryUrl` = `${issuer trimmed}/.well-known/openid-configuration`)
  → `validateDiscoveryUrl` (trusted-origin) → `fetchDiscoveryDocument` (**`redirect:"error"`** — never
  follow redirects, `:315`) → `validateDiscoveryDocument` (required fields `issuer`,
  `authorization_endpoint`, `token_endpoint`, `jwks_uri`; **issuer exact-match** modulo trailing slash) →
  `normalizeDiscoveryUrls` (resolve relative endpoints against issuer + re-check trusted-origin) →
  `selectTokenEndpointAuthMethod` (`existing` → `client_secret_basic` → `client_secret_post`) → merge
  (existing values win).
- **SSRF / private-host guards** (`validateSkipDiscoveryEndpoints` `:179`, `assertOIDCEndpointsResolvePublic`
  `:275`): every user-supplied endpoint URL must be `http(s)` and either **publicly routable**
  (`isPublicRoutableHost` — rejects loopback, RFC 1918, link-local `169.254.*`, ULA, shared-address,
  cloud-metadata FQDNs like `metadata.google.internal`, multicast, reserved) **or** allowlisted via
  `trustedOrigins`. At fetch time, `token`/`userinfo`/`jwks` hosts are additionally **DNS-resolved** and
  every resolved address re-classified (`assertEndpointResolvesPublic` `:227`, best-effort — skipped on
  runtimes without DNS). `authorizationEndpoint` is a browser redirect target, exempt from the
  resolve-check. → **`isPublicRoutableHost`/`classifyHost` have NO port equivalent** — must port a
  minimal RFC-6890 host classifier. This is the single biggest new item and a hard security requirement.
- `DiscoveryError(code, message, details)` (`types.ts:123`) + `mapDiscoveryErrorToAPIError`
  (`errors.ts:29`): `discovery_timeout`/`discovery_unexpected_error` → **502 BAD_GATEWAY**; all others →
  **400 BAD_REQUEST**; each carries the `code` on the APIError. The port's `APIError(status, code,
  message)` maps directly (status name → numeric).

---

## Domain verification — token mechanics (`routes/domain-verification.ts`)

Only registered when `options.domainVerification.enabled`. **DNS TXT record only — no meta-tag.**

- **Identifier** (`getVerificationIdentifier`, `:19`): `_${tokenPrefix}-${providerId}` where `tokenPrefix`
  default `"better-auth-token"`. The leading `_` is auto-prepended (RFC 8552 DNS convention — config
  must NOT include it). Must be ≤ **63 chars** (DNS label limit; `verify-domain` throws `BAD_REQUEST`
  `IDENTIFIER_TOO_LONG` otherwise, `:142`).
- **Token**: `generateRandomString(24)` (TS default alphabet = port default → `generate_random_string(24)`).
- **Storage**: verification store row — `identifier`, `value = token`, `expiresAt = now + 7 days`. Created
  at register time (if enabled) and by `request-domain-verification`.
- **`request-domain-verification`** (`:28`): `checkProviderAccess`; if already `domainVerified` → 409
  `CONFLICT` `DOMAIN_VERIFIED`; if an active (unexpired) verification exists → return its token; else
  generate + store a new one; **status 201**.
- **`verify-domain`** (`:96`): `checkProviderAccess`; already verified → 409; no active verification →
  404 `NO_PENDING_VERIFICATION`; then for **every** domain in `parseProviderDomains(provider.domain)`,
  `dns.resolveTxt(`${identifier}.${domain}`)` and require a record whose trimmed value equals
  **`${identifier}=${value}`** OR the **bare `${value}`** (exact match — a substring is rejected, test
  `domain-verification.test.ts` "TXT record only contains the verification token as a substring"). Any
  domain failing → **502 BAD_GATEWAY** `DOMAIN_VERIFICATION_FAILED` (multi-domain is all-or-nothing). On
  full success → `update ssoProvider set domainVerified = true` (**single provider-level bit**, even for
  multi-domain), **status 204**.
- **No DNS resolver exists in the port.** Python stdlib has no TXT resolver — needs a dependency
  (`dnspython`) or an async equivalent. Flag as a dependency decision (Open Q #3).

---

## Organization plugin seams (the port's org plugin is complete — exact seams)

All gated on `has_plugin(auth, "organization")` (port needs this tiny helper: `any(p.id ==
"organization" for p in auth.plugins)`). SSO writes `member` rows **directly via the adapter**, matching
TS — no org-API call. `member` fields: `{organizationId, userId, role, createdAt}`; role default
`"member"`; org-admin = role split on `,` ∩ `{"owner","admin"}` (`hasOrgAdminRole`, `providers.ts:120`).

1. **`assignOrganizationFromProvider`** (`org-assignment.ts:29`) — called inline in the OIDC callback
   (`sso.ts:1783`). If `provider.organizationId` set, not `provisioningOptions.disabled`, org plugin on,
   and not already a member → create `member` with `role = getRole?.({user, userInfo, token, provider})
   ?? defaultRole ?? "member"`.
2. **`assignOrganizationByDomain`** (`org-assignment.ts:95`) — the after-hook on `/callback/*`
   (`index.ts:236`), i.e. for **non-SSO** social/generic logins whose email domain maps to an org-linked
   (and, if enabled, verified) SSO provider. Same member-create logic, `userInfo:{}` (no provider profile).
   Domain match: exact `findOne where domain (+domainVerified=true if enabled)`, else `findMany` +
   `domainMatches`. **KEEP this hook** — it is the one org seam in shared code that stays.
3. **Register access control** (`sso.ts:644`): if `organizationId` given, the registrant must be a
   `member` of that org; and if org plugin on, must be org-admin (`hasOrgAdminRole`) → else
   `FORBIDDEN`.
4. **Provider CRUD access** (`checkProviderAccess`, `providers.ts:333`; `batchCheckOrgAdmin`,
   `isOrgAdmin`): for org-linked providers, access requires org-admin when the org plugin is on, else
   plain `userId` ownership. `list` (`providers.ts:249`) returns user-owned providers + org providers the
   caller admins.

`OrganizationProvisioningOptions` = `{disabled?, defaultRole? "member"|"admin", getRole?}`.

---

## Config surface (`SSOOptions`, `types.ts:137`) with ALL defaults

| option | default | notes |
|---|---|---|
| `provisionUser?({user, userInfo, token?, provider})` | — | called on register (or every login if below) |
| `provisionUserOnEveryLogin` | `false` | run `provisionUser` on every sign-in, not just first |
| `organizationProvisioning?` | — | `{disabled?, defaultRole? ("member"\|"admin"), getRole?}` |
| `defaultSSO?[]` | — | in-memory providers `{domain, providerId, oidcConfig?, samlConfig?}`; **take precedence over DB**; treated as `domainVerified:true` when domain-verif enabled |
| `defaultOverrideUserInfo` | `false` | fallback for per-provider `overrideUserInfo` |
| `disableImplicitSignUp` | `false`/undefined | when set, sign-in must pass `requestSignUp:true` to create users |
| `modelName` | `"ssoProvider"` | table name |
| `fields?` | — | per-column name overrides (`issuer/oidcConfig/samlConfig/userId/providerId/organizationId/domain`) |
| `providersLimit` | `10` | number or `(user)→Awaitable<number>`; `0` disables registration (`FORBIDDEN`) |
| `trustEmailVerified` | `false` | **deprecated** — only when true is provider `email_verified` trusted (via `parseProviderEmailVerified`) |
| `domainVerification.enabled` | `false` | adds `domainVerified` column + the 2 endpoints + sign-in gate |
| `domainVerification.tokenPrefix` | `"better-auth-token"` | `_`-prefixed at runtime |
| `redirectURI?` | — | shared callback URI (full URL or path); when set, state carries `ssoProviderId` and callback is `/sso/callback` |
| `saml?` | — | **SAML-only — ignore** |

Provider-level `oidcConfig.pkce` default `true` (`schemas.ts`/`sso.ts:256`); provider `scopes` default
`["openid","email","profile","offline_access"]`.

---

## Error responses — envelope reconciliation

Unlike the oauth-provider (spec 07), SSO uses the **port-native `APIError {code, message}` envelope
everywhere except callback redirects** — reconciliation is easy:

- **CRUD / register / domain-verification**: TS `new APIError("STATUS_NAME", {message, code?})`. Map the
  status name → numeric for the port's `APIError(status:int, code, message)`: `BAD_REQUEST`=400,
  `UNAUTHORIZED`=401, `FORBIDDEN`=403, `NOT_FOUND`=404, `CONFLICT`=409, `UNPROCESSABLE_ENTITY`=422,
  `BAD_GATEWAY`=502, `INTERNAL_SERVER_ERROR`=500. When TS supplies a `code` (e.g. `DOMAIN_VERIFIED`,
  `NO_PENDING_VERIFICATION`, `IDENTIFIER_TOO_LONG`, `DOMAIN_VERIFICATION_FAILED`, discovery `discovery_*`),
  pass it through as the port's `code`; when TS omits `code` (bare `new APIError("NOT_FOUND", {message})`),
  synthesize the code from the status name (matching how the port derives codes elsewhere).
- **Callback errors are redirects, not JSON**: `ctx.redirect(`${errorURL||callbackURL}?error=X&error_description=Y`)`
  with the `?`/`&` separator chosen dynamically. → **Reuse `generic_oauth._redirect_error`** (identical
  shape) and `_with_state_cleared`. Pre-provider-resolution failures redirect to
  `options.onAPIError.errorURL || ${baseURL}/error`.
- No `$ERROR_CODES` export in the SSO package; there is no OAuth `{error, error_description}` JSON body
  contract here (that was oauth-provider). A small `error_codes` ClassVar is optional for `auth.error_codes`
  parity.

---

## Security properties (must-preserve checklist)

1. **SSRF on all IdP endpoints**: discovery + token + userinfo + jwks URLs must be `http(s)` and either
   publicly-routable or `trustedOrigins`-allowlisted; server-side-fetched hosts DNS-resolved and
   re-classified; discovery fetch never follows redirects (`redirect:"error"`). (Discovery pipeline.)
2. **Issuer pinning**: discovery document `issuer` must exactly match the configured issuer (trailing
   slash normalized); id-token verified with `issuer = provider.issuer`, `audience = clientId`.
3. **Domain-ownership trust, not name trust**: `handleOAuthUserInfo` called with
   `trustProviderByName:false` — SSO never inherits the global `trustedProviders` list; the only trust
   signal is `isTrustedProvider = domainVerified && email-domain-matches`. Unverified providers are gated
   at sign-in and callback when `domainVerification.enabled`.
4. **Email-domain gating**: `validateEmailDomain`/`domainMatches` — exact host or `.`-suffix subdomain,
   lowercased, `tldts`-parsed; email `email_verified` only trusted when `trustEmailVerified` and only via
   strict `parseProviderEmailVerified` (boolean `true` or string `"true"` — the string `"false"` is
   unverified).
5. **Domain-verification token integrity**: DNS-TXT exact match (`identifier=value` or bare `value`, no
   substring), 7-day expiry, DNS-label ≤63, multi-domain all-or-nothing, 502 on any miss.
6. **Open-redirect / provider-secret**: `clientSecret` never returned by any read endpoint (masked
   clientId last-four only); callback redirect targets come from state (`callbackURL`/`errorURL`/
   `newUserURL`) written server-side at sign-in — validate/trust them the same way the port's social flow
   does (`ensure_trusted_url` on sign-in inputs).
7. **Account-linking rules**: reuse the port's `handle_oauth_user_info` gate — unverified + untrusted →
   `account_not_linked`; `disableSignUp` → `signup_disabled`.
8. **Namespace-collision guard** (`sso.ts:678`): reject `providerId` colliding with built-in account
   providers, configured `socialProviders`, `ctx.context.socialProviders`, `trustedProviders`, or
   `defaultSSO` providerIds (`UNPROCESSABLE_ENTITY`); also reject SCIM-provider collisions when the SCIM
   plugin is present; reject duplicate `providerId`.
9. **Identity-boundary immutability** (`providers.ts:616`): on update, if any identity field changes
   (`issuer` or OIDC `authorizationEndpoint`/`clientId`/`discoveryEndpoint`/`jwksEndpoint`/`tokenEndpoint`/
   `userInfoEndpoint`/`mapping.id`) **and** a linked `account` row exists → `409 CONFLICT`. Client-secret
   rotation with unchanged identity fields is allowed. Domain change resets `domainVerified=false`.
10. **Delete is transactional** (`providers.ts:691`): delete linked `account` rows + provider in one tx.

---

## Gap items — ordered (dependencies first)

Sizing: **S** ≈ hours, **M** ≈ a day, **L** ≈ multi-day.

**Enabling helpers (small, shared):**
1. **`has_plugin(auth, id)`** — `any(p.id == id for p in auth.plugins)`. One-liner, used by every org
   seam. **S**
2. **`handle_oauth_user_info` signature extension** — add call-time `is_trusted_provider: bool | None =
   None`, `trust_provider_by_name: bool = True`, `override_user_info: bool | None = None` to the shared
   `oauth/flow.handle_oauth_user_info`; when `trust_provider_by_name=False` skip
   `_resolve_trusted_providers`, use `is_trusted_provider` instead; `override_user_info` overrides the
   provider flag. Defaults preserve social/generic-oauth behavior (single shared change, all callers
   benefit — root-cause, not a fork). **S–M**
3. **Public-routable host classifier** — port `@better-auth/core/utils/host` `isPublicRoutableHost` +
   `classifyHost` (RFC 6890: loopback, RFC 1918, link-local, ULA, shared-address, cloud-metadata FQDNs,
   multicast, reserved). No port equivalent. Security-critical. **M**
4. **DNS resolver seam** — a TXT resolver for domain verification + an A/AAAA resolver for the discovery
   resolve-check. Needs a dependency decision (`dnspython`) — see Open Q #3. **S** (once dep chosen)

**Plugin areas:**
5. **`ssoProvider` schema + `utils`** — the table via `Field` (keep `samlConfig` nullable),
   `safeJsonParse`, `domainMatches`, `parseProviderEmailVerified`, `validateEmailDomain`,
   `parseProviderDomains` (needs a `tldts`-equivalent hostname parse — Python stdlib + a public-suffix
   lib or a minimal hostname normalizer), `maskClientId`. **M**
6. **Discovery pipeline** — `discoverOIDCConfig`/`ensureRuntimeDiscovery`/`validateDiscoveryDocument`/
   `normalizeDiscoveryUrls`/`selectTokenEndpointAuthMethod`/SSRF guards + `DiscoveryError` +
   `mapDiscoveryErrorToAPIError`. Depends on #3, #4. **L**
7. **Provider CRUD** — `list`/`get`/`update`/`delete` + `checkProviderAccess`/`isOrgAdmin`/
   `batchCheckOrgAdmin`, `sanitizeProvider` (mask + strip secret, OIDC only), `mergeOIDCConfig`,
   identity-boundary guard, transactional delete. Depends on #1, #5. **L**
8. **Register** — `/sso/register`: providersLimit, org-membership/admin gate, issuer-URL validation,
   reserved-id/SCIM/dupe guards, `validateSkipDiscoveryEndpoints`, discovery, `buildOIDCConfig`
   (plaintext-secret JSON), domain-verif token seeding, response shape (incl. `redirectURI`,
   `domainVerificationToken`). Depends on #5, #6. **L**
9. **Sign-in/sso** — provider resolution (defaultSSO→DB precedence), domain-verif gate,
   `ensureRuntimeDiscovery`, authorize-URL build (`build_authorization_url`, login_hint, PKCE, scopes),
   `redirectURI`/shared-callback state (`ssoProviderId`). Depends on #6. **M**
10. **Callback** — `handleOIDCCallback` + `callbackSSO` + `callbackSSOShared`: state consume, provider
    resolve, discovery, token exchange (`exchange_code`), profile resolve (userinfo map / id-token verify
    via `verify_id_token` + `config.mapping`), `isTrustedProvider`, `handle_oauth_user_info` (extended),
    `provisionUser`, session. Depends on #2, #6, #9. **L**
11. **Domain verification** — `/sso/request-domain-verification` + `/sso/verify-domain` (DNS-TXT,
    multi-domain all-or-nothing, DNS-label guard), `getVerificationIdentifier`. Depends on #4, #7. **M**
12. **Org assignment** — `assignOrganizationFromProvider` (callback inline) + `assignOrganizationByDomain`
    (after-hook `/callback/*`). Depends on #1. **M**

**Total: 12 items** (4 helpers + 8 plugin-area). Client-side `client.ts` excluded; all SAML excluded.

### Recommended dispatch grouping (4 waves)

- **Wave A — foundations & CRUD:** #1, #5, #7. Schema, utils, provider read/update/delete/access-control,
  org-admin checks. Independently testable (register-stub → list/get/update/delete). No discovery/network.
- **Wave B — discovery & registration:** #3, #4, #6, #8. The SSRF host classifier, discovery pipeline,
  DNS seam, and `/sso/register`. The security-heavy core.
- **Wave C — the login flow:** #2, #9, #10. Sign-in authorize URL + full callback (reuses machinery/flow/
  verify). The `handle_oauth_user_info` extension lands here.
- **Wave D — domain verification & org:** #11, #12. DNS-TXT verification + org auto-membership seams.

Rationale: A's schema/CRUD is what everything references and needs no network; B front-loads the one
genuinely-new security subsystem (host classifier + discovery) that both register and login depend on; C
is mostly assembling existing seams once B exists; D is additive and depends only on A (org) + the DNS
seam (B).

---

## Open questions (with defaults)

1. **`handle_oauth_user_info` — extend the shared helper or fork?** SSO needs `trust_provider_by_name=False`
   + `is_trusted_provider` + `override_user_info` at call time; the port's helper only has `disable_sign_up`.
   **Default: extend the shared helper** in `oauth/flow.py` with those three optional params (defaults
   reproduce today's behavior). One small diff, root-caused in the one place all callers route through,
   generic-oauth/social unaffected. Fork only if a reviewer objects to touching core.

2. **`clientSecret` plaintext storage — keep as-is?** TS stores the secret in cleartext inside the
   `oidcConfig` JSON (masked only on read). **Default: store identically (plaintext)** — it is a hard
   cross-runtime DB-compat requirement (a TS row must decrypt-free in Python and vice-versa) and the
   secret is needed cleartext at every token exchange. Do **not** add encryption. Document the posture in
   the port docstring. (If the project later wants at-rest encryption, it must be a coordinated
   both-runtimes change, out of scope here.)

3. **DNS dependency for domain verification (+ discovery resolve-check).** Python stdlib has no TXT
   resolver and no async A/AAAA-with-all resolver. **Default: add `dnspython`** (small, standard, async
   via `dns.asyncresolver`) for both `resolveTxt` (domain verification) and the discovery
   `assertEndpointResolvesPublic` A/AAAA check. If adding a dependency is unwanted, the DNS resolve-check
   in discovery is explicitly "best-effort, skipped when unavailable" in TS, so it may be deferred; but
   domain verification is non-functional without a TXT resolver — it hard-requires the dependency. Flag
   as the one real dependency decision.

4. **`tldts` hostname parsing for `parseProviderDomains`/`domainMatches`.** TS uses `tldts.getHostname`.
   **Default: a minimal hostname normalizer** (strip scheme/path, lowercase, validate label shape) is
   sufficient for the domain-matching + email-domain-gating tests; a full public-suffix library is not
   required for correctness here. Revisit only if a test asserts PSL-specific behavior (none observed in
   `utils.test.ts`).

5. **`defaultSSO` in-memory providers — support now?** They short-circuit DB resolution and are marked
   `domainVerified:true`. **Default: include** — cheap (an in-memory list checked before the DB lookup),
   and several `oidc.test.ts` cases (`OIDC SSO with defaultSSO array`) exercise it.

6. **`onRequest`/well-known interception — needed?** Unlike oauth-provider, SSO registers no well-known
   endpoints and needs no early `onRequest` router; the `init()` `skipOriginCheck` mutation is SAML-only.
   **Default: no `on_request` work** for the OIDC half.

---

Anchors verified against `packages/sso/` at v1.6.23. SAML boundary is explicit and auditable above; the
`samlConfig` column is retained (nullable, unused) solely for cross-runtime DB compatibility.
