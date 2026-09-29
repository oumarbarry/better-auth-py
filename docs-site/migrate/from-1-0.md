---
title: Upgrade from 1.0 to 1.1
description: Upgrade Better Auth for Python from 1.0 to 1.1, which follows better-auth v1.7.6. Database changes, Microsoft account ids, changed defaults and the options that keep 1.0 behavior.
---

# Upgrade from 1.0 to 1.1

Better Auth for Python 1.1 follows better-auth **v1.7.6**. Most of the release
adds features, but some defaults change so that the wire and storage format
stay identical to the TypeScript library. This page lists what you have to do,
in the order you should do it.

```bash
uv add "better-auth-server>=1.1,<1.2"
```

Most 1.1 defaults that differ from 1.0 have an option that restores the 1.0
behavior while you migrate. They are collected in
[Options that keep 1.0 behavior](#compatibility-options).

## Who needs to act

| If your project | Read |
| --- | --- |
| Uses Better Auth for Python at all | [Check these first](#check-these-first) and [Upgrade order](#upgrade-order) |
| Uses the SQLAlchemy adapter or another database adapter | [Database migrations](#database-migrations) |
| Offers Microsoft sign-in | [Microsoft Entra ID account ids](#microsoft-account-ids) |
| Calls `/unlink-account`, `/get-access-token`, `/refresh-token` or `/account-info` | [Accounts](#accounts) and [Python client](#python-client) |
| Uses social sign-in or the Generic OAuth plugin | [Social sign-in](#social-sign-in) and [Generic OAuth](#generic-oauth) |
| Runs behind a reverse proxy | [Sessions, cookies and proxies](#sessions-cookies-and-proxies) |
| Runs its own OAuth or OpenID provider | [OAuth Provider](#oauth-provider) |
| Uses SSO | [SSO](#sso) |
| Uses Captcha, Sign-In with Ethereum, Two-Factor, OAuth Proxy or another plugin | [Plugins](#plugins) |
| Has a custom adapter, secondary storage or rate-limit storage | [Storage and custom adapters](#storage-and-custom-adapters) |

## Check these first {#check-these-first}

These changes do not raise an error. The app keeps running, but something it
did in 1.0 stops happening or starts failing later.

1. **Captcha rules match full paths.** A custom rule such as `/sign-up` no
   longer covers `/sign-up/email`, so that route stops asking for a captcha.
   Write the full path or a wildcard: `/sign-up/email` or `/sign-up/**`. The
   default rules are not affected.
2. **The database schema is checked on the first request.** With the
   SQLAlchemy adapter, a missing table or column now fails every auth request,
   including routes that never touch the database. Apply the [database
   migrations](#database-migrations) before you deploy.
3. **Forwarded headers are no longer trusted by default.**
   `trusted_proxy_headers` is now `False`. If your proxy sends the public host
   only in `X-Forwarded-Host` and `X-Forwarded-Proto`, a dynamic `base_url`
   and forms posted with `Origin: null` stop working. See
   [Sessions, cookies and proxies](#sessions-cookies-and-proxies).
4. **Microsoft accounts are keyed by `oid`.** Existing `microsoft` account rows
   hold the old `sub` value, so returning users are not recognized. Migrate
   the rows or keep `sub` for now: see
   [Microsoft Entra ID account ids](#microsoft-account-ids).
5. **Generic OAuth redirect URIs change.** Providers configured through the
   Generic OAuth plugin now return to `<base>/callback/<id>` instead of
   `<base>/oauth2/callback/<id>`. Register the new URI with each provider, or
   set `legacy_routes=True`.
6. **Duplicate account keys block sign-in.** When two `account` rows share the
   same `providerId` and `accountId`, OAuth sign-in for that account is
   refused. Run the [duplicate check](#duplicate-account-keys) before you
   upgrade.
7. **OAuth Provider ID tokens lose profile claims.** If you run the OAuth
   Provider plugin, ID tokens now carry protocol claims only. Name, email and
   picture come from the UserInfo endpoint. Clients that read them from the ID
   token need `legacy_id_token_profile_claims=True` until they change.
8. **OAuth Provider no longer accepts the base URL as an audience.** Configure
   `resources`, or list the old audiences in `valid_audiences`.

## Upgrade order {#upgrade-order}

1. Run the [duplicate account check](#duplicate-account-keys) and resolve any
   rows it returns.
2. Apply the [database migrations](#database-migrations) for the features you
   use.
3. Decide how to handle [Microsoft account ids](#microsoft-account-ids): migrate
   the rows, or deploy with `account_id_claim="sub"` and migrate later.
4. Review the [breaking changes](#breaking-changes) for the areas you use and
   set the [compatibility options](#compatibility-options) you need.
5. Deploy 1.1. Sign-ins that were in progress during the deploy (the user was
   on the provider's page) must be started again.
6. Update your clients (browser code, the [Python client](#python-client),
   OAuth clients of your provider), then remove the compatibility options.

## Database migrations {#database-migrations}

The core tables (`user`, `session`, `account`, `verification`) do not change.
The changes below apply only if you use the matching plugin.

On a new, empty database, `await adapter.create_tables()` creates every table
and column listed here. On an existing database, apply the statements with
your migration tool (Alembic, or plain SQL). They are written for PostgreSQL.
For SQLite they work as written. For MySQL, quote names with backticks and use
`VARCHAR(191)` instead of `TEXT` for every column that carries a unique index.

Use the column types of your existing tables if they differ: the SQLAlchemy
adapter stores lists and JSON values as text.

### Plugin tables created before 1.0.4 {#plugin-tables-before-1-0-4}

Up to 1.0.3, `create_tables()` created plugin tables (two-factor, API keys,
passkeys, device authorization, Sign-In with Ethereum wallets, SSO, OAuth
Provider) without their `id` column, so they could never hold rows. If you
created them that way, drop the empty tables and run `create_tables()` again,
or add the column:

```sql
ALTER TABLE "twoFactor" ADD COLUMN "id" TEXT PRIMARY KEY;
```

SQLite cannot add a primary key with `ALTER TABLE`: drop and recreate the
table there. 1.0.4 already fixed this. Tables created by your own migrations
or by the TypeScript library have the column.

### Duplicate account keys {#duplicate-account-keys}

Not a schema change, but run it first. 1.1 refuses OAuth sign-in when more than
one row matches an account key, where 1.0 took the first row it found.

```sql
SELECT "providerId", "accountId", count(*)
FROM account
GROUP BY 1, 2
HAVING count(*) > 1;
```

Resolve every row returned: keep the row that belongs to the right user and
delete the others. Until then, sign-in for that account fails with
`error=internal_server_error`.

### OAuth Provider {#oauth-provider-tables}

New columns on the existing tables:

```sql
ALTER TABLE "oauthClient" ADD COLUMN "clientDiscoveryId" TEXT;
ALTER TABLE "oauthClient" ADD COLUMN "clientCredentialsScopes" TEXT DEFAULT '[]';
ALTER TABLE "oauthClient" ADD COLUMN "backchannelLogoutUri" TEXT;
ALTER TABLE "oauthClient" ADD COLUMN "backchannelLogoutSessionRequired" BOOLEAN;
ALTER TABLE "oauthClient" ADD COLUMN "applicationType" TEXT;
ALTER TABLE "oauthClient" ADD COLUMN "jwks" TEXT;
ALTER TABLE "oauthClient" ADD COLUMN "jwksUri" TEXT;
ALTER TABLE "oauthClient" ADD COLUMN "dpopBoundAccessTokens" BOOLEAN DEFAULT FALSE;

ALTER TABLE "oauthConsent" ADD COLUMN "resources" TEXT;
ALTER TABLE "oauthConsent" ADD COLUMN "requestedUserInfoClaims" TEXT;

ALTER TABLE "oauthRefreshToken" ADD COLUMN "authorizationCodeId" TEXT;
ALTER TABLE "oauthRefreshToken" ADD COLUMN "resources" TEXT;
ALTER TABLE "oauthRefreshToken" ADD COLUMN "requestedUserInfoClaims" TEXT;
ALTER TABLE "oauthRefreshToken" ADD COLUMN "rotatedAt" TIMESTAMP;
ALTER TABLE "oauthRefreshToken" ADD COLUMN "rotationReplayResponse" TEXT;
ALTER TABLE "oauthRefreshToken" ADD COLUMN "rotationReplayExpiresAt" TIMESTAMP;
ALTER TABLE "oauthRefreshToken" ADD COLUMN "confirmation" TEXT;
CREATE INDEX "oauthRefreshToken_authorizationCodeId_idx"
    ON "oauthRefreshToken" ("authorizationCodeId");

ALTER TABLE "oauthAccessToken" ADD COLUMN "authorizationCodeId" TEXT;
ALTER TABLE "oauthAccessToken" ADD COLUMN "resources" TEXT;
ALTER TABLE "oauthAccessToken" ADD COLUMN "requestedUserInfoClaims" TEXT;
ALTER TABLE "oauthAccessToken" ADD COLUMN "revoked" TIMESTAMP;
ALTER TABLE "oauthAccessToken" ADD COLUMN "confirmation" TEXT;
CREATE INDEX "oauthAccessToken_authorizationCodeId_idx"
    ON "oauthAccessToken" ("authorizationCodeId");
```

Three new tables: protected resources, the clients linked to them, and the
single-use `private_key_jwt` assertion ids.

```sql
CREATE TABLE "oauthResource" (
    "id" TEXT PRIMARY KEY,
    "identifier" TEXT NOT NULL UNIQUE,
    "name" TEXT NOT NULL,
    "accessTokenTtl" INTEGER,
    "refreshTokenTtl" INTEGER,
    "signingAlgorithm" TEXT,
    "signingKeyId" TEXT,
    "allowedScopes" TEXT,
    "customClaims" TEXT,
    "dpopBoundAccessTokensRequired" BOOLEAN DEFAULT FALSE,
    "disabled" BOOLEAN DEFAULT FALSE,
    "createdAt" TIMESTAMP,
    "updatedAt" TIMESTAMP,
    "policyVersion" INTEGER DEFAULT 1,
    "metadata" TEXT
);

CREATE TABLE "oauthClientResource" (
    "id" TEXT PRIMARY KEY,
    "clientId" TEXT NOT NULL
        REFERENCES "oauthClient" ("clientId") ON DELETE CASCADE,
    "resourceId" TEXT NOT NULL
        REFERENCES "oauthResource" ("identifier") ON DELETE CASCADE,
    "metadata" TEXT,
    "createdAt" TIMESTAMP
);
CREATE INDEX "oauthClientResource_clientId_idx"
    ON "oauthClientResource" ("clientId");
CREATE INDEX "oauthClientResource_resourceId_idx"
    ON "oauthClientResource" ("resourceId");

CREATE TABLE "oauthClientAssertion" (
    "id" TEXT PRIMARY KEY,
    "expiresAt" TIMESTAMP NOT NULL
);
```

Then bring the existing client rows in line with the 1.1 rules. A client is
public only when its `tokenEndpointAuthMethod` is `none`, and the `type` and
`public` columns are no longer read. Clients created through the 1.0 endpoints
already follow this rule; the first statement fixes rows written by hand.

```sql
UPDATE "oauthClient"
SET "tokenEndpointAuthMethod" = 'none'
WHERE ("public" = TRUE OR "type" IN ('native', 'user-agent-based'))
  AND ("tokenEndpointAuthMethod" IS NULL
       OR "tokenEndpointAuthMethod" <> 'none');

UPDATE "oauthClient"
SET "applicationType" = "type"
WHERE "type" IN ('web', 'native');

UPDATE "oauthClient"
SET "clientCredentialsScopes" = '[]'
WHERE "clientCredentialsScopes" IS NULL;
```

Review `user-agent-based` clients by hand: they are usually a `web` client
with `tokenEndpointAuthMethod` set to `none`. Once nothing reads them, you can
drop the `type` and `public` columns.

Clients whose `applicationType` stays empty keep working at the authorize and
token endpoints. The next update validates them as `web` clients, so a client
that redirects to an `http://` loopback address must be updated with
`application_type: "native"`.

### Device Authorization {#device-authorization-tables}

`deviceCode` and `userCode` are now unique. Remove duplicates first; this query
must return no rows:

```sql
SELECT "deviceCode", count(*) FROM "deviceCode" GROUP BY 1 HAVING count(*) > 1;
SELECT "userCode", count(*) FROM "deviceCode" GROUP BY 1 HAVING count(*) > 1;
```

Then add the indexes:

```sql
CREATE UNIQUE INDEX "deviceCode_deviceCode_uidx" ON "deviceCode" ("deviceCode");
CREATE UNIQUE INDEX "deviceCode_userCode_uidx" ON "deviceCode" ("userCode");
```

Both values are limited to 191 characters. On MySQL and SQL Server, change the
two columns to `VARCHAR(191)` before you create the indexes.

If you add the new `OAuthDeviceAuthorizationPlugin` (the device grant for
clients of the OAuth Provider plugin), it needs two more columns:

```sql
ALTER TABLE "deviceCode" ADD COLUMN "oauthClientId" TEXT;
ALTER TABLE "deviceCode" ADD COLUMN "resources" TEXT;
```

### Organization teams {#organization-tables}

With teams enabled, two internal columns back the atomic team capacity check.
Neither is ever returned by the API.

```sql
ALTER TABLE "team" ADD COLUMN "memberCount" INTEGER NOT NULL DEFAULT 0;
ALTER TABLE "teamMember" ADD COLUMN "membershipKey" TEXT;
CREATE UNIQUE INDEX "teamMember_membershipKey_uidx"
    ON "teamMember" ("membershipKey");
```

Existing teams start at `0` and resync their count on the next join, so there
is no backfill to run.

### SSO {#sso-tables}

The `ssoProvider` table needs its `id` column, like every plugin table: see
[Plugin tables created before 1.0.4](#plugin-tables-before-1-0-4).

## Microsoft Entra ID account ids {#microsoft-account-ids}

The built-in Microsoft provider now uses the `oid` claim as the account id,
as better-auth 1.7 does. `oid` identifies the user across every app in the
directory; the `sub` claim used by 1.0 is different for each app registration.

Existing rows with `providerId = 'microsoft'` hold the `sub` value. After the
upgrade, a returning user no longer matches that row. Depending on your
account linking settings, the sign-in either links a second account row by
email or is refused. A token without a usable claim is refused with
`unable_to_get_user_info`.

You have two ways through.

**Keep the old ids for now.** Deploy with the 1.0 claim, then migrate the rows
at your own pace:

```python
from better_auth.oauth.providers_ext import MicrosoftEntraId

MicrosoftEntraId(
    client_id="...",
    client_secret="...",
    account_id_claim="sub",  # 1.0 ids, until the rows are migrated
)
```

**Migrate the rows.** Each Microsoft account row usually stores the last ID
token it received, in plain text (only access and refresh tokens are
encrypted by `encrypt_oauth_tokens`). The token payload holds the `oid`. This
script rewrites every row that has one:

```python
import base64
import json

from sqlalchemy import create_engine, text


def token_claims(id_token: str) -> dict:
    payload = id_token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


engine = create_engine(DATABASE_URL)  # a synchronous URL
with engine.begin() as conn:
    rows = conn.execute(
        text(
            'SELECT id, "idToken" FROM account '
            "WHERE \"providerId\" = 'microsoft' AND \"idToken\" IS NOT NULL"
        )
    ).all()
    for row_id, id_token in rows:
        oid = token_claims(id_token).get("oid")
        if oid:
            conn.execute(
                text('UPDATE account SET "accountId" = :oid WHERE id = :id'),
                {"oid": oid, "id": row_id},
            )
```

The ID token was verified when it was stored, so reading its payload is
enough here. For rows without an ID token, either get the `oid` from
Microsoft Graph (`GET /me` returns it as `id`, using the stored access token
while it is valid) or keep `account_id_claim="sub"` until those users have
signed in once more.

Then check for duplicates, which would now block sign-in:

```sql
SELECT "accountId", count(*)
FROM account
WHERE "providerId" = 'microsoft'
GROUP BY 1
HAVING count(*) > 1;
```

When every row holds an `oid`, remove `account_id_claim`.

The new Microsoft Entra ID preset of the Generic OAuth plugin
(`microsoft_entra_id(tenant_id=...)`, provider id `microsoft-entra-id`) uses
`oid` from the start. It did not exist in 1.0, so it has no rows to migrate.

## Options that keep 1.0 behavior {#compatibility-options}

Each option restores one 1.0 behavior. The 1.1 default matches better-auth
v1.7.6. Several are deprecated and will be removed: treat them as a bridge
while your clients or data catch up.

| Option | 1.1 default | Set it to keep 1.0 behavior |
| --- | --- | --- |
| `BetterAuth(trusted_proxy_headers=...)` | `False` | `True`: trust `X-Forwarded-Host` and `X-Forwarded-Proto` |
| `AccountOptions(legacy_account_selection=...)` | `False` | `True`: account routes accept `providerId` bodies (deprecated) |
| `SQLAlchemyAdapter(engine, advanced=AdvancedDatabase(validate_schema=...))` | on | `False`: no schema check |
| `MicrosoftEntraId(account_id_claim=...)` | `"oid"` | `"sub"`: 1.0 account ids |
| `PayPal(legacy_id_token_sign_in=...)` | `False` | `True`: ID token sign-in with PayPal |
| `GenericOAuthPlugin(legacy_routes=...)` | `False` | `True`: `/sign-in/oauth2`, `/oauth2/callback/<id>`, `/oauth2/link` |
| `GenericOAuthConfig(pkce=...)` | `True` | `False`: no PKCE for that provider |
| `SiwePlugin(accept_legacy_wallet_fields=...)` | `False` | `True`: accept and ignore `walletAddress`, `address`, `chainId` |
| `SSOPlugin(legacy_mapping_id=...)` | `False` | `True`: account id read from `mapping.id` |
| `OAuthProviderPlugin(bind_client_auth_method=...)` | `True` | `False`: Basic and post client authentication both accepted |
| `OAuthProviderPlugin(legacy_id_token_profile_claims=...)` | `False` | `True`: profile and email claims in ID tokens (deprecated) |
| `OAuthProviderPlugin(valid_audiences=[...])` | `None` | the audiences 1.0 accepted, base URL included (deprecated) |
| `OAuthProviderPlugin(enforce_per_client_resources=...)` | on when resources exist | `False`: any client may request any configured resource |
| `OAuthProviderPlugin(client_credential_grant_default_scopes=[...])` | `None` | clients without `clientCredentialsScopes` keep the 1.0 scope rules |

The Generic OAuth options `issuer` and `require_issuer_validation` still work
but are deprecated: issuer validation now comes from discovery.

## Breaking changes by area {#breaking-changes}

### Accounts {#accounts}

**Account routes take the Better Auth account id.** `/unlink-account`,
`/get-access-token`, `/refresh-token` and `/account-info` pick the account by
its `id`, as returned by `/list-accounts`. A body with `providerId` is refused
with `400 INVALID_BODY`.

Before (1.0):

```json
{
  "providerId": "github"
}
```

After (1.1), with the `id` of the row from `/list-accounts`:

```json
{
  "accountId": "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6"
}
```

`/account-info` is a GET route, so `accountId` goes in the query string. Its
response now also includes the selected `account` (`id`, `providerId`,
`accountId`). `/refresh-token` returns the account row id as `accountId`.

`/unlink-account` also needs a fresh session now (`403 SESSION_NOT_FRESH`
otherwise). better-auth also accepts `useAccountCookie: true` on the three
token routes; this port does not store the account cookie, so that form
answers `400 ACCOUNT_NOT_FOUND`.

To keep the 1.0 bodies while clients migrate, set
`AccountOptions(legacy_account_selection=True)`. The option is deprecated.

**Password and sign-out.** `/set-password` fills an existing credential account
that has no password, and answers `PASSWORD_ALREADY_SET` (was
`USER_ALREADY_HAS_PASSWORD`) when one is set. `/sign-out` answers
`{"success": true}` even without a session, and also expires the session cache
cookie. The credential account is the one whose `accountId` is the user id.

**Passwordless sign-in clears unproven access.** A magic link or email OTP
sign-in for a user whose email is not verified now deletes every account linked
to that user (OAuth links too, not only the password) and its sessions, then
marks the email verified. Whoever proves the email owns the account.

**Stored scopes.** `account.scope` holds the granted scopes as a
comma-separated list, as better-auth stores it. Later sign-ins and
`/refresh-token` no longer rewrite it, and linking adds new scopes to the
stored ones. Rows written space-separated by 1.0 are still read correctly.

**Placeholder emails.** New users of providers that return no email get
`<id>@<provider>.placeholder.invalid`. This includes Twitter (X), TikTok and
Roblox, which used the username in 1.0. New anonymous users get
`<id>@anonymous.placeholder.invalid` (was `temp@<id>.com`) and new wallet users
`<address>@siwe.placeholder.invalid`. Existing users keep their address;
`email_domain_name` still overrides the anonymous and SIWE defaults.

### Sessions, cookies and proxies {#sessions-cookies-and-proxies}

**`trusted_proxy_headers` is off by default.** Better Auth for Python no longer
reads `X-Forwarded-Host` and `X-Forwarded-Proto` unless you allow it. This
matters in two cases: a `DynamicBaseURL` behind a proxy that rewrites the
`Host` header, and forms posted with `Origin: null` whose origin is inferred
from the request.

If your proxy passes the original `Host` header through, and your
`DynamicBaseURL` sets `protocol="https"`, you have nothing to do. Otherwise:

```python
auth = BetterAuth(
    secret=...,
    base_url=DynamicBaseURL(allowed_hosts=["example.com"], protocol="https"),
    trusted_proxy_headers=True,
)
```

Only turn it on when the proxy overwrites both headers on every request. A
proxy that appends to or passes through a client's `X-Forwarded-Host` lets that
client choose the host. See
[Production deploy](/deploy/production#forwarded-host-and-protocol).

**The session cache cookie is bound to its session.** A cache cookie is only
used with the session cookie it was issued for. A foreign, expired or tampered
one is expired, and a leftover one is cleared when the cache is off. Sign-up,
sign-in and other session creations now write the cache cookie, and profile
and session updates refresh it. Nothing to change unless you parsed that
cookie yourself.

### Social sign-in {#social-sign-in}

- **Microsoft**: see [Microsoft Entra ID account ids](#microsoft-account-ids).
- **Google** accepts RS256 ID tokens only, reads the callback profile from the
  ID token and no longer sends a nonce.
- **PayPal** ID token sign-in is off by default. Set
  `legacy_id_token_sign_in=True` to keep it.
- **Facebook** sign-in with an opaque token (not a Limited Login JWT) reads
  the identity from `idToken.accessToken`. Send the access token there; a
  request without it answers `401 FAILED_TO_GET_USER_INFO`. Limited Login
  tokens must be RS256.
- **Linking with an ID token** (`POST /link-social` with `idToken`) now answers
  `409 SOCIAL_ACCOUNT_ALREADY_LINKED` when the provider account belongs to
  another user. 1.0 answered success without linking.
- **Callback error codes** follow better-auth: `unable_to_link_account` (was
  `account_not_linked`) for an untrusted provider with an unverified email,
  `email_does_not_match` (was `email_doesnt_match`), `state_not_found` for a
  missing state and `state_mismatch` for every other state failure. If your
  frontend matches these strings, update it.
- **Error redirects.** A duplicate account key or a failed user lookup during
  OAuth sign-in redirects to `on_api_error.error_url` (default
  `<base path>/error`) with `error=internal_server_error`, not to the flow's
  error callback URL. An account whose user row no longer exists is refused
  with `unable_to_link_account`.
- **Reserved parameters.** Extra authorization or refresh parameters can no
  longer override reserved OAuth parameters such as `client_id` or
  `redirect_uri`.
- **Required additional user fields.** Mapped provider profile fields (Generic
  OAuth `map_profile_to_user`, SSO `mapping.extraFields`) now fill your
  configured additional user fields. A required additional field with no
  default and no value stops an OAuth sign-up with `MISSING_FIELD`; 1.0
  created the user without it. Give such fields a default, or map them.
- **Empty names.** A user created through OAuth without a provider name gets
  an empty `name`, not the email.
- **GitHub** sign-in sends PKCE, and only the providers that forward
  `login_hint` in better-auth still send it.
- **`get_oauth_state(ctx)`** returns the `additionalData` keys at the top
  level, as stored by better-auth. Read `state["myKey"]`, not
  `state["additionalData"]["myKey"]`.
- **`validate_user_info`.** If you set `UserOptions(validate_user_info=...)`,
  it now also runs for users created by email sign-up, admin, anonymous, email
  OTP, magic link, phone number and SIWE. The hook receives the method in
  `source`. Code that calls `InternalAdapter.create_user` directly must then
  pass `source` and `ctx`.

### Generic OAuth {#generic-oauth}

Generic OAuth providers are now regular social providers.

| 1.0 | 1.1 |
| --- | --- |
| `POST /sign-in/oauth2` with `providerId` | `POST /sign-in/social` with `provider` |
| `GET /oauth2/callback/<id>` | `GET /callback/<id>` |
| `POST /oauth2/link` | `POST /link-social` |
| PKCE off by default | PKCE on by default |

What to do:

- Register `<base_url><base_path>/callback/<id>` as the redirect URI with each
  provider, or set `GenericOAuthPlugin(legacy_routes=True)`, which keeps the
  three 1.0 routes and the 1.0 redirect URI.
- Set `pkce=False` on a provider that rejects PKCE.
- `map_profile_to_user` can no longer change the account id. Use
  `account_subject` to pick the provider field that identifies the account.
- Discovery providers verify their ID tokens with a nonce.
- Callback error codes are `invalid_code`, `unable_to_get_user_info`,
  `email_not_found` and `email_does_not_match`.
- The OAuth Proxy plugin no longer proxies `/sign-in/oauth2`.

### SSO {#sso}

- The account id is always the `sub` claim. 1.0 read `mapping.id` when it was
  set; `SSOPlugin(legacy_mapping_id=True)` keeps that.
- Callback and state errors use the better-auth codes (`state_not_found`,
  `state_mismatch`, and messages such as `account not linked`).
- A sign-in is refused with `SSO_PROVIDER_CHANGED` when its provider changes
  between sign-in and callback.
- Server-side OIDC requests refuse redirects (`oidc_endpoint_redirect`).
- SSO sign-ins started before the upgrade must be restarted.

### OAuth Provider {#oauth-provider}

If you run your own authorization server with the OAuth Provider plugin, apply
the [table changes](#oauth-provider-tables) first, then review these:

- **Client authentication.** A client must authenticate with the method it
  registered (default `client_secret_basic`). Sending two methods at once is
  refused. `bind_client_auth_method=False` accepts Basic and post again.
- **ID token claims.** ID tokens carry protocol claims only (`acr` is `"0"`).
  Profile and email claims come from UserInfo. Custom ID token claims cannot
  replace protocol claims. `legacy_id_token_profile_claims=True` keeps the 1.0
  claims (deprecated).
- **Audiences and resources.** A requested `resource` must be a configured
  resource, linked to the client unless `enforce_per_client_resources=False`.
  The base URL is no longer an accepted audience: configure `resources`, or
  list the old audiences in `valid_audiences` (deprecated). Token and refresh
  requests can narrow the resources of a grant but never widen them.
- **`client_credentials` grant.** It uses each client's
  `clientCredentialsScopes`. With `client_credential_grant_default_scopes`
  configured, clients without them keep the 1.0 rules.
- **Redirect URIs** follow the client's application type (default `web`): web
  clients need HTTPS on a public host, native clients may use loopback HTTP or
  a reverse-domain scheme. `localhost` loopback URIs may use any port.
- **Errors.** Token, introspection and revocation errors match better-auth
  v1.7.6. An invalid authorization code is a `400 invalid_grant`, and a failed
  Basic login gets a `WWW-Authenticate: Basic` challenge. Invalid
  authorization requests redirect to the client's registered redirect URI with
  an RFC 6749 error, and `state` is optional.
- **Refresh tokens.** Offline access no longer needs PKCE when an OpenID request
  sends a nonce. Reusing an authorization code revokes the tokens already
  issued for it.
- **Introspection** reports tokens of an ended session as inactive and adds
  `token_type`. Revoking a JWT access token answers `unsupported_token_type`.
- **End session.** `/oauth2/end-session` accepts GET and POST, no longer
  requires `id_token_hint`, and asks the user to confirm when there is no
  usable hint.
- **Dynamic registration.** Unauthenticated registration creates a
  confidential `client_secret_basic` client, stores the configured scope set,
  and drops unknown top-level fields instead of keeping them in `metadata`.
- **Caching.** Registration, client creation, secret rotation and device
  endpoints send `Cache-Control: no-store`, errors included.

The [OAuth Provider page](/plugins/oauth-provider) documents the new features:
protected resources, DPoP, back-channel logout, `private_key_jwt` and the
device grant.

### Plugins {#plugins}

**Captcha.** `endpoints` rules match full paths, with `*` (one segment) and
`**` (any depth) wildcards:

```python
# 1.0: a prefix matched /sign-up/email too
CaptchaPlugin(provider="cloudflare-turnstile", secret_key=..., endpoints=["/sign-up"])

# 1.1: name the route, or use a wildcard
CaptchaPlugin(
    provider="cloudflare-turnstile", secret_key=..., endpoints=["/sign-up/**"]
)
```

**Sign-In with Ethereum.** Nonces are issued before the wallet is known, so
`/siwe/nonce` takes an empty body, and the address and chain id come from the
signed message. The nonce and verify routes reject unknown body fields:
`accept_legacy_wallet_fields=True` accepts and ignores the `walletAddress`,
`address` and `chainId` fields older clients send. Nonces issued before the
upgrade stop working.

**Two-Factor.** Enabling TOTP again after it is verified returns
`TOTP_ALREADY_ENABLED`; an unfinished enrollment is restarted in place.

**OAuth Proxy.** Proxied sign-ins complete on `/callback/<provider>/oauth-proxy`,
so callback hooks run. `/oauth-proxy-callback` still works but is deprecated.

**Phone Number.** `allowed_attempts=0` now means zero attempts.

**Device Authorization.** Device and user codes are unique and limited to 191
characters (see the [table change](#device-authorization-tables)).

**Smaller changes.** Last Login Method records `"email-otp"` for email OTP
sign-ins. Have I Been Pwned also checks an empty password. One Tap rejects a
token without an email with a 400.

### Storage and custom adapters {#storage-and-custom-adapters}

- **Schema check.** Only the SQLAlchemy adapter validates the schema. For a
  custom adapter, the server logs that validation is not available (a warning
  if you asked for it with `validate_schema=True`, a debug message otherwise).
- **Rate-limit counters.** Rate limiting decides each request in one atomic
  step. Secondary storage keeps a plain integer counter through the store's
  `increment`. A counter left in the 1.0 JSON format is replaced on its next
  request, which restarts that window once.
- **Secondary storage.** Implement `increment(key, ttl)` and
  `get_and_delete(key)` on your store. Without them, the older non-atomic path
  keeps working and logs a warning once. A custom rate-limit storage can
  implement `consume(key, rule)` to decide a request in one step.
- **OAuth state** is stored through the verification storage, so
  `VerificationOptions(store_identifier=...)` and secondary storage apply to
  it. With secondary storage and no database copy, sign-ins in progress during
  the upgrade must be restarted.
- **`InternalAdapter`.** `increment_one` raises `BetterAuthError` instead of
  `ValueError` when both `increment` and `set` are empty.
  `find_account_by_key` raises `BetterAuthError` when two rows share a key.
  `revoke_unproven_account_access` returns the updated user and marks the
  email verified itself. `create_user` accepts `source` and `ctx`, required
  once `validate_user_info` is configured.

## Python client {#python-client}

`better-auth-client` sends your keyword arguments as the request body, so the
changes are in what you pass, not in the method names.

**Account routes.** Read the account `id` from `list_accounts()` and pass it
as `accountId`:

```python
accounts = client.list_accounts()
github = next(a for a in accounts if a["providerId"] == "github")

# 1.0
client.get_access_token(providerId="github")

# 1.1
client.get_access_token(accountId=github["id"])
client.refresh_token(accountId=github["id"])
client.account_info(accountId=github["id"])
client.unlink_account(accountId=github["id"])  # needs a fresh session
```

**Generic OAuth providers.** Use the social methods with the provider id:

```python
# 1.0
client.sign_in.oauth2(providerId="my-idp", callbackURL="/app")
client.oauth2.link(providerId="my-idp", callbackURL="/settings")

# 1.1
client.sign_in.social(provider="my-idp", callbackURL="/app")
client.link_social(provider="my-idp", callbackURL="/settings")
```

`sign_in.oauth2` and `oauth2.link` only reach a server that sets
`legacy_routes=True`.

## Verify the upgrade

1. Start the app against a copy of your production database. With the
   SQLAlchemy adapter, a schema problem shows up in the log as
   `Database schema mismatch` followed by the missing tables and columns.
2. Sign in with a password, with each social provider you offer, and with
   Microsoft using an existing account. The Microsoft sign-in must land on the
   existing user, not create a new one.
3. Call `/list-accounts`, then `/get-access-token` with an `accountId`.
4. If you use Captcha, send a sign-up without a captcha token: it must be
   refused.
5. If you run the OAuth Provider plugin, run one authorization code flow and
   one refresh with a real client, and check that it reads profile claims from
   UserInfo.
