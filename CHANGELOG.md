# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

This release follows better-auth v1.7.6. Some defaults change and some
plugins need new tables or columns. Read
[Upgrade from 1.0 to 1.1](https://better-auth-py.oumarbarry.dev/migrate/from-1-0)
before upgrading: it lists the database migrations, the Microsoft account id
migration, and the options that keep 1.0 behavior.

### Added

#### Core

- `UserOptions.validate_user_info` lets the app refuse a user before it is
  created, an OAuth account link, or a returning OAuth sign-in. It also gates
  users created by email sign-up, the admin create-user route, anonymous
  sign-in, email OTP, magic link, phone number and SIWE. The hook receives the
  method that created the user.
- `/account-info` also returns the selected `account` (`id`, `providerId`,
  `accountId`).
- `AuthRequest.url`, filled by the FastAPI, Flask, Django and Litestar
  integrations.
- `AccountOptions(legacy_account_selection=True)` keeps the 1.0 account
  selection bodies (see Changed). The option is deprecated.
- `APIError` accepts an optional `headers` keyword, sent with the error
  response.
- `TokenEndpointAuth` is exported from `better_auth` and `better_auth.oauth`,
  and `is_password_compromised` from `better_auth.plugins_ext`.

#### Sessions and cookies

- `session.cookie_cache.strategy="jwt"`: the session cache cookie as an
  HS256 JWT signed with the secret, as better-auth does.
- `JWTPlugin(session_cookie_cache=True)` signs that cookie with the plugin's
  JWKS keys, so another service can check it with
  `better_auth.cookie_cache.verify_session_cookie_jwt_with_jwks`.
- Sign-out returns the provider logout URL (`url`, `redirect` and a
  `Location` header) when a linked provider offers `create_end_session_url`.
  The body takes `callbackURL`, `state` and `disableRedirect`.

#### Social sign-in

- Cloudflare provider.
- `MicrosoftEntraId(account_id_claim=...)`: the ID token claim used as the
  account id, `"oid"` by default. Microsoft Entra ID `client_assertion`.
- Google `include_granted_scopes` and `hd`, Cognito `identity_provider`,
  Discord `prompt` and `permissions`.
- Social sign-in and account linking accept `additionalParams` and
  `loginHint`.
- Token endpoint authentication with `private_key_jwt`, `none` or a custom
  request hook (`TokenEndpointAuth`).
- Per-provider `require_email_verification`: an unverified email gets no
  session and a verification email is sent.
- Providers can accept IdP-initiated callbacks (`allow_idp_initiated`).
- `add_oauth_server_context` and `get_oauth_state` carry server-trusted data
  across the provider redirect.
- Mapped provider profile fields (generic OAuth `map_profile_to_user`, SSO
  `mapping.extraFields`) fill configured user additional fields at sign-up,
  on profile override and when a link updates user info. A required
  additional field with no default and no value now stops an OAuth sign-up
  with `MISSING_FIELD`, as in better-auth.
- `ProviderConfig` gains `id_token_algorithms`, `id_token_max_age`,
  `callback_path` and `create_end_session_url` for custom providers.

#### Generic OAuth

- Generic OAuth providers work as regular social providers through
  `/sign-in/social`, `/callback/<id>` and `/link-social`.
- New provider options: `account_subject`, `end_session_endpoint`,
  `post_logout_redirect_uri`, `disable_provider_logout`,
  `token_endpoint_auth`, `refresh_token_params`,
  `require_email_verification`, `allow_idp_initiated`,
  `require_id_token_verification` and `disable_id_token_nonce_binding`.
- Presets for Slack, LINE, HubSpot, Gumroad, Patreon, Yandex and Microsoft
  Entra ID.
- `GenericOAuthPlugin(legacy_routes=True)` keeps the 1.0 routes
  `/sign-in/oauth2`, `/oauth2/callback/<id>` and `/oauth2/link`.

#### SSO

- Optional `resolve_user` callback that picks, links or rejects the user
  inside the same database transaction as the account link and the session.
- `guard_provider_mutation` callback to approve or refuse provider updates
  and deletions.
- `private_key_jwt` token endpoint authentication, with keys from
  `resolve_private_key` or a `defaultSSO` entry.
- IdP-initiated sign-in with `oidcConfig.allowIdpInitiated`,
  `additionalParams` on `/sign-in/sso`, and
  `schema.ssoProvider.additionalFields` for extra provider columns.
- `legacy_mapping_id=True` keeps account ids read from `mapping.id`.

#### OAuth provider

- `private_key_jwt` client authentication (RFC 7523). Keys come from the
  client's `jwks` or `jwksUri`; each assertion `jti` works once, tracked in
  the new `oauthClientAssertion` table.
- `refresh_token_reuse_interval` lets a client retry a refresh with the
  previous token for a few seconds and get the same response.
- ID tokens carry `at_hash`; JWT access tokens carry `typ: at+jwt`,
  `client_id` and `jti`. Discovery lists `private_key_jwt` and its signing
  algorithms.
- Protected resources. Configure `resources`, or manage them with the new
  server-side admin methods. Each resource sets token lifetimes, allowed
  scopes, custom claims, a signing key pin and a DPoP requirement, and can be
  limited to linked clients.
- DPoP (RFC 9449). A DPoP proof at the token endpoint binds tokens to the
  client key (`token_type: DPoP`, `cnf.jkt`); UserInfo and introspection
  enforce and report the binding.
- OIDC back-channel logout. Ending a session revokes its OAuth tokens and
  notifies clients that registered a back-channel logout URI, after the
  session deletion commits.
- The `claims` request parameter, form POST at `/oauth2/authorize`, and
  `max_age` enforcement.
- Client fields from better-auth 1.7.6: application type, back-channel
  logout URI, inline JWKS or JWKS URI, DPoP-bound tokens and client discovery
  id.
- Protected dynamic client registration with an RFC 7591 initial access token
  (`validate_initial_access_token`).
- Dynamic registration can link protected resources
  (`client_registration_default_resources`,
  `client_registration_allowed_resources`) and can let confidential clients
  skip PKCE (`client_registration_require_pkce=False`).
- Admin client create and update accept `client_credentials_scopes`.
- `OAuthDeviceAuthorizationPlugin`: the RFC 8628 device grant for OAuth
  clients, exchanged at `/oauth2/token` and advertised in discovery.
- OAuth provider: `POST /oauth2/end-session/confirm` and the options
  `resources`, `resource_seed_mode`, `cached_resources`,
  `enforce_per_client_resources`, `identifier_validator`,
  `resource_privileges`, `dpop`, `refresh_token_reuse_interval` and
  `assertion_max_lifetime`. Without `resource_privileges`, any signed-in user
  may call the server-side resource admin methods, as in better-auth.

#### Plugins

- Two-factor: `/two-factor/enable` takes `method: "otp"` to turn on email or
  SMS codes without an authenticator app. OTP-only accounts can sign in
  without a `twoFactor` row.
- Phone number: `consume_phone_number_otp(phone_number, code)` checks and
  burns an OTP on the server without a session.
- Captcha: Vercel BotID provider (`provider="vercel-botid"`), and `*` and
  `**` wildcards in `endpoints`.
- Have I Been Pwned: `is_password_compromised(password)` helper.
- OAuth proxy: social account linking through `/link-social`.
- SIWE: `accept_legacy_wallet_fields=True` accepts and ignores the
  `walletAddress`, `address` and `chainId` fields older clients send.
- Organization: `GET /organization/get-organization` returns the
  organization without members or invitations.
- Organization: `list-user-teams` accepts `userId` and `organizationId`, so a
  caller with the `member:update` permission can list another member's teams.
- Admin: `banned_user_message` may be a sync or async function of the banned
  user.
- Username: `immutable_username=True` refuses changing a username once set,
  and `display_username=False` drops the `displayUsername` field.
- Passkey: `verify-registration` accepts `createSession: true` to sign the
  user in after registering.
- Device authorization accepts form-encoded requests, rate limits `/device`
  and shows the client and scope to the code owner.

#### Database

- SQLAlchemy adapter schema check, on by default: on first use it checks that
  every table and column Better Auth writes exists and that no required
  column is one Better Auth never fills. On a mismatch it logs one report and
  database operations fail with `SchemaMismatchError`. Turn it off with
  `AdvancedDatabase(validate_schema=False)`.
- The server logs when the database adapter cannot validate the schema: a
  warning if validation was requested explicitly, a debug message otherwise.
- `consume_one` and `increment_one` run as a single statement on PostgreSQL
  and SQLite.
- Custom rate-limit storages can implement `consume(key, rule)` to decide a
  request in one atomic step.
- `InternalAdapter.reserve_verification_value`: a first-writer-wins insert
  keyed by an id derived from the identifier (the same id as better-auth).
  It backs the lock used by the unverified-account cleanup.
- OAuth provider schema, run your migrations: new tables `oauthResource`,
  `oauthClientResource` and `oauthClientAssertion`; new columns
  `oauthClient.clientDiscoveryId`, `clientCredentialsScopes`,
  `backchannelLogoutUri`, `backchannelLogoutSessionRequired`,
  `applicationType`, `jwks`, `jwksUri` and `dpopBoundAccessTokens`;
  `oauthConsent.resources` and `requestedUserInfoClaims`;
  `oauthRefreshToken.authorizationCodeId`, `resources`,
  `requestedUserInfoClaims`, `rotatedAt`, `rotationReplayResponse`,
  `rotationReplayExpiresAt` and `confirmation`; and
  `oauthAccessToken.authorizationCodeId`, `resources`,
  `requestedUserInfoClaims`, `revoked` and `confirmation`.
- Organization: `team.memberCount` and `teamMember.membershipKey` columns
  back atomic team capacity checks. Both are internal and never returned.
  Run your migrations; existing teams resync their count on the next join.
- Device authorization: `deviceCode.oauthClientId` and `resources` columns,
  used by `OAuthDeviceAuthorizationPlugin`.

### Changed

#### Core

- `/unlink-account`, `/get-access-token`, `/refresh-token` and
  `/account-info` pick the account by its Better Auth id (`accountId` from
  `/list-accounts`) or `useAccountCookie: true`, as better-auth 1.7 does. A
  `providerId` body is refused with `INVALID_BODY`, and `/unlink-account`
  needs a fresh session. This port does not store the account cookie, so
  `useAccountCookie: true` finds no account. To keep the 1.0 bodies (`providerId` with an
  optional provider `accountId`) while clients migrate, set
  `AccountOptions(legacy_account_selection=True)`. The option is deprecated.
- `/refresh-token` returns the account row id as `accountId`.
- `/set-password` fills an existing credential account that has no password,
  and reports `PASSWORD_ALREADY_SET` (was `USER_ALREADY_HAS_PASSWORD`) when
  one is set.
- The credential account is the one whose `accountId` is the user id.
- Magic-link and email OTP sign-in to an unverified user now delete every
  account linked to that user (OAuth links too, not only the password) and
  its sessions, then mark the email verified. The cleanup runs under a lock
  stored as a verification row. `InternalAdapter.revoke_unproven_account_access`
  returns the updated user, and callers no longer update `emailVerified`
  themselves.
- `InternalAdapter.create_user` accepts `source` and `ctx`. Both are required
  once `validate_user_info` is configured.
- A custom-scheme trusted origin that names a host only matches that host;
  paths are compared after decoding and resolving `..`.
- Relative callback URLs may carry fragments, `~` and other path characters.
- The origin check error messages match better-auth.

#### Sessions and cookies

- `trusted_proxy_headers` is off by default, as in better-auth 1.7. Behind a
  proxy that sends the public host in `X-Forwarded-Host` and
  `X-Forwarded-Proto` (dynamic `base_url`, or forms posted with
  `Origin: null`), set `trusted_proxy_headers=True` and make sure the proxy
  overwrites those headers from clients.
- `/sign-out` answers `{"success": true}` without a session and also expires
  the session cache cookie.

#### Social sign-in

- Microsoft Entra ID accounts are identified by the `oid` claim instead of
  `sub`, as in better-auth 1.7. Existing `account` rows for the `microsoft`
  provider hold `sub` values and no longer match, so a returning user is
  treated as a new sign-in (implicit linking by email, or a refusal). Migrate
  those rows to `oid` before upgrading, or pass
  `MicrosoftEntraId(account_id_claim="sub")` to keep the old ids. A token
  without a usable claim is refused with `unable_to_get_user_info`.
- OAuth sign-in resolves an account only by its exact
  `(providerId, accountId)` pair. When two `account` rows share that pair,
  sign-in is refused and no session is issued. Before, the first row found
  won. This failure, like a failed user lookup during OAuth sign-in,
  redirects to `on_api_error.error_url` (default `<base path>/error`) with
  `error=internal_server_error`, not to the flow's error callback URL.
  Remove the duplicate rows to restore sign-in for that account.
  `InternalAdapter.find_account_by_key` raises `BetterAuthError` for the same
  case.
- An OAuth account whose user row no longer exists is refused with
  `unable_to_link_account` instead of signing in a missing user. Repair or
  delete the orphaned `account` row.
- The link-social callback reports `unable_to_link_account` (was
  `account_not_linked`) for an untrusted provider with an unverified email,
  and `email_does_not_match` (was `email_doesnt_match`) for a different
  email, matching better-auth. Relinking an account the user already owns
  now refreshes its tokens.
- Linking with an ID token (`POST /link-social` with `idToken`) returns
  `409 SOCIAL_ACCOUNT_ALREADY_LINKED` when the provider account belongs to
  another user. Before, it answered success without linking. Relinking your
  own account refreshes its tokens. The new account row no longer stores the
  `scopes` sent with the ID token, as in better-auth 1.7.
- ID token sign-in (`POST /sign-in/social` with `idToken`) no longer stores
  the `idToken.scopes` or `idToken.refreshToken` sent by the client on the
  account, as in better-auth.
- `account.scope` holds the granted scopes as a comma-separated list, as
  better-auth stores it. Sign-in after the first one no longer rewrites it,
  `/refresh-token` no longer rewrites it and returns the stored value, and
  the link-social callback adds new scopes to the stored ones. Rows written
  space-separated by earlier releases are still read correctly.
- The OAuth callback answers a missing state with `state_not_found` and every
  other state failure with `state_mismatch`, and redirects to the error page
  unless the flow set an error callback URL.
- OAuth state rows are stored through the verification storage, so
  `verification.store_identifier` and secondary storage apply to them. With
  secondary storage and no database copy, sign-ins in progress during the
  upgrade must be restarted.
- ID tokens go through one shared verifier. Google accepts RS256 only, tries
  every key with the token's `kid`, reads the callback profile from the ID
  token and no longer sends a nonce.
- Google sends `include_granted_scopes=true` unless
  `include_granted_scopes=False`.
- Facebook sign-in with an opaque token reads the identity from
  `idToken.accessToken` and answers `401 FAILED_TO_GET_USER_INFO` without it.
  Limited Login tokens must be RS256.
- Discord uses the `/api/oauth2/authorize` endpoint and sends `prompt=none`
  unless `prompt` is set.
- PayPal ID token sign-in is off by default (`legacy_id_token_sign_in=True`
  restores it).
- Placeholder emails use the `<id>@<provider>.placeholder.invalid` form for
  new users of providers that return no email. Twitter (X), TikTok and Roblox
  use it instead of the username, and Reddit instead of `<id>@reddit.invalid`.
- LINE takes the account id from the `sub` claim only.
- Reddit requests send the `better-auth` User-Agent.
- Reserved OAuth parameters can no longer be overridden through extra
  authorization or refresh parameters, and Basic client credentials are form
  encoded as RFC 6749 requires.
- One Tap rejects a token without an email with a 400.
- OAuth state stores the client's `additionalData` keys at the top level, like
  better-auth. States written before the upgrade are still read. Code that
  read `get_oauth_state(ctx)["additionalData"]` reads the keys directly.
- A user created through OAuth without a provider name gets an empty name
  instead of the email.
- GitHub sign-in uses PKCE and sends the `better-auth` User-Agent.
- Only the providers that forward `loginHint` upstream in better-auth still
  send `login_hint`.
- PayPal uses PKCE and client_secret_basic, and no longer sends
  `accept-language`. Paybin and GitLab check the `iss` callback parameter.
  Kakao refuses a profile without an id.

#### Generic OAuth

- The `/sign-in/oauth2`, `/oauth2/callback/<id>` and `/oauth2/link` routes
  are replaced by the social routes, and the default redirect URI is
  `<base>/callback/<id>`. Update the redirect URI registered with each
  provider, or set `legacy_routes=True`. PKCE is on by default (`pkce=False`
  restores the old default), discovery ID tokens are verified with a nonce,
  and `map_profile_to_user` can no longer change the account id (use
  `account_subject`).
- Callback error codes follow better-auth: `invalid_code`,
  `unable_to_get_user_info`, `email_not_found`, `email_does_not_match`.

#### SSO

- The account id is always the `sub` claim; `mapping.id` is ignored unless
  `legacy_mapping_id` is set.
- Callback and state error codes match better-auth 1.7.6 (`state_not_found`,
  `state_mismatch`, and messages such as `account not linked`). SSO sign-ins
  started before the upgrade must be restarted.
- Provider updates and deletions lock the provider row in a transaction, and
  a mapping change no longer counts as an identity change.

#### OAuth provider

- A client must authenticate with the method it registered (default
  `client_secret_basic`). `bind_client_auth_method=False` keeps the old
  leniency between Basic and post.
- The `client_credentials` grant uses the client's `clientCredentialsScopes`.
  With `client_credential_grant_default_scopes` configured, clients without
  them keep the previous rules.
- Token, introspection and revocation errors match better-auth 1.7.6. For
  example an invalid authorization code is a 400 `invalid_grant`, a failed
  Basic login gets a `WWW-Authenticate: Basic` challenge, and sending two
  client authentication methods is refused.
- Offline access no longer needs PKCE when an OpenID request sends a nonce.
- Introspection reports tokens of an ended session as inactive and adds
  `token_type`.
- ID tokens carry protocol claims only (`acr` is "0"), and profile and email
  claims come from UserInfo, as in better-auth 1.7. Set
  `legacy_id_token_profile_claims=True` (deprecated) to keep the scope-based
  profile and email claims in the ID token. Custom ID token claims cannot
  replace protocol claims.
- A requested `resource` must be a configured resource, linked to the client
  unless `enforce_per_client_resources=False`. The base URL is no longer
  accepted as an audience by default: configure `resources`, or list legacy
  audiences in `valid_audiences` (deprecated).
- Resource indicators are bound to the authorization grant; token and refresh
  requests can narrow them but never widen them.
- Invalid authorization requests redirect to the client's registered
  redirect URI with an RFC 6749 error, and `state` is optional.
- `/oauth2/end-session` accepts GET and POST, no longer requires
  `id_token_hint`, and asks the user to confirm when there is no usable hint.
- The social sign-in resume uses the server-trusted OAuth state, so a client
  can no longer inject its own authorization query.
- A client is public only when its token endpoint auth method is `none`; the
  `type` and `public` columns are no longer used. Clients created by 1.0
  endpoints already follow this rule.
- Redirect URIs follow the client application type (default `web`): web
  clients need HTTPS on a public host, native clients may use loopback HTTP
  or a reverse-domain scheme. Existing clients keep working until they are
  updated; a client using an HTTP loopback redirect must be updated with
  `application_type: "native"`.
- Loopback redirect URIs on `localhost` may use any port, like IP loopback
  addresses.
- Unauthenticated dynamic registration defaults to a confidential
  `client_secret_basic` client, stores the configured registration scope set,
  and drops unknown top-level fields instead of keeping them in `metadata`.
- Registration, client creation, secret rotation and device endpoints send
  `Cache-Control: no-store`, errors included.

#### Plugins

- Captcha `endpoints` rules match full paths instead of substrings. A rule
  such as `/sign-up` no longer covers `/sign-up/email`; write
  `/sign-up/email` or `/sign-up/**`. Check custom rules before upgrading, or
  those routes stop requiring a captcha. The default rules are unaffected.
- SIWE: nonces are issued before the wallet is known and stored as
  `siwe:<nonce>`; address and chain id come from the signed message. The
  nonce and verify endpoints reject unknown body fields (see
  `accept_legacy_wallet_fields`). Nonces issued before the upgrade stop
  working. New wallet users get `<address>@siwe.placeholder.invalid` unless
  `email_domain_name` is set.
- OAuth proxy: proxied sign-ins complete on
  `/callback/{provider}/oauth-proxy`, so callback hooks run.
  `/oauth-proxy-callback` still works but is deprecated. Generic OAuth
  `/sign-in/oauth2` is no longer proxied.
- Two-factor: enabling TOTP again after it is verified returns
  `TOTP_ALREADY_ENABLED`. An unfinished enrollment is restarted in place.
- Phone number: `allowed_attempts=0` now means zero attempts.
- Last login method records `"email-otp"` for email OTP sign-ins.
- Have I Been Pwned: an empty password is checked too, and a failed lookup
  reports the HTTP status.
- Anonymous: the default placeholder email is
  `<id>@anonymous.placeholder.invalid` (was `temp@<id>.com`) for new
  anonymous users. `email_domain_name` still overrides it.
- Device authorization: device codes and user codes are unique and limited to
  191 characters.

#### Database

- A database schema mismatch now fails every auth request, including routes
  that never touch the database, as better-auth does.
  `AdvancedDatabase(validate_schema=False)` turns the check off.
- Rate limiting decides each request in one atomic step per backend.
  Secondary storage uses the store's `increment` and keeps a plain integer
  counter whose expiry is set when the window opens, as better-auth 1.7 does.
  A counter left in the older JSON format is replaced on its next request,
  which restarts that window. Database counters use guarded updates and prune
  expired rows when a window resets. A window now resets exactly when it has
  elapsed.
- A secondary storage without `increment` or `get_and_delete`, or a custom
  rate-limit storage with only `get` and `set`, keeps working through the
  older non-atomic path and logs a warning once.
- `increment_one` raises `BetterAuthError` instead of `ValueError` when both
  `increment` and `set` are empty.

### Fixed

#### Core

- Password reset for a deleted user fails with `USER_NOT_FOUND`.
- `GET /reset-password/{token}` redirects with `error=INVALID_TOKEN` for an
  unknown or expired token instead of forwarding it.
- A sign-up stopped by a database hook fails with `FAILED_TO_CREATE_USER`
  and leaves no account row.
- The email sign-up response reflects changes made by user database hooks.
- Deleting a user or its sessions no longer drops cached sessions when a hook
  vetoes the delete, and keeps sessions created while it runs.
- Error redirects keep the fragment of the callback or error URL.
- A form posted with `Origin: null` from the same origin is accepted when
  Fetch Metadata confirms it.
- Email OTP sign-in returns the user with `emailVerified: true` after it
  verifies a previously unverified address.
- `scopes` in `/list-accounts` and `/get-access-token` are trimmed and empty
  entries dropped.
- The session guard answers a missing session with the message
  `Unauthorized`, as better-auth does (was `Not authenticated`).

#### Sessions and cookies

- The session cache cookie is only used with the session cookie it was
  issued for. A foreign, expired or tampered cache cookie is expired, a
  leftover one is cleared when the cache is off, and invalid payloads log a
  warning.
- Sign-up, sign-in and other session creations write the cache cookie;
  profile and session updates refresh it.
- Email OTP verification, email change and organization session updates set
  the cookie cache when the JWT plugin signs it with JWKS keys.

#### Social sign-in

- A new OAuth user and its first account are created in one transaction. If
  the account insert fails, no user row is left behind and the callback
  redirects with `unable_to_create_user`.
- Signing in again with a provider that omits a token (for example no
  refresh token) keeps the stored value instead of clearing it.
- With `override_user_info_on_sign_in`, a user update that returns nothing
  keeps the existing user for the session and logs a warning.
- A provider response with an empty account id is refused
  (`unable_to_get_user_info` on the callback, `401 FAILED_TO_GET_USER_INFO`
  for ID token sign-in) instead of creating an account with an empty id.
- Linking with an ID token and a different email now answers with the
  better-auth message `Account not linked - different emails not allowed`.
- Provider sign-up restrictions (`disable_sign_up`,
  `disable_implicit_sign_up`) now apply on the redirect callback.
- Errors raised by database or session hooks during an OAuth callback
  redirect with their own code and message.
- The account-link branch of the callback runs before the email check, as in
  better-auth.
- OAuth sign-in reports `unable_to_update_account` when a hook refuses the
  account update.
- `/account-info` answers `FAILED_TO_GET_USER_INFO` instead of a server error
  when the provider returns no profile.
- Salesforce, Figma, Atlassian, Facebook, Microsoft and Cognito refuse to
  start sign-in without the required client credentials.
- `/account-info` returns 401 `FAILED_TO_GET_USER_INFO` instead of 500 when
  the provider profile call fails.
- Signing in again with `override_user_info_on_sign_in` no longer clears the
  stored image when the provider sends none.

#### SSO

- A sign-in is refused with `SSO_PROVIDER_CHANGED` when its provider changes
  between sign-in and callback or during the account link.
- When both are present, the ID token is always verified and must match the
  userinfo subject.
- Server-side OIDC fetches refuse redirects with `oidc_endpoint_redirect`.
- The provider table declares its `id` column, so SSO works with the
  SQLAlchemy adapter.
- An expired invitation no longer blocks automatic organization membership.

#### OAuth provider

- Reusing an authorization code revokes the tokens already issued for it.
- Revoking a JWT access token reports `unsupported_token_type` instead of a
  silent success.
- UserInfo answers an invalid token with a 401 `invalid_token` Bearer
  challenge, accepts the access token in a form body and returns no-store
  responses.
- HTTP Basic client credentials are URL-decoded and the scheme name is
  case-insensitive.
- A numeric `client_registration_client_secret_expiration` is used as the
  expiry time itself, as in better-auth.
- Redirect URIs that carry credentials no longer count as loopback.
- OAuth provider client get, list and update responses keep
  `client_secret_expires_at`.
- Authorization errors on client registration, client creation, secret
  rotation and the device code and token routes send `Cache-Control: no-store`.

#### Plugins

- Two-factor: the account lock is written only while the failure count is
  still at the limit, and a challenge that cannot be cancelled returns
  `FAILED_TO_INVALIDATE_TWO_FACTOR_CHALLENGE` instead of being ignored.
- Phone number: a corrupt attempt counter no longer causes a server error.
- SIWE: a caller email is claimed through a short reservation, so two
  wallets cannot take the same email at once.
- Have I Been Pwned: padded zero-count entries no longer flag a password.
- Magic link: a refused user creation redirects to the error URL with the
  error code.
- Organization: accepting an invitation and rolling it back use a guarded
  compare-and-set, so a losing concurrent accept is no longer reported as a
  success.
- Organization: `update-member-role` checks that the role exists only after
  the permission check, so an unauthorized caller cannot probe role names.
- Passkey: registration and authentication challenges require an exact
  ceremony type match.
- Captcha: `check_bot_id` accepts a synchronous function.

#### Database

- Custom adapters without native atomic methods no longer lose concurrent
  `increment_one` updates: the shared fallback guards on the counter values
  and retries up to five times.
- A failed memory adapter transaction no longer erases writes made
  concurrently outside it.

## [1.0.4] - 2026-09-29

### Fixed

- SQLAlchemy adapter: plugin tables (two-factor, API keys, passkeys, device
  authorization, Sign-In with Ethereum wallets, OAuth provider and others)
  get their `id` primary key. Before, inserts into them failed, and
  `create_tables()` failed outright when the OAuth provider plugin was
  installed. Plugin tables created by an earlier release have no `id` column
  and could never hold rows: drop them and run `create_tables()` again, or add
  an `id` text primary key in your migration.
- SQLAlchemy adapter: string columns use `TEXT` on PostgreSQL and SQLite, as
  better-auth does, so long values such as encrypted backup codes fit. On
  MySQL, ids and foreign keys are `VARCHAR(36)`, unique or indexed strings
  `VARCHAR(255)`, and other strings `TEXT`. Existing columns are not changed.

## [1.0.3] - 2026-09-25

### Fixed

- Single-use values (magic links, one-time tokens, email and phone OTP codes,
  two-factor challenges, password reset and account deletion tokens, device
  codes) can no longer be used twice when two requests race on a database
  shared by several processes. Consuming one now deletes the row by id and
  succeeds only for the request that actually removed it, as better-auth
  does.
- Password reset and account deletion tokens are stored and read through the
  verification storage, so they follow `verification.store_identifier` and
  secondary storage like other verification values.
- An expired account deletion link is rejected with `INVALID_TOKEN` instead
  of deleting the account.
- Database hooks on `verification` deletes run once, for the consumed row. A
  `before` hook that returns `False` now stops the consume.
- A guarded counter update changes only the row it read, even when the
  condition matches several rows.

## [1.0.2] - 2026-09-25

### Fixed

- Sign-in with email rejects a malformed address with `INVALID_EMAIL` (400)
  before looking up the user, as better-auth does.
- Passwords longer than `max_password_length` are now rejected with
  `PASSWORD_TOO_LONG` before any hashing on sign-in (email, username, phone
  number), verify-password, change-password (`currentPassword`), delete-user,
  the two-factor endpoints that take a password, and admin create-user.
  Sign-up and password reset already did this. Matches better-auth #11324.
- The `PASSWORD_TOO_SHORT` and `PASSWORD_TOO_LONG` messages now read
  "Password too short" and "Password too long", the same strings as
  better-auth.
- The captcha plugin logs a warning when Cloudflare Turnstile rejects a token,
  with the error codes or the action or hostname that did not match.
- Readme links are absolute, so they also work on the PyPI project page.

## [1.0.1] - 2026-09-04

### Fixed

- Package metadata and readme now link to the documentation site at its
  current address.

## [1.0.0] - 2026-09-04

First public release of `better-auth-server`, the server-side Python port of
[better-auth](https://github.com/better-auth/better-auth).

### Added

- Wire and storage parity with better-auth (TypeScript) v1.6.29: same routes,
  JSON bodies, error codes, camelCase database columns and token encodings, so a
  Python server and a TypeScript one can share a database.
- Email and password sign-up and sign-in, email verification, password reset,
  account management and user deletion.
- Sessions stored in your database with signed cookies, sliding expiry, an
  optional signed cookie cache, bearer tokens for API clients, and list and
  revoke endpoints.
- 35 social sign-in providers with PKCE, token refresh, id-token verification
  and account linking, plus custom providers declared as one dataclass.
- 26 plugins: two-factor authentication, admin, organization with teams and
  dynamic access control, API keys, passkeys, JWT, an OAuth 2.1 authorization
  server, SSO over OIDC, generic OAuth, device authorization, Sign-In with
  Ethereum, magic link, email OTP, phone number, username, anonymous sessions,
  multi-session, one-time tokens, Google One Tap, OAuth proxy and more.
- Adapters: in-memory for development and tests, SQLAlchemy 2 async for SQLite,
  PostgreSQL and MySQL. A custom adapter implements nine async methods.
- Secondary storage protocol, rate limiting with database or key-value backends,
  trusted-proxy client IP resolution, secret rotation through a versioned
  secret configuration.
- Integrations for FastAPI, Litestar, Flask and Django.
- Security defaults: scrypt password hashing, CSRF origin checks, open-redirect
  protection on every callback URL, timing-equalized sign-in, XChaCha20-Poly1305
  encryption for stored secrets, compatible with the TypeScript implementation.
