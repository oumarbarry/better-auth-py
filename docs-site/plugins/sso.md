---
title: SSO (OIDC)
---

# SSO (OIDC)

OIDC federation: register external identity providers per domain or
organization and route `/sign-in/sso` to the right one, with SSRF-guarded
discovery, optional DNS TXT domain verification and user/organization
provisioning. Mirrors the OIDC half of the TS `@better-auth/sso` plugin. SAML
is out of scope in this port.

## Enable

```python
from better_auth import BetterAuth
from better_auth.plugins_ext import SSOPlugin

auth = BetterAuth(
    secret="a-strong-32-character-minimum-secret",
    plugins=[SSOPlugin(trust_email_verified=False)],
)
```

::: warning Changed in 1.1
The account id is always the ID token `sub` claim. `oidcConfig.mapping.id` is
ignored unless `legacy_mapping_id=True`. Callback and state error codes
changed (see [Errors](#errors)), and SSO sign-ins started before the upgrade
must be restarted. See [Upgrade from 1.0](/migrate/from-1-0).
:::

## Options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `providers_limit` | `int \| callable \| None` | `None` | Max providers a user may register. |
| `default_override_user_info` | `bool` | `False` | Overwrite user fields from the IdP on every login by default. |
| `default_sso` | `list[dict] \| None` | `None` | Statically configured providers (no DB row). |
| `domain_verification` | `dict \| None` | `None` | Enable DNS TXT domain verification (needs the `sso` extra: `dnspython`). |
| `redirect_uri` | `str \| None` | `None` | Override the callback URL registered with IdPs. |
| `model_name` | `str \| None` | `None` (`"ssoProvider"`) | Table name override. |
| `fields` | `dict[str, str] \| None` | `None` | Column-name overrides. |
| `schema` | `dict \| None` | `None` | `{"ssoProvider": {"modelName", "fields", "additionalFields"}}`. `additionalFields` adds provider columns (see below). |
| `provision_user` | `callable \| None` | `None` | `(payload) -> None`, runs when a user is provisioned. |
| `provision_user_on_every_login` | `bool` | `False` | Re-run provisioning on every login. |
| `organization_provisioning` | `dict \| None` | `None` | Auto-assign users to an organization on SSO login. |
| `trust_email_verified` | `bool` | `False` | Trust the IdP's `email_verified` claim. |
| `disable_implicit_sign_up` | `bool` | `False` | Never create users implicitly on SSO sign-in. |
| `resolve_user` | `callable \| None` | `None` | Picks, links or rejects the user for each sign-in (see below). |
| `guard_provider_mutation` | `callable \| None` | `None` | Approves or refuses provider updates and deletions (see below). |
| `resolve_private_key` | `callable \| None` | `None` | Returns the signing key for `private_key_jwt` providers (see below). |
| `legacy_mapping_id` | `bool` | `False` | Read the account id from `oidcConfig.mapping.id`, as in 1.0. Only for providers whose accounts were linked under a custom id. |
| `resolve_host` / `dns_resolver` | `callable \| None` | `None` | Test seams for the SSRF guard and DNS lookups. |

### Resolving the user

`resolve_user(input, context)` runs on every sign-in, after the ID token is
verified, inside the same database transaction as the account link and the
session. It may be async. `input` holds `protocol` (`"oidc"`), `providerId`,
`accountKey`, `providerUser`, `providerClaims`, `verifiedIdTokenClaims` and
`providerReference`. `context["database"]` is the transaction adapter. Return
one of:

- `{"action": "continue"}`: the normal sign-in.
- `{"action": "link", "userId": ..., "profile": "preserve"}` (or
  `"update"`): link the account to that user.
- `{"action": "reject", "code": ..., "message": ...}`: refuse the sign-in
  with your error code.

It needs a database adapter with native transactions and database-backed
sessions. The provider must return an ID token. A resolver that raises or
returns something else fails the sign-in with `SSO_USER_RESOLUTION_FAILED`.

```python
async def resolve_user(input, context):
    if input["providerId"] != "workforce":
        return {"action": "continue"}
    user_id = await find_provisioned_user(
        context["database"], input["accountKey"]
    )
    if user_id is None:
        return {"action": "reject", "code": "PROVISIONED_USER_NOT_FOUND"}
    return {"action": "link", "userId": user_id, "profile": "preserve"}
```

### Guarding provider changes

`guard_provider_mutation(input, context)` runs on the locked provider row
before `/sso/update-provider` and `/sso/delete-provider` write. `input` holds
`action` (`"update"` or `"delete"`), `isAuthenticationBoundaryChange` (for
updates), `provider` (`id`, `providerId`, `organizationId`) and
`providerReference`. Raise to refuse: the request fails with 409
`SSO_PROVIDER_MUTATION_REJECTED`. It needs a database adapter with native
transactions.

### Private key JWT

A provider with `oidcConfig.tokenEndpointAuthentication: "private_key_jwt"`
signs a client assertion instead of sending a secret. `privateKeyId` and
`privateKeyAlgorithm` in `oidcConfig` pick the key. The key itself never goes
in the database: put it in the provider's `default_sso` entry as
`privateKey`, or return it from `resolve_private_key`, which receives
`{"providerId", "keyId", "issuer"}`. Both use the shape
`{"privateKeyJwk" or "privateKeyPem", "kid", "algorithm"}`. Registering such a
provider without a key source is refused.

### IdP-initiated sign-in

Set `allowIdpInitiated: True` in the `oidcConfig` of a `default_sso` entry to
accept a callback the IdP starts without `state`. The callback discards the
IdP code and starts a new flow with fresh state and PKCE, then sends the user
to your `base_url`. `/sso/register` does not store this flag.

### Extra provider columns

```python
from better_auth import Field

SSOPlugin(
    schema={
        "ssoProvider": {
            "additionalFields": {
                "tier": Field(type="string", required=False),
            },
        },
    },
)
```

Additional fields are accepted by `/sso/register` and `/sso/update-provider`
and returned with the provider. A field with `input=False` is refused in a
request body. A key or column name that collides with a built-in field fails
at startup.

## Endpoints

| Method | Path |
| --- | --- |
| POST | `/sign-in/sso` |
| GET | `/sso/callback/{providerId}` |
| GET | `/sso/callback` |
| POST | `/sso/register` |
| GET | `/sso/providers` |
| GET | `/sso/get-provider` |
| POST | `/sso/update-provider` |
| POST | `/sso/delete-provider` |
| POST | `/sso/request-domain-verification` (with `domain_verification`) |
| POST | `/sso/verify-domain` (with `domain_verification`) |

`/sign-in/sso` accepts `additionalParams`, a dict of strings added to the
authorization URL. Reserved OAuth parameters (`state`, `client_id`,
`redirect_uri`, `response_type`, `code_challenge`, `code_challenge_method`,
`nonce`, `scope`) are refused.

## Errors

The callback redirects to the flow's error URL with `error` and
`error_description`. A missing `state` gives `state_not_found`, any other
state failure `state_mismatch`. Account-link failures use the better-auth
wording, for example `error=account not linked`. Provider problems use
`error=invalid_provider` with a description such as `token_not_verified`,
`id_token_userinfo_subject_mismatch` or `no_private_key_available`.

| Code | When |
| --- | --- |
| `SSO_PROVIDER_CHANGED` (409) | The provider changed between sign-in and callback, or during the account link. |
| `SSO_PROVIDER_MUTATION_REJECTED` (409) | `guard_provider_mutation` refused the change. |
| `SSO_USER_RESOLUTION_FAILED` (500) | `resolve_user` raised or returned an invalid decision. |
| `oidc_endpoint_redirect` | A configured OIDC endpoint answered with a redirect. Server-side fetches never follow redirects: configure the final URL. |

When both an ID token and UserInfo are available, the ID token is always
verified and its `sub` must match the UserInfo subject.

## Schema

| Table | Columns |
| --- | --- |
| `ssoProvider` | `id`, `issuer`, `oidcConfig`, `samlConfig`, `userId`, `providerId`, `organizationId`, `domain` (+ `domainVerified` when `domain_verification` is enabled, + your `additionalFields`) |

## Notes

- Provider updates and deletions lock the provider row in a transaction. A
  `mapping` change no longer counts as an identity change.
- `samlConfig` is retained as a nullable column for cross-runtime DB
  compatibility only; a `providerType: "saml"` registration body is rejected.
- `clientSecret` is stored in the `oidcConfig` JSON in plaintext: a deliberate
  cross-runtime contract (the secret is needed cleartext at every token
  exchange); it is masked on read.
- For a single hand-configured OAuth2/OIDC provider without per-domain
  routing, [Generic OAuth](./generic-oauth) is the lighter tool.
