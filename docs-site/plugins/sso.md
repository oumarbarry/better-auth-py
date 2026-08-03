---
title: SSO (OIDC)
---

# SSO (OIDC)

OIDC federation: register external identity providers per domain or
organization and route `/sign-in/sso` to the right one, with SSRF-guarded
discovery, optional DNS TXT domain verification and user/organization
provisioning. Mirrors the OIDC half of the TS `@better-auth/sso` plugin — SAML
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
| `provision_user` | `callable \| None` | `None` | `(payload) -> None`, runs when a user is provisioned. |
| `provision_user_on_every_login` | `bool` | `False` | Re-run provisioning on every login. |
| `organization_provisioning` | `dict \| None` | `None` | Auto-assign users to an organization on SSO login. |
| `trust_email_verified` | `bool` | `False` | Trust the IdP's `email_verified` claim. |
| `disable_implicit_sign_up` | `bool` | `False` | Never create users implicitly on SSO sign-in. |
| `resolve_host` / `dns_resolver` | `callable \| None` | `None` | Test seams for the SSRF guard and DNS lookups. |

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

## Schema

| Table | Columns |
| --- | --- |
| `ssoProvider` | `issuer`, `oidcConfig`, `samlConfig`, `userId`, `providerId`, `organizationId`, `domain` (+ `domainVerified` when `domain_verification` is enabled) |

## Notes

- `samlConfig` is retained as a nullable column for cross-runtime DB
  compatibility only; a `providerType: "saml"` registration body is rejected.
- `clientSecret` is stored in the `oidcConfig` JSON in plaintext — a deliberate
  cross-runtime contract (the secret is needed cleartext at every token
  exchange); it is masked on read.
- For a single hand-configured OAuth2/OIDC provider without per-domain
  routing, [Generic OAuth](./generic-oauth) is the lighter tool.
