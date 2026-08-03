---
title: Generic OAuth
---

# Generic OAuth

Sign in with any OAuth2/OIDC provider that is not in the built-in registry,
configured at runtime — point it at a discovery URL or spell out the endpoints.
Mirrors the TS `genericOAuth()` plugin.

## Enable

```python
from better_auth import BetterAuth
from better_auth.plugins_ext import GenericOAuthPlugin
from better_auth.plugins_ext.generic_oauth import GenericOAuthConfig

auth = BetterAuth(
    secret="a-strong-32-character-minimum-secret",
    plugins=[
        GenericOAuthPlugin(
            config=[
                GenericOAuthConfig(
                    provider_id="keycloak",
                    client_id="my-client",
                    client_secret="my-secret",
                    discovery_url="https://sso.example.com/realms/main/.well-known/openid-configuration",
                    scopes=["openid", "email", "profile"],
                    pkce=True,
                )
            ]
        )
    ],
)
```

## Options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `config` | `list[GenericOAuthConfig]` | required | One entry per provider. |

Each `GenericOAuthConfig` is a dataclass mirroring the TS per-provider config:
`provider_id`, `client_id`, `client_secret`, and either `discovery_url` or
explicit `authorization_url` / `token_url` / `user_info_url`, plus `scopes`,
`pkce`, `redirect_uri`, `response_type`, `prompt`, `access_type`,
`authorization_url_params`, `token_url_params`, `map_profile_to_user`,
`get_user_info`, `disable_implicit_sign_up`, `disable_sign_up`,
`authentication` (`"basic"` or `"post"`), `override_user_info` and friends —
check the dataclass for the full field list.

## Endpoints

| Method | Path |
| --- | --- |
| POST | `/sign-in/oauth2` |
| GET/POST | `/oauth2/callback/{providerId}` |
| POST | `/oauth2/link` |

## Notes

- Configured providers are also registered into `auth.social_providers`, so
  they ride the core social machinery (e.g. `/refresh-token`).
- Implementation notes (all matching TS behavior): the `id_token` from the
  token exchange is decoded without signature verification (it arrived over
  TLS from the token endpoint); the discovery document is re-fetched per
  endpoint call (no stale cache); `sign-in/oauth2` does not origin-check
  `callbackURL`.
- Only the discovery-based provider presets are ported; presets requiring
  bespoke fetch logic are not.
- For providers in the built-in registry, configure them directly — see
  [providers](/providers/).
