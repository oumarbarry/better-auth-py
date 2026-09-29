---
title: Anonymous
---

# Anonymous

A throwaway user and session for visitors who have not signed up. When the same
visitor later authenticates for real, the anonymous account is linked via
`on_link_account` and cleaned up. Mirrors the TS `anonymous()` plugin.

## Enable

```python
from better_auth import BetterAuth
from better_auth.plugins_ext import AnonymousPlugin

auth = BetterAuth(
    secret="a-strong-32-character-minimum-secret",
    plugins=[AnonymousPlugin(email_domain_name="example.com")],
)
```

## Options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `email_domain_name` | `str \| None` | `None` | Domain for the generated placeholder address (`temp-<id>@<domain>`); without it, `<id>@anonymous.placeholder.invalid`. |
| `on_link_account` | `callable \| None` | `None` | `({"anonymousUser": ..., "newUser": ...}) -> None`, called when the visitor signs up for real. |
| `disable_delete_anonymous_user` | `bool` | `False` | Keep the anonymous user row after linking. |
| `generate_name` | `callable \| None` | `None` | Custom display-name generator, `(ctx) -> str`. |
| `generate_random_email` | `callable \| None` | `None` | Custom placeholder-email generator. |

## Endpoints

| Method | Path |
| --- | --- |
| POST | `/sign-in/anonymous` |
| POST | `/delete-anonymous-user` |

## Schema

| Table | Added columns |
| --- | --- |
| `user` | `isAnonymous` |

## Notes

- An anonymous user cannot sign in anonymously again
  (`ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY`).
- When `user.validate_user_info` is set, it runs before the anonymous user is
  created, with `source` set to `{"action": "create-user", "method": "anonymous"}`.
- Deliberate simplification: the TS per-instance `schema` field-name override
  is not exposed.

::: warning Changed in 1.1
Without `email_domain_name`, new anonymous users get
`<id>@anonymous.placeholder.invalid` instead of `temp@<id>.com`. Existing users
keep their email. Code that detects anonymous users by the old email pattern
should check the `isAnonymous` column instead. See
[Upgrade from 1.0](/migrate/from-1-0).
:::
