---
title: Admin
---

# Admin

User administration: roles and permissions, ban and unban, impersonation,
session management, setting a user's password, and permission checks. Mirrors
the TS `admin()` plugin.

## Enable

```python
from better_auth import BetterAuth
from better_auth.plugins_ext import AdminPlugin

auth = BetterAuth(
    secret="a-strong-32-character-minimum-secret",
    plugins=[AdminPlugin(default_role="user", admin_roles=["admin"])],
)
```

## Options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `default_role` | `str` | `"user"` | Role assigned to newly created users. |
| `admin_roles` | `str \| list[str] \| None` | `None` (treated as `["admin"]`) | Roles allowed to call admin endpoints; accepts a comma string or a list. |
| `default_ban_reason` | `str \| None` | `None` | Reason recorded when banning without one. |
| `default_ban_expires_in` | `int \| None` | `None` | Ban duration in seconds when none is given; `None` = permanent. |
| `impersonation_session_duration` | `int` | `3600` | Lifetime (seconds) of impersonation sessions. |
| `roles` | `dict[str, Role] \| None` | `None` | Custom role set built from an access-control statement set. |
| `admin_user_ids` | `list[str] \| None` | `None` | Explicit user ids granted admin access regardless of role. |
| `ac` | `AccessControl \| None` | `None` | Access-control instance backing custom `roles`. |
| `banned_user_message` | `str \| None` | `None` | Message returned when a banned user tries to sign in. |
| `allow_impersonating_admins` | `bool` | `False` | Allow impersonating users who are themselves admins. |

## Endpoints

15 routes under `base_path`:

| Method | Path |
| --- | --- |
| POST | `/admin/set-role` |
| GET | `/admin/get-user` |
| POST | `/admin/create-user` |
| POST | `/admin/update-user` |
| GET | `/admin/list-users` |
| POST | `/admin/list-user-sessions` |
| POST | `/admin/ban-user` |
| POST | `/admin/unban-user` |
| POST | `/admin/impersonate-user` |
| POST | `/admin/stop-impersonating` |
| POST | `/admin/revoke-user-session` |
| POST | `/admin/revoke-user-sessions` |
| POST | `/admin/remove-user` |
| POST | `/admin/set-user-password` |
| POST | `/admin/has-permission` |

## Schema

| Table | Added columns |
| --- | --- |
| `user` | `role`, `banned`, `banReason`, `banExpires` |
| `session` | `impersonatedBy` |

## Notes

- Ban enforcement runs as a `session.create` database hook, so a banned user's
  sign-in is blocked at session creation — on every session creation in this
  port (TS gates the hook on having a request context; the effect is the same).
- TS's trusted null-session server calls (`create-user` / `has-permission`
  without a request) are not reachable through this HTTP-only router; both
  endpoints simply require a session.
- Dynamic per-organization roles live in [organization](./organization), not here.
