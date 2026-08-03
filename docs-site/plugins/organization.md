---
title: Organization
---

# Organization

Organizations, members, invitations, teams, and dynamic access control — the
largest plugin in the set. Mirrors the TS `organization()` plugin.

## Enable

```python
from better_auth import BetterAuth
from better_auth.access_control import create_access_control
from better_auth.plugins_ext import OrganizationPlugin

ac = create_access_control({"project": ["create", "share", "update", "delete"]})

auth = BetterAuth(
    secret="a-strong-32-character-minimum-secret",
    plugins=[
        OrganizationPlugin(
            ac=ac,
            roles={"admin": ac.new_role({"project": ["create", "update", "delete"]})},
            creator_role="owner",
        )
    ],
)
```

## Options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `allow_user_to_create_organization` | `bool \| callable` | `True` | Gate organization creation, statically or per user. |
| `organization_limit` | `int \| callable \| None` | `None` | Max organizations a user may create. |
| `creator_role` | `str` | `"owner"` | Role given to the creating member. |
| `membership_limit` | `int \| callable` | `100` | Max members per organization. |
| `ac` | `AccessControl \| None` | `None` | Access-control statement set backing `roles`. |
| `roles` | `dict[str, Role] \| None` | `None` | Custom role definitions. |
| `dynamic_access_control` | `dict \| None` | `None` | Enable per-organization roles stored in the database. |
| `disable_organization_deletion` | `bool` | `False` | Reject `/organization/delete`. |
| `invitation_expires_in` | `int` | `172800` | Invitation lifetime in seconds (2 days). |
| `invitation_limit` | `int \| callable \| None` | `100` | Max pending invitations per inviter. |
| `cancel_pending_invitations_on_re_invite` | `bool` | `False` | Cancel a previous pending invitation when re-inviting the same email. |
| `require_email_verification_on_invitation` | `bool \| None` | `None` | Require a verified email before accepting an invitation. |
| `send_invitation_email` | `callable \| None` | `None` | `(data) -> None`, called when an invitation is created. |
| `teams` | `dict \| None` | `None` | Team support, gated on `{"enabled": True}` (plus team options). |
| `organization_hooks` | `dict[str, callable] \| None` | `None` | Lifecycle hooks, snake_case keys (`before_create_organization`, ...); `before_*` hooks may return `{"data": {...}}` to merge. |
| `additional_fields` | `dict \| None` | `None` | Extra schema fields per organization table. |

## Endpoints

20 core routes under `/organization/`:

| Method | Path |
| --- | --- |
| POST | `/organization/create` |
| POST | `/organization/update` |
| POST | `/organization/delete` |
| POST | `/organization/set-active` |
| GET | `/organization/get-full-organization` |
| GET | `/organization/list` |
| POST | `/organization/check-slug` |
| POST | `/organization/leave` |
| GET | `/organization/list-members` |
| POST | `/organization/remove-member` |
| POST | `/organization/update-member-role` |
| GET | `/organization/get-active-member` |
| POST | `/organization/has-permission` |
| POST | `/organization/invite-member` |
| POST | `/organization/accept-invitation` |
| POST | `/organization/reject-invitation` |
| POST | `/organization/cancel-invitation` |
| GET | `/organization/get-invitation` |
| GET | `/organization/list-invitations` |
| GET | `/organization/list-user-invitations` |

With `teams={"enabled": True}`, 9 more:

| Method | Path |
| --- | --- |
| POST | `/organization/create-team` |
| POST | `/organization/update-team` |
| POST | `/organization/remove-team` |
| GET | `/organization/list-teams` |
| POST | `/organization/set-active-team` |
| GET | `/organization/list-user-teams` |
| GET | `/organization/list-team-members` |
| POST | `/organization/add-team-member` |
| POST | `/organization/remove-team-member` |

## Schema

| Table | Columns |
| --- | --- |
| `organization` | `id`, `name`, `slug`, `logo`, `metadata`, `createdAt` |
| `member` | `id`, `organizationId`, `userId`, `role`, `createdAt` |
| `invitation` | `id`, `organizationId`, `email`, `role`, `status`, `expiresAt`, `createdAt`, `inviterId` |
| `session` | adds `activeOrganizationId` |

With teams enabled: `team`, `teamMember` tables, `invitation.teamId` and
`session.activeTeamId`.

## Notes

- `metadata` is stored as a JSON string column — identical to TS, so a Python
  and a TS app can share the database.
- Deleting an organization cascades to members, invitations and teams; the
  cascade is not wrapped in a transaction here (a deliberate simplification:
  the MemoryAdapter has no transactions; TS wraps it in one).
- Team creation caps are checked with count-then-create, which races under
  heavy concurrency — the same known FIXME as TS.
- For instance-wide (non-organization) roles, see [Admin](./admin).
