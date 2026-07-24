"""organization plugin — core-org + invitations + teams + dynamic access control (phases 1-4).

Port of better-auth's ``plugins/organization`` (v1.6.23): create/update/delete/list/
get-full/set-active organizations, member management (list/leave/remove/update-role/
get-active/has-permission), check-slug, invitations, and teams (opt-in). Verified against
``routes/crud-org.ts``, ``routes/crud-members.ts``, ``routes/crud-invites.ts``,
``routes/crud-team.ts``, ``organization.ts``, ``has-permission.ts``, ``permission.ts``,
``adapter.ts``, ``types.ts`` and ``error-codes.ts``.

Wire/storage fidelity is the contract (a Python app and a TS app share one DB): the
camelCase ``organization`` / ``member`` tables, ``session.activeOrganizationId``
(``input:false``), the JSON-string ``metadata`` column, response shapes, and every error
string match the TS source exactly.

Phase 2 (invitations) is implemented: the ``invitation`` table, invite/accept/reject/
cancel/get/list/list-user endpoints, ``sendInvitationEmail`` config, the invitation cascade
in :meth:`_delete_org`, and ``invitations`` population in :meth:`_find_full_org`. Verified
against ``routes/crud-invites.ts`` and the ``adapter.ts`` invitation methods.

Phase 3 (teams) is implemented (gated on ``teams={"enabled": True}``): the ``team`` /
``teamMember`` tables, ``invitation.teamId``, ``session.activeTeamId``, the nine team
endpoints (create/update/remove/list/set-active/list-user/list-members/add-member/remove-member),
the ``teams`` config surface (defaultTeam / maximumTeams / maximumMembersPerTeam /
allowRemovingAllTeams), the default-team branch in ``create``, the ``teamId`` invite
validation + accept-path team-membership branch, and the ``before/after`` team hooks.
Verified against ``routes/crud-team.ts``, the team branches of ``routes/crud-invites.ts``,
``adapter.ts`` team methods, ``organization.ts`` wiring/schema, and ``types.ts``.

Phase 4 (dynamic access control) is implemented (gated on ``dynamic_access_control={"enabled":
True}``): the ``organizationRole`` table, the create/list/get/update/delete role endpoints
(``ac`` resource permissions + subset validation + maximumRolesPerOrganization), the dynamic-
role union merge inside :func:`has_permission`, and the DAC branch of the unknown-role lookup
in ``update-member-role`` / ``invite-member``. Verified against ``routes/crud-access-control.ts``,
``has-permission.ts``, ``permission.ts``, ``organization.ts`` and ``types.ts``. v1.6.23 defines
no role-specific hooks (``types.ts`` ``organizationHooks`` covers only org/member/invitation/team),
so none exist to port.
"""

from __future__ import annotations

import inspect
import json
from datetime import timedelta
from typing import TYPE_CHECKING, Any, ClassVar

from ..access_control import ORG_DEFAULT_ROLES, AccessControl, Role
from ..adapters.base import Where
from ..cookie_cache import set_cookie_cache
from ..crypto import generate_id
from ..endpoints import validate_email
from ..plugins import Plugin, Route
from ..schema import Field, Reference, Schema, filter_output_fields
from ..session import cookie_name, refresh_session_cookie, utcnow
from ..types import APIError, AuthResponse, Ctx

if TYPE_CHECKING:
    from collections.abc import Callable

#: exact TS strings (organization/error-codes.ts) — surfaced on ``auth.error_codes``.
#: The full table is ported once; later phases reuse the invitation/team/AC entries.
ERROR_CODES: dict[str, str] = {
    "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION": (
        "You are not allowed to create a new organization"
    ),
    "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS": (
        "You have reached the maximum number of organizations"
    ),
    "ORGANIZATION_ALREADY_EXISTS": "Organization already exists",
    "ORGANIZATION_SLUG_ALREADY_TAKEN": "Organization slug already taken",
    "ORGANIZATION_NOT_FOUND": "Organization not found",
    "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION": "User is not a member of the organization",
    "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION": (
        "You are not allowed to update this organization"
    ),
    "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION": (
        "You are not allowed to delete this organization"
    ),
    "NO_ACTIVE_ORGANIZATION": "No active organization",
    "USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION": (
        "User is already a member of this organization"
    ),
    "MEMBER_NOT_FOUND": "Member not found",
    "ROLE_NOT_FOUND": "Role not found",
    "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_TEAM": "You are not allowed to create a new team",
    "TEAM_ALREADY_EXISTS": "Team already exists",
    "TEAM_NOT_FOUND": "Team not found",
    "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER": (
        "You cannot leave the organization as the only owner"
    ),
    "YOU_CANNOT_LEAVE_THE_ORGANIZATION_WITHOUT_AN_OWNER": (
        "You cannot leave the organization without an owner"
    ),
    "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER": "You are not allowed to delete this member",
    "YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION": (
        "You are not allowed to invite users to this organization"
    ),
    "USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION": "User is already invited to this organization",
    "INVITATION_NOT_FOUND": "Invitation not found",
    "YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION": "You are not the recipient of the invitation",
    "EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION": (
        "Email verification required before accepting or rejecting invitation"
    ),
    "EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION": (
        "Email verification required to view or list invitations for the session email"
    ),
    "YOU_ARE_NOT_ALLOWED_TO_CANCEL_THIS_INVITATION": (
        "You are not allowed to cancel this invitation"
    ),
    "INVITER_IS_NO_LONGER_A_MEMBER_OF_THE_ORGANIZATION": (
        "Inviter is no longer a member of the organization"
    ),
    "YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE": (
        "You are not allowed to invite a user with this role"
    ),
    "FAILED_TO_RETRIEVE_INVITATION": "Failed to retrieve invitation",
    "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS": "You have reached the maximum number of teams",
    "UNABLE_TO_REMOVE_LAST_TEAM": "Unable to remove last team",
    "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER": "You are not allowed to update this member",
    "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED": "Organization membership limit reached",
    "YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION": (
        "You are not allowed to create teams in this organization"
    ),
    "YOU_ARE_NOT_ALLOWED_TO_DELETE_TEAMS_IN_THIS_ORGANIZATION": (
        "You are not allowed to delete teams in this organization"
    ),
    "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_TEAM": "You are not allowed to update this team",
    "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_TEAM": "You are not allowed to delete this team",
    "INVITATION_LIMIT_REACHED": "Invitation limit reached",
    "TEAM_MEMBER_LIMIT_REACHED": "Team member limit reached",
    "USER_IS_NOT_A_MEMBER_OF_THE_TEAM": "User is not a member of the team",
    "YOU_CAN_NOT_ACCESS_THE_MEMBERS_OF_THIS_TEAM": (
        "You are not allowed to list the members of this team"
    ),
    "YOU_DO_NOT_HAVE_AN_ACTIVE_TEAM": "You do not have an active team",
    "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_TEAM_MEMBER": "You are not allowed to create a new member",
    "YOU_ARE_NOT_ALLOWED_TO_REMOVE_A_TEAM_MEMBER": "You are not allowed to remove a team member",
    "YOU_ARE_NOT_ALLOWED_TO_ACCESS_THIS_ORGANIZATION": (
        "You are not allowed to access this organization as an owner"
    ),
    "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION": "You are not a member of this organization",
    "MISSING_AC_INSTANCE": (
        "Dynamic Access Control requires a pre-defined ac instance on the server auth plugin."
        " Read server logs for more information"
    ),
    "YOU_MUST_BE_IN_AN_ORGANIZATION_TO_CREATE_A_ROLE": (
        "You must be in an organization to create a role"
    ),
    "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE": "You are not allowed to create a role",
    "YOU_ARE_NOT_ALLOWED_TO_UPDATE_A_ROLE": "You are not allowed to update a role",
    "YOU_ARE_NOT_ALLOWED_TO_DELETE_A_ROLE": "You are not allowed to delete a role",
    "YOU_ARE_NOT_ALLOWED_TO_READ_A_ROLE": "You are not allowed to read a role",
    "YOU_ARE_NOT_ALLOWED_TO_LIST_A_ROLE": "You are not allowed to list a role",
    "YOU_ARE_NOT_ALLOWED_TO_GET_A_ROLE": "You are not allowed to get a role",
    "TOO_MANY_ROLES": "This organization has too many roles",
    "INVALID_RESOURCE": "The provided permission includes an invalid resource",
    "ROLE_NAME_IS_ALREADY_TAKEN": "That role name is already taken",
    "CANNOT_DELETE_A_PRE_DEFINED_ROLE": "Cannot delete a pre-defined role",
    "ROLE_IS_ASSIGNED_TO_MEMBERS": (
        "Cannot delete a role that is assigned to members."
        " Please reassign the members to a different role first"
    ),
    "INVALID_TEAM_ID": "Team id contains a reserved character",
}


async def _maybe_await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


def _err(status: int, code: str, extra: dict[str, Any] | None = None) -> APIError:
    return APIError(status, code, ERROR_CODES[code], extra=extra)


def _json_dumps(value: Any) -> str:
    """Compact ``JSON.stringify`` for the metadata column (matches the port's convention)."""
    return json.dumps(value, separators=(",", ":"))


def _parse_metadata(value: Any) -> Any:
    return json.loads(value) if isinstance(value, str) else value


def _required_str(body: dict[str, Any], key: str) -> str:
    value = body.get(key)
    if not isinstance(value, str):
        raise APIError(400, "INVALID_BODY", f"'{key}' is required")
    return value


def _required_nonempty_str(body: dict[str, Any], key: str) -> str:
    value = _required_str(body, key)
    if not value:
        raise APIError(400, "INVALID_BODY", f"'{key}' must not be empty")
    return value


def parse_roles(roles: str | list[str]) -> str:
    """TS ``parseRoles``: an array of roles is joined with commas; a string passes through."""
    return ",".join(roles) if isinstance(roles, list) else roles


# --- permission resolution (has-permission.ts + permission.ts) --------------------


def _is_valid_role_permission(value: Any) -> bool:
    """TS ``z.record(z.string(), z.array(z.string()))`` shape guard for a parsed permission."""
    if not isinstance(value, dict):
        return False
    return all(
        isinstance(k, str) and isinstance(v, list) and all(isinstance(a, str) for a in v)
        for k, v in value.items()
    )


def _resolve_roles(options: OrganizationPlugin) -> dict[str, Role]:
    """The static role table: defaults overridden by ``options.roles`` (custom ac/roles).

    Dynamic ``organizationRole`` rows are merged on top of this in :func:`has_permission`
    (the async resolver that has ``ctx`` / ``organization_id`` to query the DB), mirroring
    TS ``has-permission.ts``. This returns a fresh mutable dict so that merge can layer in.
    """
    return {**ORG_DEFAULT_ROLES, **(options.roles or {})}


def _has_permission_fn(
    role: str,
    permissions: dict[str, Any] | None,
    options: OrganizationPlugin,
    ac_roles: dict[str, Role],
    allow_creator_all_permissions: bool,
) -> bool:
    """TS ``hasPermissionFn`` (permission.ts): creator short-circuit, else any role authorizes."""
    if not permissions:
        return False
    roles = role.split(",")
    creator_role = options.creator_role or "owner"
    if creator_role in roles and allow_creator_all_permissions:
        return True
    for r in roles:
        role_obj = ac_roles.get(r)
        if role_obj is not None and role_obj.authorize(permissions).get("success"):
            return True
    return False


async def has_permission(
    *,
    role: str,
    permissions: dict[str, Any] | None,
    options: OrganizationPlugin,
    organization_id: str,
    ctx: Ctx,
    allow_creator_all_permissions: bool = False,
) -> bool:
    """TS ``hasPermission`` (has-permission.ts): resolve static roles, then merge the org's
    dynamic ``organizationRole`` rows on top (union per resource) before authorizing.

    A dynamic role UNIONS with a same-named static role (dynamic augments static, never
    shadows); a dynamic name with no static counterpart becomes a fresh role. The merge runs
    only when ``dynamicAccessControl.enabled`` and an ``ac`` instance is configured.
    """
    ac_roles = _resolve_roles(options)
    if ctx is not None and organization_id and options._dac_enabled and options.ac is not None:
        # ponytail: TS keeps a module-level `cacheAllRoles` + `useMemoryCache` to skip these
        # reads inside checkIfMemberHasPermission; dropped because the new role isn't persisted
        # until after those checks, so re-reading the DB yields the identical role set. Add the
        # cache back if per-request DB round-trips ever matter.
        rows = await ctx.adapter.find_many(
            "organizationRole", [Where("organizationId", organization_id)]
        )
        for row in rows:
            role_name = row["role"]
            parsed = json.loads(row["permission"])
            if not _is_valid_role_permission(parsed):
                raise APIError(
                    500, "INTERNAL_SERVER_ERROR", f"Invalid permissions for role {role_name}"
                )
            existing = ac_roles.get(role_name)
            merged: dict[str, list[str]] = dict(existing.statements) if existing is not None else {}
            for key, actions in parsed.items():
                merged[key] = list(dict.fromkeys([*merged.get(key, []), *actions]))
            ac_roles[role_name] = options.ac.new_role(merged)
    return _has_permission_fn(role, permissions, options, ac_roles, allow_creator_all_permissions)


class OrganizationPlugin(Plugin):
    """TS ``organization()`` — core-org endpoints (see module docstring for scope/seams).

    Constructor kwargs mirror the TS ``OrganizationOptions`` (snake_case). Hooks are passed
    as ``organization_hooks={"before_create_organization": fn, ...}`` (snake_case keys), each
    receiving a single dict argument and, for ``before_*``, optionally returning
    ``{"data": {...}}`` to merge — matching the TS ``organizationHooks`` contract.
    """

    id = "organization"
    error_codes: ClassVar[dict[str, str]] = ERROR_CODES

    def __init__(
        self,
        *,
        allow_user_to_create_organization: bool | Callable[..., Any] = True,
        organization_limit: int | Callable[..., Any] | None = None,
        creator_role: str = "owner",
        membership_limit: int | Callable[..., Any] = 100,
        ac: AccessControl | None = None,
        roles: dict[str, Role] | None = None,
        # --- dynamic access control (phase 4) — TS OrganizationOptions.dynamicAccessControl.
        # {"enabled": bool, "maximum_roles_per_organization": int | (org_id) -> Awaitable[int]}
        dynamic_access_control: dict[str, Any] | None = None,
        disable_organization_deletion: bool = False,
        # --- invitations (phase 2) — TS OrganizationOptions invitation knobs -----------
        invitation_expires_in: int = 48 * 60 * 60,  # seconds; TS default 48h
        invitation_limit: int | Callable[..., Any] | None = 100,
        cancel_pending_invitations_on_re_invite: bool = False,
        require_email_verification_on_invitation: bool | None = None,
        send_invitation_email: Callable[..., Any] | None = None,
        # --- teams (phase 3) — TS OrganizationOptions.teams (dict; snake_case sub-keys) -----
        # {"enabled", "default_team": {"enabled", "custom_create_default_team"?},
        #  "maximum_teams": int|fn, "maximum_members_per_team": int|fn, "allow_removing_all_teams"}
        teams: dict[str, Any] | None = None,
        organization_hooks: dict[str, Callable[..., Any]] | None = None,
        # {"organization": {name: Field}, "member": {...}, "invitation": {...}} — extra columns.
        additional_fields: dict[str, dict[str, Field]] | None = None,
    ) -> None:
        self.allow_user_to_create_organization = allow_user_to_create_organization
        self.organization_limit = organization_limit
        self.creator_role = creator_role
        self.membership_limit = membership_limit
        self.ac = ac
        self.roles = roles
        self.dynamic_access_control = dynamic_access_control
        self._dac_enabled = bool(dynamic_access_control and dynamic_access_control.get("enabled"))
        self.disable_organization_deletion = disable_organization_deletion
        self.invitation_expires_in = invitation_expires_in
        self.invitation_limit = invitation_limit
        self.cancel_pending_invitations_on_re_invite = cancel_pending_invitations_on_re_invite
        self.require_email_verification_on_invitation = require_email_verification_on_invitation
        self.send_invitation_email = send_invitation_email
        self.teams = teams
        self._teams_enabled = bool(teams and teams.get("enabled"))
        self.organization_hooks = organization_hooks or {}
        self._additional_fields = additional_fields or {}
        #: the default cap for list-members / full-org member fetch (TS: membershipLimit || 100)
        self._default_members_limit = (
            membership_limit
            if isinstance(membership_limit, int) and not isinstance(membership_limit, bool)
            else 100
        )
        # Per-instance schema (additionalFields make it config-dependent); shadows the
        # ClassVar default so ``auth`` reads these tables. See _build_schema.
        self.schema: Schema = self._build_schema()

    # --- schema -----------------------------------------------------------------------

    def _extra(self, model: str) -> dict[str, Field]:
        return dict(self._additional_fields.get(model, {}))

    def _build_schema(self) -> Schema:
        return {
            "organization": {
                "id": Field("string", required=True, unique=True),
                "name": Field("string", required=True, sortable=True),
                "slug": Field("string", required=True, unique=True, sortable=True, index=True),
                "logo": Field("string", required=False),
                "metadata": Field("string", required=False),  # JSON-stringified object
                "createdAt": Field("datetime", required=True),
                **self._extra("organization"),
            },
            "member": {
                "id": Field("string", required=True, unique=True),
                "organizationId": Field(
                    "string", required=True, references=Reference("organization", "id"), index=True
                ),
                "userId": Field(
                    "string", required=True, references=Reference("user", "id"), index=True
                ),
                "role": Field("string", required=True, default="member", sortable=True),
                "createdAt": Field("datetime", required=True),
                **self._extra("member"),
            },
            # invitation columns mirror organization.ts runtime schema (role is required=false
            # there, not the schema.ts type). teamId is phase 3 — omitted.
            "invitation": {
                "id": Field("string", required=True, unique=True),
                "organizationId": Field(
                    "string", required=True, references=Reference("organization", "id"), index=True
                ),
                "email": Field("string", required=True, sortable=True, index=True),
                "role": Field("string", required=False, sortable=True),
                # teamId only exists when teams are enabled (organization.ts:1157-1166)
                **(
                    {"teamId": Field("string", required=False, sortable=True)}
                    if self._teams_enabled
                    else {}
                ),
                "status": Field("string", required=True, default="pending", sortable=True),
                "expiresAt": Field("datetime", required=True),
                "createdAt": Field("datetime", required=True),
                "inviterId": Field("string", required=True, references=Reference("user", "id")),
                **self._extra("invitation"),
            },
            "session": {
                "activeOrganizationId": Field("string", required=False, input=False),
                # activeTeamId only when teams enabled (organization.ts:1230-1239)
                **(
                    {"activeTeamId": Field("string", required=False, input=False)}
                    if self._teams_enabled
                    else {}
                ),
            },
            # team + teamMember tables only when teams enabled (organization.ts:940-1006)
            **(self._team_schema() if self._teams_enabled else {}),
            # organizationRole only when dynamicAccessControl.enabled (organization.ts:1008-1048)
            **(self._organization_role_schema() if self._dac_enabled else {}),
        }

    def _organization_role_schema(self) -> Schema:
        """organizationRole table — TS OrganizationRoleDefaultFields (organization.ts:1010-1046).

        ``permission`` is a JSON-stringified ``Record<str, list[str]>`` (column is a string).
        """
        return {
            "organizationRole": {
                "id": Field("string", required=True, unique=True),
                "organizationId": Field(
                    "string", required=True, references=Reference("organization", "id"), index=True
                ),
                "role": Field("string", required=True, index=True),
                "permission": Field("string", required=True),  # JSON-stringified permissions
                "createdAt": Field("datetime", required=True),
                "updatedAt": Field("datetime", required=False, on_update=utcnow),
                **self._extra("organizationRole"),
            }
        }

    def _team_schema(self) -> Schema:
        """team + teamMember tables — TS TeamDefaultFields / TeamMemberDefaultFields (schema.ts)."""
        return {
            "team": {
                "id": Field("string", required=True, unique=True),
                "name": Field("string", required=True),
                "organizationId": Field(
                    "string", required=True, references=Reference("organization", "id"), index=True
                ),
                "createdAt": Field("datetime", required=True),
                "updatedAt": Field("datetime", required=False),
                **self._extra("team"),
            },
            "teamMember": {
                "id": Field("string", required=True, unique=True),
                "teamId": Field(
                    "string", required=True, references=Reference("team", "id"), index=True
                ),
                "userId": Field(
                    "string", required=True, references=Reference("user", "id"), index=True
                ),
                "createdAt": Field("datetime", required=False),
            },
        }

    # --- routes -----------------------------------------------------------------------

    def routes(self) -> list[Route]:
        routes: list[Route] = [
            ("POST", "/organization/create", self._create),
            ("POST", "/organization/update", self._update),
            ("POST", "/organization/delete", self._delete),
            ("POST", "/organization/set-active", self._set_active),
            ("GET", "/organization/get-full-organization", self._get_full_organization),
            ("GET", "/organization/list", self._list),
            ("POST", "/organization/check-slug", self._check_slug),
            ("POST", "/organization/leave", self._leave),
            ("GET", "/organization/list-members", self._list_members_route),
            ("POST", "/organization/remove-member", self._remove_member),
            ("POST", "/organization/update-member-role", self._update_member_role),
            ("GET", "/organization/get-active-member", self._get_active_member),
            ("POST", "/organization/has-permission", self._has_permission),
            # --- invitations (phase 2) ---------------------------------------------------
            ("POST", "/organization/invite-member", self._invite_member),
            ("POST", "/organization/accept-invitation", self._accept_invitation),
            ("POST", "/organization/reject-invitation", self._reject_invitation),
            ("POST", "/organization/cancel-invitation", self._cancel_invitation),
            ("GET", "/organization/get-invitation", self._get_invitation),
            ("GET", "/organization/list-invitations", self._list_invitations_route),
            ("GET", "/organization/list-user-invitations", self._list_user_invitations),
        ]
        # --- teams (phase 3) — registered only when teams.enabled (organization.ts:915-920)
        if self._teams_enabled:
            routes += [
                ("POST", "/organization/create-team", self._create_team_route),
                ("POST", "/organization/update-team", self._update_team_route),
                ("POST", "/organization/remove-team", self._remove_team_route),
                ("GET", "/organization/list-teams", self._list_teams_route),
                ("POST", "/organization/set-active-team", self._set_active_team_route),
                ("GET", "/organization/list-user-teams", self._list_user_teams_route),
                ("GET", "/organization/list-team-members", self._list_team_members_route),
                ("POST", "/organization/add-team-member", self._add_team_member_route),
                ("POST", "/organization/remove-team-member", self._remove_team_member_route),
            ]
        # --- dynamic access control (phase 4) — only when enabled (organization.ts:929-934)
        if self._dac_enabled:
            routes += [
                ("POST", "/organization/create-role", self._create_role),
                ("POST", "/organization/delete-role", self._delete_role),
                ("GET", "/organization/list-roles", self._list_roles),
                ("GET", "/organization/get-role", self._get_role),
                ("POST", "/organization/update-role", self._update_role),
            ]
        return routes

    # --- hooks --------------------------------------------------------------------------

    def _hook(self, name: str) -> Callable[..., Any] | None:
        return self.organization_hooks.get(name)

    async def _run_before_hook(self, name: str, payload: dict[str, Any]) -> dict[str, Any] | None:
        """Run a ``before_*`` hook; return its ``data`` merge dict, or None."""
        hook = self._hook(name)
        if hook is None:
            return None
        result = await _maybe_await(hook(payload))
        if isinstance(result, dict) and "data" in result:
            return result["data"]
        return None

    async def _run_after_hook(self, name: str, payload: dict[str, Any]) -> None:
        hook = self._hook(name)
        if hook is not None:
            await _maybe_await(hook(payload))

    # --- plugin-local adapter (mirrors adapter.ts getOrgAdapter) -----------------------
    #
    # Org/member CRUD go through the raw ``ctx.adapter`` (as TS getCurrentAdapter does);
    # only the session activeOrganizationId write routes through ``ctx.internal`` so core
    # session databaseHooks / secondary storage fire (TS setActiveOrganization).

    def _filter_org(self, org: dict[str, Any]) -> dict[str, Any]:
        return filter_output_fields(org, self.schema["organization"])

    def _shape_member(self, member: dict[str, Any], user: dict[str, Any]) -> dict[str, Any]:
        return {
            **filter_output_fields(member, self.schema["member"]),
            "user": {
                "id": user["id"],
                "name": user["name"],
                "email": user["email"],
                "image": user.get("image"),
            },
        }

    async def _attach_user(self, ctx: Ctx, member: dict[str, Any]) -> dict[str, Any] | None:
        user = await ctx.adapter.find_one("user", [Where("id", member["userId"])])
        return self._shape_member(member, user) if user is not None else None

    async def _find_org_by_slug(self, ctx: Ctx, slug: str) -> dict[str, Any] | None:
        org = await ctx.adapter.find_one("organization", [Where("slug", slug)])
        return self._filter_org(org) if org is not None else None

    async def _find_org_by_id(self, ctx: Ctx, org_id: str) -> dict[str, Any] | None:
        org = await ctx.adapter.find_one("organization", [Where("id", org_id)])
        return self._filter_org(org) if org is not None else None

    async def _create_org(self, ctx: Ctx, org_data: dict[str, Any]) -> dict[str, Any]:
        data = dict(org_data)
        metadata = data.get("metadata")
        if metadata:
            data["metadata"] = _json_dumps(metadata)
        else:
            data.pop("metadata", None)
        org = await ctx.adapter.create("organization", data)
        result = self._filter_org(org)
        result["metadata"] = _parse_metadata(result.get("metadata"))
        return result

    async def _create_member(self, ctx: Ctx, data: dict[str, Any]) -> dict[str, Any]:
        row = {"id": generate_id(), **data, "createdAt": utcnow()}
        member = await ctx.adapter.create("member", row)
        return filter_output_fields(member, self.schema["member"])

    async def _find_member_by_org(
        self, ctx: Ctx, user_id: str, org_id: str
    ) -> dict[str, Any] | None:
        member = await ctx.adapter.find_one(
            "member", [Where("userId", user_id), Where("organizationId", org_id)]
        )
        return await self._attach_user(ctx, member) if member is not None else None

    async def _find_member_by_id(self, ctx: Ctx, member_id: str) -> dict[str, Any] | None:
        member = await ctx.adapter.find_one("member", [Where("id", member_id)])
        return await self._attach_user(ctx, member) if member is not None else None

    async def _find_member_by_email(
        self, ctx: Ctx, email: str, org_id: str
    ) -> dict[str, Any] | None:
        user = await ctx.adapter.find_one("user", [Where("email", email.lower())])
        if user is None:
            return None
        member = await ctx.adapter.find_one(
            "member", [Where("organizationId", org_id), Where("userId", user["id"])]
        )
        return self._shape_member(member, user) if member is not None else None

    async def _check_membership(self, ctx: Ctx, user_id: str, org_id: str) -> dict[str, Any] | None:
        return await ctx.adapter.find_one(
            "member", [Where("userId", user_id), Where("organizationId", org_id)]
        )

    async def _users_by_ids(self, ctx: Ctx, user_ids: list[str]) -> dict[str, dict[str, Any]]:
        # Per-id ``eq`` lookups instead of one ``in`` query: the MemoryAdapter ``in``
        # operator lowercases the row value but not the query values, so it never matches
        # mixed-case generated ids (memory.py:28) — see the BLOCKED note in the report.
        # ``eq`` is case-correct. Bounded by membershipLimit, so O(n) reads are fine.
        result: dict[str, dict[str, Any]] = {}
        for uid in user_ids:
            if uid in result:
                continue
            user = await ctx.adapter.find_one("user", [Where("id", uid)])
            if user is not None:
                result[uid] = user
        return result

    async def _list_orgs(self, ctx: Ctx, user_id: str) -> list[dict[str, Any]]:
        members = await ctx.adapter.find_many("member", [Where("userId", user_id)])
        orgs: list[dict[str, Any]] = []
        seen: set[str] = set()
        for member in members:  # per-id lookup (see _users_by_ids) — no `in` operator
            org_id = member["organizationId"]
            if org_id in seen:
                continue
            seen.add(org_id)
            org = await ctx.adapter.find_one("organization", [Where("id", org_id)])
            if org is not None:
                orgs.append(self._filter_org(org))
        return orgs

    async def _list_members(
        self,
        ctx: Ctx,
        org_id: str,
        *,
        limit: int | None = None,
        offset: int | None = None,
        sort_by: str | None = None,
        sort_order: str | None = None,
        member_filter: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        where = [Where("organizationId", org_id)]
        if member_filter and member_filter.get("field"):
            where.append(
                Where(
                    member_filter["field"],
                    member_filter.get("value"),
                    member_filter.get("operator") or "eq",
                )
            )
        sort = {"field": sort_by, "direction": sort_order or "asc"} if sort_by else None
        members = await ctx.adapter.find_many(
            "member",
            where,
            limit=limit if limit is not None else self._default_members_limit,
            offset=offset or 0,
            sort_by=sort,
        )
        total = await ctx.adapter.count("member", where)
        user_map = await self._users_by_ids(ctx, [m["userId"] for m in members])
        shaped = [
            self._shape_member(m, user_map[m["userId"]]) for m in members if m["userId"] in user_map
        ]
        return {"members": shaped, "total": total}

    async def _find_full_org(
        self, ctx: Ctx, org_id: str, *, is_slug: bool, members_limit: int | None
    ) -> dict[str, Any] | None:
        field = "slug" if is_slug else "id"
        org = await ctx.adapter.find_one("organization", [Where(field, org_id)])
        if org is None:
            return None
        members = await ctx.adapter.find_many(
            "member",
            [Where("organizationId", org["id"])],
            limit=members_limit if members_limit else self._default_members_limit,
        )
        user_map = await self._users_by_ids(ctx, [m["userId"] for m in members])
        shaped = [
            self._shape_member(m, user_map[m["userId"]]) for m in members if m["userId"] in user_map
        ]
        invitations = await ctx.adapter.find_many(
            "invitation", [Where("organizationId", org["id"])]
        )
        result: dict[str, Any] = {
            **self._filter_org(org),
            "members": shaped,
            "invitations": [self._filter_invitation(i) for i in invitations],
        }
        if self._teams_enabled:  # getFullOrganization includeTeams (crud-org.ts:697)
            result["teams"] = await self._list_teams(ctx, org["id"])
        return result

    async def _update_org(
        self, ctx: Ctx, org_id: str, data: dict[str, Any]
    ) -> dict[str, Any] | None:
        update = dict(data)
        if isinstance(update.get("metadata"), dict):
            update["metadata"] = _json_dumps(update["metadata"])
        org = await ctx.adapter.update("organization", [Where("id", org_id)], update)
        if org is None:
            return None
        result = self._filter_org(org)
        result["metadata"] = _parse_metadata(result.get("metadata"))
        return result

    async def _update_member(self, ctx: Ctx, member_id: str, role: str) -> dict[str, Any] | None:
        member = await ctx.adapter.update("member", [Where("id", member_id)], {"role": role})
        return filter_output_fields(member, self.schema["member"]) if member is not None else None

    async def _delete_member(
        self, ctx: Ctx, member_id: str, *, org_id: str | None = None, user_id: str | None = None
    ) -> None:
        await ctx.adapter.delete("member", [Where("id", member_id)])
        # teams: drop the departing user's team memberships across this org's teams
        # (adapter.ts:387-405). Per-team delete_many avoids MemoryAdapter's `in` operator,
        # which lowercases mixed-case ids and never matches (see _users_by_ids).
        if self._teams_enabled and org_id and user_id:
            for team in await self._list_teams(ctx, org_id):
                await self._remove_team_member_row(ctx, team["id"], user_id)

    async def _delete_org(self, ctx: Ctx, org_id: str) -> None:
        # ponytail: TS wraps this in a transaction for atomicity; MemoryAdapter isn't
        # concurrent, so a plain cascade suffices — wrap it when a real adapter needs it.
        await ctx.adapter.delete_many("member", [Where("organizationId", org_id)])
        await ctx.adapter.delete_many("invitation", [Where("organizationId", org_id)])
        await ctx.adapter.delete("organization", [Where("id", org_id)])

    # --- invitation adapter helpers (adapter.ts invitation methods) --------------------

    def _filter_invitation(self, inv: dict[str, Any]) -> dict[str, Any]:
        return filter_output_fields(inv, self.schema["invitation"])

    def _expiry(self, seconds: int) -> Any:
        return utcnow() + timedelta(seconds=seconds)

    def _require_verified_email_for_invitation(self) -> bool:
        """TS ``shouldRequireVerifiedEmailForInvitationIdAction`` for accept/reject/get.

        When the option is set, honour it. Otherwise the port always mints opaque random
        invitation ids (:func:`crypto.generate_id`), so TS's built-in-opaque-id branch is
        always taken → no verification required. Set the option to ``True`` to gate by-id
        actions when ids may leak (e.g. exposed invitation lists).
        """
        if self.require_email_verification_on_invitation is not None:
            return self.require_email_verification_on_invitation
        return False

    async def _find_invitation_by_id(self, ctx: Ctx, invitation_id: str) -> dict[str, Any] | None:
        inv = await ctx.adapter.find_one("invitation", [Where("id", invitation_id)])
        return self._filter_invitation(inv) if inv is not None else None

    async def _find_pending_invitation(
        self, ctx: Ctx, email: str, org_id: str
    ) -> list[dict[str, Any]]:
        rows = await ctx.adapter.find_many(
            "invitation",
            [
                Where("email", email.lower()),
                Where("organizationId", org_id),
                Where("status", "pending"),
            ],
        )
        now = utcnow()
        return [self._filter_invitation(r) for r in rows if r["expiresAt"] > now]

    async def _find_pending_invitations(self, ctx: Ctx, org_id: str) -> list[dict[str, Any]]:
        rows = await ctx.adapter.find_many(
            "invitation", [Where("organizationId", org_id), Where("status", "pending")]
        )
        now = utcnow()
        return [self._filter_invitation(r) for r in rows if r["expiresAt"] > now]

    async def _list_invitation_rows(self, ctx: Ctx, org_id: str) -> list[dict[str, Any]]:
        rows = await ctx.adapter.find_many("invitation", [Where("organizationId", org_id)])
        return [self._filter_invitation(r) for r in rows]

    async def _list_user_invitation_rows(self, ctx: Ctx, email: str) -> list[dict[str, Any]]:
        rows = await ctx.adapter.find_many("invitation", [Where("email", email.lower())])
        result: list[dict[str, Any]] = []
        for inv in rows:
            org = await ctx.adapter.find_one("organization", [Where("id", inv["organizationId"])])
            result.append(
                {
                    **self._filter_invitation(inv),
                    "organizationName": org["name"] if org is not None else None,
                }
            )
        return result

    async def _create_invitation(
        self, ctx: Ctx, invitation: dict[str, Any], user: dict[str, Any]
    ) -> dict[str, Any]:
        row = {
            "id": generate_id(),
            "status": "pending",
            "expiresAt": self._expiry(self.invitation_expires_in),
            "createdAt": utcnow(),
            "inviterId": user["id"],
            **invitation,  # role, email, organizationId (+ before-hook overrides) win
        }
        created = await ctx.adapter.create("invitation", row)
        return self._filter_invitation(created)

    async def _update_invitation(
        self, ctx: Ctx, invitation_id: str, status: str, *, from_status: str | None = None
    ) -> dict[str, Any] | None:
        """Set the invitation status; ``from_status`` guards the transition (CAS)."""
        where = [Where("id", invitation_id)]
        if from_status is not None:
            where.append(Where("status", from_status))
        updated = await ctx.adapter.update("invitation", where, {"status": status})
        return self._filter_invitation(updated) if updated is not None else None

    async def _set_active_org(
        self, ctx: Ctx, token: str, org_id: str | None
    ) -> dict[str, Any] | None:
        return await ctx.internal.update_session(token, {"activeOrganizationId": org_id})

    def _apply_session_cookie(
        self, ctx: Ctx, resp: AuthResponse, token: str, session: dict[str, Any] | None, user: Any
    ) -> None:
        """Refresh the session cookie (and cache cookie, if enabled) — TS setSessionCookie."""
        resp.set_cookie(refresh_session_cookie(ctx.auth, ctx.request, token))
        if session is not None and ctx.auth.session_options.cookie_cache.enabled:
            dont_remember = cookie_name(ctx.auth, "dont_remember") in ctx.request.cookies()
            cache = set_cookie_cache(ctx.auth, session, user, dont_remember)
            if cache is not None:
                resp.set_cookie(cache)

    # --- endpoints --------------------------------------------------------------------

    async def _require_session(self, ctx: Ctx) -> dict[str, Any]:
        session = await ctx.get_session()
        if session is None:
            raise APIError(401, "UNAUTHORIZED", "Not authenticated")
        return session

    async def _org_limit_reached(self, user: dict[str, Any], user_orgs: list[Any]) -> bool:
        limit = self.organization_limit
        if isinstance(limit, bool) or limit is None:
            return False  # bool isn't a numeric cap; None is unlimited
        if isinstance(limit, int):
            return len(user_orgs) >= limit
        return bool(await _maybe_await(limit(user)))  # callable(user) -> hasReached

    async def _create(self, ctx: Ctx) -> AuthResponse:
        body = ctx.body()
        name = _required_nonempty_str(body, "name")
        slug = _required_nonempty_str(body, "slug")
        metadata = body.get("metadata")
        if metadata is not None and not isinstance(metadata, dict):
            raise APIError(400, "INVALID_BODY", "metadata must be an object")

        # SEAM: the server-only ``userId`` create path (no session) needs a server API
        # surface that doesn't exist this phase; over HTTP a session is always required.
        session = await self._require_session(ctx)
        user = session["user"]

        allow = self.allow_user_to_create_organization
        can_create = await _maybe_await(allow(user)) if callable(allow) else allow
        if not can_create:
            raise _err(403, "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION")

        user_orgs = await self._list_orgs(ctx, user["id"])
        if await self._org_limit_reached(user, user_orgs):
            raise _err(403, "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS")

        if await self._find_org_by_slug(ctx, slug):
            raise _err(400, "ORGANIZATION_ALREADY_EXISTS")

        org_data: dict[str, Any] = {"name": name, "slug": slug, "createdAt": utcnow()}
        if "logo" in body:
            org_data["logo"] = body["logo"]
        if metadata is not None:
            org_data["metadata"] = metadata
        for key in self._extra("organization"):
            if key in body:
                org_data[key] = body[key]

        merged = await self._run_before_hook(
            "before_create_organization", {"organization": org_data, "user": user}
        )
        if merged is not None:
            org_data = {**org_data, **merged}

        organization = await self._create_org(ctx, org_data)

        member_data: dict[str, Any] = {
            "userId": user["id"],
            "organizationId": organization["id"],
            "role": self.creator_role or "owner",
        }
        merged = await self._run_before_hook(
            "before_add_member",
            {"member": dict(member_data), "user": user, "organization": organization},
        )
        if merged is not None:
            member_data = {**member_data, **merged}
        member = await self._create_member(ctx, member_data)
        await self._run_after_hook(
            "after_add_member", {"member": member, "user": user, "organization": organization}
        )

        # teams.defaultTeam: create the default team + join it (crud-org.ts:220-263)
        team_member: dict[str, Any] | None = None
        if self._teams_enabled:
            default_team = (self.teams or {}).get("default_team")
            if default_team is None or default_team.get("enabled") is not False:
                team_data: dict[str, Any] = {
                    "organizationId": organization["id"],
                    "name": organization["name"],
                    "createdAt": utcnow(),
                }
                merged = await self._run_before_hook(
                    "before_create_team",
                    {
                        "team": {
                            "organizationId": organization["id"],
                            "name": organization["name"],
                        },
                        "user": user,
                        "organization": organization,
                    },
                )
                if merged is not None:
                    team_data = {**team_data, **merged}
                custom = default_team.get("custom_create_default_team") if default_team else None
                default_team_row = (
                    await _maybe_await(custom(organization, ctx))
                    if custom is not None
                    else await self._create_team(ctx, team_data)
                )
                team_member = await self._find_or_create_team_member(
                    ctx, default_team_row["id"], user["id"]
                )
                await self._run_after_hook(
                    "after_create_team",
                    {"team": default_team_row, "user": user, "organization": organization},
                )

        await self._run_after_hook(
            "after_create_organization",
            {"organization": organization, "user": user, "member": member},
        )

        if not body.get("keepCurrentActiveOrganization"):
            await self._set_active_org(ctx, session["session"]["token"], organization["id"])
            if team_member is not None:
                await self._set_active_team(ctx, session["session"]["token"], team_member["teamId"])

        return AuthResponse(body={**organization, "members": [member]})

    async def _check_slug(self, ctx: Ctx) -> AuthResponse:
        slug = _required_str(ctx.body(), "slug")
        if await self._find_org_by_slug(ctx, slug) is None:
            return AuthResponse(body={"status": True})
        raise _err(400, "ORGANIZATION_SLUG_ALREADY_TAKEN")

    async def _update(self, ctx: Ctx) -> AuthResponse:
        body = ctx.body()
        data = body.get("data")
        if not isinstance(data, dict):
            raise APIError(400, "INVALID_BODY", "data is required")
        if "name" in data and (not isinstance(data["name"], str) or not data["name"]):
            raise APIError(400, "INVALID_BODY", "name must not be empty")
        if "slug" in data and (not isinstance(data["slug"], str) or not data["slug"]):
            raise APIError(400, "INVALID_BODY", "slug must not be empty")
        if (
            "metadata" in data
            and data["metadata"] is not None
            and not isinstance(data["metadata"], dict)
        ):
            raise APIError(400, "INVALID_BODY", "metadata must be an object")
        allowed = {"name", "slug", "logo", "metadata", *self._extra("organization")}
        data = {k: v for k, v in data.items() if k in allowed}

        session = await self._require_session(ctx)
        org_id = body.get("organizationId") or session["session"].get("activeOrganizationId")
        if not org_id:
            raise _err(400, "ORGANIZATION_NOT_FOUND")
        member = await self._find_member_by_org(ctx, session["user"]["id"], org_id)
        if member is None:
            raise _err(400, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION")
        if not await has_permission(
            role=member["role"],
            permissions={"organization": ["update"]},
            options=self,
            organization_id=org_id,
            ctx=ctx,
        ):
            raise _err(403, "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION")

        if isinstance(data.get("slug"), str):
            existing = await self._find_org_by_slug(ctx, data["slug"])
            if existing is not None and existing["id"] != org_id:
                raise _err(400, "ORGANIZATION_SLUG_ALREADY_TAKEN")

        merged = await self._run_before_hook(
            "before_update_organization",
            {"organization": data, "user": session["user"], "member": member},
        )
        if merged is not None:
            data = {**data, **merged}
        updated = await self._update_org(ctx, org_id, data)
        await self._run_after_hook(
            "after_update_organization",
            {"organization": updated, "user": session["user"], "member": member},
        )
        return AuthResponse(body=updated)

    async def _delete(self, ctx: Ctx) -> AuthResponse:
        if self.disable_organization_deletion:
            raise APIError(
                404, "ORGANIZATION_DELETION_DISABLED", "Organization deletion is disabled"
            )
        session = await self._require_session(ctx)
        org_id = ctx.body().get("organizationId")
        if not org_id:
            raise _err(400, "ORGANIZATION_NOT_FOUND")
        member = await self._find_member_by_org(ctx, session["user"]["id"], org_id)
        if member is None:
            raise _err(400, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION")
        if not await has_permission(
            role=member["role"],
            permissions={"organization": ["delete"]},
            options=self,
            organization_id=org_id,
            ctx=ctx,
        ):
            raise _err(403, "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION")
        if org_id == session["session"].get("activeOrganizationId"):
            await self._set_active_org(ctx, session["session"]["token"], None)
        org = await self._find_org_by_id(ctx, org_id)
        if org is None:
            raise APIError(400, "BAD_REQUEST", "Organization not found")
        await self._run_after_hook(
            "before_delete_organization", {"organization": org, "user": session["user"]}
        )
        await self._delete_org(ctx, org_id)
        await self._run_after_hook(
            "after_delete_organization", {"organization": org, "user": session["user"]}
        )
        return AuthResponse(body=org)

    async def _get_full_organization(self, ctx: Ctx) -> AuthResponse:
        session = await self._require_session(ctx)
        query = ctx.request.query
        org_slug = query.get("organizationSlug")
        org_id = (
            org_slug
            or query.get("organizationId")
            or session["session"].get("activeOrganizationId")
        )
        if not org_id:
            return AuthResponse(body=None)
        members_limit = query.get("membersLimit")
        full = await self._find_full_org(
            ctx,
            org_id,
            is_slug=bool(org_slug),
            members_limit=int(members_limit) if members_limit else None,
        )
        if full is None:
            raise _err(400, "ORGANIZATION_NOT_FOUND")
        if await self._check_membership(ctx, session["user"]["id"], full["id"]) is None:
            await self._set_active_org(ctx, session["session"]["token"], None)
            raise _err(403, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION")
        return AuthResponse(body=full)

    async def _set_active(self, ctx: Ctx) -> AuthResponse:
        session = await self._require_session(ctx)
        body = ctx.body()
        token = session["session"]["token"]
        active_org = session["session"].get("activeOrganizationId")
        org_id = body.get("organizationId")
        org_slug = body.get("organizationSlug")

        # explicit null → unset (only if there is an active org to clear)
        if "organizationId" in body and org_id is None:
            if not active_org:
                return AuthResponse(body=None)
            updated = await self._set_active_org(ctx, token, None)
            resp = AuthResponse(body=None)
            self._apply_session_cookie(ctx, resp, token, updated, session["user"])
            return resp

        if not org_id and not org_slug:
            if not active_org:
                return AuthResponse(body=None)
            org_id = active_org

        if org_slug and not org_id:
            org = await self._find_org_by_slug(ctx, org_slug)
            if org is None:
                raise _err(400, "ORGANIZATION_NOT_FOUND")
            org_id = org["id"]

        if not org_id:
            raise _err(400, "ORGANIZATION_NOT_FOUND")

        if await self._check_membership(ctx, session["user"]["id"], org_id) is None:
            await self._set_active_org(ctx, token, None)
            raise _err(403, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION")

        organization = await self._find_org_by_id(ctx, org_id)
        if organization is None:
            raise _err(400, "ORGANIZATION_NOT_FOUND")
        updated = await self._set_active_org(ctx, token, organization["id"])
        resp = AuthResponse(body=organization)
        self._apply_session_cookie(ctx, resp, token, updated, session["user"])
        return resp

    async def _list(self, ctx: Ctx) -> AuthResponse:
        session = await self._require_session(ctx)
        return AuthResponse(body=await self._list_orgs(ctx, session["user"]["id"]))

    async def _leave(self, ctx: Ctx) -> AuthResponse:
        session = await self._require_session(ctx)
        org_id = _required_str(ctx.body(), "organizationId")
        member = await self._find_member_by_org(ctx, session["user"]["id"], org_id)
        if member is None:
            raise _err(400, "MEMBER_NOT_FOUND")
        creator_role = self.creator_role or "owner"
        if creator_role in member["role"].split(","):
            members = await ctx.adapter.find_many("member", [Where("organizationId", org_id)])
            owners = [m for m in members if creator_role in m["role"].split(",")]
            if len(owners) <= 1:
                raise _err(400, "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER")
        await self._delete_member(ctx, member["id"], org_id=org_id, user_id=member["userId"])
        if session["session"].get("activeOrganizationId") == org_id:
            await self._set_active_org(ctx, session["session"]["token"], None)
        return AuthResponse(body=member)

    async def _list_members_route(self, ctx: Ctx) -> AuthResponse:
        session = await self._require_session(ctx)
        query = ctx.request.query
        org_id = query.get("organizationId") or session["session"].get("activeOrganizationId")
        if query.get("organizationSlug"):
            org = await self._find_org_by_slug(ctx, query["organizationSlug"])
            if org is None:
                raise _err(400, "ORGANIZATION_NOT_FOUND")
            org_id = org["id"]
        if not org_id:
            raise _err(400, "NO_ACTIVE_ORGANIZATION")
        if await self._find_member_by_org(ctx, session["user"]["id"], org_id) is None:
            raise _err(403, "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION")
        member_filter = (
            {
                "field": query["filterField"],
                "operator": query.get("filterOperator"),
                "value": query.get("filterValue"),
            }
            if query.get("filterField")
            else None
        )
        result = await self._list_members(
            ctx,
            org_id,
            limit=int(query["limit"]) if query.get("limit") else None,
            offset=int(query["offset"]) if query.get("offset") else None,
            sort_by=query.get("sortBy"),
            sort_order=query.get("sortDirection"),
            member_filter=member_filter,
        )
        return AuthResponse(body=result)

    async def _remove_member(self, ctx: Ctx) -> AuthResponse:
        session = await self._require_session(ctx)
        body = ctx.body()
        org_id = body.get("organizationId") or session["session"].get("activeOrganizationId")
        if not org_id:
            raise _err(400, "NO_ACTIVE_ORGANIZATION")
        actor = await self._find_member_by_org(ctx, session["user"]["id"], org_id)
        if actor is None:
            raise _err(400, "MEMBER_NOT_FOUND")
        member_id_or_email = _required_str(body, "memberIdOrEmail")
        if "@" in member_id_or_email:
            to_remove = await self._find_member_by_email(ctx, member_id_or_email, org_id)
        else:
            found = await self._find_member_by_id(ctx, member_id_or_email)
            to_remove = {k: v for k, v in found.items() if k != "user"} if found else None
        if to_remove is None:
            raise _err(400, "MEMBER_NOT_FOUND")

        creator_role = self.creator_role or "owner"
        if creator_role in to_remove["role"].split(","):
            actor_roles = [r.strip() for r in actor["role"].split(",")]
            if creator_role not in actor_roles:
                raise _err(400, "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER")
            listed = await self._list_members(ctx, org_id)
            owners = [m for m in listed["members"] if creator_role in m["role"].split(",")]
            if len(owners) <= 1:
                raise _err(400, "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER")

        if not await has_permission(
            role=actor["role"],
            permissions={"member": ["delete"]},
            options=self,
            organization_id=org_id,
            ctx=ctx,
        ):
            raise _err(401, "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER")

        if to_remove["organizationId"] != org_id:
            raise _err(400, "MEMBER_NOT_FOUND")
        organization = await self._find_org_by_id(ctx, org_id)
        if organization is None:
            raise _err(400, "ORGANIZATION_NOT_FOUND")
        removed_user = await ctx.adapter.find_one("user", [Where("id", to_remove["userId"])])
        if removed_user is None:
            raise APIError(400, "BAD_REQUEST", "User not found")

        await self._run_after_hook(
            "before_remove_member",
            {"member": to_remove, "user": removed_user, "organization": organization},
        )
        await self._delete_member(
            ctx, to_remove["id"], org_id=to_remove["organizationId"], user_id=to_remove["userId"]
        )
        if (
            session["user"]["id"] == to_remove["userId"]
            and session["session"].get("activeOrganizationId") == to_remove["organizationId"]
        ):
            await self._set_active_org(ctx, session["session"]["token"], None)
        await self._run_after_hook(
            "after_remove_member",
            {"member": to_remove, "user": removed_user, "organization": organization},
        )
        return AuthResponse(body={"member": to_remove})

    async def _update_member_role(self, ctx: Ctx) -> AuthResponse:
        session = await self._require_session(ctx)
        body = ctx.body()
        raw_role = body.get("role")
        if not raw_role:
            raise APIError(400, "INVALID_BODY", "role is required")
        org_id = body.get("organizationId") or session["session"].get("activeOrganizationId")
        if not org_id:
            raise _err(400, "NO_ACTIVE_ORGANIZATION")
        member_id = _required_str(body, "memberId")

        role_list = raw_role if isinstance(raw_role, list) else [raw_role]
        role_to_set: list[str] = []
        for entry in role_list:
            if not isinstance(entry, str):
                continue
            role_to_set.extend(p.strip() for p in entry.split(",") if p.strip())
        if not role_to_set:
            raise APIError(400, "INVALID_BODY", "role is required")

        valid_static = set(_resolve_roles(self).keys())
        unknown = [r for r in role_to_set if r not in valid_static]
        if unknown:
            # DAC: consult organizationRole rows before rejecting (crud-members.ts:576-602).
            still_invalid = await self._filter_dynamic_role_names(ctx, org_id, unknown)
            if still_invalid:
                raise APIError(400, "ROLE_NOT_FOUND", f"ROLE_NOT_FOUND: {', '.join(still_invalid)}")

        actor = await self._find_member_by_org(ctx, session["user"]["id"], org_id)
        if actor is None:
            raise _err(400, "MEMBER_NOT_FOUND")
        to_update = (
            actor if actor["id"] == member_id else await self._find_member_by_id(ctx, member_id)
        )
        if to_update is None:
            raise _err(400, "MEMBER_NOT_FOUND")
        if to_update["organizationId"] != org_id:
            raise _err(403, "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER")

        creator_role = self.creator_role or "owner"
        updater_is_creator = creator_role in actor["role"].split(",")
        is_updating_creator = creator_role in to_update["role"].split(",")
        is_setting_creator = creator_role in role_to_set
        if (is_updating_creator and not updater_is_creator) or (
            is_setting_creator and not updater_is_creator
        ):
            raise _err(403, "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER")

        if updater_is_creator and actor["id"] == to_update["id"]:
            members = await ctx.adapter.find_many("member", [Where("organizationId", org_id)])
            owners = [m for m in members if creator_role in m["role"].split(",")]
            if len(owners) <= 1 and not is_setting_creator:
                raise _err(400, "YOU_CANNOT_LEAVE_THE_ORGANIZATION_WITHOUT_AN_OWNER")

        if not await has_permission(
            role=actor["role"],
            permissions={"member": ["update"]},
            options=self,
            organization_id=org_id,
            ctx=ctx,
            allow_creator_all_permissions=True,
        ):
            raise _err(403, "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER")

        organization = await self._find_org_by_id(ctx, org_id)
        if organization is None:
            raise _err(400, "ORGANIZATION_NOT_FOUND")
        updated_user = await ctx.adapter.find_one("user", [Where("id", to_update["userId"])])
        if updated_user is None:
            raise APIError(400, "BAD_REQUEST", "User not found")

        previous_role = to_update["role"]
        new_role = parse_roles(role_to_set)
        merged = await self._run_before_hook(
            "before_update_member_role",
            {
                "member": to_update,
                "newRole": new_role,
                "user": updated_user,
                "organization": organization,
            },
        )
        role_value = merged.get("role", new_role) if merged is not None else new_role
        updated = await self._update_member(ctx, member_id, role_value)
        if updated is None:
            raise _err(400, "MEMBER_NOT_FOUND")
        await self._run_after_hook(
            "after_update_member_role",
            {
                "member": updated,
                "previousRole": previous_role,
                "user": updated_user,
                "organization": organization,
            },
        )
        return AuthResponse(body=updated)

    async def _get_active_member(self, ctx: Ctx) -> AuthResponse:
        session = await self._require_session(ctx)
        org_id = session["session"].get("activeOrganizationId")
        if not org_id:
            raise _err(400, "NO_ACTIVE_ORGANIZATION")
        member = await self._find_member_by_org(ctx, session["user"]["id"], org_id)
        if member is None:
            raise _err(400, "MEMBER_NOT_FOUND")
        return AuthResponse(body=member)

    async def _has_permission(self, ctx: Ctx) -> AuthResponse:
        session = await self._require_session(ctx)
        body = ctx.body()
        org_id = body.get("organizationId") or session["session"].get("activeOrganizationId")
        if not org_id:
            raise _err(400, "NO_ACTIVE_ORGANIZATION")
        member = await self._find_member_by_org(ctx, session["user"]["id"], org_id)
        if member is None:
            raise _err(401, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION")
        # ``permissions`` is canonical; ``permission`` is the deprecated alias (TS xor body).
        permissions = body.get("permissions")
        if permissions is None:
            permissions = body.get("permission")
        result = await has_permission(
            role=member["role"],
            permissions=permissions,
            options=self,
            organization_id=org_id,
            ctx=ctx,
        )
        return AuthResponse(body={"error": None, "success": result})

    # --- invitation endpoints (routes/crud-invites.ts) --------------------------------

    async def _invitation_limit(
        self, user: dict[str, Any], organization: dict[str, Any], member: dict[str, Any], ctx: Ctx
    ) -> int:
        limit = self.invitation_limit
        if limit is None or isinstance(limit, bool):
            return 100  # None -> TS ?? 100; bool isn't a numeric cap
        if isinstance(limit, int):
            return limit
        return await _maybe_await(
            limit({"user": user, "organization": organization, "member": member}, ctx)
        )

    async def _invite_member(self, ctx: Ctx) -> AuthResponse:
        session = await self._require_session(ctx)
        user = session["user"]
        body = ctx.body()
        org_id = body.get("organizationId") or session["session"].get("activeOrganizationId")
        if not org_id:
            raise _err(400, "ORGANIZATION_NOT_FOUND")
        email = validate_email(_required_str(body, "email"))  # lowercased; INVALID_EMAIL on bad

        member = await self._find_member_by_org(ctx, user["id"], org_id)
        if member is None:
            raise _err(400, "MEMBER_NOT_FOUND")
        if not await has_permission(
            role=member["role"],
            permissions={"invitation": ["create"]},
            options=self,
            organization_id=org_id,
            ctx=ctx,
        ):
            raise _err(403, "YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION")

        creator_role = self.creator_role or "owner"
        raw_role = body.get("role")
        if not raw_role:
            raise APIError(400, "INVALID_BODY", "role is required")
        roles = parse_roles(raw_role)
        roles_array = [r.strip() for r in roles.split(",") if r.strip()]
        valid_static = set(_resolve_roles(self).keys())
        unknown = [r for r in roles_array if r not in valid_static]
        if unknown:
            # DAC: consult organizationRole rows before rejecting (crud-invites.ts:299-322).
            still_invalid = await self._filter_dynamic_role_names(ctx, org_id, unknown)
            if still_invalid:
                raise APIError(
                    400,
                    "ROLE_NOT_FOUND",
                    f"{ERROR_CODES['ROLE_NOT_FOUND']}: {', '.join(still_invalid)}",
                )
        member_roles = [r.strip() for r in member["role"].split(",")]
        if creator_role not in member_roles and creator_role in roles.split(","):
            raise _err(403, "YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE")

        if await self._find_member_by_email(ctx, email, org_id) is not None:
            raise _err(400, "USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION")
        already_invited = await self._find_pending_invitation(ctx, email, org_id)
        if (
            already_invited
            and not body.get("resend")
            and not self.cancel_pending_invitations_on_re_invite
        ):
            raise _err(400, "USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION")

        organization = await self._find_org_by_id(ctx, org_id)
        if organization is None:
            raise _err(400, "ORGANIZATION_NOT_FOUND")

        # resend: reuse the existing invitation, refresh its expiry, re-send the email.
        if already_invited and body.get("resend"):
            existing = already_invited[0]
            new_expires = self._expiry(self.invitation_expires_in)
            await ctx.adapter.update(
                "invitation", [Where("id", existing["id"])], {"expiresAt": new_expires}
            )
            updated = {**existing, "expiresAt": new_expires}
            await self._maybe_send_invitation_email(ctx, updated, organization, member, user)
            return AuthResponse(body=updated)

        if already_invited and self.cancel_pending_invitations_on_re_invite:
            await self._update_invitation(ctx, already_invited[0]["id"], "canceled")

        limit = await self._invitation_limit(user, organization, member, ctx)
        pending = await self._find_pending_invitations(ctx, org_id)
        if len(pending) >= limit:
            raise _err(403, "INVITATION_LIMIT_REACHED")

        # teams: validate requested teamId(s) (crud-invites.ts:455-538)
        team_ids: list[str] = []
        if self._teams_enabled and body.get("teamId"):
            raw_team = body["teamId"]
            team_ids = [raw_team] if isinstance(raw_team, str) else list(raw_team)
            if any("," in t for t in team_ids):
                raise _err(400, "INVALID_TEAM_ID")
            for tid in team_ids:  # every team must belong to this organization
                if await self._find_team_by_id(ctx, tid, org_id=org_id) is None:
                    raise _err(400, "TEAM_NOT_FOUND")
            if (self.teams or {}).get("maximum_members_per_team") is not None:
                for tid in team_ids:
                    team = await self._find_team_by_id(
                        ctx, tid, org_id=org_id, include_members=True
                    )
                    if team is None:
                        raise _err(400, "TEAM_NOT_FOUND")
                    resolved = await self._resolve_max_members_per_team(tid, org_id, session)
                    if resolved is not None and len(team["members"]) >= resolved:
                        raise _err(403, "TEAM_MEMBER_LIMIT_REACHED")

        invitation_data: dict[str, Any] = {"role": roles, "email": email, "organizationId": org_id}
        for key in self._extra("invitation"):
            if key in body:
                invitation_data[key] = body[key]
        merged = await self._run_before_hook(
            "before_create_invitation",
            {
                "invitation": {
                    **invitation_data,
                    "inviterId": user["id"],
                    "teamId": team_ids[0] if team_ids else None,
                },
                "inviter": user,
                "organization": organization,
            },
        )
        if merged is not None:
            invitation_data = {**invitation_data, **merged}
        # teamIds → teamId column (comma-joined) — derived from the request, TS wins over hook
        if self._teams_enabled:
            invitation_data["teamId"] = ",".join(team_ids) if team_ids else None

        invitation = await self._create_invitation(ctx, invitation_data, user)
        await self._maybe_send_invitation_email(ctx, invitation, organization, member, user)
        await self._run_after_hook(
            "after_create_invitation",
            {"invitation": invitation, "inviter": user, "organization": organization},
        )
        return AuthResponse(body=invitation)

    async def _maybe_send_invitation_email(
        self,
        ctx: Ctx,
        invitation: dict[str, Any],
        organization: dict[str, Any],
        member: dict[str, Any],
        user: dict[str, Any],
    ) -> None:
        if self.send_invitation_email is None:
            return
        # ponytail: TS runs this in the background (runInBackgroundOrAwait); we await it
        # inline — simplest correct for a single-process app. Add a task runner if it ever
        # needs to be fire-and-forget.
        await _maybe_await(
            self.send_invitation_email(
                {
                    "id": invitation["id"],
                    "role": invitation["role"],
                    "email": invitation["email"].lower(),
                    "organization": organization,
                    "inviter": {**member, "user": user},
                    "invitation": invitation,
                },
                ctx.request,
            )
        )

    async def _accept_invitation(self, ctx: Ctx) -> AuthResponse:
        session = await self._require_session(ctx)
        user = session["user"]
        invitation_id = _required_str(ctx.body(), "invitationId")
        invitation = await self._find_invitation_by_id(ctx, invitation_id)
        if (
            invitation is None
            or invitation["expiresAt"] < utcnow()
            or invitation["status"] != "pending"
        ):
            raise _err(400, "INVITATION_NOT_FOUND")
        if invitation["email"].lower() != user["email"].lower():
            raise _err(403, "YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION")
        if self._require_verified_email_for_invitation() and not user.get("emailVerified"):
            raise _err(403, "EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION")

        members_count = await ctx.adapter.count(
            "member", [Where("organizationId", invitation["organizationId"])]
        )
        organization = await self._find_org_by_id(ctx, invitation["organizationId"])
        if organization is None:
            raise _err(400, "ORGANIZATION_NOT_FOUND")
        membership_limit = self.membership_limit
        if isinstance(membership_limit, bool):
            limit = 100  # bool isn't a numeric cap
        elif isinstance(membership_limit, int):
            limit = membership_limit or 100  # TS `membershipLimit || 100` (0 -> 100)
        else:
            limit = await _maybe_await(membership_limit(user, organization))
        if members_count >= limit:
            raise _err(403, "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED")

        await self._run_before_hook(
            "before_accept_invitation",
            {"invitation": invitation, "user": user, "organization": organization},
        )
        # Claim the pending -> accepted transition atomically (fromStatus guard).
        accepted = await self._update_invitation(
            ctx, invitation_id, "accepted", from_status="pending"
        )
        if accepted is None:
            raise _err(400, "INVITATION_NOT_FOUND")

        # teams: create the team membership(s) the invitation carried (crud-invites.ts:755-823)
        team_active_session: dict[str, Any] | None = None
        if self._teams_enabled and accepted.get("teamId"):
            try:
                invited_team_ids = accepted["teamId"].split(",")
                for tid in invited_team_ids:
                    team = await self._find_team_by_id(ctx, tid, org_id=accepted["organizationId"])
                    if team is None:
                        raise _err(400, "TEAM_NOT_FOUND")
                    resolved = await self._resolve_max_members_per_team(
                        tid, accepted["organizationId"], session
                    )
                    if resolved is not None:
                        result = await self._add_team_member_with_limit(
                            ctx, tid, user["id"], resolved
                        )
                        if result["status"] == "limitReached":
                            raise _err(403, "TEAM_MEMBER_LIMIT_REACHED")
                    else:
                        await self._find_or_create_team_member(ctx, tid, user["id"])
                if len(invited_team_ids) == 1:  # single team → set it active + refresh cookie
                    team_active_session = await self._set_active_team(
                        ctx, session["session"]["token"], invited_team_ids[0]
                    )
            except (
                Exception
            ):  # release the claim so the invitee can retry (crud-invites.ts:839-847)
                await self._update_invitation(ctx, invitation_id, "pending")
                raise

        member = await self._create_member(
            ctx,
            {
                "userId": user["id"],
                "organizationId": accepted["organizationId"],
                "role": accepted["role"],
            },
        )
        await self._set_active_org(ctx, session["session"]["token"], accepted["organizationId"])
        await self._run_after_hook(
            "after_accept_invitation",
            {
                "invitation": accepted,
                "member": member,
                "user": user,
                "organization": organization,
            },
        )
        resp = AuthResponse(body={"invitation": accepted, "member": member})
        if team_active_session is not None:
            self._apply_session_cookie(
                ctx, resp, session["session"]["token"], team_active_session, user
            )
        return resp

    async def _reject_invitation(self, ctx: Ctx) -> AuthResponse:
        session = await self._require_session(ctx)
        user = session["user"]
        invitation_id = _required_str(ctx.body(), "invitationId")
        invitation = await self._find_invitation_by_id(ctx, invitation_id)
        # reject does not check expiry — only that it is still pending (TS parity).
        if invitation is None or invitation["status"] != "pending":
            raise APIError(400, "INVITATION_NOT_FOUND", "Invitation not found!")
        if invitation["email"].lower() != user["email"].lower():
            raise _err(403, "YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION")
        if self._require_verified_email_for_invitation() and not user.get("emailVerified"):
            raise _err(403, "EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION")
        organization = await self._find_org_by_id(ctx, invitation["organizationId"])
        if organization is None:
            raise _err(400, "ORGANIZATION_NOT_FOUND")
        await self._run_before_hook(
            "before_reject_invitation",
            {"invitation": invitation, "user": user, "organization": organization},
        )
        rejected = await self._update_invitation(ctx, invitation_id, "rejected")
        await self._run_after_hook(
            "after_reject_invitation",
            {"invitation": rejected or invitation, "user": user, "organization": organization},
        )
        return AuthResponse(body={"invitation": rejected, "member": None})

    async def _cancel_invitation(self, ctx: Ctx) -> AuthResponse:
        session = await self._require_session(ctx)
        user = session["user"]
        invitation_id = _required_str(ctx.body(), "invitationId")
        invitation = await self._find_invitation_by_id(ctx, invitation_id)
        if invitation is None:
            raise _err(400, "INVITATION_NOT_FOUND")
        member = await self._find_member_by_org(ctx, user["id"], invitation["organizationId"])
        if member is None:
            raise _err(400, "MEMBER_NOT_FOUND")
        if not await has_permission(
            role=member["role"],
            permissions={"invitation": ["cancel"]},
            options=self,
            organization_id=invitation["organizationId"],
            ctx=ctx,
        ):
            raise _err(403, "YOU_ARE_NOT_ALLOWED_TO_CANCEL_THIS_INVITATION")
        organization = await self._find_org_by_id(ctx, invitation["organizationId"])
        if organization is None:
            raise _err(400, "ORGANIZATION_NOT_FOUND")
        await self._run_before_hook(
            "before_cancel_invitation",
            {"invitation": invitation, "cancelledBy": user, "organization": organization},
        )
        canceled = await self._update_invitation(ctx, invitation_id, "canceled")
        await self._run_after_hook(
            "after_cancel_invitation",
            {
                "invitation": canceled or invitation,
                "cancelledBy": user,
                "organization": organization,
            },
        )
        return AuthResponse(body=canceled)

    async def _get_invitation(self, ctx: Ctx) -> AuthResponse:
        session = await ctx.get_session()
        if session is None:
            raise APIError(401, "UNAUTHORIZED", "Not authenticated")
        user = session["user"]
        invitation_id = ctx.request.query.get("id")
        if not invitation_id:
            raise APIError(400, "BAD_REQUEST", "id is required")
        invitation = await self._find_invitation_by_id(ctx, invitation_id)
        if (
            invitation is None
            or invitation["status"] != "pending"
            or invitation["expiresAt"] < utcnow()
        ):
            raise APIError(400, "BAD_REQUEST", "Invitation not found!")
        if invitation["email"].lower() != user["email"].lower():
            raise _err(403, "YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION")
        if self._require_verified_email_for_invitation() and not user.get("emailVerified"):
            raise _err(403, "EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION")
        organization = await self._find_org_by_id(ctx, invitation["organizationId"])
        if organization is None:
            raise _err(400, "ORGANIZATION_NOT_FOUND")
        inviter = await self._find_member_by_org(
            ctx, invitation["inviterId"], invitation["organizationId"]
        )
        if inviter is None:
            raise _err(400, "INVITER_IS_NO_LONGER_A_MEMBER_OF_THE_ORGANIZATION")
        return AuthResponse(
            body={
                **invitation,
                "organizationName": organization["name"],
                "organizationSlug": organization["slug"],
                "inviterEmail": inviter["user"]["email"],
            }
        )

    async def _list_invitations_route(self, ctx: Ctx) -> AuthResponse:
        session = await self._require_session(ctx)
        user = session["user"]
        org_id = ctx.request.query.get("organizationId") or session["session"].get(
            "activeOrganizationId"
        )
        if not org_id:
            raise APIError(400, "BAD_REQUEST", "Organization ID is required")
        if await self._find_member_by_org(ctx, user["id"], org_id) is None:
            raise APIError(403, "FORBIDDEN", "You are not a member of this organization")
        return AuthResponse(body=await self._list_invitation_rows(ctx, org_id))

    async def _list_user_invitations(self, ctx: Ctx) -> AuthResponse:
        session = await ctx.get_session()
        # Over HTTP a request always exists, so a client-supplied email is always rejected;
        # only sessionless server-side SDK calls (not this transport) may pass it.
        if ctx.request.query.get("email"):
            raise APIError(
                400, "BAD_REQUEST", "User email cannot be passed for client side API calls."
            )
        if session is not None and not session["user"].get("emailVerified"):
            raise _err(403, "EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION")
        user_email = session["user"]["email"] if session is not None else None
        if not user_email:
            raise APIError(400, "BAD_REQUEST", "Missing session headers, or email query parameter.")
        invitations = await self._list_user_invitation_rows(ctx, user_email)
        pending = [i for i in invitations if i["status"] == "pending"]
        return AuthResponse(body=pending)

    # --- team adapter helpers (adapter.ts team methods) --------------------------------

    def _filter_team(self, team: dict[str, Any]) -> dict[str, Any]:
        return filter_output_fields(team, self.schema["team"])

    def _filter_team_member(self, tm: dict[str, Any]) -> dict[str, Any]:
        return filter_output_fields(tm, self.schema["teamMember"])

    async def _create_team(self, ctx: Ctx, data: dict[str, Any]) -> dict[str, Any]:
        team = await ctx.adapter.create("team", {"id": generate_id(), **data})
        return self._filter_team(team)

    async def _find_team_by_id(
        self, ctx: Ctx, team_id: str, *, org_id: str | None = None, include_members: bool = False
    ) -> dict[str, Any] | None:
        where = [Where("id", team_id)]
        if org_id:
            where.append(Where("organizationId", org_id))
        team = await ctx.adapter.find_one("team", where)
        if team is None:
            return None
        result = self._filter_team(team)
        if include_members:
            members = await ctx.adapter.find_many("teamMember", [Where("teamId", team_id)])
            result["members"] = [self._filter_team_member(m) for m in members]
        return result

    async def _update_team(
        self, ctx: Ctx, team_id: str, data: dict[str, Any]
    ) -> dict[str, Any] | None:
        update = {k: v for k, v in data.items() if k not in ("id", "organizationId")}
        update["updatedAt"] = utcnow()  # TS team.updatedAt onUpdate (organization.ts:966-971)
        team = await ctx.adapter.update("team", [Where("id", team_id)], update)
        return self._filter_team(team) if team is not None else None

    async def _delete_team(self, ctx: Ctx, team_id: str) -> None:
        await ctx.adapter.delete_many("teamMember", [Where("teamId", team_id)])
        await ctx.adapter.delete("team", [Where("id", team_id)])

    async def _list_teams(self, ctx: Ctx, org_id: str) -> list[dict[str, Any]]:
        teams = await ctx.adapter.find_many("team", [Where("organizationId", org_id)])
        return [self._filter_team(t) for t in teams]

    async def _set_active_team(
        self, ctx: Ctx, token: str, team_id: str | None
    ) -> dict[str, Any] | None:
        return await ctx.internal.update_session(token, {"activeTeamId": team_id})

    async def _find_team_member(
        self, ctx: Ctx, team_id: str, user_id: str
    ) -> dict[str, Any] | None:
        tm = await ctx.adapter.find_one(
            "teamMember", [Where("teamId", team_id), Where("userId", user_id)]
        )
        return self._filter_team_member(tm) if tm is not None else None

    async def _create_team_member_row(self, ctx: Ctx, team_id: str, user_id: str) -> dict[str, Any]:
        tm = await ctx.adapter.create(
            "teamMember",
            {"id": generate_id(), "teamId": team_id, "userId": user_id, "createdAt": utcnow()},
        )
        return self._filter_team_member(tm)

    async def _find_or_create_team_member(
        self, ctx: Ctx, team_id: str, user_id: str
    ) -> dict[str, Any]:
        existing = await self._find_team_member(ctx, team_id, user_id)
        if existing is not None:
            return existing
        return await self._create_team_member_row(ctx, team_id, user_id)

    async def _add_team_member_with_limit(
        self, ctx: Ctx, team_id: str, user_id: str, maximum: int
    ) -> dict[str, Any]:
        # ponytail: count-then-create races under concurrency (TS FIXME team-cap-race);
        # MemoryAdapter is single-process, so this is exact. Add a unique constraint for a real DB.
        existing = await self._find_team_member(ctx, team_id, user_id)
        if existing is not None:
            return {"status": "added", "member": existing}
        count = await ctx.adapter.count("teamMember", [Where("teamId", team_id)])
        if count >= maximum:
            return {"status": "limitReached"}
        member = await self._create_team_member_row(ctx, team_id, user_id)
        return {"status": "added", "member": member}

    async def _remove_team_member_row(self, ctx: Ctx, team_id: str, user_id: str) -> None:
        await ctx.adapter.delete_many(
            "teamMember", [Where("teamId", team_id), Where("userId", user_id)]
        )

    async def _list_team_members(self, ctx: Ctx, team_id: str) -> list[dict[str, Any]]:
        members = await ctx.adapter.find_many("teamMember", [Where("teamId", team_id)])
        return [self._filter_team_member(m) for m in members]

    async def _list_teams_by_user(self, ctx: Ctx, user_id: str) -> list[dict[str, Any]]:
        tms = await ctx.adapter.find_many("teamMember", [Where("userId", user_id)])
        teams: list[dict[str, Any]] = []
        seen: set[str] = set()
        for tm in tms:  # per-id lookup — MemoryAdapter `in` lowercases ids (see _users_by_ids)
            tid = tm["teamId"]
            if tid in seen:
                continue
            seen.add(tid)
            team = await ctx.adapter.find_one("team", [Where("id", tid)])
            if team is not None:
                teams.append(self._filter_team(team))
        return teams

    async def _resolve_maximum_teams(
        self, ctx: Ctx, org_id: str, session: dict[str, Any] | None
    ) -> int | None:
        mt = (self.teams or {}).get("maximum_teams")
        if mt is None or isinstance(mt, bool):
            return None  # unlimited; bool isn't a numeric cap
        if isinstance(mt, int):
            return mt
        return await _maybe_await(mt({"organizationId": org_id, "session": session}, ctx))

    async def _resolve_max_members_per_team(
        self, team_id: str, org_id: str, session: dict[str, Any] | None
    ) -> int | None:
        """TS resolveMaximumMembersPerTeam (adapter.ts:34) — None when unconfigured."""
        m = (self.teams or {}).get("maximum_members_per_team")
        if m is None or isinstance(m, bool):
            return None
        if isinstance(m, int):
            return m
        if session is None:  # fn needs a session; over HTTP one always exists
            raise APIError(500, "INTERNAL_SERVER_ERROR", "maximumMembersPerTeam needs a session")
        return await _maybe_await(
            m({"teamId": team_id, "session": session, "organizationId": org_id})
        )

    async def _drop_team_from_pending_invitations(
        self, ctx: Ctx, org_id: str, team_id: str
    ) -> None:
        """crud-team.ts:353-381 — strip the removed team from pending invitations' teamId list."""
        pending = await self._find_pending_invitations(ctx, org_id)
        for inv in pending:
            team_id_str = inv.get("teamId")
            if not team_id_str:
                continue
            team_ids = team_id_str.split(",")
            if team_id not in team_ids:
                continue
            remaining = [t for t in team_ids if t != team_id]
            await ctx.adapter.update(
                "invitation",
                [Where("id", inv["id"])],
                {"teamId": ",".join(remaining) if remaining else None},
            )

    # --- team endpoints (routes/crud-team.ts) -----------------------------------------

    async def _create_team_route(self, ctx: Ctx) -> AuthResponse:
        session = await self._require_session(ctx)
        body = ctx.body()
        org_id = body.get("organizationId") or session["session"].get("activeOrganizationId")
        if not org_id:
            raise _err(400, "NO_ACTIVE_ORGANIZATION")
        name = _required_str(body, "name")
        member = await self._find_member_by_org(ctx, session["user"]["id"], org_id)
        if member is None:  # TS reuses the invite error string here (crud-team.ts:122-127)
            raise _err(403, "YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION")
        if not await has_permission(
            role=member["role"],
            permissions={"team": ["create"]},
            options=self,
            organization_id=org_id,
            ctx=ctx,
        ):
            raise _err(403, "YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION")

        existing_teams = await self._list_teams(ctx, org_id)
        maximum = await self._resolve_maximum_teams(ctx, org_id, session)
        if maximum and len(existing_teams) >= maximum:
            raise _err(400, "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS")

        organization = await self._find_org_by_id(ctx, org_id)
        if organization is None:
            raise _err(400, "ORGANIZATION_NOT_FOUND")

        extra = {k: v for k, v in body.items() if k in self._extra("team")}
        team_data = {
            "name": name,
            "organizationId": org_id,
            "createdAt": utcnow(),
            "updatedAt": utcnow(),
            **extra,
        }
        merged = await self._run_before_hook(
            "before_create_team",
            {
                "team": {"name": name, "organizationId": org_id, **extra},
                "user": session["user"],
                "organization": organization,
            },
        )
        if merged is not None:
            team_data = {**team_data, **merged}
        created = await self._create_team(ctx, team_data)
        await self._run_after_hook(
            "after_create_team",
            {"team": created, "user": session["user"], "organization": organization},
        )
        return AuthResponse(body=created)

    async def _update_team_route(self, ctx: Ctx) -> AuthResponse:
        session = await self._require_session(ctx)
        body = ctx.body()
        team_id = _required_str(body, "teamId")
        data = body.get("data")
        if not isinstance(data, dict):
            raise APIError(400, "INVALID_BODY", "data is required")
        org_id = data.get("organizationId") or session["session"].get("activeOrganizationId")
        if not org_id:
            raise _err(400, "NO_ACTIVE_ORGANIZATION")
        member = await self._find_member_by_org(ctx, session["user"]["id"], org_id)
        if member is None:
            raise _err(403, "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_TEAM")
        if not await has_permission(
            role=member["role"],
            permissions={"team": ["update"]},
            options=self,
            organization_id=org_id,
            ctx=ctx,
        ):
            raise _err(403, "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_TEAM")
        team = await self._find_team_by_id(ctx, team_id, org_id=org_id)
        if team is None or team["organizationId"] != org_id:
            raise _err(400, "TEAM_NOT_FOUND")
        organization = await self._find_org_by_id(ctx, org_id)
        if organization is None:
            raise _err(400, "ORGANIZATION_NOT_FOUND")
        updates = {k: v for k, v in data.items() if k not in ("organizationId", "id")}
        merged = await self._run_before_hook(
            "before_update_team",
            {
                "team": team,
                "updates": updates,
                "user": session["user"],
                "organization": organization,
            },
        )
        # TS: when the hook returns data, that data IS the update (not merged with updates)
        updated = await self._update_team(
            ctx, team["id"], merged if merged is not None else updates
        )
        await self._run_after_hook(
            "after_update_team",
            {"team": updated, "user": session["user"], "organization": organization},
        )
        return AuthResponse(body=updated)

    async def _remove_team_route(self, ctx: Ctx) -> AuthResponse:
        session = await self._require_session(ctx)
        body = ctx.body()
        team_id = _required_str(body, "teamId")
        org_id = body.get("organizationId") or session["session"].get("activeOrganizationId")
        if not org_id:
            raise _err(400, "NO_ACTIVE_ORGANIZATION")
        member = await self._find_member_by_org(ctx, session["user"]["id"], org_id)
        # cannot delete your own active team (crud-team.ts:286)
        if member is None or session["session"].get("activeTeamId") == team_id:
            raise _err(403, "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_TEAM")
        if not await has_permission(
            role=member["role"],
            permissions={"team": ["delete"]},
            options=self,
            organization_id=org_id,
            ctx=ctx,
        ):
            raise _err(403, "YOU_ARE_NOT_ALLOWED_TO_DELETE_TEAMS_IN_THIS_ORGANIZATION")
        team = await self._find_team_by_id(ctx, team_id, org_id=org_id)
        if team is None or team["organizationId"] != org_id:
            raise _err(400, "TEAM_NOT_FOUND")
        if not (self.teams or {}).get("allow_removing_all_teams"):
            teams = await self._list_teams(ctx, org_id)
            if len(teams) <= 1:
                raise _err(400, "UNABLE_TO_REMOVE_LAST_TEAM")
        organization = await self._find_org_by_id(ctx, org_id)
        if organization is None:
            raise _err(400, "ORGANIZATION_NOT_FOUND")
        # before_delete_team is fire-only (no data merge), like before_delete_organization
        await self._run_after_hook(
            "before_delete_team",
            {"team": team, "user": session["user"], "organization": organization},
        )
        await self._delete_team(ctx, team["id"])
        await self._drop_team_from_pending_invitations(ctx, org_id, team["id"])
        await self._run_after_hook(
            "after_delete_team",
            {"team": team, "user": session["user"], "organization": organization},
        )
        return AuthResponse(body={"message": "Team removed successfully."})

    async def _list_teams_route(self, ctx: Ctx) -> AuthResponse:
        session = await self._require_session(ctx)
        query = ctx.request.query
        org_id = query.get("organizationId") or session["session"].get("activeOrganizationId")
        if not org_id:
            raise _err(400, "NO_ACTIVE_ORGANIZATION")
        if await self._find_member_by_org(ctx, session["user"]["id"], org_id) is None:
            raise _err(403, "YOU_ARE_NOT_ALLOWED_TO_ACCESS_THIS_ORGANIZATION")
        return AuthResponse(body=await self._list_teams(ctx, org_id))

    async def _set_active_team_route(self, ctx: Ctx) -> AuthResponse:
        session = await self._require_session(ctx)
        body = ctx.body()
        token = session["session"]["token"]

        # explicit null → unset (only if there is an active team to clear)
        if "teamId" in body and body["teamId"] is None:
            if not session["session"].get("activeTeamId"):
                return AuthResponse(body=None)
            updated = await self._set_active_team(ctx, token, None)
            resp = AuthResponse(body=None)
            self._apply_session_cookie(ctx, resp, token, updated, session["user"])
            return resp

        team_id = body.get("teamId")
        if not team_id:
            active = session["session"].get("activeTeamId")
            if not active:
                return AuthResponse(body=None)
            team_id = active

        active_org = session["session"].get("activeOrganizationId")
        if not active_org:
            raise _err(400, "NO_ACTIVE_ORGANIZATION")
        team = await self._find_team_by_id(ctx, team_id, org_id=active_org)
        if team is None:
            raise _err(400, "TEAM_NOT_FOUND")
        if await self._find_team_member(ctx, team_id, session["user"]["id"]) is None:
            raise _err(403, "USER_IS_NOT_A_MEMBER_OF_THE_TEAM")
        updated = await self._set_active_team(ctx, token, team["id"])
        resp = AuthResponse(body=team)
        self._apply_session_cookie(ctx, resp, token, updated, session["user"])
        return resp

    async def _list_user_teams_route(self, ctx: Ctx) -> AuthResponse:
        session = await self._require_session(ctx)
        user_id = session["user"]["id"]
        teams = await self._list_teams_by_user(ctx, user_id)
        # keep only teams whose org the caller is actually a member of (crud-team.ts:862-881)
        result: list[dict[str, Any]] = []
        member_of: dict[str, bool] = {}
        for team in teams:
            oid = team["organizationId"]
            if oid not in member_of:
                member_of[oid] = await self._check_membership(ctx, user_id, oid) is not None
            if member_of[oid]:
                result.append(team)
        return AuthResponse(body=result)

    async def _list_team_members_route(self, ctx: Ctx) -> AuthResponse:
        session = await self._require_session(ctx)
        query = ctx.request.query
        team_id = query.get("teamId") or session["session"].get("activeTeamId")
        if not team_id:
            raise _err(400, "YOU_DO_NOT_HAVE_AN_ACTIVE_TEAM")
        team = await self._find_team_by_id(ctx, team_id)
        if team is None:
            raise _err(400, "TEAM_NOT_FOUND")
        # org membership (not just a teamMember row) is the requirement (crud-team.ts:969-978)
        if await self._check_membership(ctx, session["user"]["id"], team["organizationId"]) is None:
            raise _err(400, "USER_IS_NOT_A_MEMBER_OF_THE_TEAM")
        if await self._find_team_member(ctx, team_id, session["user"]["id"]) is None:
            raise _err(400, "USER_IS_NOT_A_MEMBER_OF_THE_TEAM")
        return AuthResponse(body=await self._list_team_members(ctx, team_id))

    async def _add_team_member_route(self, ctx: Ctx) -> AuthResponse:
        session = await self._require_session(ctx)
        body = ctx.body()
        org_id = body.get("organizationId") or session["session"].get("activeOrganizationId")
        if not org_id:
            raise _err(400, "NO_ACTIVE_ORGANIZATION")
        team_id = _required_str(body, "teamId")
        target_user_id = _required_str(body, "userId")
        current = await self._find_member_by_org(ctx, session["user"]["id"], org_id)
        if current is None:
            raise _err(400, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION")
        if not await has_permission(
            role=current["role"],
            permissions={"member": ["update"]},
            options=self,
            organization_id=org_id,
            ctx=ctx,
        ):
            raise _err(403, "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_TEAM_MEMBER")
        to_add = await self._find_member_by_org(ctx, target_user_id, org_id)
        if to_add is None:
            raise _err(400, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION")
        team = await self._find_team_by_id(ctx, team_id, org_id=org_id)
        if team is None:
            raise _err(400, "TEAM_NOT_FOUND")
        organization = await self._find_org_by_id(ctx, org_id)
        if organization is None:
            raise _err(400, "ORGANIZATION_NOT_FOUND")
        user_being_added = await ctx.adapter.find_one("user", [Where("id", target_user_id)])
        if user_being_added is None:
            raise APIError(400, "BAD_REQUEST", "User not found")
        await self._run_after_hook(  # before_add_team_member is fire-only (TS ignores the merge)
            "before_add_team_member",
            {
                "teamMember": {"teamId": team_id, "userId": target_user_id},
                "team": team,
                "user": user_being_added,
                "organization": organization,
            },
        )
        maximum = await self._resolve_max_members_per_team(team_id, org_id, session)
        if maximum is not None:
            result = await self._add_team_member_with_limit(ctx, team_id, target_user_id, maximum)
            if result["status"] == "limitReached":
                raise _err(403, "TEAM_MEMBER_LIMIT_REACHED")
            team_member = result["member"]
        else:
            team_member = await self._find_or_create_team_member(ctx, team_id, target_user_id)
        await self._run_after_hook(
            "after_add_team_member",
            {
                "teamMember": team_member,
                "team": team,
                "user": user_being_added,
                "organization": organization,
            },
        )
        return AuthResponse(body=team_member)

    async def _remove_team_member_route(self, ctx: Ctx) -> AuthResponse:
        session = await self._require_session(ctx)
        body = ctx.body()
        org_id = body.get("organizationId") or session["session"].get("activeOrganizationId")
        if not org_id:
            raise _err(400, "NO_ACTIVE_ORGANIZATION")
        team_id = _required_str(body, "teamId")
        target_user_id = _required_str(body, "userId")
        current = await self._find_member_by_org(ctx, session["user"]["id"], org_id)
        if current is None:
            raise _err(400, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION")
        if not await has_permission(
            role=current["role"],
            permissions={"member": ["delete"]},
            options=self,
            organization_id=org_id,
            ctx=ctx,
        ):
            raise _err(403, "YOU_ARE_NOT_ALLOWED_TO_REMOVE_A_TEAM_MEMBER")
        to_remove = await self._find_member_by_org(ctx, target_user_id, org_id)
        if to_remove is None:
            raise _err(400, "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION")
        team = await self._find_team_by_id(ctx, team_id, org_id=org_id)
        if team is None:
            raise _err(400, "TEAM_NOT_FOUND")
        organization = await self._find_org_by_id(ctx, org_id)
        if organization is None:
            raise _err(400, "ORGANIZATION_NOT_FOUND")
        user_being_removed = await ctx.adapter.find_one("user", [Where("id", target_user_id)])
        if user_being_removed is None:
            raise APIError(400, "BAD_REQUEST", "User not found")
        team_member = await self._find_team_member(ctx, team_id, target_user_id)
        if team_member is None:
            raise _err(400, "USER_IS_NOT_A_MEMBER_OF_THE_TEAM")
        await self._run_after_hook(
            "before_remove_team_member",
            {
                "teamMember": team_member,
                "team": team,
                "user": user_being_removed,
                "organization": organization,
            },
        )
        await self._remove_team_member_row(ctx, team_id, target_user_id)
        await self._run_after_hook(
            "after_remove_team_member",
            {
                "teamMember": team_member,
                "team": team,
                "user": user_being_removed,
                "organization": organization,
            },
        )
        return AuthResponse(body={"message": "Team member removed successfully."})

    # --- dynamic access control (routes/crud-access-control.ts) ------------------------

    def _filter_role(self, role: dict[str, Any]) -> dict[str, Any]:
        return filter_output_fields(role, self.schema["organizationRole"])

    def _predefined_role_names(self) -> list[str]:
        """TS ``options.roles ? Object.keys(options.roles) : ["owner","admin","member"]``."""
        return list(self.roles.keys()) if self.roles else ["owner", "admin", "member"]

    async def _resolve_maximum_roles(self, org_id: str) -> float:
        """TS ``maximumRolesPerOrganization`` (default ``Number.POSITIVE_INFINITY``)."""
        m = (self.dynamic_access_control or {}).get("maximum_roles_per_organization")
        if m is None or isinstance(m, bool):
            return float("inf")
        if isinstance(m, int):
            return m
        return await _maybe_await(m(org_id))

    def _role_additional_from_body(self, additional: dict[str, Any]) -> dict[str, Any]:
        """Client-settable additionalFields present in the payload (``input:false`` skipped;
        the adapter applies their default)."""
        result: dict[str, Any] = {}
        for key, field in self._extra("organizationRole").items():
            if field.input is False:
                continue
            if key in additional:
                result[key] = additional[key]
        return result

    def _check_role_name_taken_by_predefined(self, role_name: str) -> None:
        if role_name in self._predefined_role_names():
            raise _err(400, "ROLE_NAME_IS_ALREADY_TAKEN")

    async def _check_role_name_taken_in_db(self, ctx: Ctx, org_id: str, role_name: str) -> None:
        existing = await ctx.adapter.find_one(
            "organizationRole", [Where("organizationId", org_id), Where("role", role_name)]
        )
        if existing is not None:
            raise _err(400, "ROLE_NAME_IS_ALREADY_TAKEN")

    def _check_invalid_resources(self, permission: dict[str, Any]) -> None:
        """checkForInvalidResources: every requested resource must be in ``ac.statements``."""
        valid = set(self.ac.statements.keys()) if self.ac is not None else set()
        if any(resource not in valid for resource in permission):
            raise _err(400, "INVALID_RESOURCE")

    async def _check_member_has_permission(
        self,
        ctx: Ctx,
        *,
        member: dict[str, Any],
        organization_id: str,
        permission_required: dict[str, Any],
        action: str,
    ) -> None:
        """checkIfMemberHasPermission: the actor can only grant permissions they hold.

        crud-access-control.ts:1150-1204 — checks every requested resource:perm pair
        (not just the first miss) and throws once with the full ``missingPermissions``
        list, formatted ``f"{resource}:{perm}"``, top-level on the error body.
        """
        codes = {
            "create": "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE",
            "update": "YOU_ARE_NOT_ALLOWED_TO_UPDATE_A_ROLE",
            "delete": "YOU_ARE_NOT_ALLOWED_TO_DELETE_A_ROLE",
            "read": "YOU_ARE_NOT_ALLOWED_TO_READ_A_ROLE",
            "list": "YOU_ARE_NOT_ALLOWED_TO_LIST_A_ROLE",
        }
        missing: list[str] = []
        for resource, perms in permission_required.items():
            for perm in perms:
                if not await has_permission(
                    role=member["role"],
                    permissions={resource: [perm]},
                    options=self,
                    organization_id=organization_id,
                    ctx=ctx,
                ):
                    missing.append(f"{resource}:{perm}")
        if missing:
            raise _err(
                403,
                codes.get(action, "YOU_ARE_NOT_ALLOWED_TO_GET_A_ROLE"),
                extra={"missingPermissions": missing},
            )

    async def _filter_dynamic_role_names(
        self, ctx: Ctx, org_id: str, unknown: list[str]
    ) -> list[str]:
        """crud-members/crud-invites: with DAC enabled, drop names that exist as
        ``organizationRole`` rows for the org; the remainder is still invalid. Disabled → all
        unknown names stay invalid."""
        if not self._dac_enabled:
            return unknown
        # ponytail: fetch-all + filter instead of a `role IN (...)` query — dodges the
        # MemoryAdapter `in` case quirk (see _users_by_ids); the found-name set is identical.
        rows = await ctx.adapter.find_many("organizationRole", [Where("organizationId", org_id)])
        found = {r["role"] for r in rows}
        return [r for r in unknown if r not in found]

    def _role_condition(self, source: dict[str, Any]) -> Where:
        """The roleName/roleId selector (schema requires exactly one); ROLE_NOT_FOUND if absent."""
        if source.get("roleName"):
            return Where("role", source["roleName"])
        if source.get("roleId"):
            return Where("id", source["roleId"])
        raise _err(400, "ROLE_NOT_FOUND")

    async def _create_role(self, ctx: Ctx) -> AuthResponse:
        session = await self._require_session(ctx)
        user = session["user"]
        body = ctx.body()
        role_name = body.get("role")
        if not isinstance(role_name, str):
            raise APIError(400, "INVALID_BODY", "role is required")
        permission = body.get("permission")
        if not isinstance(permission, dict):
            raise APIError(400, "INVALID_BODY", "permission is required")
        additional = body.get("additionalFields") or {}

        if self.ac is None:
            raise _err(501, "MISSING_AC_INSTANCE")

        org_id = body.get("organizationId") or session["session"].get("activeOrganizationId")
        if not org_id:
            raise _err(400, "YOU_MUST_BE_IN_AN_ORGANIZATION_TO_CREATE_A_ROLE")

        role_name = role_name.lower()  # normalizeRoleName
        self._check_role_name_taken_by_predefined(role_name)

        member = await self._check_membership(ctx, user["id"], org_id)
        if member is None:
            raise _err(403, "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION")
        if not await has_permission(
            role=member["role"],
            permissions={"ac": ["create"]},
            options=self,
            organization_id=org_id,
            ctx=ctx,
        ):
            raise _err(403, "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE")

        maximum = await self._resolve_maximum_roles(org_id)
        roles_in_db = await ctx.adapter.count("organizationRole", [Where("organizationId", org_id)])
        if roles_in_db >= maximum:
            raise _err(400, "TOO_MANY_ROLES")

        self._check_invalid_resources(permission)
        await self._check_member_has_permission(
            ctx,
            member=member,
            organization_id=org_id,
            permission_required=permission,
            action="create",
        )
        await self._check_role_name_taken_in_db(ctx, org_id, role_name)

        new_role = self.ac.new_role(permission)
        row = {
            "organizationId": org_id,
            "role": role_name,
            "permission": _json_dumps(permission),
            "createdAt": utcnow(),
            **self._role_additional_from_body(additional),
        }
        created = await ctx.adapter.create("organizationRole", row)
        role_data = {**self._filter_role(created), "permission": permission}
        return AuthResponse(
            body={"success": True, "roleData": role_data, "statements": new_role.statements}
        )

    async def _delete_role(self, ctx: Ctx) -> AuthResponse:
        session = await self._require_session(ctx)
        user = session["user"]
        body = ctx.body()
        org_id = body.get("organizationId") or session["session"].get("activeOrganizationId")
        if not org_id:
            raise _err(400, "NO_ACTIVE_ORGANIZATION")
        member = await self._check_membership(ctx, user["id"], org_id)
        if member is None:
            raise _err(403, "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION")
        if not await has_permission(
            role=member["role"],
            permissions={"ac": ["delete"]},
            options=self,
            organization_id=org_id,
            ctx=ctx,
        ):
            raise _err(403, "YOU_ARE_NOT_ALLOWED_TO_DELETE_A_ROLE")

        role_name = body.get("roleName")
        if role_name and role_name in self._predefined_role_names():
            raise _err(400, "CANNOT_DELETE_A_PRE_DEFINED_ROLE")
        condition = self._role_condition(body)

        existing = await ctx.adapter.find_one(
            "organizationRole", [Where("organizationId", org_id), condition]
        )
        if existing is None:
            raise _err(400, "ROLE_NOT_FOUND")

        # reject deletion while any member still holds the role (comma-split exact match).
        role_to_delete = existing["role"]
        members = await ctx.adapter.find_many(
            "member",
            [Where("organizationId", org_id), Where("role", role_to_delete, "contains")],
        )
        if any(role_to_delete in [r.strip() for r in m["role"].split(",")] for m in members):
            raise _err(400, "ROLE_IS_ASSIGNED_TO_MEMBERS")

        await ctx.adapter.delete_many(
            "organizationRole", [Where("organizationId", org_id), condition]
        )
        return AuthResponse(body={"success": True})

    async def _list_roles(self, ctx: Ctx) -> AuthResponse:
        session = await self._require_session(ctx)
        user = session["user"]
        query = ctx.request.query
        org_id = query.get("organizationId") or session["session"].get("activeOrganizationId")
        if not org_id:
            raise _err(400, "NO_ACTIVE_ORGANIZATION")
        member = await self._check_membership(ctx, user["id"], org_id)
        if member is None:
            raise _err(403, "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION")
        if not await has_permission(
            role=member["role"],
            permissions={"ac": ["read"]},
            options=self,
            organization_id=org_id,
            ctx=ctx,
        ):
            raise _err(403, "YOU_ARE_NOT_ALLOWED_TO_LIST_A_ROLE")
        rows = await ctx.adapter.find_many("organizationRole", [Where("organizationId", org_id)])
        return AuthResponse(
            body=[{**self._filter_role(r), "permission": json.loads(r["permission"])} for r in rows]
        )

    async def _get_role(self, ctx: Ctx) -> AuthResponse:
        session = await self._require_session(ctx)
        user = session["user"]
        query = ctx.request.query
        org_id = query.get("organizationId") or session["session"].get("activeOrganizationId")
        if not org_id:
            raise _err(400, "NO_ACTIVE_ORGANIZATION")
        member = await self._check_membership(ctx, user["id"], org_id)
        if member is None:
            raise _err(403, "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION")
        if not await has_permission(
            role=member["role"],
            permissions={"ac": ["read"]},
            options=self,
            organization_id=org_id,
            ctx=ctx,
        ):
            raise _err(403, "YOU_ARE_NOT_ALLOWED_TO_READ_A_ROLE")
        condition = self._role_condition(query)
        role = await ctx.adapter.find_one(
            "organizationRole", [Where("organizationId", org_id), condition]
        )
        if role is None:
            raise _err(400, "ROLE_NOT_FOUND")
        return AuthResponse(
            body={**self._filter_role(role), "permission": json.loads(role["permission"])}
        )

    async def _update_role(self, ctx: Ctx) -> AuthResponse:
        session = await self._require_session(ctx)
        user = session["user"]
        body = ctx.body()
        if self.ac is None:
            raise _err(501, "MISSING_AC_INSTANCE")
        org_id = body.get("organizationId") or session["session"].get("activeOrganizationId")
        if not org_id:
            raise _err(400, "NO_ACTIVE_ORGANIZATION")
        member = await self._check_membership(ctx, user["id"], org_id)
        if member is None:
            raise _err(403, "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION")
        if not await has_permission(
            role=member["role"],
            permissions={"ac": ["update"]},
            options=self,
            organization_id=org_id,
            ctx=ctx,
        ):
            raise _err(403, "YOU_ARE_NOT_ALLOWED_TO_UPDATE_A_ROLE")

        condition = self._role_condition(body)
        role = await ctx.adapter.find_one(
            "organizationRole", [Where("organizationId", org_id), condition]
        )
        if role is None:
            raise _err(400, "ROLE_NOT_FOUND")
        role["permission"] = json.loads(role["permission"]) if role.get("permission") else None

        data = body.get("data")
        if not isinstance(data, dict):
            raise APIError(400, "INVALID_BODY", "data is required")
        new_permission = data.get("permission")
        new_role_name = data.get("roleName")

        update_data = self._role_additional_from_body(
            {k: v for k, v in data.items() if k not in ("permission", "roleName")}
        )
        if new_permission is not None:
            self._check_invalid_resources(new_permission)
            await self._check_member_has_permission(
                ctx,
                member=member,
                organization_id=org_id,
                permission_required=new_permission,
                action="update",
            )
            update_data["permission"] = new_permission
        if new_role_name:
            new_role_name = new_role_name.lower()
            self._check_role_name_taken_by_predefined(new_role_name)
            await self._check_role_name_taken_in_db(ctx, org_id, new_role_name)
            update_data["role"] = new_role_name

        update = dict(update_data)
        if update_data.get("permission") is not None:
            update["permission"] = _json_dumps(update_data["permission"])
        await ctx.adapter.update_many(
            "organizationRole", [Where("organizationId", org_id), condition], update
        )
        role_data = {
            **role,
            **update,
            "permission": update_data.get("permission") or role.get("permission") or None,
        }
        return AuthResponse(body={"success": True, "roleData": role_data})
