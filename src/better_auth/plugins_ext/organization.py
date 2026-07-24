"""organization plugin — PHASE 1 (core-org): orgs, members, static roles/permissions.

Port of better-auth's ``plugins/organization`` (v1.6.23), core-org subset only:
create/update/delete/list/get-full/set-active organizations, member management
(list/leave/remove/update-role/get-active/has-permission), and check-slug. Verified
against ``routes/crud-org.ts``, ``routes/crud-members.ts``, ``organization.ts``,
``has-permission.ts``, ``permission.ts``, ``adapter.ts`` and ``error-codes.ts``.

Wire/storage fidelity is the contract (a Python app and a TS app share one DB): the
camelCase ``organization`` / ``member`` tables, ``session.activeOrganizationId``
(``input:false``), the JSON-string ``metadata`` column, response shapes, and every error
string match the TS source exactly.

SEAMS for later phases (do not implement here):
- Phase 2 (invitations): the ``invitation`` table, invite/accept/reject/cancel endpoints,
  ``sendInvitationEmail`` config, and the invitation cascade in :meth:`_delete_org` /
  ``invitations`` population in :meth:`_find_full_org` (currently always ``[]``).
- Phase 3 (teams): the ``team``/``teamMember`` tables, ``session.activeTeamId``, team
  endpoints, and the default-team creation branch in ``create``.
- Phase 4 (dynamic access control): the ``organizationRole`` table and the dynamic-role
  merge inside :func:`has_permission` (single resolver seam) + the unknown-role lookup in
  ``update-member-role``. This phase resolves STATIC roles only.
"""

from __future__ import annotations

import inspect
import json
from typing import TYPE_CHECKING, Any, ClassVar

from ..access_control import ORG_DEFAULT_ROLES, AccessControl, Role
from ..adapters.base import Where
from ..cookie_cache import set_cookie_cache
from ..crypto import generate_id
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


def _err(status: int, code: str) -> APIError:
    return APIError(status, code, ERROR_CODES[code])


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


def _resolve_roles(options: OrganizationPlugin) -> dict[str, Role]:
    """The static role table: defaults overridden by ``options.roles`` (custom ac/roles).

    PHASE 4 SEAM: this is the single resolver where dynamic ``organizationRole`` rows will
    be merged (load rows for the org, JSON-parse each ``permission``, dedup per resource,
    rebuild via ``options.ac.new_role(merged)``). Static roles only in this phase.
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
    """TS ``hasPermission`` — ASYNC because phase 4 loads dynamic roles from the DB.

    In THIS phase it resolves STATIC roles only (via :func:`_resolve_roles`) and delegates
    to :func:`_has_permission_fn`. ``organization_id`` / ``ctx`` are unused now but are the
    inputs the phase-4 dynamic-role query needs, so the signature is already the final one.
    """
    ac_roles = _resolve_roles(options)
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
        disable_organization_deletion: bool = False,
        organization_hooks: dict[str, Callable[..., Any]] | None = None,
        # {"organization": {name: Field}, "member": {name: Field}} — extra columns.
        additional_fields: dict[str, dict[str, Field]] | None = None,
    ) -> None:
        self.allow_user_to_create_organization = allow_user_to_create_organization
        self.organization_limit = organization_limit
        self.creator_role = creator_role
        self.membership_limit = membership_limit
        self.ac = ac
        self.roles = roles
        self.disable_organization_deletion = disable_organization_deletion
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
            # activeTeamId (teams) is intentionally NOT added here — phase 3.
            "session": {"activeOrganizationId": Field("string", required=False, input=False)},
        }

    # --- routes -----------------------------------------------------------------------

    def routes(self) -> list[Route]:
        return [
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
        ]

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

    async def _check_membership(
        self, ctx: Ctx, user_id: str, org_id: str
    ) -> dict[str, Any] | None:
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
            self._shape_member(m, user_map[m["userId"]])
            for m in members
            if m["userId"] in user_map
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
            self._shape_member(m, user_map[m["userId"]])
            for m in members
            if m["userId"] in user_map
        ]
        # PHASE 2 SEAM: populate ``invitations`` from the invitation table (always [] now).
        return {**self._filter_org(org), "members": shaped, "invitations": []}

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

    async def _update_member(
        self, ctx: Ctx, member_id: str, role: str
    ) -> dict[str, Any] | None:
        member = await ctx.adapter.update("member", [Where("id", member_id)], {"role": role})
        return filter_output_fields(member, self.schema["member"]) if member is not None else None

    async def _delete_member(self, ctx: Ctx, member_id: str) -> None:
        await ctx.adapter.delete("member", [Where("id", member_id)])

    async def _delete_org(self, ctx: Ctx, org_id: str) -> None:
        # ponytail: TS wraps this in a transaction for atomicity; MemoryAdapter isn't
        # concurrent, so a plain cascade suffices — wrap it when a real adapter needs it.
        await ctx.adapter.delete_many("member", [Where("organizationId", org_id)])
        # PHASE 2 SEAM: also delete this org's invitation rows here.
        await ctx.adapter.delete("organization", [Where("id", org_id)])

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

        # PHASE 3 SEAM: when teams.defaultTeam is enabled, create the default team + join it.

        await self._run_after_hook(
            "after_create_organization",
            {"organization": organization, "user": user, "member": member},
        )

        if not body.get("keepCurrentActiveOrganization"):
            await self._set_active_org(ctx, session["session"]["token"], organization["id"])

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
        if "metadata" in data and data["metadata"] is not None and not isinstance(
            data["metadata"], dict
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
        org_id = org_slug or query.get("organizationId") or session["session"].get(
            "activeOrganizationId"
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
        await self._delete_member(ctx, member["id"])
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
        await self._delete_member(ctx, to_remove["id"])
        if session["user"]["id"] == to_remove["userId"] and session["session"].get(
            "activeOrganizationId"
        ) == to_remove["organizationId"]:
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
            # PHASE 4 SEAM: when dynamicAccessControl is enabled, resolve unknown names
            # against organizationRole rows before rejecting.
            raise APIError(400, "ROLE_NOT_FOUND", f"ROLE_NOT_FOUND: {', '.join(unknown)}")

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
