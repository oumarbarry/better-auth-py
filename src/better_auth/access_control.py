"""Access-control subsystem — role-based authorization, no HTTP.

Ports the shared subsystem in TS ``plugins/access/access.ts`` + ``types.ts``, plus the
default statement/role tables from ``plugins/admin/access/statement.ts`` and
``plugins/organization/access/statement.ts``. Pure logic: given a role's allowed
actions per resource, decide whether a requested set of actions is authorized.

``create_access_control(statements)`` registers a plugin's resource -> allowed-actions
table; ``.new_role(role_statements)`` mints a :class:`Role` from it. TS types
``role_statements`` as a subset of the base statements via ``RoleInput``/``Subset``,
but that constraint is enforced *only* by the TS type checker — ``newRole`` itself
does zero runtime validation (it just calls ``role(statements)``), so this port
performs no validation either: any statements dict is accepted.

``Role.authorize(request, connector)`` is synchronous. The async variant used by the
organization plugin (loads dynamic per-org permissions and merges them with the
static role) is layered on top elsewhere and is out of scope here.
"""

from __future__ import annotations

from typing import Any, Literal

#: resource -> allowed action strings.
Statements = dict[str, list[str]]
Connector = Literal["AND", "OR"]
#: one resource's requested actions: either a plain action list (implicit AND) or
#: ``{"actions": [...], "connector": "OR" | "AND"}``.
ActionRequest = list[str] | dict[str, Any]
AuthorizeRequest = dict[str, ActionRequest]
AuthorizeResult = dict[str, Any]


class AccessControlError(Exception):
    """A per-resource request value is neither an action list nor an
    ``{actions, connector}`` object (TS ``BetterAuthError`` parity: ``access.ts``'s
    ``normalizeActionRequest`` throws ``"Invalid access control request"``)."""


def _unknown_resource_response(resource: str) -> AuthorizeResult:
    return {"success": False, "error": f"You are not allowed to access resource: {resource}"}


def _unauthorized_resource_response(resource: str) -> AuthorizeResult:
    return {"success": False, "error": f'unauthorized to access resource "{resource}"'}


def _normalize_connector(connector: Any) -> Connector:
    return "OR" if connector == "OR" else "AND"


def _normalize_action_request(requested_actions: Any) -> tuple[list[Any], Connector]:
    if isinstance(requested_actions, list):
        return requested_actions, "AND"
    if not isinstance(requested_actions, dict):
        raise AccessControlError("Invalid access control request")
    actions = requested_actions.get("actions")
    if not isinstance(actions, list):
        return [], _normalize_connector(requested_actions.get("connector"))
    return actions, _normalize_connector(requested_actions.get("connector"))


def _has_allowed_action(allowed_actions: list[str], requested_action: Any) -> bool:
    return isinstance(requested_action, str) and requested_action in allowed_actions


def _is_resource_authorized(
    allowed_actions: list[str], actions: list[Any], connector: Connector
) -> bool:
    if len(actions) == 0:
        return False
    if connector == "OR":
        return any(_has_allowed_action(allowed_actions, a) for a in actions)
    return all(_has_allowed_action(allowed_actions, a) for a in actions)


class Role:
    """A resource -> allowed-actions table plus request-time authorization checks."""

    def __init__(self, statements: Statements) -> None:
        self.statements = statements

    def authorize(
        self, request: AuthorizeRequest, connector: Connector = "AND"
    ) -> AuthorizeResult:
        has_authorized_resource = False
        for requested_resource, requested_actions in request.items():
            # NB: membership test, not truthiness — a resource key that *exists* with
            # an empty allowed-actions list (`[]`) is not "unknown". In JS, `![]` is
            # `false` (arrays are always truthy), so TS's `!allowedActions` check only
            # ever catches an absent key; Python's `[]` is falsy, so a naive `if not
            # self.statements.get(...)` would wrongly conflate the two cases.
            if requested_resource not in self.statements:
                if connector == "AND":
                    return _unknown_resource_response(requested_resource)
                continue

            allowed_actions = self.statements[requested_resource]
            actions, action_connector = _normalize_action_request(requested_actions)
            is_authorized = _is_resource_authorized(allowed_actions, actions, action_connector)

            if is_authorized:
                has_authorized_resource = True
            if is_authorized and connector == "OR":
                return {"success": True}
            if not is_authorized and connector == "AND":
                return _unauthorized_resource_response(requested_resource)

        if has_authorized_resource:
            return {"success": True}
        return {"success": False, "error": "Not authorized"}


def role(statements: Statements) -> Role:
    return Role(statements)


class AccessControl:
    """Base statement registry for a plugin; mints :class:`Role` objects from it."""

    def __init__(self, statements: Statements) -> None:
        self.statements = statements

    def new_role(self, statements: Statements) -> Role:
        return role(statements)


def create_access_control(statements: Statements) -> AccessControl:
    return AccessControl(statements)


# --- admin defaults (plugins/admin/access/statement.ts) ---------------------------

ADMIN_DEFAULT_STATEMENTS: Statements = {
    "user": [
        "create",
        "list",
        "set-role",
        "ban",
        "impersonate",
        "impersonate-admins",
        "delete",
        "set-password",
        "set-email",
        "get",
        "update",
    ],
    "session": ["list", "revoke", "delete"],
}

_admin_ac = create_access_control(ADMIN_DEFAULT_STATEMENTS)

ADMIN_DEFAULT_ROLES: dict[str, Role] = {
    "admin": _admin_ac.new_role(
        {
            "user": [
                "create",
                "list",
                "set-role",
                "ban",
                "impersonate",
                "delete",
                "set-password",
                "set-email",
                "get",
                "update",
            ],
            "session": ["list", "revoke", "delete"],
        }
    ),
    "user": _admin_ac.new_role({"user": [], "session": []}),
}


# --- organization defaults (plugins/organization/access/statement.ts) -------------

ORG_DEFAULT_STATEMENTS: Statements = {
    "organization": ["update", "delete"],
    "member": ["create", "update", "delete"],
    "invitation": ["create", "cancel"],
    "team": ["create", "update", "delete"],
    "ac": ["create", "read", "update", "delete"],
}

_org_ac = create_access_control(ORG_DEFAULT_STATEMENTS)

ORG_DEFAULT_ROLES: dict[str, Role] = {
    "admin": _org_ac.new_role(
        {
            "organization": ["update"],
            "invitation": ["create", "cancel"],
            "member": ["create", "update", "delete"],
            "team": ["create", "update", "delete"],
            "ac": ["create", "read", "update", "delete"],
        }
    ),
    "owner": _org_ac.new_role(
        {
            "organization": ["update", "delete"],
            "member": ["create", "update", "delete"],
            "invitation": ["create", "cancel"],
            "team": ["create", "update", "delete"],
            "ac": ["create", "read", "update", "delete"],
        }
    ),
    "member": _org_ac.new_role(
        {
            "organization": [],
            "member": [],
            "invitation": [],
            "team": [],
            "ac": ["read"],  # members can see all roles for their org
        }
    ),
}
