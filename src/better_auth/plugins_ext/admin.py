"""admin plugin — user administration: roles/permissions, ban, impersonation,
session management, password/email set, permission checks.

Verified against TS ``packages/better-auth/src/plugins/admin/`` (admin.ts, routes.ts,
schema.ts, error-codes.ts, has-permission.ts, access/statement.ts, types.ts) at v1.6.23.

Two TS conventions are adapted to this HTTP-only port:

- **Ban enforcement** is a ``session.create.before`` databaseHook. TS gates it on
  ``if (!ctx) return`` because the hook body needs ``ctx.context.internalAdapter``;
  here the hook is a closure that captures ``auth`` directly, so it runs on every
  session creation (which is exactly when a banned user's sign-in must be blocked).
- **Trusted null-session server calls** (TS ``create-user`` / ``has-permission`` when
  invoked with no request/headers) are not reachable through this router — every
  endpoint is served over HTTP, where TS's ``(ctx.request || ctx.headers)`` guard is
  always true. So both endpoints simply require a session (401 otherwise).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar

from ..access_control import ADMIN_DEFAULT_ROLES, Role
from ..adapters.base import Where
from ..crypto import generate_id, sign_value, unsign_value
from ..endpoints import EMAIL_RE
from ..plugins import HookSet, Plugin, PluginHook, Route
from ..schema import Field, Schema
from ..session import build_cookie, clear_cookie, cookie_name, get_session
from ..types import APIError, AuthResponse, Ctx

#: TS ``ADMIN_ERROR_CODES`` (error-codes.ts) — exact strings; the dict KEY is the wire
#: ``code`` and the value is the human message (both land on the response body).
ADMIN_ERROR_CODES: dict[str, str] = {
    "FAILED_TO_CREATE_USER": "Failed to create user",
    "USER_ALREADY_EXISTS": "User already exists.",
    "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL": "User already exists. Use another email.",
    "YOU_CANNOT_BAN_YOURSELF": "You cannot ban yourself",
    "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE": "You are not allowed to change users role",
    "YOU_ARE_NOT_ALLOWED_TO_CREATE_USERS": "You are not allowed to create users",
    "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS": "You are not allowed to list users",
    "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS_SESSIONS": "You are not allowed to list users sessions",
    "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS": "You are not allowed to ban users",
    "YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS": "You are not allowed to impersonate users",
    "YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS": "You are not allowed to revoke users sessions",
    "YOU_ARE_NOT_ALLOWED_TO_DELETE_USERS": "You are not allowed to delete users",
    "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PASSWORD": "You are not allowed to set users password",
    "BANNED_USER": "You have been banned from this application",
    "YOU_ARE_NOT_ALLOWED_TO_GET_USER": "You are not allowed to get user",
    "NO_DATA_TO_UPDATE": "No data to update",
    "YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS": "You are not allowed to update users",
    "YOU_CANNOT_REMOVE_YOURSELF": "You cannot remove yourself",
    "YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE": (
        "You are not allowed to set a non-existent role value"
    ),
    "YOU_CANNOT_IMPERSONATE_ADMINS": "You cannot impersonate admins",
    "INVALID_ROLE_TYPE": "Invalid role type",
    "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_EMAIL": "You are not allowed to update users email",
    "PASSWORD_CANNOT_BE_UPDATED_VIA_UPDATE_USER": (
        "Password cannot be updated through update-user. "
        "Use the set-user-password endpoint instead"
    ),
}

#: TS ``schema.ts`` — all columns ``input:false`` (never taken from client input; the
#: admin endpoints write them through ``internalAdapter``, which bypasses input parsing).
_SCHEMA: Schema = {
    "user": {
        "role": Field("string", required=False, input=False),
        "banned": Field("boolean", required=False, input=False, default=False),
        "banReason": Field("string", required=False, input=False),
        "banExpires": Field("datetime", required=False, input=False),
    },
    "session": {
        "impersonatedBy": Field("string", required=False, input=False),
    },
}

_BAN_FIELDS = ("banned", "banReason", "banExpires")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _err(status: int, code: str) -> APIError:
    return APIError(status, code, ADMIN_ERROR_CODES[code])


def _not_found() -> APIError:
    return APIError(404, "USER_NOT_FOUND", "User not found")


def _parse_roles(roles: str | list[str]) -> str:
    return ",".join(roles) if isinstance(roles, list) else roles


def _to_aware(dt: Any) -> datetime:
    if isinstance(dt, str):
        dt = datetime.fromisoformat(dt.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _to_int(value: Any) -> int | None:
    """``Number(x) || undefined`` — absent/invalid/zero become ``None`` (omitted)."""
    if value is None:
        return None
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    return n or None


class AdminPlugin(Plugin):
    """TS ``admin()`` — see module docstring for the source files."""

    id = "admin"
    schema: ClassVar[Schema] = _SCHEMA
    error_codes: ClassVar[dict[str, str]] = ADMIN_ERROR_CODES

    def __init__(
        self,
        *,
        default_role: str = "user",
        admin_roles: str | list[str] | None = None,
        default_ban_reason: str | None = None,
        default_ban_expires_in: int | None = None,
        impersonation_session_duration: int = 3600,
        roles: dict[str, Role] | None = None,
        admin_user_ids: list[str] | None = None,
        ac: Any = None,
        banned_user_message: str | None = None,
        allow_impersonating_admins: bool = False,
    ) -> None:
        self.default_role = default_role
        self.roles = roles
        self.admin_user_ids = admin_user_ids
        self.ac = ac
        self.default_ban_reason = default_ban_reason
        self.default_ban_expires_in = default_ban_expires_in
        self.impersonation_session_duration = impersonation_session_duration
        self.allow_impersonating_admins = allow_impersonating_admins
        self.banned_user_message = banned_user_message or (
            "You have been banned from this application. "
            "Please contact support if you believe this is an error."
        )
        # normalize admin_roles (accepts a comma string or a list); default ["admin"]
        explicit = admin_roles is not None
        if isinstance(admin_roles, str):
            self.admin_roles = admin_roles.split(",")
        else:
            self.admin_roles = list(admin_roles) if admin_roles is not None else ["admin"]

        # TS validates adminRoles against the role table only when explicitly configured.
        if explicit:
            valid = {name.lower() for name in (self.roles or ADMIN_DEFAULT_ROLES)}
            invalid = [r for r in self.admin_roles if r.lower() not in valid]
            if invalid:
                raise ValueError(
                    f"Invalid admin roles: {', '.join(invalid)}. "
                    "Admin roles must be defined in the 'roles' configuration."
                )

    # --- init: default-role + ban-enforcement databaseHooks ---------------------------

    def init(self, auth: Any) -> None:
        default_role = self.default_role
        banned_message = self.banned_user_message

        async def user_create_before(data: dict[str, Any], ctx: Any = None) -> Any:
            # Inject the default role unless the create payload already set one.
            return {"data": {"role": default_role, **data}}

        async def session_create_before(data: dict[str, Any], ctx: Any = None) -> Any:
            user = await auth.adapter.find_one("user", [Where("id", data["userId"])])
            if user and user.get("banned"):
                ban_expires = user.get("banExpires")
                if ban_expires is not None and _to_aware(ban_expires) < _now():
                    # ban has lapsed — lift it lazily and let the sign-in proceed
                    await auth.internal.update_user(
                        data["userId"],
                        {"banned": False, "banReason": None, "banExpires": None},
                    )
                    return None
                raise APIError(403, "BANNED_USER", banned_message)
            return None

        auth.internal.hooks.append({"user": {"create": {"before": user_create_before}}})
        auth.internal.hooks.append({"session": {"create": {"before": session_create_before}}})

    # --- TS BetterAuthPlugin surface --------------------------------------------------

    def routes(self) -> list[Route]:
        return [
            ("POST", "/admin/set-role", self._set_role),
            ("GET", "/admin/get-user", self._get_user),
            ("POST", "/admin/create-user", self._create_user),
            ("POST", "/admin/update-user", self._update_user),
            ("GET", "/admin/list-users", self._list_users),
            ("POST", "/admin/list-user-sessions", self._list_user_sessions),
            ("POST", "/admin/ban-user", self._ban_user),
            ("POST", "/admin/unban-user", self._unban_user),
            ("POST", "/admin/impersonate-user", self._impersonate_user),
            ("POST", "/admin/stop-impersonating", self._stop_impersonating),
            ("POST", "/admin/revoke-user-session", self._revoke_user_session),
            ("POST", "/admin/revoke-user-sessions", self._revoke_user_sessions),
            ("POST", "/admin/remove-user", self._remove_user),
            ("POST", "/admin/set-user-password", self._set_user_password),
            ("POST", "/admin/has-permission", self._has_permission_endpoint),
        ]

    def hooks(self) -> HookSet:
        # TS hooks.after[0]: hide impersonated sessions from a user's own /list-sessions.
        return HookSet(
            after=[
                PluginHook(
                    lambda ctx: ctx.request.path == "/list-sessions",
                    self._filter_impersonated_sessions,
                )
            ]
        )

    # --- permission checking (has-permission.ts; SYNCHRONOUS) -------------------------

    def has_permission(
        self,
        *,
        user_id: str | None = None,
        role: str | None = None,
        permissions: dict[str, Any],
    ) -> bool:
        if user_id and self.admin_user_ids and user_id in self.admin_user_ids:
            return True
        if not permissions:
            return False
        act_roles = self.roles or ADMIN_DEFAULT_ROLES
        for name in (role or self.default_role or "user").split(","):
            _role = act_roles.get(name)
            if _role is not None and _role.authorize(permissions).get("success"):
                return True
        return False

    # --- helpers ----------------------------------------------------------------------

    async def _admin_session(self, ctx: Ctx) -> dict[str, Any]:
        """TS ``adminMiddleware`` — an authoritative (cookie-cache-bypassing) session,
        or 401. Also the effective replacement for TS ``getAuthoritativeSessionFromCtx``
        on create-user/has-permission (the trusted null-session path is unreachable here)."""
        result, _cookies = await get_session(ctx.auth, ctx.request, disable_cache=True)
        if result is None:
            raise APIError(401, "UNAUTHORIZED", "Not authenticated")
        return result

    def _require(
        self, session: dict[str, Any], permissions: dict[str, Any], code: str
    ) -> None:
        user = session["user"]
        if not self.has_permission(
            user_id=user["id"], role=user.get("role"), permissions=permissions
        ):
            raise _err(403, code)

    # --- endpoints --------------------------------------------------------------------

    async def _set_role(self, ctx: Ctx) -> AuthResponse:
        session = await self._admin_session(ctx)
        self._require(session, {"user": ["set-role"]}, "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE")
        body = ctx.body()
        role = body["role"]
        if self.roles:
            for r in role if isinstance(role, list) else [role]:
                if r not in self.roles:
                    raise _err(400, "YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE")
        user_id = str(body["userId"])
        if await ctx.adapter.find_one("user", [Where("id", user_id)]) is None:
            raise _not_found()
        updated = await ctx.internal.update_user(user_id, {"role": _parse_roles(role)})
        return AuthResponse(body={"user": ctx.auth.parse_user_output(updated)})

    async def _get_user(self, ctx: Ctx) -> AuthResponse:
        session = await self._admin_session(ctx)
        self._require(session, {"user": ["get"]}, "YOU_ARE_NOT_ALLOWED_TO_GET_USER")
        user = await ctx.adapter.find_one("user", [Where("id", ctx.request.query.get("id"))])
        if user is None:
            raise _not_found()
        return AuthResponse(body=ctx.auth.parse_user_output(user))

    async def _create_user(self, ctx: Ctx) -> AuthResponse:
        body = ctx.body()
        session = await self._admin_session(ctx)
        self._require(session, {"user": ["create"]}, "YOU_ARE_NOT_ALLOWED_TO_CREATE_USERS")

        user_data = dict(body.get("data") or {})
        data_role = user_data.pop("role", None)
        requested_role = body.get("role") if body.get("role") is not None else data_role

        if requested_role is not None:
            # `data.role` goes through the same set-role authorization as top-level role
            self._require(
                session, {"user": ["set-role"]}, "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE"
            )
            for r in requested_role if isinstance(requested_role, list) else [requested_role]:
                if not isinstance(r, str):
                    raise _err(400, "INVALID_ROLE_TYPE")
                if self.roles and r not in self.roles:
                    raise _err(400, "YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE")

        if any(k in user_data for k in _BAN_FIELDS):
            self._require(session, {"user": ["ban"]}, "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS")

        email = str(body["email"]).lower()
        if not EMAIL_RE.match(email):
            raise APIError(400, "INVALID_EMAIL", "Invalid email")
        if await ctx.adapter.find_one("user", [Where("email", email)]) is not None:
            raise _err(400, "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL")

        user = await ctx.internal.create_user(
            {
                **user_data,
                "email": email,
                "name": body["name"],
                "role": (
                    _parse_roles(requested_role)
                    if requested_role is not None
                    else self.default_role
                ),
            }
        )
        if user is None:
            raise _err(500, "FAILED_TO_CREATE_USER")
        if body.get("password"):
            hashed = await ctx.auth.hash_password_checked(body["password"], ctx.request.path)
            # TS linkAccount == createAccount (byte-identical); create_account covers it.
            await ctx.internal.create_account(
                {
                    "accountId": user["id"],
                    "providerId": "credential",
                    "password": hashed,
                    "userId": user["id"],
                }
            )
        return AuthResponse(body={"user": ctx.auth.parse_user_output(user)})

    async def _update_user(self, ctx: Ctx) -> AuthResponse:
        session = await self._admin_session(ctx)
        self._require(session, {"user": ["update"]}, "YOU_ARE_NOT_ALLOWED_TO_UPDATE_USERS")
        body = ctx.body()
        data = dict(body.get("data") or {})
        if not data:
            raise _err(400, "NO_DATA_TO_UPDATE")
        if "password" in data:
            raise _err(400, "PASSWORD_CANNOT_BE_UPDATED_VIA_UPDATE_USER")

        user_id = str(body["userId"])

        if "role" in data:
            self._require(
                session, {"user": ["set-role"]}, "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE"
            )
            role_value = data["role"]
            input_roles = role_value if isinstance(role_value, list) else [role_value]
            for r in input_roles:
                if not isinstance(r, str):
                    raise _err(400, "INVALID_ROLE_TYPE")
                if self.roles and r not in self.roles:
                    raise _err(400, "YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE")
            data["role"] = _parse_roles(input_roles)

        if any(k in data for k in _BAN_FIELDS):
            self._require(session, {"user": ["ban"]}, "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS")
            if data.get("banned") is True and user_id == session["user"]["id"]:
                raise _err(400, "YOU_CANNOT_BAN_YOURSELF")

        if "email" in data or "emailVerified" in data:
            self._require(
                session, {"user": ["set-email"]}, "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_EMAIL"
            )
            if "email" in data:
                email = str(data["email"]).lower()
                if not EMAIL_RE.match(email):
                    raise APIError(400, "INVALID_EMAIL", "Invalid email")
                existing = await ctx.adapter.find_one("user", [Where("email", email)])
                if existing is not None and existing["id"] != user_id:
                    raise _err(400, "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL")
                data["email"] = email

        if await ctx.adapter.find_one("user", [Where("id", user_id)]) is None:
            raise _not_found()

        updated = await ctx.internal.update_user(user_id, data)
        if data.get("banned") is True:
            await ctx.internal.delete_user_sessions(user_id)
        return AuthResponse(body=ctx.auth.parse_user_output(updated))

    async def _list_users(self, ctx: Ctx) -> AuthResponse:
        session = await self._admin_session(ctx)
        self._require(session, {"user": ["list"]}, "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS")
        q = ctx.request.query

        where: list[Where] = []
        if q.get("searchValue"):
            where.append(
                Where(
                    q.get("searchField") or "email",
                    q["searchValue"],
                    q.get("searchOperator") or "contains",
                )
            )
        if q.get("filterValue") is not None:
            where.append(
                Where(
                    q.get("filterField") or "email",
                    q["filterValue"],
                    q.get("filterOperator") or "eq",
                )
            )

        limit = _to_int(q.get("limit"))
        offset = _to_int(q.get("offset"))
        sort_by = (
            {"field": q["sortBy"], "direction": q.get("sortDirection") or "asc"}
            if q.get("sortBy")
            else None
        )
        try:
            users = await ctx.internal.list_users(limit, offset, sort_by, where or None)
            total = await ctx.internal.count_total_users(where or None)
        except Exception:
            # TS swallows adapter errors → empty result
            return AuthResponse(body={"users": [], "total": 0})

        result: dict[str, Any] = {
            "users": [ctx.auth.parse_user_output(u) for u in users],
            "total": total,
        }
        if limit is not None:
            result["limit"] = limit
        if offset is not None:
            result["offset"] = offset
        return AuthResponse(body=result)

    async def _list_user_sessions(self, ctx: Ctx) -> AuthResponse:
        session = await self._admin_session(ctx)
        self._require(
            session, {"session": ["list"]}, "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS_SESSIONS"
        )
        sessions = await ctx.internal.list_sessions(str(ctx.body()["userId"]))
        return AuthResponse(body={"sessions": [ctx.auth.parse_session_output(s) for s in sessions]})

    async def _ban_user(self, ctx: Ctx) -> AuthResponse:
        session = await self._admin_session(ctx)
        self._require(session, {"user": ["ban"]}, "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS")
        body = ctx.body()
        user_id = str(body["userId"])
        if await ctx.adapter.find_one("user", [Where("id", user_id)]) is None:
            raise _not_found()
        if user_id == session["user"]["id"]:
            raise _err(400, "YOU_CANNOT_BAN_YOURSELF")

        ban_expires_in = body.get("banExpiresIn") or self.default_ban_expires_in
        ban_expires = _now() + timedelta(seconds=ban_expires_in) if ban_expires_in else None
        updated = await ctx.internal.update_user(
            user_id,
            {
                "banned": True,
                "banReason": body.get("banReason") or self.default_ban_reason or "No reason",
                "banExpires": ban_expires,
                "updatedAt": _now(),
            },
        )
        await ctx.internal.delete_user_sessions(user_id)  # revoke all sessions
        return AuthResponse(body={"user": ctx.auth.parse_user_output(updated)})

    async def _unban_user(self, ctx: Ctx) -> AuthResponse:
        session = await self._admin_session(ctx)
        self._require(session, {"user": ["ban"]}, "YOU_ARE_NOT_ALLOWED_TO_BAN_USERS")
        user_id = str(ctx.body()["userId"])
        if await ctx.adapter.find_one("user", [Where("id", user_id)]) is None:
            raise _not_found()
        updated = await ctx.internal.update_user(
            user_id,
            {"banned": False, "banExpires": None, "banReason": None, "updatedAt": _now()},
        )
        return AuthResponse(body={"user": ctx.auth.parse_user_output(updated)})

    async def _impersonate_user(self, ctx: Ctx) -> AuthResponse:
        session = await self._admin_session(ctx)
        self._require(
            session, {"user": ["impersonate"]}, "YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS"
        )
        target = await ctx.adapter.find_one("user", [Where("id", str(ctx.body()["userId"]))])
        if target is None:
            raise _not_found()

        admin_roles = [r.strip() for r in self.admin_roles]
        target_roles = (target.get("role") or self.default_role or "user").split(",")
        is_target_admin = any(r in admin_roles for r in target_roles) or (
            target["id"] in (self.admin_user_ids or [])
        )
        if is_target_admin:
            can = self.allow_impersonating_admins or self.has_permission(
                user_id=session["user"]["id"],
                role=session["user"].get("role"),
                permissions={"user": ["impersonate-admins"]},
            )
            if not can:
                raise _err(403, "YOU_CANNOT_IMPERSONATE_ADMINS")

        # Hand-built session row: a fixed impersonationSessionDuration expiry that the
        # generic internal.create_session can't express (it always recomputes expiresAt).
        # Routing through internal.create still fires the databaseHooks.
        now = _now()
        imp_session = {
            "id": generate_id(),
            "token": generate_id(32),
            "userId": target["id"],
            "impersonatedBy": session["user"]["id"],
            "expiresAt": now + timedelta(seconds=self.impersonation_session_duration),
            "ipAddress": ctx.request.client_ip or "",
            "userAgent": ctx.request.headers.get("user-agent", ""),
            "createdAt": now,
            "updatedAt": now,
        }
        created = await ctx.internal.create("session", imp_session)
        if created is None:
            raise _err(500, "FAILED_TO_CREATE_USER")

        auth = ctx.auth
        dont_remember_flag = (
            "true" if cookie_name(auth, "dont_remember") in ctx.request.cookies() else ""
        )
        admin_cookie_value = sign_value(
            auth.secret, f'{session["session"]["token"]}:{dont_remember_flag}'
        )
        response = AuthResponse(
            body={
                "session": auth.parse_session_output(created),
                "user": auth.parse_user_output(target),
            }
        )
        # admin_session persists (session-cookie attributes); swap the active session to
        # the impersonation session as a browser-session cookie (TS setSessionCookie(…, true)).
        response.set_cookie(
            build_cookie(auth, admin_cookie_value, auth.session_options.expires_in, "admin_session")
        )
        response.set_cookie(build_cookie(auth, sign_value(auth.secret, imp_session["token"]), None))
        response.set_cookie(build_cookie(auth, "true", None, "dont_remember"))
        return response

    async def _stop_impersonating(self, ctx: Ctx) -> AuthResponse:
        auth = ctx.auth
        result, _cookies = await get_session(auth, ctx.request, disable_cache=True)
        if result is None:
            raise APIError(401, "UNAUTHORIZED", "Not authenticated")
        imp_session = result["session"]
        if not imp_session.get("impersonatedBy"):
            raise APIError(400, "BAD_REQUEST", "You are not impersonating anyone")

        admin_user = await ctx.adapter.find_one(
            "user", [Where("id", imp_session["impersonatedBy"])]
        )
        if admin_user is None:
            raise APIError(500, "INTERNAL_SERVER_ERROR", "Failed to find user")

        raw = ctx.request.cookies().get(cookie_name(auth, "admin_session"))
        admin_cookie = unsign_value(auth.secret, raw) if raw else None
        if not admin_cookie:
            raise APIError(500, "INTERNAL_SERVER_ERROR", "Failed to find admin session")
        admin_token, _, dont_remember_flag = admin_cookie.partition(":")
        admin_session = await ctx.internal.find_session(admin_token)
        if admin_session is None or admin_session["session"]["userId"] != admin_user["id"]:
            raise APIError(500, "INTERNAL_SERVER_ERROR", "Failed to find admin session")

        await ctx.internal.delete_session(imp_session["token"])

        response = AuthResponse(
            body={
                "session": auth.parse_session_output(admin_session["session"]),
                "user": auth.parse_user_output(admin_session["user"]),
            }
        )
        signed = sign_value(auth.secret, admin_token)
        if dont_remember_flag:
            response.set_cookie(build_cookie(auth, signed, None))
            response.set_cookie(build_cookie(auth, "true", None, "dont_remember"))
        else:
            response.set_cookie(build_cookie(auth, signed, auth.session_options.expires_in))
            response.set_cookie(clear_cookie(auth, "dont_remember"))
        response.set_cookie(clear_cookie(auth, "admin_session"))
        return response

    async def _revoke_user_session(self, ctx: Ctx) -> AuthResponse:
        session = await self._admin_session(ctx)
        self._require(
            session, {"session": ["revoke"]}, "YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS"
        )
        await ctx.internal.delete_session(ctx.body()["sessionToken"])
        return AuthResponse(body={"success": True})

    async def _revoke_user_sessions(self, ctx: Ctx) -> AuthResponse:
        session = await self._admin_session(ctx)
        self._require(
            session, {"session": ["revoke"]}, "YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS"
        )
        await ctx.internal.delete_user_sessions(str(ctx.body()["userId"]))
        return AuthResponse(body={"success": True})

    async def _remove_user(self, ctx: Ctx) -> AuthResponse:
        session = await self._admin_session(ctx)
        self._require(session, {"user": ["delete"]}, "YOU_ARE_NOT_ALLOWED_TO_DELETE_USERS")
        user_id = str(ctx.body()["userId"])
        if user_id == session["user"]["id"]:
            raise _err(400, "YOU_CANNOT_REMOVE_YOURSELF")
        if await ctx.adapter.find_one("user", [Where("id", user_id)]) is None:
            raise _not_found()
        await ctx.internal.delete_user_sessions(user_id)
        await ctx.internal.delete_user(user_id)  # cascades sessions + accounts
        return AuthResponse(body={"success": True})

    async def _set_user_password(self, ctx: Ctx) -> AuthResponse:
        session = await self._admin_session(ctx)
        self._require(
            session, {"user": ["set-password"]}, "YOU_ARE_NOT_ALLOWED_TO_SET_USERS_PASSWORD"
        )
        body = ctx.body()
        new_password = body["newPassword"]
        user_id = str(body["userId"])
        cfg = ctx.auth.email_and_password
        if len(new_password) < cfg.min_password_length:
            raise APIError(400, "PASSWORD_TOO_SHORT", "Password too short")
        if len(new_password) > cfg.max_password_length:
            raise APIError(400, "PASSWORD_TOO_LONG", "Password too long")
        if await ctx.adapter.find_one("user", [Where("id", user_id)]) is None:
            raise _not_found()

        hashed = await ctx.auth.hash_password_checked(new_password, ctx.request.path)
        accounts = await ctx.adapter.find_many("account", [Where("userId", user_id)])
        has_credential = any(a.get("providerId") == "credential" for a in accounts)
        if has_credential:
            await ctx.internal.update_password(user_id, hashed)
        else:
            await ctx.internal.create_account(
                {
                    "userId": user_id,
                    "providerId": "credential",
                    "accountId": user_id,
                    "password": hashed,
                }
            )
        return AuthResponse(body={"status": True})

    async def _has_permission_endpoint(self, ctx: Ctx) -> AuthResponse:
        body = ctx.body()
        permissions = body.get("permissions") or body.get("permission")
        if not permissions:
            raise APIError(
                400, "BAD_REQUEST", "invalid permission check. no permission(s) were passed."
            )
        # Session required (HTTP-only port); TS checks the session user's own permissions.
        session = await self._admin_session(ctx)
        user = session["user"]
        result = self.has_permission(
            user_id=user["id"], role=user.get("role"), permissions=permissions
        )
        return AuthResponse(body={"error": None, "success": result})

    # --- hooks ---------------------------------------------------------------------

    async def _filter_impersonated_sessions(self, ctx: Ctx) -> AuthResponse | None:
        response = ctx.response
        if response is None or not isinstance(response.body, list):
            return None
        filtered = [s for s in response.body if not s.get("impersonatedBy")]
        return AuthResponse(status=response.status, body=filtered, headers=response.headers)
