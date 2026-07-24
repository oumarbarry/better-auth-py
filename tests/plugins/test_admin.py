"""admin plugin — user administration: roles/permissions, ban, impersonation,
session management, password/email set, permission checks.

Verified against TS `packages/better-auth/src/plugins/admin/` (admin.ts, routes.ts,
schema.ts, error-codes.ts, has-permission.ts, access/statement.ts) at v1.6.23.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from better_auth import IPAddressOptions
from better_auth.adapters.base import Where
from better_auth.crypto import hash_password
from better_auth.plugins_ext.admin import ADMIN_ERROR_CODES, AdminPlugin
from better_auth.session import cookie_name, utcnow
from better_auth.types import APIError
from conftest import make_auth, make_client, sign_up

PASSWORD = "s3cret-password"


def admin_auth(**kwargs):
    return make_auth(plugins=[AdminPlugin(**kwargs)])


async def _become_admin(auth, client, *, email="ada@example.com"):
    """Sign up + promote to the admin role. get-session re-reads the user, so the
    existing sign-up session cookie now authorizes as admin."""
    await sign_up(client, email=email)
    user = await auth.adapter.find_one("user", [Where("email", email)])
    await auth.adapter.update("user", [Where("id", user["id"])], {"role": "admin"})
    return user


async def _seed_user(auth, *, email, name="Bob", role="user"):
    return await auth.internal.create_user(
        {"email": email, "name": name, "emailVerified": True, "role": role}
    )


# --- schema -----------------------------------------------------------------------


def test_schema_adds_user_and_session_columns():
    auth = admin_auth()
    user = auth.schema["user"]
    assert user["role"].type == "string" and user["role"].input is False
    assert user["banned"].type == "boolean" and user["banned"].default is False
    assert user["banned"].input is False
    assert user["banReason"].type == "string" and user["banReason"].input is False
    assert user["banExpires"].type == "datetime" and user["banExpires"].input is False
    session = auth.schema["session"]
    assert session["impersonatedBy"].type == "string" and session["impersonatedBy"].input is False


# --- error codes: exact strings ----------------------------------------------------


def test_error_codes_exact_strings():
    assert ADMIN_ERROR_CODES["USER_ALREADY_EXISTS"] == "User already exists."
    assert ADMIN_ERROR_CODES["BANNED_USER"] == "You have been banned from this application"
    assert ADMIN_ERROR_CODES["YOU_CANNOT_BAN_YOURSELF"] == "You cannot ban yourself"
    assert ADMIN_ERROR_CODES["YOU_CANNOT_IMPERSONATE_ADMINS"] == "You cannot impersonate admins"
    assert ADMIN_ERROR_CODES["INVALID_ROLE_TYPE"] == "Invalid role type"
    assert ADMIN_ERROR_CODES["NO_DATA_TO_UPDATE"] == "No data to update"
    assert (
        ADMIN_ERROR_CODES["YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE"]
        == "You are not allowed to set a non-existent role value"
    )
    assert (
        ADMIN_ERROR_CODES["YOU_ARE_NOT_ALLOWED_TO_SET_USERS_EMAIL"]
        == "You are not allowed to update users email"
    )
    assert (
        ADMIN_ERROR_CODES["PASSWORD_CANNOT_BE_UPDATED_VIA_UPDATE_USER"]
        == "Password cannot be updated through update-user. "
        "Use the set-user-password endpoint instead"
    )
    assert (
        ADMIN_ERROR_CODES["USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL"]
        == "User already exists. Use another email."
    )


def test_error_codes_surface_on_auth_instance():
    auth = admin_auth()
    assert auth.error_codes["BANNED_USER"] == "You have been banned from this application"


# --- config defaults + validation --------------------------------------------------


def test_config_defaults():
    p = AdminPlugin()
    assert p.default_role == "user"
    assert p.admin_roles == ["admin"]
    assert p.impersonation_session_duration == 3600
    assert p.allow_impersonating_admins is False
    assert p.banned_user_message == (
        "You have been banned from this application. "
        "Please contact support if you believe this is an error."
    )


def test_admin_roles_comma_string_accepted():
    assert AdminPlugin(admin_roles="admin").admin_roles == ["admin"]


def test_invalid_admin_roles_raise():
    with pytest.raises(ValueError, match="Invalid admin roles"):
        AdminPlugin(admin_roles=["superuser"])  # not in default roles


def test_custom_roles_allow_custom_admin_role():
    from better_auth.access_control import ADMIN_DEFAULT_STATEMENTS, create_access_control

    ac = create_access_control(ADMIN_DEFAULT_STATEMENTS)
    roles = {"superuser": ac.new_role({"user": ["create", "list"]})}
    p = AdminPlugin(roles=roles, admin_roles=["superuser"])
    assert p.admin_roles == ["superuser"]


# --- permission matrix (synchronous has_permission) -------------------------------


def test_has_permission_admin_role_authorized():
    p = AdminPlugin()
    assert p.has_permission(role="admin", permissions={"user": ["create"]}) is True


def test_has_permission_user_role_denied():
    p = AdminPlugin()
    assert p.has_permission(role="user", permissions={"user": ["create"]}) is False


def test_has_permission_admin_user_ids_bypass():
    p = AdminPlugin(admin_user_ids=["uid-1"])
    # role "user" would normally be denied; admin_user_ids overrides
    assert p.has_permission(user_id="uid-1", role="user", permissions={"user": ["create"]}) is True
    assert p.has_permission(user_id="uid-2", role="user", permissions={"user": ["create"]}) is False


def test_has_permission_default_role_when_none():
    p = AdminPlugin(default_role="admin")
    assert p.has_permission(permissions={"user": ["create"]}) is True


def test_has_permission_admin_lacks_impersonate_admins():
    # default admin role deliberately excludes "impersonate-admins"
    p = AdminPlugin()
    assert p.has_permission(role="admin", permissions={"user": ["impersonate-admins"]}) is False


# --- set-role ----------------------------------------------------------------------


async def test_set_role_promotes_user():
    auth = admin_auth()
    async with make_client(auth) as client:
        await _become_admin(auth, client)
        target = await _seed_user(auth, email="bob@x.com")
        r = await client.post(
            "/api/auth/admin/set-role", json={"userId": target["id"], "role": "admin"}
        )
        assert r.status_code == 200
        assert r.json()["user"]["role"] == "admin"


async def test_set_role_array_joined_comma():
    auth = admin_auth()
    async with make_client(auth) as client:
        await _become_admin(auth, client)
        target = await _seed_user(auth, email="bob@x.com")
        r = await client.post(
            "/api/auth/admin/set-role", json={"userId": target["id"], "role": ["admin", "user"]}
        )
        assert r.status_code == 200
        assert r.json()["user"]["role"] == "admin,user"


async def test_set_role_denied_for_non_admin():
    auth = admin_auth()
    async with make_client(auth) as client:
        await sign_up(client)  # plain user
        target = await _seed_user(auth, email="bob@x.com")
        r = await client.post(
            "/api/auth/admin/set-role", json={"userId": target["id"], "role": "admin"}
        )
        assert r.status_code == 403
        assert r.json()["code"] == "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE"
        assert r.json()["message"] == ADMIN_ERROR_CODES["YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE"]


async def test_set_role_requires_session():
    auth = admin_auth()
    async with make_client(auth) as client:
        r = await client.post("/api/auth/admin/set-role", json={"userId": "x", "role": "admin"})
        assert r.status_code == 401


async def test_set_role_nonexistent_role_value_rejected():
    from better_auth.access_control import ADMIN_DEFAULT_STATEMENTS, create_access_control

    ac = create_access_control(ADMIN_DEFAULT_STATEMENTS)
    roles = {
        "admin": ac.new_role({"user": ["create", "set-role"]}),
        "user": ac.new_role({"user": []}),
    }
    auth = admin_auth(roles=roles)
    async with make_client(auth) as client:
        await _become_admin(auth, client)
        target = await _seed_user(auth, email="bob@x.com")
        r = await client.post(
            "/api/auth/admin/set-role", json={"userId": target["id"], "role": "ghost"}
        )
        assert r.status_code == 400
        assert r.json()["code"] == "YOU_ARE_NOT_ALLOWED_TO_SET_NON_EXISTENT_VALUE"


# --- get-user ----------------------------------------------------------------------


async def test_get_user_returns_user():
    auth = admin_auth()
    async with make_client(auth) as client:
        await _become_admin(auth, client)
        target = await _seed_user(auth, email="bob@x.com")
        r = await client.get("/api/auth/admin/get-user", params={"id": target["id"]})
        assert r.status_code == 200
        assert r.json()["email"] == "bob@x.com"


async def test_get_user_not_found():
    auth = admin_auth()
    async with make_client(auth) as client:
        await _become_admin(auth, client)
        r = await client.get("/api/auth/admin/get-user", params={"id": "nope"})
        assert r.status_code == 404


# --- create-user -------------------------------------------------------------------


async def test_create_user_with_password_creates_credential():
    auth = admin_auth()
    async with make_client(auth) as client:
        await _become_admin(auth, client)
        r = await client.post(
            "/api/auth/admin/create-user",
            json={"email": "new@x.com", "name": "New", "password": PASSWORD},
        )
        assert r.status_code == 200
        assert r.json()["user"]["email"] == "new@x.com"
        new_user = await auth.adapter.find_one("user", [Where("email", "new@x.com")])
        account = await auth.adapter.find_one(
            "account", [Where("userId", new_user["id"]), Where("providerId", "credential")]
        )
        assert account is not None


async def test_create_user_default_role_applied():
    auth = admin_auth()
    async with make_client(auth) as client:
        await _become_admin(auth, client)
        await client.post("/api/auth/admin/create-user", json={"email": "new@x.com", "name": "New"})
        new_user = await auth.adapter.find_one("user", [Where("email", "new@x.com")])
        assert new_user["role"] == "user"


async def test_create_user_duplicate_email_rejected():
    auth = admin_auth()
    async with make_client(auth) as client:
        await _become_admin(auth, client)
        r = await client.post(
            "/api/auth/admin/create-user", json={"email": "ada@example.com", "name": "Dup"}
        )
        assert r.status_code == 400
        assert r.json()["code"] == "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL"


async def test_create_user_role_requires_set_role_permission():
    # a caller with user:create but not user:set-role cannot assign a role
    from better_auth.access_control import ADMIN_DEFAULT_STATEMENTS, create_access_control

    ac = create_access_control(ADMIN_DEFAULT_STATEMENTS)
    roles = {"admin": ac.new_role({"user": ["create"]}), "user": ac.new_role({"user": []})}
    auth = admin_auth(roles=roles)
    async with make_client(auth) as client:
        await _become_admin(auth, client)
        r = await client.post(
            "/api/auth/admin/create-user",
            json={"email": "new@x.com", "name": "New", "role": "admin"},
        )
        assert r.status_code == 403
        assert r.json()["code"] == "YOU_ARE_NOT_ALLOWED_TO_CHANGE_USERS_ROLE"


async def test_create_user_data_role_also_authorized():
    # privilege-escalation guard: role smuggled via `data` is authorized too
    from better_auth.access_control import ADMIN_DEFAULT_STATEMENTS, create_access_control

    ac = create_access_control(ADMIN_DEFAULT_STATEMENTS)
    roles = {"admin": ac.new_role({"user": ["create"]}), "user": ac.new_role({"user": []})}
    auth = admin_auth(roles=roles)
    async with make_client(auth) as client:
        await _become_admin(auth, client)
        r = await client.post(
            "/api/auth/admin/create-user",
            json={"email": "new@x.com", "name": "New", "data": {"role": "admin"}},
        )
        assert r.status_code == 403


async def test_create_user_admin_user_ids_bypass_over_http():
    uid = "fixed-admin-uid"
    auth = admin_auth(admin_user_ids=[uid])
    await auth.internal.create_user(
        {"id": uid, "name": "Sp", "email": "sp@x.com", "emailVerified": True}, force_allow_id=True
    )
    await auth.internal.create_account(
        {
            "userId": uid,
            "accountId": uid,
            "providerId": "credential",
            "password": hash_password(PASSWORD),
        }
    )
    async with make_client(auth) as client:
        signin = await client.post(
            "/api/auth/sign-in/email", json={"email": "sp@x.com", "password": PASSWORD}
        )
        assert signin.status_code == 200
        # role is the default "user" but admin_user_ids grants create
        r = await client.post(
            "/api/auth/admin/create-user", json={"email": "new@x.com", "name": "New"}
        )
        assert r.status_code == 200


# --- update-user -------------------------------------------------------------------


async def test_update_user_changes_name():
    auth = admin_auth()
    async with make_client(auth) as client:
        await _become_admin(auth, client)
        target = await _seed_user(auth, email="bob@x.com")
        r = await client.post(
            "/api/auth/admin/update-user", json={"userId": target["id"], "data": {"name": "Bobby"}}
        )
        assert r.status_code == 200
        assert r.json()["name"] == "Bobby"


async def test_update_user_rejects_password_key():
    auth = admin_auth()
    async with make_client(auth) as client:
        await _become_admin(auth, client)
        target = await _seed_user(auth, email="bob@x.com")
        r = await client.post(
            "/api/auth/admin/update-user",
            json={"userId": target["id"], "data": {"password": "x"}},
        )
        assert r.status_code == 400
        assert r.json()["code"] == "PASSWORD_CANNOT_BE_UPDATED_VIA_UPDATE_USER"


async def test_update_user_empty_data_rejected():
    auth = admin_auth()
    async with make_client(auth) as client:
        await _become_admin(auth, client)
        target = await _seed_user(auth, email="bob@x.com")
        r = await client.post(
            "/api/auth/admin/update-user", json={"userId": target["id"], "data": {}}
        )
        assert r.status_code == 400
        assert r.json()["code"] == "NO_DATA_TO_UPDATE"


async def test_update_user_ban_via_update_revokes_sessions():
    auth = admin_auth()
    async with make_client(auth) as client:
        await _become_admin(auth, client)
        target = await _seed_user(auth, email="bob@x.com")
        # give the target a session
        await auth.internal.create_session(target["id"])
        r = await client.post(
            "/api/auth/admin/update-user",
            json={"userId": target["id"], "data": {"banned": True}},
        )
        assert r.status_code == 200
        assert await auth.adapter.find_many("session", [Where("userId", target["id"])]) == []


async def test_update_user_cannot_ban_self():
    auth = admin_auth()
    async with make_client(auth) as client:
        admin = await _become_admin(auth, client)
        r = await client.post(
            "/api/auth/admin/update-user",
            json={"userId": admin["id"], "data": {"banned": True}},
        )
        assert r.status_code == 400
        assert r.json()["code"] == "YOU_CANNOT_BAN_YOURSELF"


# --- list-users: search / filter / sort / paginate --------------------------------


async def _seed_many(auth):
    await _seed_user(auth, email="ann@example.com", name="Ann")
    await _seed_user(auth, email="bea@other.com", name="Bea")
    await _seed_user(auth, email="cid@example.com", name="Cid", role="admin")


async def test_list_users_returns_users_and_total():
    auth = admin_auth()
    async with make_client(auth) as client:
        await _become_admin(auth, client)  # ada
        await _seed_many(auth)
        r = await client.get("/api/auth/admin/list-users")
        assert r.status_code == 200
        body = r.json()
        assert body["total"] == 4  # ada + 3 seeded
        assert len(body["users"]) == 4


async def test_list_users_search_contains():
    auth = admin_auth()
    async with make_client(auth) as client:
        await _become_admin(auth, client)
        await _seed_many(auth)
        r = await client.get(
            "/api/auth/admin/list-users",
            params={
                "searchValue": "example.com",
                "searchField": "email",
                "searchOperator": "ends_with",
            },
        )
        emails = {u["email"] for u in r.json()["users"]}
        assert emails == {"ada@example.com", "ann@example.com", "cid@example.com"}


async def test_list_users_pagination_includes_limit_offset():
    auth = admin_auth()
    async with make_client(auth) as client:
        await _become_admin(auth, client)
        await _seed_many(auth)
        r = await client.get(
            "/api/auth/admin/list-users",
            params={"limit": "2", "offset": "1", "sortBy": "email", "sortDirection": "asc"},
        )
        body = r.json()
        assert body["limit"] == 2 and body["offset"] == 1
        assert [u["email"] for u in body["users"]] == ["ann@example.com", "bea@other.com"]


async def test_list_users_sort_desc():
    auth = admin_auth()
    async with make_client(auth) as client:
        await _become_admin(auth, client)
        await _seed_many(auth)
        r = await client.get(
            "/api/auth/admin/list-users", params={"sortBy": "email", "sortDirection": "desc"}
        )
        emails = [u["email"] for u in r.json()["users"]]
        assert emails == sorted(emails, reverse=True)


async def test_list_users_filter_by_role():
    auth = admin_auth()
    async with make_client(auth) as client:
        await _become_admin(auth, client)
        await _seed_many(auth)
        r = await client.get(
            "/api/auth/admin/list-users",
            params={"filterField": "role", "filterValue": "admin", "filterOperator": "eq"},
        )
        emails = {u["email"] for u in r.json()["users"]}
        assert emails == {"ada@example.com", "cid@example.com"}


async def test_list_users_denied_for_non_admin():
    auth = admin_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        r = await client.get("/api/auth/admin/list-users")
        assert r.status_code == 403
        assert r.json()["code"] == "YOU_ARE_NOT_ALLOWED_TO_LIST_USERS"


# --- list-user-sessions ------------------------------------------------------------


async def test_list_user_sessions():
    auth = admin_auth()
    async with make_client(auth) as client:
        await _become_admin(auth, client)
        target = await _seed_user(auth, email="bob@x.com")
        await auth.internal.create_session(target["id"])
        await auth.internal.create_session(target["id"])
        r = await client.post("/api/auth/admin/list-user-sessions", json={"userId": target["id"]})
        assert r.status_code == 200
        assert len(r.json()["sessions"]) == 2


# --- ban / unban / enforcement -----------------------------------------------------


async def test_ban_user_sets_fields_and_revokes_sessions():
    auth = admin_auth()
    async with make_client(auth) as client:
        await _become_admin(auth, client)
        target = await _seed_user(auth, email="bob@x.com")
        await auth.internal.create_session(target["id"])
        r = await client.post(
            "/api/auth/admin/ban-user",
            json={"userId": target["id"], "banReason": "spam", "banExpiresIn": 3600},
        )
        assert r.status_code == 200
        assert r.json()["user"]["banned"] is True
        assert r.json()["user"]["banReason"] == "spam"
        banned = await auth.adapter.find_one("user", [Where("id", target["id"])])
        assert banned["banExpires"] is not None
        assert await auth.adapter.find_many("session", [Where("userId", target["id"])]) == []


async def test_ban_user_default_reason():
    auth = admin_auth()
    async with make_client(auth) as client:
        await _become_admin(auth, client)
        target = await _seed_user(auth, email="bob@x.com")
        r = await client.post("/api/auth/admin/ban-user", json={"userId": target["id"]})
        assert r.json()["user"]["banReason"] == "No reason"


async def test_ban_user_configured_default_reason():
    auth = admin_auth(default_ban_reason="TOS violation")
    async with make_client(auth) as client:
        await _become_admin(auth, client)
        target = await _seed_user(auth, email="bob@x.com")
        r = await client.post("/api/auth/admin/ban-user", json={"userId": target["id"]})
        assert r.json()["user"]["banReason"] == "TOS violation"


async def test_ban_cannot_ban_self():
    auth = admin_auth()
    async with make_client(auth) as client:
        admin = await _become_admin(auth, client)
        r = await client.post("/api/auth/admin/ban-user", json={"userId": admin["id"]})
        assert r.status_code == 400
        assert r.json()["code"] == "YOU_CANNOT_BAN_YOURSELF"


async def test_unban_user_clears_fields():
    auth = admin_auth()
    async with make_client(auth) as client:
        await _become_admin(auth, client)
        target = await _seed_user(auth, email="bob@x.com")
        await client.post("/api/auth/admin/ban-user", json={"userId": target["id"]})
        r = await client.post("/api/auth/admin/unban-user", json={"userId": target["id"]})
        assert r.status_code == 200
        assert r.json()["user"]["banned"] is False
        unbanned = await auth.adapter.find_one("user", [Where("id", target["id"])])
        assert unbanned["banExpires"] is None and unbanned["banReason"] is None


async def test_banned_user_cannot_sign_in():
    auth = admin_auth()
    async with make_client(auth) as admin_client, make_client(auth) as bob_client:
        await _become_admin(auth, admin_client)
        await sign_up(bob_client, email="bob@example.com", name="Bob")
        bob = await auth.adapter.find_one("user", [Where("email", "bob@example.com")])
        await admin_client.post("/api/auth/admin/ban-user", json={"userId": bob["id"]})

        r = await bob_client.post(
            "/api/auth/sign-in/email", json={"email": "bob@example.com", "password": PASSWORD}
        )
        assert r.status_code == 403
        assert r.json()["code"] == "BANNED_USER"
        # the thrown message is bannedUserMessage (the long default), not the shorter
        # ADMIN_ERROR_CODES["BANNED_USER"] string (TS admin.ts session.create.before)
        assert r.json()["message"] == (
            "You have been banned from this application. "
            "Please contact support if you believe this is an error."
        )


async def test_banned_user_message_configurable():
    auth = admin_auth(banned_user_message="Custom ban msg")
    async with make_client(auth) as admin_client, make_client(auth) as bob_client:
        await _become_admin(auth, admin_client)
        await sign_up(bob_client, email="bob@example.com", name="Bob")
        bob = await auth.adapter.find_one("user", [Where("email", "bob@example.com")])
        await admin_client.post("/api/auth/admin/ban-user", json={"userId": bob["id"]})
        r = await bob_client.post(
            "/api/auth/sign-in/email", json={"email": "bob@example.com", "password": PASSWORD}
        )
        assert r.json()["message"] == "Custom ban msg"


async def test_expired_ban_auto_unbans_on_sign_in():
    auth = admin_auth()
    async with make_client(auth) as admin_client, make_client(auth) as bob_client:
        await _become_admin(auth, admin_client)
        await sign_up(bob_client, email="bob@example.com", name="Bob")
        bob = await auth.adapter.find_one("user", [Where("email", "bob@example.com")])
        await admin_client.post(
            "/api/auth/admin/ban-user", json={"userId": bob["id"], "banExpiresIn": 3600}
        )
        # blocked while ban active
        blocked = await bob_client.post(
            "/api/auth/sign-in/email", json={"email": "bob@example.com", "password": PASSWORD}
        )
        assert blocked.status_code == 403

        # force the ban into the past → next sign-in auto-unbans and succeeds
        await auth.adapter.update(
            "user", [Where("id", bob["id"])], {"banExpires": utcnow() - timedelta(hours=1)}
        )
        ok = await bob_client.post(
            "/api/auth/sign-in/email", json={"email": "bob@example.com", "password": PASSWORD}
        )
        assert ok.status_code == 200
        refreshed = await auth.adapter.find_one("user", [Where("id", bob["id"])])
        assert refreshed["banned"] is False


# --- impersonation -----------------------------------------------------------------


async def test_impersonate_and_stop_round_trip():
    auth = admin_auth()
    async with make_client(auth) as client:
        admin = await _become_admin(auth, client)
        target = await _seed_user(auth, email="bob@x.com")

        imp = await client.post("/api/auth/admin/impersonate-user", json={"userId": target["id"]})
        assert imp.status_code == 200
        assert imp.json()["user"]["id"] == target["id"]
        assert imp.json()["session"]["impersonatedBy"] == admin["id"]

        # admin_session cookie was set (signed)
        assert cookie_name(auth, "admin_session") in imp.headers.get("set-cookie", "") or any(
            cookie_name(auth, "admin_session") in c
            for c in imp.headers.get_list("set-cookie")
        )

        # now acting as the target
        who = await client.get("/api/auth/get-session")
        assert who.json()["user"]["id"] == target["id"]

        stop = await client.post("/api/auth/admin/stop-impersonating")
        assert stop.status_code == 200
        assert stop.json()["user"]["id"] == admin["id"]

        # restored to admin
        who2 = await client.get("/api/auth/get-session")
        assert who2.json()["user"]["id"] == admin["id"]


async def test_impersonate_ip_disable_tracking_stores_empty():
    # routes.ts:1272 hands ipAddress resolution to internalAdapter.createSession, which
    # resolves via getIp(headers, options) (internal-adapter.ts:349) — honoring
    # advanced.ipAddress. The Python port hand-builds the session row instead (a fixed
    # impersonation-duration expiry create_session can't express), so it must call
    # get_request_ip itself to keep that behavior. A raw client_ip read would never
    # honor disable_ip_tracking; get_request_ip does.
    auth = make_auth(
        plugins=[AdminPlugin()], ip_address=IPAddressOptions(disable_ip_tracking=True)
    )
    async with make_client(auth) as client:
        await _become_admin(auth, client)
        target = await _seed_user(auth, email="bob@x.com")
        imp = await client.post(
            "/api/auth/admin/impersonate-user",
            json={"userId": target["id"]},
            headers={"x-forwarded-for": "203.0.113.7"},
        )
        assert imp.status_code == 200
        assert imp.json()["session"]["ipAddress"] == ""


async def test_impersonate_ip_resolves_via_trusted_proxies():
    # A 3-hop forwarded chain where a spoofed hop sits left of the real client: naive
    # leftmost parsing (the old raw client_ip path) would pick the spoofed "203.0.113.7"
    # entry; get_request_ip walks the chain right-to-left, skips the trusted proxy, and
    # lands on the true client "1.2.3.4".
    auth = make_auth(
        plugins=[AdminPlugin()],
        ip_address=IPAddressOptions(trusted_proxies=["10.0.0.0/8"]),
    )
    async with make_client(auth) as client:
        await _become_admin(auth, client)
        target = await _seed_user(auth, email="bob@x.com")
        imp = await client.post(
            "/api/auth/admin/impersonate-user",
            json={"userId": target["id"]},
            headers={"x-forwarded-for": "203.0.113.7, 1.2.3.4, 10.0.0.5"},
        )
        assert imp.status_code == 200
        assert imp.json()["session"]["ipAddress"] == "1.2.3.4"


async def test_impersonate_denied_for_non_admin():
    auth = admin_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        target = await _seed_user(auth, email="bob@x.com")
        r = await client.post("/api/auth/admin/impersonate-user", json={"userId": target["id"]})
        assert r.status_code == 403
        assert r.json()["code"] == "YOU_ARE_NOT_ALLOWED_TO_IMPERSONATE_USERS"


async def test_impersonate_admin_blocked_by_default():
    auth = admin_auth()
    async with make_client(auth) as client:
        await _become_admin(auth, client)
        target = await _seed_user(auth, email="bob@x.com", role="admin")
        r = await client.post("/api/auth/admin/impersonate-user", json={"userId": target["id"]})
        assert r.status_code == 403
        assert r.json()["code"] == "YOU_CANNOT_IMPERSONATE_ADMINS"


async def test_impersonate_admin_allowed_with_flag():
    auth = admin_auth(allow_impersonating_admins=True)
    async with make_client(auth) as client:
        await _become_admin(auth, client)
        target = await _seed_user(auth, email="bob@x.com", role="admin")
        r = await client.post("/api/auth/admin/impersonate-user", json={"userId": target["id"]})
        assert r.status_code == 200


async def test_stop_impersonating_without_impersonation_rejected():
    auth = admin_auth()
    async with make_client(auth) as client:
        await _become_admin(auth, client)
        r = await client.post("/api/auth/admin/stop-impersonating")
        assert r.status_code == 400


# --- revoke sessions ---------------------------------------------------------------


async def test_revoke_user_session_by_token():
    auth = admin_auth()
    async with make_client(auth) as client:
        await _become_admin(auth, client)
        target = await _seed_user(auth, email="bob@x.com")
        s = await auth.internal.create_session(target["id"])
        r = await client.post(
            "/api/auth/admin/revoke-user-session", json={"sessionToken": s["token"]}
        )
        assert r.status_code == 200 and r.json()["success"] is True
        assert await auth.adapter.find_one("session", [Where("token", s["token"])]) is None


async def test_revoke_user_sessions_all():
    auth = admin_auth()
    async with make_client(auth) as client:
        await _become_admin(auth, client)
        target = await _seed_user(auth, email="bob@x.com")
        await auth.internal.create_session(target["id"])
        await auth.internal.create_session(target["id"])
        r = await client.post("/api/auth/admin/revoke-user-sessions", json={"userId": target["id"]})
        assert r.status_code == 200
        assert await auth.adapter.find_many("session", [Where("userId", target["id"])]) == []


async def test_revoke_denied_for_non_admin():
    auth = admin_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        r = await client.post("/api/auth/admin/revoke-user-sessions", json={"userId": "x"})
        assert r.status_code == 403
        assert r.json()["code"] == "YOU_ARE_NOT_ALLOWED_TO_REVOKE_USERS_SESSIONS"


# --- remove-user (hard delete cascade) --------------------------------------------


async def test_remove_user_cascades():
    auth = admin_auth()
    async with make_client(auth) as client:
        await _become_admin(auth, client)
        target = await _seed_user(auth, email="bob@x.com")
        await auth.internal.create_account(
            {"userId": target["id"], "accountId": "g", "providerId": "google", "accessToken": "t"}
        )
        await auth.internal.create_session(target["id"])
        r = await client.post("/api/auth/admin/remove-user", json={"userId": target["id"]})
        assert r.status_code == 200 and r.json()["success"] is True
        assert await auth.adapter.find_one("user", [Where("id", target["id"])]) is None
        assert await auth.adapter.find_many("account", [Where("userId", target["id"])]) == []
        assert await auth.adapter.find_many("session", [Where("userId", target["id"])]) == []


async def test_remove_user_cannot_remove_self():
    auth = admin_auth()
    async with make_client(auth) as client:
        admin = await _become_admin(auth, client)
        r = await client.post("/api/auth/admin/remove-user", json={"userId": admin["id"]})
        assert r.status_code == 400
        assert r.json()["code"] == "YOU_CANNOT_REMOVE_YOURSELF"


# --- set-user-password -------------------------------------------------------------


async def test_set_user_password_updates_existing_credential():
    auth = admin_auth()
    async with make_client(auth) as admin_client, make_client(auth) as bob_client:
        await _become_admin(auth, admin_client)
        await sign_up(bob_client, email="bob@example.com", name="Bob")
        bob = await auth.adapter.find_one("user", [Where("email", "bob@example.com")])
        r = await admin_client.post(
            "/api/auth/admin/set-user-password",
            json={"userId": bob["id"], "newPassword": "new-password-123"},
        )
        assert r.status_code == 200 and r.json()["status"] is True
        # bob can sign in with the new password
        signin = await bob_client.post(
            "/api/auth/sign-in/email",
            json={"email": "bob@example.com", "password": "new-password-123"},
        )
        assert signin.status_code == 200


async def test_set_user_password_creates_credential_when_missing():
    auth = admin_auth()
    async with make_client(auth) as client:
        await _become_admin(auth, client)
        target = await _seed_user(auth, email="bob@example.com")  # no credential account
        r = await client.post(
            "/api/auth/admin/set-user-password",
            json={"userId": target["id"], "newPassword": "new-password-123"},
        )
        assert r.status_code == 200
        account = await auth.adapter.find_one(
            "account", [Where("userId", target["id"]), Where("providerId", "credential")]
        )
        assert account is not None


async def test_set_user_password_respects_password_checks():
    auth = admin_auth()

    async def reject(password, path):
        if "pwned" in password:
            raise APIError(400, "PASSWORD_COMPROMISED", "compromised password")

    auth.password_checks.append(reject)
    async with make_client(auth) as client:
        await _become_admin(auth, client)
        target = await _seed_user(auth, email="bob@x.com")
        r = await client.post(
            "/api/auth/admin/set-user-password",
            json={"userId": target["id"], "newPassword": "totally-pwned-pw"},
        )
        assert r.status_code == 400
        assert r.json()["code"] == "PASSWORD_COMPROMISED"


async def test_set_user_password_too_short():
    auth = admin_auth()
    async with make_client(auth) as client:
        await _become_admin(auth, client)
        target = await _seed_user(auth, email="bob@x.com")
        r = await client.post(
            "/api/auth/admin/set-user-password", json={"userId": target["id"], "newPassword": "x"}
        )
        assert r.status_code == 400
        assert r.json()["code"] == "PASSWORD_TOO_SHORT"


# --- has-permission endpoint -------------------------------------------------------


async def test_has_permission_endpoint_admin_true():
    auth = admin_auth()
    async with make_client(auth) as client:
        await _become_admin(auth, client)
        r = await client.post(
            "/api/auth/admin/has-permission", json={"permissions": {"user": ["create"]}}
        )
        assert r.status_code == 200
        assert r.json() == {"error": None, "success": True}


async def test_has_permission_endpoint_user_false():
    auth = admin_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        r = await client.post(
            "/api/auth/admin/has-permission", json={"permissions": {"user": ["create"]}}
        )
        assert r.status_code == 200
        assert r.json() == {"error": None, "success": False}


async def test_has_permission_endpoint_missing_permissions():
    auth = admin_auth()
    async with make_client(auth) as client:
        await _become_admin(auth, client)
        r = await client.post("/api/auth/admin/has-permission", json={})
        assert r.status_code == 400


async def test_has_permission_endpoint_accepts_permission_singular():
    auth = admin_auth()
    async with make_client(auth) as client:
        await _become_admin(auth, client)
        r = await client.post(
            "/api/auth/admin/has-permission", json={"permission": {"user": ["create"]}}
        )
        assert r.status_code == 200
        assert r.json()["success"] is True


# --- list-sessions after-hook filters impersonated sessions ------------------------


async def test_list_sessions_hides_impersonated_sessions():
    auth = admin_auth()
    async with make_client(auth) as client:
        user = await _become_admin(auth, client)
        # a normal session exists (from sign-up); add an impersonated one for the same user
        await auth.internal.create("session", {
            "id": "imp", "token": "imp-token", "userId": user["id"],
            "impersonatedBy": "someone", "expiresAt": utcnow() + timedelta(hours=1),
            "createdAt": utcnow(), "updatedAt": utcnow(),
        })
        r = await client.get("/api/auth/list-sessions")
        assert r.status_code == 200
        assert all(not s.get("impersonatedBy") for s in r.json())
