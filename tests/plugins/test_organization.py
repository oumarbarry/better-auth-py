"""organization plugin — PHASE 1 (core-org): orgs, members, roles/permissions.

Verified against TS ``packages/better-auth/src/plugins/organization`` at v1.6.23
(routes/crud-org.ts, routes/crud-members.ts, organization.ts, has-permission.ts,
error-codes.ts). Invitations, teams, and dynamic access control are later phases.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from typing import Any

from better_auth import MemoryAdapter
from better_auth.access_control import (
    ORG_DEFAULT_ROLES,
    ORG_DEFAULT_STATEMENTS,
    create_access_control,
)
from better_auth.adapters.base import Where
from better_auth.config import AdvancedDatabase
from better_auth.crypto import generate_id
from better_auth.plugins_ext.organization import ERROR_CODES, OrganizationPlugin
from better_auth.schema import Field
from better_auth.session import utcnow
from conftest import make_auth, make_client, sign_up


def org_auth(**kwargs: Any):
    return make_auth(plugins=[OrganizationPlugin(**kwargs)])


def _bearer(token: str) -> dict[str, str]:
    return {"authorization": f"Bearer {token}"}


async def _seed_member(auth, org_id: str, user_id: str, role: str) -> dict[str, Any]:
    """Insert a member row directly (there is no server addMember surface this phase)."""
    return await auth.adapter.create(
        "member",
        {
            "id": generate_id(),
            "organizationId": org_id,
            "userId": user_id,
            "role": role,
            "createdAt": utcnow(),
        },
    )


async def _create_org(client, *, name="Acme", slug="acme", **body):
    return await client.post(
        "/api/auth/organization/create", json={"name": name, "slug": slug, **body}
    )


# --- create -----------------------------------------------------------------------


async def test_create_makes_creator_an_owner_member_and_sets_active():
    async with make_client(org_auth()) as client:
        await sign_up(client)
        res = await _create_org(client, metadata={"plan": "pro"})
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["name"] == "Acme"
        assert body["slug"] == "acme"
        assert body["metadata"] == {"plan": "pro"}  # round-trips string -> object
        assert len(body["members"]) == 1
        assert body["members"][0]["role"] == "owner"

        session = (await client.get("/api/auth/get-session")).json()
        assert session["session"]["activeOrganizationId"] == body["id"]


async def test_create_stores_metadata_as_json_string_in_db():
    auth = org_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        body = (await _create_org(client, metadata={"a": 1})).json()
        row = await auth.adapter.find_one("organization", [Where("id", body["id"])])
        assert isinstance(row["metadata"], str)
        assert row["metadata"] == '{"a":1}'


async def test_create_duplicate_slug_rejected():
    async with make_client(org_auth()) as client:
        await sign_up(client)
        await _create_org(client, slug="dupe")
        res = await _create_org(client, name="Other", slug="dupe")
        assert res.status_code == 400
        assert res.json()["code"] == "ORGANIZATION_ALREADY_EXISTS"
        assert res.json()["message"] == ERROR_CODES["ORGANIZATION_ALREADY_EXISTS"]


async def test_create_empty_slug_and_name_rejected():
    async with make_client(org_auth()) as client:
        await sign_up(client)
        assert (await _create_org(client, slug="")).status_code == 400
        assert (await _create_org(client, name="")).status_code == 400


async def test_create_requires_session():
    async with make_client(org_auth()) as client:
        res = await _create_org(client)
        assert res.status_code == 401


async def test_allow_user_to_create_organization_false_forbids():
    async with make_client(org_auth(allow_user_to_create_organization=False)) as client:
        await sign_up(client)
        res = await _create_org(client)
        assert res.status_code == 403
        assert res.json()["code"] == "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_ORGANIZATION"


async def test_allow_user_to_create_organization_async_fn():
    async def allow(user):
        return user["email"] != "ada@example.com"

    async with make_client(org_auth(allow_user_to_create_organization=allow)) as client:
        await sign_up(client)  # ada@example.com
        assert (await _create_org(client)).status_code == 403


async def test_organization_limit_number_enforced():
    async with make_client(org_auth(organization_limit=1)) as client:
        await sign_up(client)
        assert (await _create_org(client, slug="one")).status_code == 200
        res = await _create_org(client, name="Two", slug="two")
        assert res.status_code == 403
        assert res.json()["code"] == "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_ORGANIZATIONS"


async def test_organization_limit_async_fn():
    async def limit(user):
        return True  # always "reached"

    async with make_client(org_auth(organization_limit=limit)) as client:
        await sign_up(client)
        assert (await _create_org(client)).status_code == 403


async def test_keep_current_active_organization():
    async with make_client(org_auth()) as client:
        await sign_up(client)
        first = (await _create_org(client, slug="first")).json()
        await _create_org(client, name="Second", slug="second", keepCurrentActiveOrganization=True)
        session = (await client.get("/api/auth/get-session")).json()
        assert session["session"]["activeOrganizationId"] == first["id"]


# --- create hooks -----------------------------------------------------------------


async def test_before_create_organization_hook_merges_data():
    async def before(data):
        return {"data": {**data["organization"], "name": "changed-name"}}

    auth = org_auth(organization_hooks={"before_create_organization": before})
    async with make_client(auth) as c:
        await sign_up(c)
        body = (await _create_org(c)).json()
        assert body["name"] == "changed-name"


async def test_after_create_organization_hook_fires():
    calls: list[Any] = []

    async def after(data):
        calls.append(data["organization"]["id"])

    async with make_client(org_auth(organization_hooks={"after_create_organization": after})) as c:
        await sign_up(c)
        body = (await _create_org(c)).json()
        assert calls == [body["id"]]


async def test_before_add_member_hook_changes_role():
    async def before(data):
        return {"data": {"role": "admin"}}

    async with make_client(org_auth(organization_hooks={"before_add_member": before})) as c:
        await sign_up(c)
        await _create_org(c)
        member = (await c.get("/api/auth/organization/get-active-member")).json()
        assert member["role"] == "admin"


# --- check-slug -------------------------------------------------------------------


async def test_check_slug_available_and_taken():
    async with make_client(org_auth()) as client:
        await sign_up(client)
        await _create_org(client, slug="taken")

        avail = await client.post("/api/auth/organization/check-slug", json={"slug": "free"})
        assert avail.status_code == 200
        assert avail.json()["status"] is True

        taken = await client.post("/api/auth/organization/check-slug", json={"slug": "taken"})
        assert taken.status_code == 400
        assert taken.json()["code"] == "ORGANIZATION_SLUG_ALREADY_TAKEN"
        assert taken.json()["message"] == ERROR_CODES["ORGANIZATION_SLUG_ALREADY_TAKEN"]


# --- update -----------------------------------------------------------------------


async def test_update_by_owner_and_metadata_roundtrip():
    async with make_client(org_auth()) as client:
        await sign_up(client)
        org = (await _create_org(client)).json()
        res = await client.post(
            "/api/auth/organization/update",
            json={"organizationId": org["id"], "data": {"name": "Renamed", "metadata": {"x": 2}}},
        )
        assert res.status_code == 200
        assert res.json()["name"] == "Renamed"
        assert res.json()["metadata"] == {"x": 2}


async def test_update_null_logo_clears_it():
    async with make_client(org_auth()) as client:
        await sign_up(client)
        org = (await _create_org(client, logo="https://x/l.png")).json()
        res = await client.post(
            "/api/auth/organization/update",
            json={"organizationId": org["id"], "data": {"logo": None}},
        )
        assert res.json()["logo"] is None


async def test_update_duplicate_slug_rejected():
    async with make_client(org_auth()) as client:
        await sign_up(client)
        await _create_org(client, slug="taken-a")
        org_b = (await _create_org(client, name="B", slug="slug-b")).json()
        res = await client.post(
            "/api/auth/organization/update",
            json={"organizationId": org_b["id"], "data": {"slug": "taken-a"}},
        )
        assert res.status_code == 400
        assert res.json()["code"] == "ORGANIZATION_SLUG_ALREADY_TAKEN"


async def test_update_forbidden_for_plain_member():
    auth = org_auth()
    async with make_client(auth) as owner_c, make_client(auth) as member_c:
        await sign_up(owner_c)
        member = await sign_up(member_c, email="m@x.com", name="Mem")
        org = (await _create_org(owner_c)).json()
        await _seed_member(auth, org["id"], member["user"]["id"], "member")
        res = await member_c.post(
            "/api/auth/organization/update",
            json={"organizationId": org["id"], "data": {"name": "Nope"}},
        )
        assert res.status_code == 403
        assert res.json()["code"] == "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_ORGANIZATION"


async def test_update_non_member_rejected():
    auth = org_auth()
    async with make_client(auth) as owner_c, make_client(auth) as other_c:
        await sign_up(owner_c)
        await sign_up(other_c, email="o@x.com", name="Other")
        org = (await _create_org(owner_c)).json()
        res = await other_c.post(
            "/api/auth/organization/update",
            json={"organizationId": org["id"], "data": {"name": "Nope"}},
        )
        assert res.status_code == 400
        assert res.json()["code"] == "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION"


# --- delete -----------------------------------------------------------------------


async def test_delete_by_owner_cascades_members_and_clears_active():
    auth = org_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        org = (await _create_org(client)).json()
        res = await client.post("/api/auth/organization/delete", json={"organizationId": org["id"]})
        assert res.status_code == 200
        assert await auth.adapter.find_one("organization", [Where("id", org["id"])]) is None
        assert await auth.adapter.find_many("member", [Where("organizationId", org["id"])]) == []
        session = (await client.get("/api/auth/get-session")).json()
        assert session["session"].get("activeOrganizationId") is None


async def test_delete_forbidden_for_admin():
    auth = org_auth()
    async with make_client(auth) as owner_c, make_client(auth) as admin_c:
        await sign_up(owner_c)
        admin = await sign_up(admin_c, email="a@x.com", name="Admin")
        org = (await _create_org(owner_c)).json()
        await _seed_member(auth, org["id"], admin["user"]["id"], "admin")
        res = await admin_c.post(
            "/api/auth/organization/delete", json={"organizationId": org["id"]}
        )
        assert res.status_code == 403
        assert res.json()["code"] == "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_ORGANIZATION"


async def test_delete_disabled_returns_not_found():
    async with make_client(org_auth(disable_organization_deletion=True)) as client:
        await sign_up(client)
        org = (await _create_org(client)).json()
        res = await client.post("/api/auth/organization/delete", json={"organizationId": org["id"]})
        assert res.status_code == 404
        assert res.json()["code"] == "ORGANIZATION_DELETION_DISABLED"


async def test_delete_hooks_fire():
    calls: list[str] = []
    hooks = {
        "before_delete_organization": lambda d: calls.append("before"),
        "after_delete_organization": lambda d: calls.append("after"),
    }
    async with make_client(org_auth(organization_hooks=hooks)) as client:
        await sign_up(client)
        org = (await _create_org(client)).json()
        await client.post("/api/auth/organization/delete", json={"organizationId": org["id"]})
        assert calls == ["before", "after"]


async def test_delete_hooks_receive_endpoint_context():
    """TS 3bf0e4981 (crud-org.ts:607-624) passes ``ctx`` as the hooks' second argument."""
    seen: dict[str, dict[str, bool]] = {}

    def _record(name: str, ctx: Any) -> None:
        seen[name] = {
            "has_ctx": ctx is not None,
            "has_request": getattr(ctx, "request", None) is not None,
        }

    async def before(data, ctx=None):
        _record("before", ctx)

    async def after(data, ctx=None):
        _record("after", ctx)

    hooks = {"before_delete_organization": before, "after_delete_organization": after}
    async with make_client(org_auth(organization_hooks=hooks)) as client:
        await sign_up(client)
        org = (await _create_org(client, slug="org-for-delete-ctx")).json()
        res = await client.post(
            "/api/auth/organization/delete", json={"organizationId": org["id"]}
        )
        assert res.status_code == 200, res.text
        assert seen["before"] == {"has_ctx": True, "has_request": True}
        assert seen["after"] == {"has_ctx": True, "has_request": True}


# --- get-full-organization --------------------------------------------------------


async def test_get_full_by_id_slug_and_active():
    async with make_client(org_auth()) as client:
        await sign_up(client)
        org = (await _create_org(client, slug="full")).json()

        by_active = (await client.get("/api/auth/organization/get-full-organization")).json()
        assert by_active["id"] == org["id"]
        assert len(by_active["members"]) == 1
        assert by_active["members"][0]["user"]["email"] == "ada@example.com"
        assert by_active["invitations"] == []

        by_id = await client.get(
            "/api/auth/organization/get-full-organization", params={"organizationId": org["id"]}
        )
        assert by_id.json()["id"] == org["id"]

        by_slug = await client.get(
            "/api/auth/organization/get-full-organization", params={"organizationSlug": "full"}
        )
        assert by_slug.json()["id"] == org["id"]


async def test_get_full_null_when_no_active_and_no_query():
    async with make_client(org_auth()) as client:
        await sign_up(client)  # no org created -> no active org
        res = await client.get("/api/auth/organization/get-full-organization")
        assert res.status_code == 200
        assert res.json() is None


async def test_get_full_non_member_forbidden():
    auth = org_auth()
    async with make_client(auth) as owner_c, make_client(auth) as other_c:
        await sign_up(owner_c)
        await sign_up(other_c, email="o@x.com", name="Other")
        org = (await _create_org(owner_c)).json()
        res = await other_c.get(
            "/api/auth/organization/get-full-organization", params={"organizationId": org["id"]}
        )
        assert res.status_code == 403
        assert res.json()["code"] == "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION"


async def test_get_full_not_found():
    async with make_client(org_auth()) as client:
        await sign_up(client)
        res = await client.get(
            "/api/auth/organization/get-full-organization", params={"organizationId": "nope"}
        )
        assert res.status_code == 400
        assert res.json()["code"] == "ORGANIZATION_NOT_FOUND"


async def test_get_full_members_limit():
    auth = org_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        org = (await _create_org(client)).json()
        for i in range(3):
            u = await auth.adapter.create("user", {"email": f"u{i}@x.com", "name": f"u{i}"})
            await _seed_member(auth, org["id"], u["id"], "member")
        full = (await client.get("/api/auth/organization/get-full-organization")).json()
        assert len(full["members"]) == 4
        limited = await client.get(
            "/api/auth/organization/get-full-organization", params={"membersLimit": 1}
        )
        assert len(limited.json()["members"]) == 1


# --- set-active -------------------------------------------------------------------


async def test_set_active_by_id_refreshes_cookie():
    async with make_client(org_auth()) as client:
        await sign_up(client)
        org = (await _create_org(client, keepCurrentActiveOrganization=True)).json()
        res = await client.post(
            "/api/auth/organization/set-active", json={"organizationId": org["id"]}
        )
        assert res.status_code == 200
        assert res.json()["id"] == org["id"]
        # cookie refresh: a session_token Set-Cookie is emitted (setSessionCookie parity)
        set_cookies = res.headers.get_list("set-cookie")
        assert any("session_token" in c for c in set_cookies)
        session = (await client.get("/api/auth/get-session")).json()
        assert session["session"]["activeOrganizationId"] == org["id"]


async def test_set_active_by_slug():
    async with make_client(org_auth()) as client:
        await sign_up(client)
        org = (await _create_org(client, slug="target", keepCurrentActiveOrganization=True)).json()
        res = await client.post(
            "/api/auth/organization/set-active", json={"organizationSlug": "target"}
        )
        assert res.status_code == 200
        session = (await client.get("/api/auth/get-session")).json()
        assert session["session"]["activeOrganizationId"] == org["id"]


async def test_set_active_null_unsets():
    async with make_client(org_auth()) as client:
        await sign_up(client)
        await _create_org(client)  # sets active
        res = await client.post("/api/auth/organization/set-active", json={"organizationId": None})
        assert res.status_code == 200
        assert res.json() is None
        session = (await client.get("/api/auth/get-session")).json()
        assert session["session"].get("activeOrganizationId") is None


async def test_set_active_non_member_forbidden():
    auth = org_auth()
    async with make_client(auth) as owner_c, make_client(auth) as other_c:
        await sign_up(owner_c)
        await sign_up(other_c, email="o@x.com", name="Other")
        org = (await _create_org(owner_c)).json()
        res = await other_c.post(
            "/api/auth/organization/set-active", json={"organizationId": org["id"]}
        )
        assert res.status_code == 403
        assert res.json()["code"] == "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION"


# --- list -------------------------------------------------------------------------


async def test_list_returns_user_orgs():
    async with make_client(org_auth()) as client:
        await sign_up(client)
        await _create_org(client, slug="a", keepCurrentActiveOrganization=True)
        await _create_org(client, name="B", slug="b", keepCurrentActiveOrganization=True)
        res = await client.get("/api/auth/organization/list")
        assert res.status_code == 200
        assert len(res.json()) == 2


# --- leave ------------------------------------------------------------------------


async def test_leave_organization_as_member():
    auth = org_auth()
    async with make_client(auth) as owner_c, make_client(auth) as member_c:
        await sign_up(owner_c)
        member = await sign_up(member_c, email="m@x.com", name="Mem")
        org = (await _create_org(owner_c)).json()
        await _seed_member(auth, org["id"], member["user"]["id"], "member")
        res = await member_c.post(
            "/api/auth/organization/leave", json={"organizationId": org["id"]}
        )
        assert res.status_code == 200
        assert res.json()["userId"] == member["user"]["id"]
        assert await auth.adapter.find_many("member", [Where("userId", member["user"]["id"])]) == []


async def test_sole_owner_cannot_leave():
    async with make_client(org_auth()) as client:
        await sign_up(client)
        org = (await _create_org(client)).json()
        res = await client.post("/api/auth/organization/leave", json={"organizationId": org["id"]})
        assert res.status_code == 400
        assert res.json()["code"] == "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER"


# --- list-members -----------------------------------------------------------------


async def test_list_members_membership_required():
    auth = org_auth()
    async with make_client(auth) as owner_c, make_client(auth) as other_c:
        await sign_up(owner_c)
        await sign_up(other_c, email="o@x.com", name="Other")
        org = (await _create_org(owner_c)).json()
        res = await other_c.get(
            "/api/auth/organization/list-members", params={"organizationId": org["id"]}
        )
        assert res.status_code == 403
        assert res.json()["code"] == "YOU_ARE_NOT_A_MEMBER_OF_THIS_ORGANIZATION"


async def test_list_members_pagination_and_total():
    auth = org_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        org = (await _create_org(client)).json()
        for i in range(4):
            u = await auth.adapter.create("user", {"email": f"lm{i}@x.com", "name": f"lm{i}"})
            await _seed_member(auth, org["id"], u["id"], "member")
        allm = (await client.get("/api/auth/organization/list-members")).json()
        assert allm["total"] == 5
        assert len(allm["members"]) == 5
        limited = await client.get("/api/auth/organization/list-members", params={"limit": 2})
        assert len(limited.json()["members"]) == 2
        assert limited.json()["total"] == 5
        offset = await client.get("/api/auth/organization/list-members", params={"offset": 3})
        assert len(offset.json()["members"]) == 2


async def test_list_members_above_adapter_default_limit_returns_every_user():
    """membershipLimit above the adapter's default find_many cap still joins every user.

    TS bae71988a (adapter.ts:222-234) bounds the user fetch by ``members.length``; the port
    resolves users with per-id ``find_one`` (``_users_by_ids``), which is unbounded by
    construction. Regression guard: the join must not be capped at
    ``default_find_many_limit`` (100). Mirrors crud-members.test.ts "listMembers with >100
    members".
    """
    auth = org_auth(membership_limit=500)
    async with make_client(auth) as client:
        await sign_up(client)
        org = (await _create_org(client)).json()
        for i in range(110):  # owner + 110 = 111 > the 100 default find_many limit
            u = await auth.adapter.create(
                "user", {"email": f"large-org-{i}@test.com", "name": f"large-org-{i}"}
            )
            await _seed_member(auth, org["id"], u["id"], "member")
        res = await client.get(
            "/api/auth/organization/list-members", params={"organizationId": org["id"]}
        )
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["total"] == 111
        assert len(body["members"]) == 111
        assert all(
            isinstance(m["user"]["id"], str) and isinstance(m["user"]["email"], str)
            for m in body["members"]
        )


# --- remove-member ----------------------------------------------------------------


async def test_remove_member_by_email_and_id():
    auth = org_auth()
    async with make_client(auth) as owner_c, make_client(auth) as m_c:
        await sign_up(owner_c)
        member = await sign_up(m_c, email="rm@x.com", name="Rm")
        org = (await _create_org(owner_c)).json()
        seeded = await _seed_member(auth, org["id"], member["user"]["id"], "member")
        res = await owner_c.post(
            "/api/auth/organization/remove-member",
            json={"organizationId": org["id"], "memberIdOrEmail": "rm@x.com"},
        )
        assert res.status_code == 200
        assert res.json()["member"]["id"] == seeded["id"]
        assert await auth.adapter.find_one("member", [Where("id", seeded["id"])]) is None


async def test_remove_member_forbidden_for_plain_member():
    auth = org_auth()
    async with make_client(auth) as owner_c, make_client(auth) as m_c:
        await sign_up(owner_c)
        member = await sign_up(m_c, email="rm@x.com", name="Rm")
        org = (await _create_org(owner_c)).json()
        await _seed_member(auth, org["id"], member["user"]["id"], "member")
        other = await auth.adapter.create("user", {"email": "victim@x.com", "name": "V"})
        victim = await _seed_member(auth, org["id"], other["id"], "member")
        res = await m_c.post(
            "/api/auth/organization/remove-member",
            json={"organizationId": org["id"], "memberIdOrEmail": victim["id"]},
        )
        assert res.status_code == 401
        assert res.json()["code"] == "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_MEMBER"


async def test_remove_last_owner_rejected():
    auth = org_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        org = (await _create_org(client)).json()
        owner_member = (await client.get("/api/auth/organization/get-active-member")).json()
        res = await client.post(
            "/api/auth/organization/remove-member",
            json={"organizationId": org["id"], "memberIdOrEmail": owner_member["id"]},
        )
        assert res.status_code == 400
        assert res.json()["code"] == "YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER"


# --- update-member-role -----------------------------------------------------------


async def test_owner_updates_member_role():
    auth = org_auth()
    async with make_client(auth) as owner_c, make_client(auth) as m_c:
        await sign_up(owner_c)
        member = await sign_up(m_c, email="mr@x.com", name="Mr")
        org = (await _create_org(owner_c)).json()
        seeded = await _seed_member(auth, org["id"], member["user"]["id"], "member")
        res = await owner_c.post(
            "/api/auth/organization/update-member-role",
            json={"organizationId": org["id"], "memberId": seeded["id"], "role": "admin"},
        )
        assert res.status_code == 200
        assert res.json()["role"] == "admin"


async def test_admin_cannot_demote_owner():
    auth = org_auth()
    async with make_client(auth) as owner_c, make_client(auth) as admin_c:
        await sign_up(owner_c)
        admin = await sign_up(admin_c, email="ad@x.com", name="Ad")
        org = (await _create_org(owner_c)).json()
        await _seed_member(auth, org["id"], admin["user"]["id"], "admin")
        owner_member = (await owner_c.get("/api/auth/organization/get-active-member")).json()
        res = await admin_c.post(
            "/api/auth/organization/update-member-role",
            json={"organizationId": org["id"], "memberId": owner_member["id"], "role": "admin"},
        )
        assert res.status_code == 403
        assert res.json()["code"] == "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_MEMBER"


async def test_admin_cannot_escalate_to_owner_via_comma_role():
    auth = org_auth()
    async with make_client(auth) as owner_c, make_client(auth) as admin_c:
        await sign_up(owner_c)
        admin = await sign_up(admin_c, email="ad@x.com", name="Ad")
        org = (await _create_org(owner_c)).json()
        seeded = await _seed_member(auth, org["id"], admin["user"]["id"], "admin")
        res = await admin_c.post(
            "/api/auth/organization/update-member-role",
            json={"organizationId": org["id"], "memberId": seeded["id"], "role": "admin,owner"},
        )
        assert res.status_code == 403
        persisted = await auth.adapter.find_one("member", [Where("id", seeded["id"])])
        assert persisted["role"] == "admin"


async def test_update_member_role_unknown_role_rejected():
    auth = org_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        u = await auth.adapter.create("user", {"email": "ur@x.com", "name": "Ur"})
        org = (await _create_org(client)).json()
        seeded = await _seed_member(auth, org["id"], u["id"], "member")
        res = await client.post(
            "/api/auth/organization/update-member-role",
            json={"organizationId": org["id"], "memberId": seeded["id"], "role": "superadmin"},
        )
        assert res.status_code == 400
        assert "ROLE_NOT_FOUND" in res.json()["message"]


async def test_update_member_role_empty_rejected():
    auth = org_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        u = await auth.adapter.create("user", {"email": "er@x.com", "name": "Er"})
        org = (await _create_org(client)).json()
        seeded = await _seed_member(auth, org["id"], u["id"], "member")
        for role in ([], ","):
            res = await client.post(
                "/api/auth/organization/update-member-role",
                json={"organizationId": org["id"], "memberId": seeded["id"], "role": role},
            )
            assert res.status_code == 400


async def test_last_owner_cannot_self_demote():
    auth = org_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        org = (await _create_org(client)).json()
        owner_member = (await client.get("/api/auth/organization/get-active-member")).json()
        res = await client.post(
            "/api/auth/organization/update-member-role",
            json={"organizationId": org["id"], "memberId": owner_member["id"], "role": "admin"},
        )
        assert res.status_code == 400
        assert res.json()["code"] == "YOU_CANNOT_LEAVE_THE_ORGANIZATION_WITHOUT_AN_OWNER"


# --- get-active-member ------------------------------------------------------------


async def test_get_active_member():
    async with make_client(org_auth()) as client:
        await sign_up(client)
        org = (await _create_org(client)).json()
        res = await client.get("/api/auth/organization/get-active-member")
        assert res.status_code == 200
        assert res.json()["role"] == "owner"
        assert res.json()["organizationId"] == org["id"]


async def test_get_active_member_no_active_org():
    async with make_client(org_auth()) as client:
        await sign_up(client)
        res = await client.get("/api/auth/organization/get-active-member")
        assert res.status_code == 400
        assert res.json()["code"] == "NO_ACTIVE_ORGANIZATION"


# --- has-permission ---------------------------------------------------------------


async def test_has_permission_and_shape():
    async with make_client(org_auth()) as client:
        await sign_up(client)
        await _create_org(client)  # owner
        res = await client.post(
            "/api/auth/organization/has-permission",
            json={"permissions": {"member": ["update"], "invitation": ["create"]}},
        )
        assert res.status_code == 200
        assert res.json() == {"error": None, "success": True}


async def test_has_permission_or_shape():
    auth = org_auth()
    async with make_client(auth) as owner_c, make_client(auth) as admin_c:
        await sign_up(owner_c)
        admin = await sign_up(admin_c, email="ad@x.com", name="Ad")
        org = (await _create_org(owner_c)).json()
        await _seed_member(auth, org["id"], admin["user"]["id"], "admin")
        # admin has organization:["update"] but not delete; OR connector -> success
        res = await admin_c.post(
            "/api/auth/organization/has-permission",
            json={
                "organizationId": org["id"],
                "permissions": {
                    "organization": {"actions": ["update", "delete"], "connector": "OR"}
                },
            },
        )
        assert res.json()["success"] is True


async def test_has_permission_denied_for_member():
    auth = org_auth()
    async with make_client(auth) as owner_c, make_client(auth) as m_c:
        await sign_up(owner_c)
        member = await sign_up(m_c, email="mm@x.com", name="Mm")
        org = (await _create_org(owner_c)).json()
        await _seed_member(auth, org["id"], member["user"]["id"], "member")
        res = await m_c.post(
            "/api/auth/organization/has-permission",
            json={"organizationId": org["id"], "permissions": {"organization": ["update"]}},
        )
        assert res.json()["success"] is False


async def test_has_permission_non_member_unauthorized():
    auth = org_auth()
    async with make_client(auth) as owner_c, make_client(auth) as other_c:
        await sign_up(owner_c)
        await sign_up(other_c, email="o@x.com", name="Other")
        org = (await _create_org(owner_c)).json()
        res = await other_c.post(
            "/api/auth/organization/has-permission",
            json={"organizationId": org["id"], "permissions": {"organization": ["update"]}},
        )
        assert res.status_code == 401
        assert res.json()["code"] == "USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION"


async def test_has_permission_no_active_org():
    async with make_client(org_auth()) as client:
        await sign_up(client)
        res = await client.post(
            "/api/auth/organization/has-permission",
            json={"permissions": {"organization": ["update"]}},
        )
        assert res.status_code == 400
        assert res.json()["code"] == "NO_ACTIVE_ORGANIZATION"


# --- error strings byte-exact -----------------------------------------------------


def test_error_codes_match_ts_exactly():
    assert ERROR_CODES["ORGANIZATION_ALREADY_EXISTS"] == "Organization already exists"
    assert ERROR_CODES["ORGANIZATION_SLUG_ALREADY_TAKEN"] == "Organization slug already taken"
    assert ERROR_CODES["ORGANIZATION_NOT_FOUND"] == "Organization not found"
    assert (
        ERROR_CODES["USER_IS_NOT_A_MEMBER_OF_THE_ORGANIZATION"]
        == "User is not a member of the organization"
    )
    assert ERROR_CODES["NO_ACTIVE_ORGANIZATION"] == "No active organization"
    assert ERROR_CODES["MEMBER_NOT_FOUND"] == "Member not found"
    assert ERROR_CODES["ROLE_NOT_FOUND"] == "Role not found"
    assert (
        ERROR_CODES["YOU_CANNOT_LEAVE_THE_ORGANIZATION_AS_THE_ONLY_OWNER"]
        == "You cannot leave the organization as the only owner"
    )


# ==================================================================================
# PHASE 2 — invitations (routes/crud-invites.ts, adapter.ts invitation methods)
# ==================================================================================


async def _invite(client, email, role="member", **body):
    return await client.post(
        "/api/auth/organization/invite-member", json={"email": email, "role": role, **body}
    )


async def _verify_email(auth, user_id: str) -> None:
    await auth.adapter.update("user", [Where("id", user_id)], {"emailVerified": True})


async def _seed_invitation(
    auth,
    org_id: str,
    email: str,
    inviter_id: str,
    *,
    role: str = "member",
    status: str = "pending",
    expires_in: int = 48 * 3600,
) -> dict[str, Any]:
    return await auth.adapter.create(
        "invitation",
        {
            "id": generate_id(),
            "organizationId": org_id,
            "email": email.lower(),
            "role": role,
            "status": status,
            "inviterId": inviter_id,
            "expiresAt": utcnow() + timedelta(seconds=expires_in),
            "createdAt": utcnow(),
        },
    )


async def _owner_with_org(auth, client, *, slug="acme"):
    owner = await sign_up(client)
    org = (await _create_org(client, slug=slug)).json()
    return owner, org


# --- invite-member ----------------------------------------------------------------


async def test_invite_member_creates_pending_invitation():
    auth = org_auth()
    async with make_client(auth) as client:
        owner, org = await _owner_with_org(auth, client)
        res = await _invite(client, "Bob@Example.com", role="member")
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["email"] == "bob@example.com"  # lowercased
        assert body["role"] == "member"
        assert body["status"] == "pending"
        assert body["organizationId"] == org["id"]
        assert body["inviterId"] == owner["user"]["id"]
        assert "id" in body and "expiresAt" in body
        row = await auth.adapter.find_one("invitation", [Where("id", body["id"])])
        assert row is not None and row["status"] == "pending"


async def test_invite_member_no_org_rejected():
    auth = org_auth()
    async with make_client(auth) as client:
        await sign_up(client)  # no org, no active org
        res = await _invite(client, "bob@example.com")
        assert res.status_code == 400
        assert res.json()["code"] == "ORGANIZATION_NOT_FOUND"


async def test_invite_member_invalid_email_rejected():
    auth = org_auth()
    async with make_client(auth) as client:
        await _owner_with_org(auth, client)
        res = await _invite(client, "not-an-email")
        assert res.status_code == 400
        assert res.json()["code"] == "INVALID_EMAIL"


async def test_invite_member_forbidden_for_plain_member():
    auth = org_auth()
    async with make_client(auth) as owner_c, make_client(auth) as member_c:
        _, org = await _owner_with_org(auth, owner_c)
        member = await sign_up(member_c, email="m@x.com", name="Mem")
        await _seed_member(auth, org["id"], member["user"]["id"], "member")
        res = await member_c.post(
            "/api/auth/organization/invite-member",
            json={"organizationId": org["id"], "email": "bob@example.com", "role": "member"},
        )
        assert res.status_code == 403
        assert res.json()["code"] == "YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION"


async def test_invite_member_non_member_rejected():
    auth = org_auth()
    async with make_client(auth) as owner_c, make_client(auth) as other_c:
        _, org = await _owner_with_org(auth, owner_c)
        await sign_up(other_c, email="o@x.com", name="Other")
        res = await other_c.post(
            "/api/auth/organization/invite-member",
            json={"organizationId": org["id"], "email": "bob@example.com", "role": "member"},
        )
        assert res.status_code == 400
        assert res.json()["code"] == "MEMBER_NOT_FOUND"


async def test_invite_member_unknown_role_rejected():
    auth = org_auth()
    async with make_client(auth) as client:
        await _owner_with_org(auth, client)
        res = await _invite(client, "bob@example.com", role="superadmin")
        assert res.status_code == 400
        assert res.json()["message"] == "Role not found: superadmin"


async def test_admin_cannot_invite_owner_role():
    auth = org_auth()
    async with make_client(auth) as owner_c, make_client(auth) as admin_c:
        _, org = await _owner_with_org(auth, owner_c)
        admin = await sign_up(admin_c, email="ad@x.com", name="Ad")
        await _seed_member(auth, org["id"], admin["user"]["id"], "admin")
        res = await admin_c.post(
            "/api/auth/organization/invite-member",
            json={"organizationId": org["id"], "email": "bob@example.com", "role": "owner"},
        )
        assert res.status_code == 403
        assert res.json()["code"] == "YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE"


async def test_invite_member_already_member_rejected():
    auth = org_auth()
    async with make_client(auth) as owner_c, make_client(auth) as m_c:
        _, org = await _owner_with_org(auth, owner_c)
        member = await sign_up(m_c, email="already@x.com", name="Al")
        await _seed_member(auth, org["id"], member["user"]["id"], "member")
        res = await _invite(owner_c, "already@x.com")
        assert res.status_code == 400
        assert res.json()["code"] == "USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION"


async def test_invite_member_id_is_generated_by_the_adapter():
    """TS f59a0ee78 (adapter.ts:1042-1049) drops the app-generated invitation id.

    With ``generate_id="uuid"`` the invitation row must get a UUID like every other model,
    instead of the plugin's own opaque id.
    """
    auth = make_auth(
        adapter=MemoryAdapter(AdvancedDatabase(generate_id="uuid")),
        plugins=[OrganizationPlugin()],
    )
    async with make_client(auth) as client:
        await _owner_with_org(auth, client)
        invitation = (await _invite(client, "bob@example.com")).json()
        assert uuid.UUID(invitation["id"]).version == 4


async def test_invite_member_honors_caller_provided_id():
    """A ``before_create_invitation`` id override still wins (TS changeset)."""
    hooks = {
        "before_create_invitation": lambda d: {"data": {"id": "caller-supplied-invitation-id"}}
    }
    auth = org_auth(organization_hooks=hooks)
    async with make_client(auth) as client:
        await _owner_with_org(auth, client)
        invitation = (await _invite(client, "bob@example.com")).json()
        assert invitation["id"] == "caller-supplied-invitation-id"


def _uuid4(value: Any) -> bool:
    try:
        return uuid.UUID(str(value)).version == 4
    except (ValueError, AttributeError, TypeError):
        return False


async def test_create_row_ids_are_generated_by_the_adapter():
    """Every org model defers ``id`` to the adapter, like TS adapter.ts (f59a0ee78).

    TS passes no explicit id on create for organization (:86-105, ``forceAllowId``),
    member (:323-338, ``Omit<MemberInput, "id">``), team (:658-665, ``forceAllowId``) or
    teamMember (:917-925, ``Omit<TeamMember, "id">``). With ``generate_id="uuid"`` every
    row must therefore carry a UUID.
    """
    auth = make_auth(
        adapter=MemoryAdapter(AdvancedDatabase(generate_id="uuid")),
        plugins=[OrganizationPlugin(teams={"enabled": True})],
    )
    async with make_client(auth) as client:
        await sign_up(client)
        org = (await _create_org(client)).json()  # also makes the owner member + default team
        member = (await auth.adapter.find_many("member", [Where("organizationId", org["id"])]))[0]
        team = (await auth.adapter.find_many("team", [Where("organizationId", org["id"])]))[0]
        team_member = (await auth.adapter.find_many("teamMember", [Where("teamId", team["id"])]))[0]
        # one dict so a failure names every offending model at once
        assert {
            "organization": _uuid4(org["id"]),
            "member": _uuid4(member["id"]),
            "team": _uuid4(team["id"]),
            "teamMember": _uuid4(team_member["id"]),
        } == {"organization": True, "member": True, "team": True, "teamMember": True}


async def test_create_honors_hook_supplied_organization_and_team_ids():
    """TS keeps ``forceAllowId: true`` on organization/team create, so a
    ``before_create_*`` hook id still wins (adapter.ts:104, :663)."""
    hooks = {
        "before_create_organization": lambda d: {"data": {"id": "hook-org-id"}},
        "before_create_team": lambda d: {"data": {"id": "hook-team-id"}},
    }
    auth = org_auth(teams={"enabled": True}, organization_hooks=hooks)
    async with make_client(auth) as client:
        await sign_up(client)
        org = (await _create_org(client)).json()
        assert org["id"] == "hook-org-id"
        team = (await auth.adapter.find_many("team", [Where("organizationId", org["id"])]))[0]
        assert team["id"] == "hook-team-id"


async def test_invite_member_duplicate_pending_rejected():
    auth = org_auth()
    async with make_client(auth) as client:
        await _owner_with_org(auth, client)
        assert (await _invite(client, "bob@example.com")).status_code == 200
        res = await _invite(client, "bob@example.com")
        assert res.status_code == 400
        assert res.json()["code"] == "USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION"


async def test_invite_member_resend_reuses_invitation_and_resends_email():
    sent: list[dict[str, Any]] = []

    async def send(data, request=None):
        sent.append(data)

    auth = org_auth(send_invitation_email=send)
    async with make_client(auth) as client:
        await _owner_with_org(auth, client)
        first = (await _invite(client, "bob@example.com")).json()
        res = await _invite(client, "bob@example.com", resend=True)
        assert res.status_code == 200
        assert res.json()["id"] == first["id"]  # same invitation reused
        assert len(sent) == 2  # sent on create and on resend
        rows = await auth.adapter.find_many("invitation", [Where("email", "bob@example.com")])
        assert len(rows) == 1  # no duplicate row


async def test_invite_member_cancel_pending_on_reinvite():
    auth = org_auth(cancel_pending_invitations_on_re_invite=True)
    async with make_client(auth) as client:
        await _owner_with_org(auth, client)
        first = (await _invite(client, "bob@example.com")).json()
        second = (await _invite(client, "bob@example.com")).json()
        assert second["id"] != first["id"]
        old = await auth.adapter.find_one("invitation", [Where("id", first["id"])])
        new = await auth.adapter.find_one("invitation", [Where("id", second["id"])])
        assert old["status"] == "canceled"
        assert new["status"] == "pending"


async def test_invitation_limit_reached():
    auth = org_auth(invitation_limit=1)
    async with make_client(auth) as client:
        await _owner_with_org(auth, client)
        assert (await _invite(client, "a@x.com")).status_code == 200
        res = await _invite(client, "b@x.com")
        assert res.status_code == 403
        assert res.json()["code"] == "INVITATION_LIMIT_REACHED"


async def test_send_invitation_email_payload_shape():
    captured: list[Any] = []

    async def send(data, request=None):
        captured.append((data, request))

    auth = org_auth(send_invitation_email=send)
    async with make_client(auth) as client:
        owner, org = await _owner_with_org(auth, client)
        inv = (await _invite(client, "bob@example.com", role="admin")).json()
        assert len(captured) == 1
        data, request = captured[0]
        assert data["id"] == inv["id"]
        assert data["role"] == "admin"
        assert data["email"] == "bob@example.com"
        assert data["organization"]["id"] == org["id"]
        assert data["invitation"]["id"] == inv["id"]
        assert data["inviter"]["user"]["id"] == owner["user"]["id"]
        assert data["inviter"]["role"] == "owner"
        assert request is not None


async def test_before_create_invitation_hook_merges_data():
    async def before(data):
        assert data["invitation"]["email"] == "bob@example.com"
        assert data["invitation"]["inviterId"]
        return {"data": {"role": "admin"}}

    auth = org_auth(organization_hooks={"before_create_invitation": before})
    async with make_client(auth) as client:
        await _owner_with_org(auth, client)
        res = await _invite(client, "bob@example.com", role="member")
        assert res.status_code == 200
        assert res.json()["role"] == "admin"


async def test_after_create_invitation_hook_fires():
    calls: list[str] = []

    async def after(data):
        calls.append(data["invitation"]["id"])

    auth = org_auth(organization_hooks={"after_create_invitation": after})
    async with make_client(auth) as client:
        await _owner_with_org(auth, client)
        inv = (await _invite(client, "bob@example.com")).json()
        assert calls == [inv["id"]]


# --- accept-invitation ------------------------------------------------------------


async def test_accept_invitation_full_flow():
    auth = org_auth()
    async with make_client(auth) as owner_c, make_client(auth) as invitee_c:
        _, org = await _owner_with_org(auth, owner_c)
        inv = (await _invite(owner_c, "bob@example.com", role="admin")).json()
        bob = await sign_up(invitee_c, email="bob@example.com", name="Bob")
        res = await invitee_c.post(
            "/api/auth/organization/accept-invitation", json={"invitationId": inv["id"]}
        )
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["invitation"]["status"] == "accepted"
        assert body["member"]["role"] == "admin"
        assert body["member"]["userId"] == bob["user"]["id"]
        assert body["member"]["organizationId"] == org["id"]
        # active org set for the invitee
        session = (await invitee_c.get("/api/auth/get-session")).json()
        assert session["session"]["activeOrganizationId"] == org["id"]


async def test_accept_invitation_wrong_recipient():
    auth = org_auth()
    async with make_client(auth) as owner_c, make_client(auth) as carol_c:
        _, _org = await _owner_with_org(auth, owner_c)
        inv = (await _invite(owner_c, "bob@example.com")).json()
        await sign_up(carol_c, email="carol@example.com", name="Carol")
        res = await carol_c.post(
            "/api/auth/organization/accept-invitation", json={"invitationId": inv["id"]}
        )
        assert res.status_code == 403
        assert res.json()["code"] == "YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION"


async def test_accept_invitation_expired():
    auth = org_auth()
    async with make_client(auth) as owner_c, make_client(auth) as invitee_c:
        owner, org = await _owner_with_org(auth, owner_c)
        inv = await _seed_invitation(
            auth, org["id"], "bob@example.com", owner["user"]["id"], expires_in=-10
        )
        await sign_up(invitee_c, email="bob@example.com", name="Bob")
        res = await invitee_c.post(
            "/api/auth/organization/accept-invitation", json={"invitationId": inv["id"]}
        )
        assert res.status_code == 400
        assert res.json()["code"] == "INVITATION_NOT_FOUND"


async def test_accept_invitation_membership_limit_reached():
    auth = org_auth(membership_limit=1)
    async with make_client(auth) as owner_c, make_client(auth) as invitee_c:
        owner, org = await _owner_with_org(auth, owner_c)
        inv = await _seed_invitation(auth, org["id"], "bob@example.com", owner["user"]["id"])
        await sign_up(invitee_c, email="bob@example.com", name="Bob")
        res = await invitee_c.post(
            "/api/auth/organization/accept-invitation", json={"invitationId": inv["id"]}
        )
        assert res.status_code == 403
        assert res.json()["code"] == "ORGANIZATION_MEMBERSHIP_LIMIT_REACHED"


async def test_accept_invitation_requires_verified_email_when_configured():
    auth = org_auth(require_email_verification_on_invitation=True)
    async with make_client(auth) as owner_c, make_client(auth) as invitee_c:
        owner, org = await _owner_with_org(auth, owner_c)
        inv = await _seed_invitation(auth, org["id"], "bob@example.com", owner["user"]["id"])
        await sign_up(invitee_c, email="bob@example.com", name="Bob")  # emailVerified False
        res = await invitee_c.post(
            "/api/auth/organization/accept-invitation", json={"invitationId": inv["id"]}
        )
        assert res.status_code == 403
        assert (
            res.json()["code"]
            == "EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION"
        )


async def test_accept_invitation_hooks_fire():
    before: list[str] = []
    after: list[str] = []

    async def before_hook(data):
        before.append(data["invitation"]["id"])

    async def after_hook(data):
        after.append(data["member"]["id"])

    auth = org_auth(
        organization_hooks={
            "before_accept_invitation": before_hook,
            "after_accept_invitation": after_hook,
        }
    )
    async with make_client(auth) as owner_c, make_client(auth) as invitee_c:
        _, _org = await _owner_with_org(auth, owner_c)
        inv = (await _invite(owner_c, "bob@example.com")).json()
        await sign_up(invitee_c, email="bob@example.com", name="Bob")
        res = await invitee_c.post(
            "/api/auth/organization/accept-invitation", json={"invitationId": inv["id"]}
        )
        assert res.status_code == 200
        assert before == [inv["id"]]
        assert len(after) == 1


# --- reject-invitation ------------------------------------------------------------


async def test_reject_invitation():
    calls: list[str] = []
    auth = org_auth(
        organization_hooks={
            "before_reject_invitation": lambda d: calls.append("before"),
            "after_reject_invitation": lambda d: calls.append("after"),
        }
    )
    async with make_client(auth) as owner_c, make_client(auth) as invitee_c:
        _, _org = await _owner_with_org(auth, owner_c)
        inv = (await _invite(owner_c, "bob@example.com")).json()
        await sign_up(invitee_c, email="bob@example.com", name="Bob")
        res = await invitee_c.post(
            "/api/auth/organization/reject-invitation", json={"invitationId": inv["id"]}
        )
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["invitation"]["status"] == "rejected"
        assert body["member"] is None
        assert calls == ["before", "after"]


async def test_reject_invitation_wrong_recipient():
    auth = org_auth()
    async with make_client(auth) as owner_c, make_client(auth) as carol_c:
        _, _org = await _owner_with_org(auth, owner_c)
        inv = (await _invite(owner_c, "bob@example.com")).json()
        await sign_up(carol_c, email="carol@example.com", name="Carol")
        res = await carol_c.post(
            "/api/auth/organization/reject-invitation", json={"invitationId": inv["id"]}
        )
        assert res.status_code == 403
        assert res.json()["code"] == "YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION"


async def test_reject_invitation_not_found():
    auth = org_auth()
    async with make_client(auth) as client:
        await _owner_with_org(auth, client)
        res = await client.post(
            "/api/auth/organization/reject-invitation", json={"invitationId": "nope"}
        )
        assert res.status_code == 400
        assert res.json()["code"] == "INVITATION_NOT_FOUND"
        assert res.json()["message"] == "Invitation not found!"


# --- cancel-invitation ------------------------------------------------------------


async def test_cancel_invitation_by_owner():
    calls: list[str] = []
    auth = org_auth(
        organization_hooks={
            "before_cancel_invitation": lambda d: calls.append(d["cancelledBy"]["id"]),
            "after_cancel_invitation": lambda d: calls.append("after"),
        }
    )
    async with make_client(auth) as client:
        owner, _ = await _owner_with_org(auth, client)
        inv = (await _invite(client, "bob@example.com")).json()
        res = await client.post(
            "/api/auth/organization/cancel-invitation", json={"invitationId": inv["id"]}
        )
        assert res.status_code == 200, res.text
        assert res.json()["status"] == "canceled"
        assert calls == [owner["user"]["id"], "after"]


async def test_cancel_invitation_forbidden_for_plain_member():
    auth = org_auth()
    async with make_client(auth) as owner_c, make_client(auth) as member_c:
        _, org = await _owner_with_org(auth, owner_c)
        member = await sign_up(member_c, email="m@x.com", name="Mem")
        await _seed_member(auth, org["id"], member["user"]["id"], "member")
        inv = (await _invite(owner_c, "bob@example.com")).json()
        res = await member_c.post(
            "/api/auth/organization/cancel-invitation", json={"invitationId": inv["id"]}
        )
        assert res.status_code == 403
        assert res.json()["code"] == "YOU_ARE_NOT_ALLOWED_TO_CANCEL_THIS_INVITATION"


async def test_cancel_invitation_not_found():
    auth = org_auth()
    async with make_client(auth) as client:
        await _owner_with_org(auth, client)
        res = await client.post(
            "/api/auth/organization/cancel-invitation", json={"invitationId": "nope"}
        )
        assert res.status_code == 400
        assert res.json()["code"] == "INVITATION_NOT_FOUND"


# --- get-invitation ---------------------------------------------------------------


async def test_get_invitation():
    auth = org_auth()
    async with make_client(auth) as owner_c, make_client(auth) as invitee_c:
        owner, org = await _owner_with_org(auth, owner_c, slug="glob")
        inv = (await _invite(owner_c, "bob@example.com", role="admin")).json()
        await sign_up(invitee_c, email="bob@example.com", name="Bob")
        res = await invitee_c.get("/api/auth/organization/get-invitation", params={"id": inv["id"]})
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["id"] == inv["id"]
        assert body["organizationName"] == org["name"]
        assert body["organizationSlug"] == "glob"
        assert body["inviterEmail"] == owner["user"]["email"]


async def test_get_invitation_wrong_recipient():
    auth = org_auth()
    async with make_client(auth) as owner_c, make_client(auth) as carol_c:
        _, _org = await _owner_with_org(auth, owner_c)
        inv = (await _invite(owner_c, "bob@example.com")).json()
        await sign_up(carol_c, email="carol@example.com", name="Carol")
        res = await carol_c.get("/api/auth/organization/get-invitation", params={"id": inv["id"]})
        assert res.status_code == 403
        assert res.json()["code"] == "YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION"


async def test_get_invitation_expired_not_found():
    auth = org_auth()
    async with make_client(auth) as owner_c, make_client(auth) as invitee_c:
        owner, org = await _owner_with_org(auth, owner_c)
        inv = await _seed_invitation(
            auth, org["id"], "bob@example.com", owner["user"]["id"], expires_in=-10
        )
        await sign_up(invitee_c, email="bob@example.com", name="Bob")
        res = await invitee_c.get("/api/auth/organization/get-invitation", params={"id": inv["id"]})
        assert res.status_code == 400
        assert res.json()["message"] == "Invitation not found!"


async def test_get_invitation_inviter_no_longer_member():
    auth = org_auth()
    async with make_client(auth) as owner_c, make_client(auth) as invitee_c:
        _, org = await _owner_with_org(auth, owner_c)
        # inviter id that is not a member of the org
        inv = await _seed_invitation(auth, org["id"], "bob@example.com", "ghost-user")
        await sign_up(invitee_c, email="bob@example.com", name="Bob")
        res = await invitee_c.get("/api/auth/organization/get-invitation", params={"id": inv["id"]})
        assert res.status_code == 400
        assert res.json()["code"] == "INVITER_IS_NO_LONGER_A_MEMBER_OF_THE_ORGANIZATION"


# --- list-invitations (org scoped) ------------------------------------------------


async def test_list_invitations_org_scoped():
    auth = org_auth()
    async with make_client(auth) as client:
        _, _org = await _owner_with_org(auth, client)
        await _invite(client, "bob@example.com")
        await _invite(client, "carol@example.com")
        res = await client.get("/api/auth/organization/list-invitations")
        assert res.status_code == 200, res.text
        emails = {i["email"] for i in res.json()}
        assert emails == {"bob@example.com", "carol@example.com"}


async def test_list_invitations_non_member_forbidden():
    auth = org_auth()
    async with make_client(auth) as owner_c, make_client(auth) as other_c:
        _, org = await _owner_with_org(auth, owner_c)
        await sign_up(other_c, email="o@x.com", name="Other")
        res = await other_c.get(
            "/api/auth/organization/list-invitations", params={"organizationId": org["id"]}
        )
        assert res.status_code == 403
        assert res.json()["message"] == "You are not a member of this organization"


async def test_list_invitations_no_org_rejected():
    auth = org_auth()
    async with make_client(auth) as client:
        await sign_up(client)  # no active org
        res = await client.get("/api/auth/organization/list-invitations")
        assert res.status_code == 400


# --- list-user-invitations (session-email scoped) ---------------------------------


async def test_list_user_invitations_pending_only():
    auth = org_auth()
    async with make_client(auth) as owner_c, make_client(auth) as invitee_c:
        owner, org = await _owner_with_org(auth, owner_c)
        await _invite(owner_c, "bob@example.com")
        # a non-pending invitation for the same email must be filtered out
        await _seed_invitation(
            auth, org["id"], "bob@example.com", owner["user"]["id"], status="rejected"
        )
        bob = await sign_up(invitee_c, email="bob@example.com", name="Bob")
        await _verify_email(auth, bob["user"]["id"])
        res = await invitee_c.get("/api/auth/organization/list-user-invitations")
        assert res.status_code == 200, res.text
        body = res.json()
        assert len(body) == 1
        assert body[0]["status"] == "pending"
        assert body[0]["organizationName"] == org["name"]


async def test_list_user_invitations_requires_verified_email():
    auth = org_auth()
    async with make_client(auth) as owner_c, make_client(auth) as invitee_c:
        await _owner_with_org(auth, owner_c)
        await _invite(owner_c, "bob@example.com")
        await sign_up(invitee_c, email="bob@example.com", name="Bob")  # unverified
        res = await invitee_c.get("/api/auth/organization/list-user-invitations")
        assert res.status_code == 403
        assert res.json()["code"] == "EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION"


async def test_list_user_invitations_email_query_rejected():
    auth = org_auth()
    async with make_client(auth) as client:
        user = await sign_up(client)
        await _verify_email(auth, user["user"]["id"])
        res = await client.get(
            "/api/auth/organization/list-user-invitations", params={"email": "x@y.com"}
        )
        assert res.status_code == 400
        assert res.json()["message"] == "User email cannot be passed for client side API calls."


# --- full-org invitations population + delete cascade -----------------------------


async def test_full_organization_includes_invitations():
    auth = org_auth()
    async with make_client(auth) as client:
        _, _org = await _owner_with_org(auth, client)
        await _invite(client, "bob@example.com")
        full = (await client.get("/api/auth/organization/get-full-organization")).json()
        assert len(full["invitations"]) == 1
        assert full["invitations"][0]["email"] == "bob@example.com"


async def test_delete_org_cascades_invitations():
    auth = org_auth()
    async with make_client(auth) as client:
        _, org = await _owner_with_org(auth, client)
        await _invite(client, "bob@example.com")
        await client.post("/api/auth/organization/delete", json={"organizationId": org["id"]})
        assert (
            await auth.adapter.find_many("invitation", [Where("organizationId", org["id"])]) == []
        )


# --- invitation error strings byte-exact ------------------------------------------


def test_invitation_error_codes_match_ts_exactly():
    assert ERROR_CODES["INVITATION_NOT_FOUND"] == "Invitation not found"
    assert (
        ERROR_CODES["YOU_ARE_NOT_THE_RECIPIENT_OF_THE_INVITATION"]
        == "You are not the recipient of the invitation"
    )
    assert (
        ERROR_CODES["INVITER_IS_NO_LONGER_A_MEMBER_OF_THE_ORGANIZATION"]
        == "Inviter is no longer a member of the organization"
    )
    assert (
        ERROR_CODES["ORGANIZATION_MEMBERSHIP_LIMIT_REACHED"]
        == "Organization membership limit reached"
    )
    assert ERROR_CODES["INVITATION_LIMIT_REACHED"] == "Invitation limit reached"
    assert (
        ERROR_CODES["USER_IS_ALREADY_INVITED_TO_THIS_ORGANIZATION"]
        == "User is already invited to this organization"
    )
    assert (
        ERROR_CODES["USER_IS_ALREADY_A_MEMBER_OF_THIS_ORGANIZATION"]
        == "User is already a member of this organization"
    )
    assert (
        ERROR_CODES["YOU_ARE_NOT_ALLOWED_TO_INVITE_USERS_TO_THIS_ORGANIZATION"]
        == "You are not allowed to invite users to this organization"
    )
    assert (
        ERROR_CODES["YOU_ARE_NOT_ALLOWED_TO_INVITE_USER_WITH_THIS_ROLE"]
        == "You are not allowed to invite a user with this role"
    )
    assert (
        ERROR_CODES["YOU_ARE_NOT_ALLOWED_TO_CANCEL_THIS_INVITATION"]
        == "You are not allowed to cancel this invitation"
    )
    assert (
        ERROR_CODES["EMAIL_VERIFICATION_REQUIRED_BEFORE_ACCEPTING_OR_REJECTING_INVITATION"]
        == "Email verification required before accepting or rejecting invitation"
    )
    assert (
        ERROR_CODES["EMAIL_VERIFICATION_REQUIRED_FOR_INVITATION"]
        == "Email verification required to view or list invitations for the session email"
    )


# ==================================================================================
# PHASE 3 — teams (routes/crud-team.ts, adapter.ts team methods, crud-invites team
# branches, crud-org default-team, organization.ts team schema/wiring, types.ts hooks)
# ==================================================================================


def _teams_auth(*, default_team=True, **teams):
    """org auth with teams enabled; default_team=False disables the org-create default team."""
    cfg: dict[str, Any] = {"enabled": True, **teams}
    if default_team is False:
        cfg["default_team"] = {"enabled": False}
    return org_auth(teams=cfg)


async def _create_team(client, name="Eng", **body):
    return await client.post("/api/auth/organization/create-team", json={"name": name, **body})


# --- teams disabled: no leakage into core ------------------------------------------


def test_teams_disabled_no_schema_addition():
    auth = org_auth()  # teams not configured
    assert "team" not in auth.schema
    assert "teamMember" not in auth.schema
    assert "activeTeamId" not in auth.schema["session"]
    assert "teamId" not in auth.schema["invitation"]


def test_teams_enabled_adds_schema():
    auth = org_auth(teams={"enabled": True})
    assert "team" in auth.schema
    assert "teamMember" in auth.schema
    assert "activeTeamId" in auth.schema["session"]
    assert auth.schema["session"]["activeTeamId"].input is False
    assert "teamId" in auth.schema["invitation"]


async def test_teams_disabled_endpoints_absent():
    auth = org_auth()
    async with make_client(auth) as client:
        await _owner_with_org(auth, client)
        for path in (
            "create-team",
            "remove-team",
            "update-team",
            "set-active-team",
            "add-team-member",
            "remove-team-member",
        ):
            res = await client.post(f"/api/auth/organization/{path}", json={})
            assert res.status_code == 404, f"{path} -> {res.status_code}"
        for path in ("list-teams", "list-user-teams", "list-team-members"):
            res = await client.get(f"/api/auth/organization/{path}")
            assert res.status_code == 404, f"{path} -> {res.status_code}"


# --- default team on org create ----------------------------------------------------


async def test_default_team_created_on_org_create():
    auth = _teams_auth()
    async with make_client(auth) as client:
        owner = await sign_up(client)
        org = (await _create_org(client)).json()
        teams = await auth.adapter.find_many("team", [Where("organizationId", org["id"])])
        assert len(teams) == 1
        assert teams[0]["name"] == "Acme"
        tms = await auth.adapter.find_many("teamMember", [Where("teamId", teams[0]["id"])])
        assert len(tms) == 1 and tms[0]["userId"] == owner["user"]["id"]
        session = (await client.get("/api/auth/get-session")).json()
        assert session["session"]["activeTeamId"] == teams[0]["id"]


async def test_default_team_disabled():
    auth = _teams_auth(default_team=False)
    async with make_client(auth) as client:
        await sign_up(client)
        org = (await _create_org(client)).json()
        teams = await auth.adapter.find_many("team", [Where("organizationId", org["id"])])
        assert teams == []
        session = (await client.get("/api/auth/get-session")).json()
        assert not session["session"].get("activeTeamId")


# --- create-team -------------------------------------------------------------------


async def test_create_team():
    auth = _teams_auth(default_team=False)
    async with make_client(auth) as client:
        await _owner_with_org(auth, client)
        res = await _create_team(client, "Eng")
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["name"] == "Eng"
        assert "id" in body and body["organizationId"]
        assert "createdAt" in body and "updatedAt" in body
        row = await auth.adapter.find_one("team", [Where("id", body["id"])])
        assert row is not None


async def test_create_team_forbidden_for_member():
    auth = _teams_auth(default_team=False)
    async with make_client(auth) as owner_c, make_client(auth) as member_c:
        _, org = await _owner_with_org(auth, owner_c)
        member = await sign_up(member_c, email="m@x.com", name="Mem")
        await _seed_member(auth, org["id"], member["user"]["id"], "member")
        res = await _create_team(member_c, "Eng", organizationId=org["id"])
        assert res.status_code == 403
        assert res.json()["code"] == "YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION"


async def test_create_team_maximum_teams_number():
    auth = _teams_auth(default_team=False, maximum_teams=1)
    async with make_client(auth) as client:
        await _owner_with_org(auth, client)
        assert (await _create_team(client, "A")).status_code == 200
        res = await _create_team(client, "B")
        assert res.status_code == 400
        assert res.json()["code"] == "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS"


async def test_create_team_maximum_teams_fn():
    seen: list[Any] = []

    async def maximum(data, ctx=None):
        seen.append(data["organizationId"])
        return 1

    auth = _teams_auth(default_team=False, maximum_teams=maximum)
    async with make_client(auth) as client:
        await _owner_with_org(auth, client)
        assert (await _create_team(client, "A")).status_code == 200
        res = await _create_team(client, "B")
        assert res.status_code == 400
        assert res.json()["code"] == "YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS"
        assert seen  # the function was consulted


async def test_create_team_no_active_org_rejected():
    auth = _teams_auth(default_team=False)
    async with make_client(auth) as client:
        await sign_up(client)  # no org, no active org
        res = await _create_team(client, "A")
        assert res.status_code == 400
        assert res.json()["code"] == "NO_ACTIVE_ORGANIZATION"


# --- update-team -------------------------------------------------------------------


async def test_update_team():
    auth = _teams_auth(default_team=False)
    async with make_client(auth) as client:
        await _owner_with_org(auth, client)
        team = (await _create_team(client, "Eng")).json()
        res = await client.post(
            "/api/auth/organization/update-team",
            json={"teamId": team["id"], "data": {"name": "Engineering"}},
        )
        assert res.status_code == 200, res.text
        assert res.json()["name"] == "Engineering"


async def test_update_team_not_found():
    auth = _teams_auth(default_team=False)
    async with make_client(auth) as client:
        await _owner_with_org(auth, client)
        await _create_team(client, "Eng")
        res = await client.post(
            "/api/auth/organization/update-team",
            json={"teamId": "nope", "data": {"name": "X"}},
        )
        assert res.status_code == 400
        assert res.json()["code"] == "TEAM_NOT_FOUND"


async def test_update_team_forbidden_for_member():
    auth = _teams_auth(default_team=False)
    async with make_client(auth) as owner_c, make_client(auth) as member_c:
        _, org = await _owner_with_org(auth, owner_c)
        team = (await _create_team(owner_c, "Eng")).json()
        member = await sign_up(member_c, email="m@x.com", name="Mem")
        await _seed_member(auth, org["id"], member["user"]["id"], "member")
        res = await member_c.post(
            "/api/auth/organization/update-team",
            json={"teamId": team["id"], "data": {"name": "X", "organizationId": org["id"]}},
        )
        assert res.status_code == 403
        assert res.json()["code"] == "YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_TEAM"


# --- remove-team -------------------------------------------------------------------


async def test_remove_team():
    auth = _teams_auth(default_team=False)
    async with make_client(auth) as client:
        await _owner_with_org(auth, client)
        t1 = (await _create_team(client, "A")).json()
        await _create_team(client, "B")  # 2nd team so last-team guard doesn't fire
        res = await client.post("/api/auth/organization/remove-team", json={"teamId": t1["id"]})
        assert res.status_code == 200, res.text
        assert res.json()["message"] == "Team removed successfully."
        assert await auth.adapter.find_many("team", [Where("id", t1["id"])]) == []


async def test_remove_last_team_guard():
    auth = _teams_auth(default_team=False)
    async with make_client(auth) as client:
        await _owner_with_org(auth, client)
        t = (await _create_team(client, "A")).json()
        res = await client.post("/api/auth/organization/remove-team", json={"teamId": t["id"]})
        assert res.status_code == 400
        assert res.json()["code"] == "UNABLE_TO_REMOVE_LAST_TEAM"


async def test_remove_last_team_allowed_when_configured():
    auth = _teams_auth(default_team=False, allow_removing_all_teams=True)
    async with make_client(auth) as client:
        await _owner_with_org(auth, client)
        t = (await _create_team(client, "A")).json()
        res = await client.post("/api/auth/organization/remove-team", json={"teamId": t["id"]})
        assert res.status_code == 200, res.text
        assert await auth.adapter.find_many("team", []) == []


async def test_remove_active_team_forbidden():
    auth = _teams_auth()  # default team is created and set active
    async with make_client(auth) as client:
        await sign_up(client)
        await _create_org(client)
        session = (await client.get("/api/auth/get-session")).json()
        active_team = session["session"]["activeTeamId"]
        res = await client.post("/api/auth/organization/remove-team", json={"teamId": active_team})
        assert res.status_code == 403
        assert res.json()["code"] == "YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_TEAM"


async def test_remove_team_hooks_fire():
    calls: list[str] = []
    auth = org_auth(
        teams={"enabled": True, "default_team": {"enabled": False}},
        organization_hooks={
            "before_delete_team": lambda d: calls.append("before"),
            "after_delete_team": lambda d: calls.append("after"),
        },
    )
    async with make_client(auth) as client:
        await _owner_with_org(auth, client)
        t1 = (await _create_team(client, "A")).json()
        await _create_team(client, "B")
        res = await client.post("/api/auth/organization/remove-team", json={"teamId": t1["id"]})
        assert res.status_code == 200, res.text
        assert calls == ["before", "after"]


# --- list-teams --------------------------------------------------------------------


async def test_list_teams():
    auth = _teams_auth(default_team=False)
    async with make_client(auth) as client:
        await _owner_with_org(auth, client)
        await _create_team(client, "A")
        await _create_team(client, "B")
        res = await client.get("/api/auth/organization/list-teams")
        assert res.status_code == 200, res.text
        assert len(res.json()) == 2


async def test_list_teams_non_member_forbidden():
    auth = _teams_auth(default_team=False)
    async with make_client(auth) as owner_c, make_client(auth) as other_c:
        _, org = await _owner_with_org(auth, owner_c)
        await sign_up(other_c, email="o@x.com", name="Other")
        res = await other_c.get(f"/api/auth/organization/list-teams?organizationId={org['id']}")
        assert res.status_code == 403
        assert res.json()["code"] == "YOU_ARE_NOT_ALLOWED_TO_ACCESS_THIS_ORGANIZATION"


# --- set-active-team ---------------------------------------------------------------


async def test_set_active_team_sets_session_and_cookie():
    auth = _teams_auth()  # default team active
    async with make_client(auth) as client:
        owner = await sign_up(client)
        await _create_org(client)
        team_b = (await _create_team(client, "B")).json()
        await client.post(
            "/api/auth/organization/add-team-member",
            json={"teamId": team_b["id"], "userId": owner["user"]["id"]},
        )
        res = await client.post(
            "/api/auth/organization/set-active-team", json={"teamId": team_b["id"]}
        )
        assert res.status_code == 200, res.text
        assert res.json()["id"] == team_b["id"]
        set_cookies = res.headers.get_list("set-cookie")
        assert any("session_token" in c for c in set_cookies)
        session = (await client.get("/api/auth/get-session")).json()
        assert session["session"]["activeTeamId"] == team_b["id"]


async def test_set_active_team_null_unsets():
    auth = _teams_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        await _create_org(client)  # default team -> activeTeamId set
        res = await client.post("/api/auth/organization/set-active-team", json={"teamId": None})
        assert res.status_code == 200
        assert res.json() is None
        session = (await client.get("/api/auth/get-session")).json()
        assert not session["session"].get("activeTeamId")


async def test_set_active_team_not_a_member():
    auth = _teams_auth(default_team=False)
    async with make_client(auth) as client:
        await _owner_with_org(auth, client)  # sets active org
        team = (await _create_team(client, "A")).json()  # creator is NOT a team member
        res = await client.post(
            "/api/auth/organization/set-active-team", json={"teamId": team["id"]}
        )
        assert res.status_code == 403
        assert res.json()["code"] == "USER_IS_NOT_A_MEMBER_OF_THE_TEAM"


# --- list-user-teams / list-team-members -------------------------------------------


async def test_list_user_teams():
    auth = _teams_auth()  # default team; owner is a member
    async with make_client(auth) as client:
        await sign_up(client)
        org = (await _create_org(client)).json()
        res = await client.get("/api/auth/organization/list-user-teams")
        assert res.status_code == 200, res.text
        teams = res.json()
        assert len(teams) == 1
        assert teams[0]["organizationId"] == org["id"]


async def test_list_team_members():
    auth = _teams_auth()  # default team active, owner a member
    async with make_client(auth) as client:
        owner = await sign_up(client)
        await _create_org(client)
        res = await client.get("/api/auth/organization/list-team-members")
        assert res.status_code == 200, res.text
        members = res.json()
        assert len(members) == 1
        assert members[0]["userId"] == owner["user"]["id"]


async def test_list_team_members_no_active_team():
    auth = _teams_auth(default_team=False)
    async with make_client(auth) as client:
        await _owner_with_org(auth, client)  # no active team
        res = await client.get("/api/auth/organization/list-team-members")
        assert res.status_code == 400
        assert res.json()["code"] == "YOU_DO_NOT_HAVE_AN_ACTIVE_TEAM"


# --- add-team-member / remove-team-member ------------------------------------------


async def test_add_team_member():
    auth = _teams_auth(default_team=False)
    async with make_client(auth) as owner_c, make_client(auth) as member_c:
        _, org = await _owner_with_org(auth, owner_c)
        member = await sign_up(member_c, email="m@x.com", name="Mem")
        await _seed_member(auth, org["id"], member["user"]["id"], "member")
        team = (await _create_team(owner_c, "A")).json()
        res = await owner_c.post(
            "/api/auth/organization/add-team-member",
            json={"teamId": team["id"], "userId": member["user"]["id"]},
        )
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["userId"] == member["user"]["id"]
        assert body["teamId"] == team["id"]


async def test_add_team_member_forbidden_for_member():
    auth = _teams_auth(default_team=False)
    async with make_client(auth) as owner_c, make_client(auth) as member_c:
        _, org = await _owner_with_org(auth, owner_c)
        member = await sign_up(member_c, email="m@x.com", name="Mem")
        await _seed_member(auth, org["id"], member["user"]["id"], "member")
        team = (await _create_team(owner_c, "A")).json()
        res = await member_c.post(
            "/api/auth/organization/add-team-member",
            json={
                "teamId": team["id"],
                "userId": member["user"]["id"],
                "organizationId": org["id"],
            },
        )
        assert res.status_code == 403
        assert res.json()["code"] == "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_TEAM_MEMBER"


async def test_add_team_member_limit_reached():
    auth = _teams_auth(default_team=False, maximum_members_per_team=1)
    async with make_client(auth) as owner_c, make_client(auth) as member_c:
        owner, org = await _owner_with_org(auth, owner_c)
        member = await sign_up(member_c, email="m@x.com", name="Mem")
        await _seed_member(auth, org["id"], member["user"]["id"], "member")
        team = (await _create_team(owner_c, "A")).json()
        r1 = await owner_c.post(
            "/api/auth/organization/add-team-member",
            json={"teamId": team["id"], "userId": owner["user"]["id"]},
        )
        assert r1.status_code == 200, r1.text
        r2 = await owner_c.post(
            "/api/auth/organization/add-team-member",
            json={"teamId": team["id"], "userId": member["user"]["id"]},
        )
        assert r2.status_code == 403
        assert r2.json()["code"] == "TEAM_MEMBER_LIMIT_REACHED"


async def test_remove_team_member():
    auth = _teams_auth(default_team=False)
    async with make_client(auth) as owner_c, make_client(auth) as member_c:
        _, org = await _owner_with_org(auth, owner_c)
        member = await sign_up(member_c, email="m@x.com", name="Mem")
        await _seed_member(auth, org["id"], member["user"]["id"], "member")
        team = (await _create_team(owner_c, "A")).json()
        await owner_c.post(
            "/api/auth/organization/add-team-member",
            json={"teamId": team["id"], "userId": member["user"]["id"]},
        )
        res = await owner_c.post(
            "/api/auth/organization/remove-team-member",
            json={"teamId": team["id"], "userId": member["user"]["id"]},
        )
        assert res.status_code == 200, res.text
        assert res.json()["message"] == "Team member removed successfully."
        tm = await auth.adapter.find_one(
            "teamMember",
            [Where("teamId", team["id"]), Where("userId", member["user"]["id"])],
        )
        assert tm is None


async def test_add_team_member_hooks_fire():
    calls: list[str] = []
    auth = org_auth(
        teams={"enabled": True, "default_team": {"enabled": False}},
        organization_hooks={
            "before_add_team_member": lambda d: calls.append("before"),
            "after_add_team_member": lambda d: calls.append("after"),
        },
    )
    async with make_client(auth) as owner_c, make_client(auth) as member_c:
        _, org = await _owner_with_org(auth, owner_c)
        member = await sign_up(member_c, email="m@x.com", name="Mem")
        await _seed_member(auth, org["id"], member["user"]["id"], "member")
        team = (await _create_team(owner_c, "A")).json()
        res = await owner_c.post(
            "/api/auth/organization/add-team-member",
            json={"teamId": team["id"], "userId": member["user"]["id"]},
        )
        assert res.status_code == 200, res.text
        assert calls == ["before", "after"]


async def test_leave_org_removes_team_memberships():
    auth = _teams_auth()  # default team; owner is a team member of it
    async with make_client(auth) as owner_c, make_client(auth) as bob_c:
        await sign_up(owner_c)
        org = (await _create_org(owner_c)).json()
        team = (await owner_c.get("/api/auth/organization/list-teams")).json()[0]
        bob = await sign_up(bob_c, email="bob@x.com", name="Bob")
        await _seed_member(auth, org["id"], bob["user"]["id"], "member")
        await owner_c.post(
            "/api/auth/organization/add-team-member",
            json={"teamId": team["id"], "userId": bob["user"]["id"]},
        )
        before = (await owner_c.get("/api/auth/organization/list-team-members")).json()
        assert any(m["userId"] == bob["user"]["id"] for m in before)
        # bob leaves the org → his team membership is cleaned up (adapter.ts:387-405)
        res = await bob_c.post("/api/auth/organization/leave", json={"organizationId": org["id"]})
        assert res.status_code == 200, res.text
        after = (await owner_c.get("/api/auth/organization/list-team-members")).json()
        assert all(m["userId"] != bob["user"]["id"] for m in after)
        tm = await auth.adapter.find_one(
            "teamMember",
            [Where("teamId", team["id"]), Where("userId", bob["user"]["id"])],
        )
        assert tm is None


# --- invitation integration --------------------------------------------------------


async def test_invite_with_team_id_creates_membership_on_accept():
    auth = _teams_auth(default_team=False)
    async with make_client(auth) as owner_c, make_client(auth) as invitee_c:
        await _owner_with_org(auth, owner_c)
        team = (await _create_team(owner_c, "A")).json()
        inv = (
            await owner_c.post(
                "/api/auth/organization/invite-member",
                json={"email": "bob@example.com", "role": "member", "teamId": team["id"]},
            )
        ).json()
        assert inv.get("teamId") == team["id"]
        bob = await sign_up(invitee_c, email="bob@example.com", name="Bob")
        res = await invitee_c.post(
            "/api/auth/organization/accept-invitation", json={"invitationId": inv["id"]}
        )
        assert res.status_code == 200, res.text
        tm = await auth.adapter.find_one(
            "teamMember",
            [Where("teamId", team["id"]), Where("userId", bob["user"]["id"])],
        )
        assert tm is not None
        session = (await invitee_c.get("/api/auth/get-session")).json()
        assert session["session"]["activeTeamId"] == team["id"]  # single team -> set active


async def test_invite_team_not_found():
    auth = _teams_auth(default_team=False)
    async with make_client(auth) as client:
        await _owner_with_org(auth, client)
        res = await client.post(
            "/api/auth/organization/invite-member",
            json={"email": "bob@example.com", "role": "member", "teamId": "nope"},
        )
        assert res.status_code == 400
        assert res.json()["code"] == "TEAM_NOT_FOUND"


async def test_invite_invalid_team_id():
    auth = _teams_auth(default_team=False)
    async with make_client(auth) as client:
        await _owner_with_org(auth, client)
        res = await client.post(
            "/api/auth/organization/invite-member",
            json={"email": "bob@example.com", "role": "member", "teamId": "a,b"},
        )
        assert res.status_code == 400
        assert res.json()["code"] == "INVALID_TEAM_ID"


async def test_invite_team_member_limit_reached():
    auth = _teams_auth(default_team=False, maximum_members_per_team=1)
    async with make_client(auth) as owner_c:
        owner, _org = await _owner_with_org(auth, owner_c)
        team = (await _create_team(owner_c, "A")).json()
        await owner_c.post(
            "/api/auth/organization/add-team-member",
            json={"teamId": team["id"], "userId": owner["user"]["id"]},
        )
        res = await owner_c.post(
            "/api/auth/organization/invite-member",
            json={"email": "bob@example.com", "role": "member", "teamId": team["id"]},
        )
        assert res.status_code == 403
        assert res.json()["code"] == "TEAM_MEMBER_LIMIT_REACHED"


# --- get-full-organization includes teams ------------------------------------------


async def test_get_full_organization_includes_teams():
    auth = _teams_auth()  # default team
    async with make_client(auth) as client:
        await sign_up(client)
        await _create_org(client)
        full = (await client.get("/api/auth/organization/get-full-organization")).json()
        assert "teams" in full
        assert len(full["teams"]) == 1


# --- team hooks --------------------------------------------------------------------


async def test_create_team_hooks_fire_and_merge():
    calls: list[tuple[str, str]] = []

    async def before(data):
        calls.append(("before", data["team"]["name"]))
        return {"data": {"name": data["team"]["name"] + "-x"}}

    async def after(data):
        calls.append(("after", data["team"]["name"]))

    auth = org_auth(
        teams={"enabled": True, "default_team": {"enabled": False}},
        organization_hooks={"before_create_team": before, "after_create_team": after},
    )
    async with make_client(auth) as client:
        await _owner_with_org(auth, client)
        res = await _create_team(client, "Eng")
        assert res.status_code == 200, res.text
        assert res.json()["name"] == "Eng-x"  # before-hook data merged
        assert ("before", "Eng") in calls
        assert ("after", "Eng-x") in calls


async def test_update_team_hooks_fire():
    calls: list[str] = []
    auth = org_auth(
        teams={"enabled": True, "default_team": {"enabled": False}},
        organization_hooks={
            "before_update_team": lambda d: calls.append("before"),
            "after_update_team": lambda d: calls.append("after"),
        },
    )
    async with make_client(auth) as client:
        await _owner_with_org(auth, client)
        team = (await _create_team(client, "Eng")).json()
        res = await client.post(
            "/api/auth/organization/update-team",
            json={"teamId": team["id"], "data": {"name": "E2"}},
        )
        assert res.status_code == 200, res.text
        assert calls == ["before", "after"]


# --- team error strings byte-exact -------------------------------------------------


def test_team_error_codes_match_ts_exactly():
    assert ERROR_CODES["TEAM_NOT_FOUND"] == "Team not found"
    assert (
        ERROR_CODES["YOU_HAVE_REACHED_THE_MAXIMUM_NUMBER_OF_TEAMS"]
        == "You have reached the maximum number of teams"
    )
    assert ERROR_CODES["UNABLE_TO_REMOVE_LAST_TEAM"] == "Unable to remove last team"
    assert (
        ERROR_CODES["YOU_ARE_NOT_ALLOWED_TO_CREATE_TEAMS_IN_THIS_ORGANIZATION"]
        == "You are not allowed to create teams in this organization"
    )
    assert (
        ERROR_CODES["YOU_ARE_NOT_ALLOWED_TO_DELETE_TEAMS_IN_THIS_ORGANIZATION"]
        == "You are not allowed to delete teams in this organization"
    )
    assert (
        ERROR_CODES["YOU_ARE_NOT_ALLOWED_TO_UPDATE_THIS_TEAM"]
        == "You are not allowed to update this team"
    )
    assert (
        ERROR_CODES["YOU_ARE_NOT_ALLOWED_TO_DELETE_THIS_TEAM"]
        == "You are not allowed to delete this team"
    )
    assert ERROR_CODES["TEAM_MEMBER_LIMIT_REACHED"] == "Team member limit reached"
    assert ERROR_CODES["USER_IS_NOT_A_MEMBER_OF_THE_TEAM"] == "User is not a member of the team"
    assert ERROR_CODES["YOU_DO_NOT_HAVE_AN_ACTIVE_TEAM"] == "You do not have an active team"
    assert ERROR_CODES["INVALID_TEAM_ID"] == "Team id contains a reserved character"
    assert (
        ERROR_CODES["YOU_ARE_NOT_ALLOWED_TO_CREATE_A_NEW_TEAM_MEMBER"]
        == "You are not allowed to create a new member"
    )
    assert (
        ERROR_CODES["YOU_ARE_NOT_ALLOWED_TO_REMOVE_A_TEAM_MEMBER"]
        == "You are not allowed to remove a team member"
    )
    assert (
        ERROR_CODES["YOU_ARE_NOT_ALLOWED_TO_ACCESS_THIS_ORGANIZATION"]
        == "You are not allowed to access this organization as an owner"
    )


# ============================================================================
# PHASE 4 — dynamic access control (routes/crud-access-control.ts,
# has-permission.ts merge, organization.ts schema/wiring, types.ts config).
# There are NO role-specific hooks in v1.6.23 (types.ts organizationHooks has
# only org/member/invitation/team hooks), so none are ported/tested.
# ============================================================================


def _dac_plugin(**kwargs: Any) -> OrganizationPlugin:
    """Org plugin wired for DAC: a custom ``ac`` statement universe (project/sales +
    org defaults) and static owner/admin/member roles built from it, mirroring
    crud-access-control.test.ts."""
    ac = create_access_control(
        {
            "project": ["create", "read", "update", "delete"],
            "sales": ["create", "read", "update", "delete"],
            **ORG_DEFAULT_STATEMENTS,
        }
    )
    roles = {
        "owner": ac.new_role(
            {
                "project": ["create", "delete", "update", "read"],
                "sales": ["create", "read", "update", "delete"],
                **ORG_DEFAULT_ROLES["owner"].statements,
            }
        ),
        "admin": ac.new_role(
            {
                "project": ["create", "read", "delete", "update"],
                "sales": ["create", "read"],
                **ORG_DEFAULT_ROLES["admin"].statements,
            }
        ),
        "member": ac.new_role(
            {
                "project": ["read"],
                "sales": ["read"],
                **ORG_DEFAULT_ROLES["member"].statements,
            }
        ),
    }
    dac = kwargs.pop("dynamic_access_control", {"enabled": True})
    return OrganizationPlugin(
        ac=ac,
        roles=roles,
        dynamic_access_control=dac,
        additional_fields={
            "organizationRole": {
                "color": Field("string", default="#ffffff", required=True),
                "serverOnlyValue": Field(
                    "string", default="server-only-value", input=False, required=True
                ),
            }
        },
        **kwargs,
    )


def _dac_auth(**kwargs: Any):
    return make_auth(plugins=[_dac_plugin(**kwargs)])


async def _create_role(client, *, role, permission, organizationId=None, **extra):
    body: dict[str, Any] = {"role": role, "permission": permission}
    if organizationId:
        body["organizationId"] = organizationId
    body.update(extra)
    return await client.post("/api/auth/organization/create-role", json=body)


# --- enabled gate -----------------------------------------------------------------


async def test_dac_disabled_no_schema_and_endpoints_404():
    auth = org_auth()  # DAC off
    assert "organizationRole" not in auth.schema
    async with make_client(auth) as client:
        await sign_up(client)
        await _create_org(client)
        res = await client.post(
            "/api/auth/organization/create-role",
            json={"role": "x", "permission": {"project": ["create"]}},
        )
        assert res.status_code == 404
        assert (await client.get("/api/auth/organization/list-roles")).status_code == 404


async def test_dac_enabled_adds_organization_role_schema():
    auth = _dac_auth()
    assert "organizationRole" in auth.schema
    cols = auth.schema["organizationRole"]
    assert cols["role"].type == "string" and cols["role"].required
    assert cols["permission"].type == "string" and cols["permission"].required
    assert cols["organizationId"].required and cols["organizationId"].references is not None
    assert cols["createdAt"].type == "datetime"
    assert "updatedAt" in cols and cols["updatedAt"].required is False


# --- create role ------------------------------------------------------------------


async def test_create_role_flow_normalizes_and_stores_json_string():
    auth = _dac_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        await _create_org(client)
        res = await _create_role(
            client,
            role="Editor",
            permission={"project": ["create"]},
            additionalFields={"color": "#000000"},
        )
        assert res.status_code == 200, res.text
        data = res.json()
        assert data["success"] is True
        assert data["roleData"]["role"] == "editor"  # normalizeRoleName lowercases
        assert data["roleData"]["permission"] == {"project": ["create"]}
        assert data["roleData"]["color"] == "#000000"
        assert data["roleData"]["serverOnlyValue"] == "server-only-value"  # input:false default
        assert data["statements"] == {"project": ["create"]}
        row = await auth.adapter.find_one("organizationRole", [Where("id", data["roleData"]["id"])])
        assert isinstance(row["permission"], str)
        assert row["permission"] == '{"project":["create"]}'


async def test_create_role_requires_ac_instance():
    auth = make_auth(plugins=[OrganizationPlugin(dynamic_access_control={"enabled": True})])
    async with make_client(auth) as client:
        await sign_up(client)
        await _create_org(client)
        res = await client.post(
            "/api/auth/organization/create-role",
            json={"role": "x", "permission": {"project": ["create"]}},
        )
        assert res.status_code == 501
        assert res.json()["code"] == "MISSING_AC_INSTANCE"
        assert res.json()["message"] == ERROR_CODES["MISSING_AC_INSTANCE"]


async def test_create_role_name_collision_predefined_and_existing():
    auth = _dac_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        await _create_org(client)
        res = await _create_role(client, role="admin", permission={"project": ["create"]})
        assert res.status_code == 400
        assert res.json()["code"] == "ROLE_NAME_IS_ALREADY_TAKEN"
        assert res.json()["message"] == ERROR_CODES["ROLE_NAME_IS_ALREADY_TAKEN"]
        assert (
            await _create_role(client, role="dupe", permission={"project": ["read"]})
        ).status_code == 200
        res2 = await _create_role(client, role="dupe", permission={"project": ["create"]})
        assert res2.status_code == 400
        assert res2.json()["code"] == "ROLE_NAME_IS_ALREADY_TAKEN"


async def test_create_role_invalid_resource_rejected():
    auth = _dac_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        await _create_org(client)
        res = await _create_role(client, role="bad", permission={"nonexistent": ["read"]})
        assert res.status_code == 400
        assert res.json()["code"] == "INVALID_RESOURCE"
        assert res.json()["message"] == ERROR_CODES["INVALID_RESOURCE"]


async def test_create_role_subset_of_own_permissions_enforced():
    auth = _dac_auth()
    async with make_client(auth) as owner_c, make_client(auth) as admin_c:
        await sign_up(owner_c)
        admin = await sign_up(admin_c, email="a@x.com", name="Admin")
        org = (await _create_org(owner_c)).json()
        await _seed_member(auth, org["id"], admin["user"]["id"], "admin")
        # admin has sales:[create,read] but not delete/update -> rejected
        res = await _create_role(
            admin_c,
            role="toobig",
            permission={"sales": ["create", "delete", "update", "read"]},
            organizationId=org["id"],
        )
        assert res.status_code == 403
        assert res.json()["code"] == "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE"
        assert res.json()["message"] == ERROR_CODES["YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE"]
        # crud-access-control.ts:1172-1204 — missingPermissions is `${resource}:${perm}`
        # for every requested perm the actor's role lacks, top-level on the error body.
        assert res.json()["missingPermissions"] == ["sales:delete", "sales:update"]


async def test_create_role_forbidden_without_ac_create_permission():
    auth = _dac_auth()
    async with make_client(auth) as owner_c, make_client(auth) as mem_c:
        await sign_up(owner_c)
        mem = await sign_up(mem_c, email="m@x.com", name="Mem")
        org = (await _create_org(owner_c)).json()
        await _seed_member(auth, org["id"], mem["user"]["id"], "member")
        res = await _create_role(
            mem_c, role="x", permission={"project": ["create"]}, organizationId=org["id"]
        )
        assert res.status_code == 403
        assert res.json()["code"] == "YOU_ARE_NOT_ALLOWED_TO_CREATE_A_ROLE"


async def test_maximum_roles_per_organization_number():
    auth = _dac_auth(dynamic_access_control={"enabled": True, "maximum_roles_per_organization": 1})
    async with make_client(auth) as client:
        await sign_up(client)
        await _create_org(client)
        assert (
            await _create_role(client, role="one", permission={"project": ["read"]})
        ).status_code == 200
        res = await _create_role(client, role="two", permission={"project": ["read"]})
        assert res.status_code == 400
        assert res.json()["code"] == "TOO_MANY_ROLES"
        assert res.json()["message"] == ERROR_CODES["TOO_MANY_ROLES"]


async def test_maximum_roles_per_organization_fn():
    async def limit(org_id):
        return 1

    auth = _dac_auth(
        dynamic_access_control={"enabled": True, "maximum_roles_per_organization": limit}
    )
    async with make_client(auth) as client:
        await sign_up(client)
        await _create_org(client)
        assert (
            await _create_role(client, role="one", permission={"project": ["read"]})
        ).status_code == 200
        assert (
            await _create_role(client, role="two", permission={"project": ["read"]})
        ).status_code == 400


# --- list / get -------------------------------------------------------------------


async def test_list_roles_returns_parsed_permission():
    auth = _dac_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        await _create_org(client)
        await _create_role(client, role="r1", permission={"project": ["create"], "ac": ["read"]})
        res = await client.get("/api/auth/organization/list-roles")
        assert res.status_code == 200
        roles = res.json()
        assert isinstance(roles, list) and len(roles) >= 1
        found = next(r for r in roles if r["role"] == "r1")
        assert found["permission"] == {"project": ["create"], "ac": ["read"]}
        assert found["color"] == "#ffffff"


async def test_list_roles_forbidden_without_ac_read():
    auth = _dac_auth()
    async with make_client(auth) as owner_c, make_client(auth) as mem_c:
        await sign_up(owner_c)
        mem = await sign_up(mem_c, email="m@x.com", name="Mem")
        org = (await _create_org(owner_c)).json()
        member_row = await _seed_member(auth, org["id"], mem["user"]["id"], "member")
        await _create_role(owner_c, role="restricted", permission={"project": ["create"]})
        await owner_c.post(
            "/api/auth/organization/update-member-role",
            json={"memberId": member_row["id"], "role": "restricted", "organizationId": org["id"]},
        )
        res = await mem_c.get(
            "/api/auth/organization/list-roles", params={"organizationId": org["id"]}
        )
        assert res.status_code == 403
        assert res.json()["code"] == "YOU_ARE_NOT_ALLOWED_TO_LIST_A_ROLE"


async def test_get_role_by_id_and_name_and_not_found():
    auth = _dac_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        org = (await _create_org(client)).json()
        created = (
            await _create_role(
                client,
                role="g1",
                permission={"project": ["read"]},
                additionalFields={"color": "#abc123"},
            )
        ).json()["roleData"]
        by_id = await client.get(
            "/api/auth/organization/get-role",
            params={"roleId": created["id"], "organizationId": org["id"]},
        )
        assert by_id.status_code == 200
        assert by_id.json()["role"] == "g1"
        assert by_id.json()["permission"] == {"project": ["read"]}
        assert by_id.json()["color"] == "#abc123"
        by_name = await client.get(
            "/api/auth/organization/get-role",
            params={"roleName": "g1", "organizationId": org["id"]},
        )
        assert by_name.status_code == 200
        assert by_name.json()["id"] == created["id"]
        nf = await client.get(
            "/api/auth/organization/get-role",
            params={"roleName": "ghost", "organizationId": org["id"]},
        )
        assert nf.status_code == 400
        assert nf.json()["code"] == "ROLE_NOT_FOUND"


# --- update -----------------------------------------------------------------------


async def test_update_role_permission_is_replaced_not_merged():
    auth = _dac_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        org = (await _create_org(client)).json()
        created = (
            await _create_role(client, role="u1", permission={"project": ["create"]})
        ).json()["roleData"]
        res = await client.post(
            "/api/auth/organization/update-role",
            json={
                "roleId": created["id"],
                "data": {"permission": {"project": ["create", "delete"]}},
            },
        )
        assert res.status_code == 200, res.text
        assert res.json()["roleData"]["permission"] == {"project": ["create", "delete"]}
        got = await client.get(
            "/api/auth/organization/get-role",
            params={"roleId": created["id"], "organizationId": org["id"]},
        )
        assert got.json()["permission"] == {"project": ["create", "delete"]}


async def test_update_role_name_and_additional_fields():
    auth = _dac_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        org = (await _create_org(client)).json()
        await _create_role(
            client,
            role="u2",
            permission={"project": ["read"]},
            additionalFields={"color": "#000"},
        )
        res = await client.post(
            "/api/auth/organization/update-role",
            json={"roleName": "u2", "data": {"roleName": "U2-Renamed", "color": "#fff"}},
        )
        assert res.status_code == 200, res.text
        assert res.json()["roleData"]["role"] == "u2-renamed"  # normalized
        assert res.json()["roleData"]["color"] == "#fff"
        assert (
            await client.get(
                "/api/auth/organization/get-role",
                params={"roleName": "u2-renamed", "organizationId": org["id"]},
            )
        ).status_code == 200


async def test_update_role_forbidden_without_ac_update():
    auth = _dac_auth()
    async with make_client(auth) as owner_c, make_client(auth) as mem_c:
        await sign_up(owner_c)
        mem = await sign_up(mem_c, email="m@x.com", name="Mem")
        org = (await _create_org(owner_c)).json()
        await _seed_member(auth, org["id"], mem["user"]["id"], "member")
        created = (
            await _create_role(owner_c, role="prot", permission={"project": ["read"]})
        ).json()["roleData"]
        res = await mem_c.post(
            "/api/auth/organization/update-role",
            json={
                "roleId": created["id"],
                "organizationId": org["id"],
                "data": {"roleName": "hijack"},
            },
        )
        assert res.status_code == 403
        assert res.json()["code"] == "YOU_ARE_NOT_ALLOWED_TO_UPDATE_A_ROLE"


# --- delete -----------------------------------------------------------------------


async def test_delete_role_by_id_and_by_name():
    auth = _dac_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        await _create_org(client)
        r1 = (await _create_role(client, role="d1", permission={"project": ["read"]})).json()[
            "roleData"
        ]
        res = await client.post("/api/auth/organization/delete-role", json={"roleId": r1["id"]})
        assert res.status_code == 200 and res.json()["success"] is True
        assert await auth.adapter.find_one("organizationRole", [Where("id", r1["id"])]) is None
        (await _create_role(client, role="d2", permission={"project": ["read"]}))
        res2 = await client.post("/api/auth/organization/delete-role", json={"roleName": "d2"})
        assert res2.status_code == 200


async def test_delete_predefined_role_rejected():
    auth = _dac_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        await _create_org(client)
        res = await client.post("/api/auth/organization/delete-role", json={"roleName": "admin"})
        assert res.status_code == 400
        assert res.json()["code"] == "CANNOT_DELETE_A_PRE_DEFINED_ROLE"
        assert res.json()["message"] == ERROR_CODES["CANNOT_DELETE_A_PRE_DEFINED_ROLE"]


async def test_delete_role_not_found():
    auth = _dac_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        await _create_org(client)
        res = await client.post("/api/auth/organization/delete-role", json={"roleName": "ghost"})
        assert res.status_code == 400
        assert res.json()["code"] == "ROLE_NOT_FOUND"


async def test_delete_role_assigned_to_member_rejected_then_allowed_after_reassign():
    auth = _dac_auth()
    async with make_client(auth) as owner_c, make_client(auth) as mem_c:
        await sign_up(owner_c)
        mem = await sign_up(mem_c, email="m@x.com", name="Mem")
        org = (await _create_org(owner_c)).json()
        member_row = await _seed_member(auth, org["id"], mem["user"]["id"], "member")
        await _create_role(owner_c, role="assigned", permission={"project": ["read"]})
        await owner_c.post(
            "/api/auth/organization/update-member-role",
            json={"memberId": member_row["id"], "role": "assigned", "organizationId": org["id"]},
        )
        res = await owner_c.post(
            "/api/auth/organization/delete-role", json={"roleName": "assigned"}
        )
        assert res.status_code == 400
        assert res.json()["code"] == "ROLE_IS_ASSIGNED_TO_MEMBERS"
        assert res.json()["message"] == ERROR_CODES["ROLE_IS_ASSIGNED_TO_MEMBERS"]
        await owner_c.post(
            "/api/auth/organization/update-member-role",
            json={"memberId": member_row["id"], "role": "member", "organizationId": org["id"]},
        )
        assert (
            await owner_c.post("/api/auth/organization/delete-role", json={"roleName": "assigned"})
        ).status_code == 200


async def test_delete_role_rejected_when_member_has_it_among_multiple_roles():
    auth = _dac_auth()
    async with make_client(auth) as owner_c, make_client(auth) as mem_c:
        await sign_up(owner_c)
        mem = await sign_up(mem_c, email="m@x.com", name="Mem")
        org = (await _create_org(owner_c)).json()
        await _create_role(owner_c, role="multi", permission={"project": ["read"]})
        await _seed_member(auth, org["id"], mem["user"]["id"], "multi,member")
        res = await owner_c.post("/api/auth/organization/delete-role", json={"roleName": "multi"})
        assert res.status_code == 400
        assert res.json()["code"] == "ROLE_IS_ASSIGNED_TO_MEMBERS"


# --- permission merge -------------------------------------------------------------


async def test_member_with_dynamic_role_passes_and_fails_has_permission():
    auth = _dac_auth()
    async with make_client(auth) as owner_c, make_client(auth) as mem_c:
        await sign_up(owner_c)
        mem = await sign_up(mem_c, email="m@x.com", name="Mem")
        org = (await _create_org(owner_c)).json()
        member_row = await _seed_member(auth, org["id"], mem["user"]["id"], "member")
        await _create_role(owner_c, role="creator", permission={"project": ["create"]})
        assign = await owner_c.post(
            "/api/auth/organization/update-member-role",
            json={"memberId": member_row["id"], "role": "creator", "organizationId": org["id"]},
        )
        assert assign.status_code == 200, assign.text
        ok = await mem_c.post(
            "/api/auth/organization/has-permission",
            json={"organizationId": org["id"], "permissions": {"project": ["create"]}},
        )
        assert ok.status_code == 200 and ok.json()["success"] is True
        no = await mem_c.post(
            "/api/auth/organization/has-permission",
            json={"organizationId": org["id"], "permissions": {"project": ["delete"]}},
        )
        assert no.json()["success"] is False


async def test_dynamic_role_unions_with_same_named_static_role():
    auth = _dac_auth()
    async with make_client(auth) as owner_c, make_client(auth) as admin_c:
        await sign_up(owner_c)
        admin = await sign_up(admin_c, email="a@x.com", name="Admin")
        org = (await _create_org(owner_c)).json()
        await _seed_member(auth, org["id"], admin["user"]["id"], "admin")

        async def can(perms):
            r = await admin_c.post(
                "/api/auth/organization/has-permission",
                json={"organizationId": org["id"], "permissions": perms},
            )
            return r.json()["success"]

        assert await can({"sales": ["delete"]}) is False  # static admin lacks sales:delete
        # seed a dynamic role sharing the static name (bypasses the create-role name guard)
        await auth.adapter.create(
            "organizationRole",
            {
                "id": generate_id(),
                "organizationId": org["id"],
                "role": "admin",
                "permission": '{"sales":["delete"]}',
                "createdAt": utcnow(),
            },
        )
        assert await can({"sales": ["delete"]}) is True  # union grants it now
        assert await can({"organization": ["delete"]}) is False  # neither grants -> denied


async def test_invalid_stored_permission_raises_500():
    auth = _dac_auth()
    async with make_client(auth) as owner_c, make_client(auth) as mem_c:
        await sign_up(owner_c)
        mem = await sign_up(mem_c, email="m@x.com", name="Mem")
        org = (await _create_org(owner_c)).json()
        await _seed_member(auth, org["id"], mem["user"]["id"], "member")
        await auth.adapter.create(
            "organizationRole",
            {
                "id": generate_id(),
                "organizationId": org["id"],
                "role": "member",
                "permission": '{"project":"notanarray"}',
                "createdAt": utcnow(),
            },
        )
        res = await mem_c.post(
            "/api/auth/organization/has-permission",
            json={"organizationId": org["id"], "permissions": {"project": ["read"]}},
        )
        assert res.status_code == 500


# --- update-member-role / invite consult dynamic roles (SEAMs) --------------------


async def test_update_member_role_unknown_role_still_rejected_with_dac():
    auth = _dac_auth()
    async with make_client(auth) as owner_c, make_client(auth) as mem_c:
        await sign_up(owner_c)
        mem = await sign_up(mem_c, email="m@x.com", name="Mem")
        org = (await _create_org(owner_c)).json()
        member_row = await _seed_member(auth, org["id"], mem["user"]["id"], "member")
        res = await owner_c.post(
            "/api/auth/organization/update-member-role",
            json={"memberId": member_row["id"], "role": "ghost", "organizationId": org["id"]},
        )
        assert res.status_code == 400
        assert res.json()["code"] == "ROLE_NOT_FOUND"
        assert res.json()["message"] == "ROLE_NOT_FOUND: ghost"


async def test_invite_member_accepts_dynamic_role_name():
    auth = _dac_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        org = (await _create_org(client)).json()
        await _create_role(client, role="inviterole", permission={"project": ["read"]})
        res = await client.post(
            "/api/auth/organization/invite-member",
            json={"email": "new@x.com", "role": "inviterole", "organizationId": org["id"]},
        )
        assert res.status_code == 200, res.text
        assert res.json()["role"] == "inviterole"


async def test_invite_member_unknown_role_rejected_with_dac():
    auth = _dac_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        org = (await _create_org(client)).json()
        res = await client.post(
            "/api/auth/organization/invite-member",
            json={"email": "new@x.com", "role": "ghost", "organizationId": org["id"]},
        )
        assert res.status_code == 400
        assert res.json()["code"] == "ROLE_NOT_FOUND"
        assert res.json()["message"] == f"{ERROR_CODES['ROLE_NOT_FOUND']}: ghost"
