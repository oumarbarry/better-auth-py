"""organization plugin — PHASE 1 (core-org): orgs, members, roles/permissions.

Verified against TS ``packages/better-auth/src/plugins/organization`` at v1.6.23
(routes/crud-org.ts, routes/crud-members.ts, organization.ts, has-permission.ts,
error-codes.ts). Invitations, teams, and dynamic access control are later phases.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from better_auth.adapters.base import Where
from better_auth.crypto import generate_id
from better_auth.plugins_ext.organization import ERROR_CODES, OrganizationPlugin
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
        res = await invitee_c.get(
            "/api/auth/organization/get-invitation", params={"id": inv["id"]}
        )
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
        res = await carol_c.get(
            "/api/auth/organization/get-invitation", params={"id": inv["id"]}
        )
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
        res = await invitee_c.get(
            "/api/auth/organization/get-invitation", params={"id": inv["id"]}
        )
        assert res.status_code == 400
        assert res.json()["message"] == "Invitation not found!"


async def test_get_invitation_inviter_no_longer_member():
    auth = org_auth()
    async with make_client(auth) as owner_c, make_client(auth) as invitee_c:
        _, org = await _owner_with_org(auth, owner_c)
        # inviter id that is not a member of the org
        inv = await _seed_invitation(auth, org["id"], "bob@example.com", "ghost-user")
        await sign_up(invitee_c, email="bob@example.com", name="Bob")
        res = await invitee_c.get(
            "/api/auth/organization/get-invitation", params={"id": inv["id"]}
        )
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
