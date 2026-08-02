"""Wire-compat fixes tracked in docs/plans/gap/01-core-http.md, gap items
1 (/verify-password), 2 (/list-accounts), 3 (/revoke-session — see
test_sessions.py), 4 (/update-user), 7 (/change-password revokeOtherSessions —
see test_email_password.py)."""

from better_auth.crypto import generate_id
from better_auth.session import utcnow
from conftest import SIGNUP, sign_up

# --- gap item 1: /verify-password ------------------------------------------------------


async def test_verify_password_returns_status_true(client):
    await sign_up(client)
    response = await client.post("/api/auth/verify-password", json={"password": SIGNUP["password"]})
    assert response.status_code == 200
    assert response.json() == {"status": True}


async def test_verify_password_throws_invalid_password_on_mismatch(client):
    await sign_up(client)
    response = await client.post("/api/auth/verify-password", json={"password": "wrong-password"})
    assert response.status_code == 400
    assert response.json()["code"] == "INVALID_PASSWORD"


# --- gap item 2: /list-accounts ---------------------------------------------------------


async def test_list_accounts_emits_scopes_array_not_scope(client):
    await sign_up(client)
    accounts = (await client.get("/api/auth/list-accounts")).json()
    assert len(accounts) == 1
    assert accounts[0]["scopes"] == []
    assert "scope" not in accounts[0]


async def test_list_accounts_splits_scope_string_on_comma(auth, client):
    await sign_up(client)
    now = utcnow()
    await auth.adapter.create(
        "account",
        {
            "id": generate_id(),
            "accountId": "gh-1",
            "providerId": "github",
            "userId": (await client.get("/api/auth/get-session")).json()["user"]["id"],
            "scope": "repo,gist",
            "createdAt": now,
            "updatedAt": now,
        },
    )
    accounts = (await client.get("/api/auth/list-accounts")).json()
    github = next(a for a in accounts if a["providerId"] == "github")
    assert github["scopes"] == ["repo", "gist"]
    assert "scope" not in github


# --- gap item 4: /update-user ------------------------------------------------------------


async def test_update_user_throws_email_can_not_be_updated(client):
    await sign_up(client)
    response = await client.post("/api/auth/update-user", json={"email": "new@example.com"})
    assert response.status_code == 400
    assert response.json()["code"] == "EMAIL_CAN_NOT_BE_UPDATED"


async def test_update_user_with_no_fields_errors(client):
    await sign_up(client)
    response = await client.post("/api/auth/update-user", json={})
    assert response.status_code == 400


async def test_update_user_refreshes_session_cookie(client):
    await sign_up(client)
    response = await client.post("/api/auth/update-user", json={"name": "Grace Hopper"})
    assert response.status_code == 200
    assert any(
        c.startswith("better-auth.session_token=") for c in response.headers.get_list("set-cookie")
    )
    session = (await client.get("/api/auth/get-session")).json()
    assert session["user"]["name"] == "Grace Hopper"
