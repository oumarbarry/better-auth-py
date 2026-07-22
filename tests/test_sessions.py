from datetime import timedelta

from better_auth.adapters.base import Where
from better_auth.session import utcnow
from conftest import SIGNUP, make_client, sign_up


async def test_get_session_null_when_anonymous(client):
    response = await client.get("/api/auth/get-session")
    assert response.status_code == 200
    assert response.json() is None
    assert response.headers["cache-control"] == "no-store"


async def test_get_session_post_not_allowed(client):
    response = await client.post("/api/auth/get-session")
    assert response.status_code == 405


async def test_list_sessions_and_revoke_others(auth, client):
    await sign_up(client)
    await client.post("/api/auth/sign-in/email", json=SIGNUP)

    sessions = (await client.get("/api/auth/list-sessions")).json()
    assert len(sessions) == 2

    assert (await client.post("/api/auth/revoke-other-sessions")).json() == {"status": True}
    sessions = (await client.get("/api/auth/list-sessions")).json()
    assert len(sessions) == 1


async def test_revoke_sessions_revokes_current_too(client):
    await sign_up(client)
    assert (await client.post("/api/auth/revoke-sessions")).json() == {"status": True}
    assert (await client.get("/api/auth/get-session")).json() is None


async def test_revoke_session_of_another_user_is_silent(auth, client):
    """Wire-compat fix: unknown/foreign tokens are a silent no-op ({"status":true}),
    never an error — matches TS anti-enumeration semantics (session.ts:812).
    The old behavior (400 SESSION_NOT_FOUND) was the bug."""
    victim = await sign_up(client)
    async with make_client(auth) as attacker:
        await sign_up(attacker, email="mallory@example.com")
        response = await attacker.post("/api/auth/revoke-session", json={"token": victim["token"]})
        assert response.status_code == 200
        assert response.json() == {"status": True}
        # the foreign token must NOT actually have been revoked
        assert (await client.get("/api/auth/get-session")).json() is not None


async def test_remember_me_false_sets_browser_session_cookie(client):
    await sign_up(client)
    client.cookies.clear()
    response = await client.post("/api/auth/sign-in/email", json={**SIGNUP, "rememberMe": False})
    cookies = response.headers.get_list("set-cookie")
    session_cookie = next(c for c in cookies if c.startswith("better-auth.session_token="))
    assert "Max-Age" not in session_cookie
    assert any(c.startswith("better-auth.dont_remember=true") for c in cookies)


async def test_expired_session_is_deleted_and_cookie_cleared(auth, client):
    await sign_up(client)
    await auth.adapter.update_many("session", [], {"expiresAt": utcnow() - timedelta(seconds=1)})
    response = await client.get("/api/auth/get-session")
    assert response.json() is None
    cleared = response.headers.get_list("set-cookie")
    assert any("Max-Age=0" in c for c in cleared)
    assert await auth.adapter.find_many("session") == []


async def test_update_age_refresh_extends_expiry(auth, client):
    await sign_up(client)
    options = auth.session_options
    stale_expiry = utcnow() + timedelta(seconds=options.expires_in - options.update_age - 60)
    await auth.adapter.update_many("session", [], {"expiresAt": stale_expiry})

    response = await client.get("/api/auth/get-session")
    assert response.json() is not None
    assert any(
        c.startswith("better-auth.session_token=") for c in response.headers.get_list("set-cookie")
    )
    row = await auth.adapter.find_one("session", [Where("userId", response.json()["user"]["id"])])
    assert row["expiresAt"] > stale_expiry


async def test_fresh_session_is_not_refreshed(auth, client):
    await sign_up(client)
    response = await client.get("/api/auth/get-session")
    assert response.json() is not None
    assert response.headers.get_list("set-cookie") == []


async def test_tampered_cookie_is_rejected(client):
    await sign_up(client)
    client.cookies.clear()
    client.cookies.set("better-auth.session_token", "forged-token.AAAA", domain="testserver")
    response = await client.get("/api/auth/get-session")
    assert response.json() is None
