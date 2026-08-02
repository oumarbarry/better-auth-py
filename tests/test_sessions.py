from datetime import timedelta

from better_auth.adapters.base import Where
from better_auth.config import SessionOptions
from better_auth.session import utcnow
from conftest import SIGNUP, make_auth, make_client, sign_up


async def test_get_session_null_when_anonymous(client):
    response = await client.get("/api/auth/get-session")
    assert response.status_code == 200
    assert response.json() is None
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"


async def test_get_session_authenticated_is_not_cacheable(client):
    """TS 46d2bf02c — ``ctx.setHeader("cache-control","no-store")`` + ``pragma: no-cache``."""
    await sign_up(client)
    response = await client.get("/api/auth/get-session")
    assert response.status_code == 200
    assert response.json()["user"]["email"] == SIGNUP["email"]
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"


async def test_session_gated_endpoints_do_not_inherit_no_store(client):
    """The get-session cache headers must not leak onto endpoints that merely
    resolve a session (TS ``getSessionFromCtx`` skips cache-control/pragma)."""
    await sign_up(client)
    response = await client.get("/api/auth/list-sessions")
    assert response.status_code == 200
    assert "cache-control" not in response.headers
    assert "pragma" not in response.headers


async def test_get_session_post_requires_defer_session_refresh(client):
    """``/get-session`` is ``method: ["GET","POST"]`` (session.ts:36), but the handler
    rejects POST unless ``session.deferSessionRefresh`` is enabled (session.ts:82-86):
    ``APIError.from("METHOD_NOT_ALLOWED", METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED)``.
    Mirrors session-api.test.ts:1964 "should reject POST when deferSessionRefresh is
    not enabled"; the body carries TS's code/message verbatim (core codes.ts:66-67).
    """
    response = await client.post("/api/auth/get-session")
    assert response.status_code == 405
    assert response.json() == {
        "code": "METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED",
        "message": "POST method requires deferSessionRefresh to be enabled in session config",
    }


# --- session.deferSessionRefresh (session.ts:78-86, 385-389, 437-455) -----------------
# Mirrors the TS suite at session-api.test.ts:1835-2082. TS forces `updateAge: 0` to make
# a session due for refresh straight away; same trick here.


def _defer_auth(**session_kwargs):
    return make_auth(session=SessionOptions(defer_session_refresh=True, **session_kwargs))


def _session_write_spy(auth):
    """Count writes to the ``session`` table (TS spies on ``internalAdapter.updateSession``
    / ``deleteSession``)."""
    calls = {"update": 0, "delete": 0}
    internal = auth.internal
    update, delete_many = internal.update, internal.delete_many

    async def spy_update(model, where, data, **kwargs):
        calls["update"] += model == "session"
        return await update(model, where, data, **kwargs)

    async def spy_delete_many(model, where, **kwargs):
        calls["delete"] += model == "session"
        return await delete_many(model, where, **kwargs)

    internal.update, internal.delete_many = spy_update, spy_delete_many
    return calls


async def test_defer_get_returns_needs_refresh_true_when_due():
    """session-api.test.ts:1840 — GET carries ``needsRefresh`` (session.ts:440-455)."""
    auth = _defer_auth(update_age=0)
    async with make_client(auth) as client:
        await sign_up(client)
        body = (await client.get("/api/auth/get-session")).json()
        assert body["needsRefresh"] is True
        assert body["user"]["email"] == SIGNUP["email"]


async def test_defer_get_returns_needs_refresh_false_when_fresh():
    """session-api.test.ts:1870 — a session that isn't due yet reports ``False``."""
    auth = _defer_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        assert (await client.get("/api/auth/get-session")).json()["needsRefresh"] is False


async def test_defer_get_performs_no_session_write():
    """session-api.test.ts:1897 — the deferred GET must not touch the session row."""
    auth = _defer_auth(update_age=0)
    async with make_client(auth) as client:
        await sign_up(client)
        before = (await auth.adapter.find_many("session"))[0]
        calls = _session_write_spy(auth)
        response = await client.get("/api/auth/get-session")
        assert response.status_code == 200
        assert calls == {"update": 0, "delete": 0}
        assert (await auth.adapter.find_many("session"))[0]["expiresAt"] == before["expiresAt"]


async def test_defer_post_refreshes_and_omits_needs_refresh():
    """session-api.test.ts:1929 — POST does the write the GET deferred, and its body has
    no ``needsRefresh`` (it took the normal refresh path)."""
    auth = _defer_auth(update_age=0)
    async with make_client(auth) as client:
        await sign_up(client)
        stale = utcnow() + timedelta(seconds=auth.session_options.expires_in - 60)
        await auth.adapter.update_many("session", [], {"expiresAt": stale})
        calls = _session_write_spy(auth)

        response = await client.post("/api/auth/get-session")
        assert response.status_code == 200
        body = response.json()
        assert body["user"]["email"] == SIGNUP["email"]
        assert "needsRefresh" not in body
        assert calls["update"] == 1
        assert (await auth.adapter.find_many("session"))[0]["expiresAt"] > stale
        # the no-store headers are set for both methods (session.ts:74-75)
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["pragma"] == "no-cache"


async def test_defer_get_keeps_expired_session_row():
    """session-api.test.ts:1985 — GET returns null but leaves the cleanup to POST
    (session.ts:385-389), so a read replica never writes."""
    auth = _defer_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        await auth.adapter.update_many("session", [], {"expiresAt": utcnow() - timedelta(1)})
        calls = _session_write_spy(auth)

        response = await client.get("/api/auth/get-session")
        assert response.json() is None
        assert calls["delete"] == 0
        assert len(await auth.adapter.find_many("session")) == 1
        assert any("Max-Age=0" in c for c in response.headers.get_list("set-cookie"))


async def test_defer_post_deletes_expired_session_row():
    """session-api.test.ts:2018 — POST performs the deferred cleanup."""
    auth = _defer_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        await auth.adapter.update_many("session", [], {"expiresAt": utcnow() - timedelta(1)})
        calls = _session_write_spy(auth)

        assert (await client.post("/api/auth/get-session")).json() is None
        assert calls["delete"] == 1
        assert await auth.adapter.find_many("session") == []


async def test_without_defer_get_still_refreshes_and_omits_needs_refresh():
    """session-api.test.ts:2052 — default behaviour is untouched."""
    auth = make_auth(session=SessionOptions(update_age=0))
    async with make_client(auth) as client:
        await sign_up(client)
        calls = _session_write_spy(auth)
        body = (await client.get("/api/auth/get-session")).json()
        assert "needsRefresh" not in body
        assert calls["update"] == 1


async def test_defer_needs_refresh_false_when_session_refresh_disabled():
    """session-api.test.ts:2085 — ``session.disableSessionRefresh`` folds into the
    ``needsRefresh`` predicate (session.ts:429-435), so a due session reports ``False``."""
    auth = _defer_auth(update_age=0, disable_session_refresh=True)
    async with make_client(auth) as client:
        await sign_up(client)
        body = (await client.get("/api/auth/get-session")).json()
        assert body is not None
        assert body["needsRefresh"] is False


async def test_disable_session_refresh_skips_refresh_on_plain_get():
    """The same predicate gates the write itself (session.ts:456), so the option skips the
    refresh on an ordinary GET too — ``regardless of the updateAge option``
    (init-options.ts:909-915). Contrast with the ``update_age=0`` case above it."""
    auth = make_auth(session=SessionOptions(update_age=0, disable_session_refresh=True))
    async with make_client(auth) as client:
        await sign_up(client)
        before = (await auth.adapter.find_many("session"))[0]
        calls = _session_write_spy(auth)

        body = (await client.get("/api/auth/get-session")).json()
        assert body["user"]["email"] == SIGNUP["email"]
        assert "needsRefresh" not in body  # only the deferred read carries the flag
        assert calls["update"] == 0
        assert (await auth.adapter.find_many("session"))[0]["expiresAt"] == before["expiresAt"]


async def test_defer_does_not_leak_needs_refresh_into_other_endpoints():
    """Session-gated endpoints resolve through the same read path (TS forces
    ``method: "GET"`` in getSessionFromCtx, session.ts:563) — they must still not write,
    and ``needsRefresh`` must not surface in their bodies."""
    auth = _defer_auth(update_age=0)
    async with make_client(auth) as client:
        await sign_up(client)
        calls = _session_write_spy(auth)
        sessions = (await client.get("/api/auth/list-sessions")).json()
        assert calls["update"] == 0
        assert all("needsRefresh" not in s for s in sessions)


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
