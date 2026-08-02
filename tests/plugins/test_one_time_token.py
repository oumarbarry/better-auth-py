"""one-time-token plugin — mint a short-lived single-use token from a session, then
exchange it for that session.

Verified against TS `packages/better-auth/src/plugins/one-time-token/index.ts` (and
`utils.ts`) and `one-time-token.test.ts` at v1.6.23.
"""

from __future__ import annotations

import asyncio
from datetime import timedelta

from better_auth import Where
from better_auth.crypto import default_key_hasher
from better_auth.plugins_ext.one_time_token import OneTimeTokenPlugin
from better_auth.session import utcnow
from better_auth.types import AuthRequest, Ctx
from conftest import SIGNUP, make_auth, make_client, sign_up


def ott_auth(**kwargs):
    return make_auth(plugins=[OneTimeTokenPlugin(**kwargs)])


def _ott_plugin(auth) -> OneTimeTokenPlugin:
    return next(p for p in auth.plugins if isinstance(p, OneTimeTokenPlugin))


# --- generate + verify happy path ---------------------------------------------------


async def test_generate_and_verify_returns_session_then_single_use():
    auth = ott_auth()
    async with make_client(auth) as client:
        data = await sign_up(client)
        gen = await client.get("/api/auth/one-time-token/generate")
        assert gen.status_code == 200
        token = gen.json()["token"]
        assert len(token) == 32

    async with make_client(auth) as verifier:
        verify = await verifier.post("/api/auth/one-time-token/verify", json={"token": token})
        assert verify.status_code == 200
        body = verify.json()
        assert body["session"]["token"] == data["token"]
        assert body["user"]["email"] == "ada@example.com"
        cookies = verify.headers.get_list("set-cookie")
        assert any(c.startswith("better-auth.session_token=") for c in cookies)

        second = await verifier.post("/api/auth/one-time-token/verify", json={"token": token})
        assert second.status_code == 400
        assert second.json()["message"] == "Invalid token"


async def test_verify_is_single_use_under_concurrency():
    """Required concurrency proof: N concurrent verifies of the SAME token -> exactly
    one success. The atomic consume itself is already proven (W3-A); this proves the
    endpoint actually routes through it."""
    auth = ott_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        gen = await client.get("/api/auth/one-time-token/generate")
        token = gen.json()["token"]

        results = await asyncio.gather(
            *(
                client.post("/api/auth/one-time-token/verify", json={"token": token})
                for _ in range(8)
            )
        )
    successes = [r for r in results if r.status_code == 200]
    failures = [r for r in results if r.status_code == 400]
    assert len(successes) == 1
    assert len(failures) == 7


async def test_generate_requires_session():
    async with make_client(ott_auth()) as client:
        response = await client.get("/api/auth/one-time-token/generate")
        assert response.status_code == 401


async def test_verify_invalid_token_message():
    async with make_client(ott_auth()) as client:
        response = await client.post("/api/auth/one-time-token/verify", json={"token": "nope"})
        assert response.status_code == 400
        assert response.json()["message"] == "Invalid token"


async def test_verify_missing_token_message():
    async with make_client(ott_auth()) as client:
        response = await client.post("/api/auth/one-time-token/verify", json={})
        assert response.status_code == 400
        assert response.json()["message"] == "Invalid token"


# --- expiry ---------------------------------------------------------------------------


async def test_token_expires_after_expires_in():
    auth = ott_auth(expires_in=1)
    async with make_client(auth) as client:
        await sign_up(client)
        gen = await client.get("/api/auth/one-time-token/generate")
        token = gen.json()["token"]

        row = await auth.adapter.find_one(
            "verification", [Where("identifier", f"one-time-token:{token}")]
        )
        assert row is not None
        await auth.adapter.update_many(
            "verification", [Where("id", row["id"])], {"expiresAt": utcnow() - timedelta(seconds=1)}
        )

        verify = await client.post("/api/auth/one-time-token/verify", json={"token": token})
        assert verify.status_code == 400
        assert verify.json()["message"] == "Invalid token"


async def test_verify_rejects_when_underlying_session_expired():
    auth = ott_auth()
    async with make_client(auth) as client:
        data = await sign_up(client)
        gen = await client.get("/api/auth/one-time-token/generate")
        token = gen.json()["token"]

        await auth.adapter.update_many(
            "session",
            [Where("token", data["token"])],
            {"expiresAt": utcnow() - timedelta(seconds=1)},
        )

        verify = await client.post("/api/auth/one-time-token/verify", json={"token": token})
        assert verify.status_code == 400
        assert verify.json()["message"] == "Session expired"


# --- storeToken options ---------------------------------------------------------------


async def test_store_token_hashed_stores_hashed_identifier():
    async def fixed_token(session, ctx):
        return "123456"

    auth = ott_auth(store_token="hashed", generate_token=fixed_token)
    async with make_client(auth) as client:
        await sign_up(client)
        gen = await client.get("/api/auth/one-time-token/generate")
        assert gen.json()["token"] == "123456"

        hashed = default_key_hasher("123456")
        row = await auth.adapter.find_one(
            "verification", [Where("identifier", f"one-time-token:{hashed}")]
        )
        assert row is not None

        verify = await client.post("/api/auth/one-time-token/verify", json={"token": "123456"})
        assert verify.status_code == 200
        assert verify.json()["user"]["email"] == "ada@example.com"


async def test_store_token_custom_hasher():
    async def fixed_token(session, ctx):
        return "123456"

    auth = ott_auth(
        store_token={"type": "custom-hasher", "hash": lambda token: token + "hashed"},
        generate_token=fixed_token,
    )
    async with make_client(auth) as client:
        await sign_up(client)
        gen = await client.get("/api/auth/one-time-token/generate")
        assert gen.json()["token"] == "123456"

        row = await auth.adapter.find_one(
            "verification", [Where("identifier", "one-time-token:123456hashed")]
        )
        assert row is not None

        verify = await client.post("/api/auth/one-time-token/verify", json={"token": "123456"})
        assert verify.status_code == 200


# --- disableClientRequest --------------------------------------------------------------


async def test_disable_client_request_blocks_http_dispatched_calls():
    auth = ott_auth(disable_client_request=True)
    async with make_client(auth) as client:
        await sign_up(client)
        response = await client.get("/api/auth/one-time-token/generate")
        assert response.status_code == 400
        assert response.json()["message"] == "Client requests are disabled"


async def test_disable_client_request_still_allows_server_side_token_minting():
    """The Python port is HTTP-dispatch-only — there is no `auth.api.X()` surface
    distinct from the HTTP endpoint, so `disable_client_request` disables the public
    `/one-time-token/generate` endpoint outright (see the ``generate`` docstring). A
    first-party server integration mints a token without going through HTTP at all,
    by calling the plugin's internal generator directly — the capability itself is
    never gated, only the public endpoint is."""
    auth = ott_auth(disable_client_request=True)
    async with make_client(auth) as client:
        await sign_up(client)
    user = await auth.adapter.find_one("user", [Where("email", "ada@example.com")])
    session = await auth.adapter.find_one("session", [Where("userId", user["id"])])

    plugin = _ott_plugin(auth)
    request = AuthRequest(method="GET", path="/one-time-token/generate")
    ctx = Ctx(auth=auth, request=request)
    token = await plugin._generate_token(ctx, {"session": session, "user": user})
    assert token


# --- disableSetSessionCookie ------------------------------------------------------------


async def test_disable_set_session_cookie_suppresses_cookie():
    auth = ott_auth(disable_set_session_cookie=True)
    async with make_client(auth) as client:
        await sign_up(client)
        gen = await client.get("/api/auth/one-time-token/generate")
        token = gen.json()["token"]

    async with make_client(auth) as verifier:
        verify = await verifier.post("/api/auth/one-time-token/verify", json={"token": token})
        assert verify.status_code == 200
        assert verify.headers.get("set-cookie") is None


async def test_session_cookie_set_by_default():
    auth = ott_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        gen = await client.get("/api/auth/one-time-token/generate")
        token = gen.json()["token"]

    async with make_client(auth) as verifier:
        verify = await verifier.post("/api/auth/one-time-token/verify", json={"token": token})
        assert verify.headers.get("set-cookie") is not None


# --- setOttHeaderOnNewSession -----------------------------------------------------------


async def test_set_ott_header_on_new_session_sign_up():
    auth = ott_auth(set_ott_header_on_new_session=True)
    async with make_client(auth) as client:
        response = await client.post(
            "/api/auth/sign-up/email",
            json={"name": "Ada", "email": "ada@example.com", "password": "s3cret-password"},
        )
        assert response.status_code == 200
        token = response.headers.get("set-ott")
        assert token is not None
        assert len(token) == 32
        exposed = response.headers.get("access-control-expose-headers", "")
        assert "set-ott" in [h.strip() for h in exposed.split(",")]


async def test_set_ott_header_on_new_session_sign_in():
    auth = ott_auth(set_ott_header_on_new_session=True)
    async with make_client(auth) as client:
        await sign_up(client)
        client.cookies.clear()
        response = await client.post("/api/auth/sign-in/email", json=SIGNUP)
        assert response.status_code == 200
        token = response.headers.get("set-ott")
        assert token is not None
        assert len(token) == 32


async def test_set_ott_header_not_set_by_default():
    async with make_client(ott_auth()) as client:
        response = await client.post(
            "/api/auth/sign-up/email",
            json={"name": "Ada", "email": "ada@example.com", "password": "s3cret-password"},
        )
        assert response.status_code == 200
        assert response.headers.get("set-ott") is None


async def test_verify_itself_sets_ott_header_when_enabled():
    """TS `setSessionCookie` also calls `ctx.context.setNewSession(session)`, so
    verifying a token (which sets the session cookie) also re-arms the
    `setOttHeaderOnNewSession` after-hook for its own response."""
    auth = ott_auth(set_ott_header_on_new_session=True)
    async with make_client(auth) as client:
        await sign_up(client)
        gen = await client.get("/api/auth/one-time-token/generate")
        token = gen.json()["token"]

    async with make_client(auth) as verifier:
        response = await verifier.post("/api/auth/one-time-token/verify", json={"token": token})
        assert response.status_code == 200
        assert response.headers.get("set-ott") is not None


async def test_verify_does_not_set_ott_header_when_cookie_disabled():
    auth = ott_auth(set_ott_header_on_new_session=True, disable_set_session_cookie=True)
    async with make_client(auth) as client:
        await sign_up(client)
        gen = await client.get("/api/auth/one-time-token/generate")
        token = gen.json()["token"]

    async with make_client(auth) as verifier:
        response = await verifier.post("/api/auth/one-time-token/verify", json={"token": token})
        assert response.status_code == 200
        assert response.headers.get("set-ott") is None
