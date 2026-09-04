"""multi-session plugin — several device sessions signed in at once, switched/revoked
via per-session cookies.

Verified against TS `packages/better-auth/src/plugins/multi-session/index.ts` (+
`error-codes.ts`, `multi-session.test.ts`) at v1.6.23.
"""

from __future__ import annotations

from datetime import timedelta

from better_auth.adapters.base import Where
from better_auth.crypto import unsign_value
from better_auth.plugins_ext.multi_session import ERROR_CODES, MultiSessionPlugin
from better_auth.session import utcnow
from conftest import SECRET, SIGNUP, make_auth, make_client


def multi_session_auth(**kwargs):
    return make_auth(plugins=[MultiSessionPlugin(**kwargs)])


async def _sign_up(client, **overrides):
    payload = {**SIGNUP, **overrides}
    response = await client.post("/api/auth/sign-up/email", json=payload)
    assert response.status_code == 200, response.text
    return response


async def _sign_in(client, **overrides):
    payload = {"email": SIGNUP["email"], "password": SIGNUP["password"], **overrides}
    response = await client.post("/api/auth/sign-in/email", json=payload)
    assert response.status_code == 200, response.text
    return response


def _multi_name(token: str) -> str:
    return f"better-auth.session_token_multi-{token.lower()}"


def _cookie_value(set_cookie_headers: list[str], name: str) -> str | None:
    for raw in set_cookie_headers:
        cname, _, rest = raw.partition("=")
        if cname == name:
            return rest.split(";", 1)[0]
    return None


def _is_cleared(set_cookie_headers: list[str], name: str) -> bool:
    return any(c.startswith(f"{name}=") and "Max-Age=0" in c for c in set_cookie_headers)


# --- config / error-code shape ----------------------------------------------------------


def test_default_maximum_sessions_is_five():
    assert MultiSessionPlugin().maximum_sessions == 5


def test_error_codes_shape():
    assert ERROR_CODES == {"INVALID_SESSION_TOKEN": "Invalid session token"}
    assert MultiSessionPlugin.error_codes == ERROR_CODES


# --- cookie scheme: name pattern + signing byte-compat -----------------------------------


async def test_sign_up_sets_multi_session_cookie_with_signed_value():
    async with make_client(multi_session_auth()) as client:
        response = await _sign_up(client)
        token = response.json()["token"]
        set_cookies = response.headers.get_list("set-cookie")

        name = _multi_name(token)
        assert any(c.startswith(f"{name}=") for c in set_cookies)
        raw_value = _cookie_value(set_cookies, name)
        assert raw_value is not None
        # signed exactly like the main session cookie (crypto.sign_value/unsign_value)
        assert unsign_value(SECRET, raw_value) == token


# --- list-device-sessions -----------------------------------------------------------------


async def test_two_sign_ins_list_shows_both_sessions():
    async with make_client(multi_session_auth()) as client:
        await _sign_up(client)
        await _sign_up(client, email="second@example.com")

        response = await client.get("/api/auth/multi-session/list-device-sessions")
        assert response.status_code == 200
        body = response.json()
        assert len(body) == 2
        assert {item["user"]["email"] for item in body} == {SIGNUP["email"], "second@example.com"}


async def test_expired_session_filtered_from_device_list():
    auth = multi_session_auth()
    async with make_client(auth) as client:
        stale = (await _sign_up(client)).json()
        await _sign_up(client, email="fresh@example.com")
        await auth.adapter.update(
            "session",
            [Where("token", stale["token"])],
            {"expiresAt": utcnow() - timedelta(seconds=1)},
        )

        body = (await client.get("/api/auth/multi-session/list-device-sessions")).json()
        assert len(body) == 1
        assert body[0]["user"]["email"] == "fresh@example.com"


# --- set-active -----------------------------------------------------------------------


async def test_set_active_switches_active_session():
    async with make_client(multi_session_auth()) as client:
        first = (await _sign_up(client)).json()
        await _sign_up(client, email="second@example.com")
        assert (await client.get("/api/auth/get-session")).json()["user"]["email"] == (
            "second@example.com"
        )

        response = await client.post(
            "/api/auth/multi-session/set-active", json={"sessionToken": first["token"]}
        )
        assert response.status_code == 200
        assert response.json()["user"]["email"] == SIGNUP["email"]
        assert (await client.get("/api/auth/get-session")).json()["user"]["email"] == (
            SIGNUP["email"]
        )


async def test_set_active_rejects_unknown_token():
    async with make_client(multi_session_auth()) as client:
        await _sign_up(client)
        response = await client.post(
            "/api/auth/multi-session/set-active", json={"sessionToken": "not-a-real-token"}
        )
        assert response.status_code == 401
        assert response.json() == {
            "code": "INVALID_SESSION_TOKEN",
            "message": "Invalid session token",
        }


async def test_set_active_rejects_expired_session_and_clears_its_cookie():
    auth = multi_session_auth()
    async with make_client(auth) as client:
        data = (await _sign_up(client)).json()
        token = data["token"]
        await auth.adapter.update(
            "session", [Where("token", token)], {"expiresAt": utcnow() - timedelta(seconds=1)}
        )

        response = await client.post(
            "/api/auth/multi-session/set-active", json={"sessionToken": token}
        )
        assert response.status_code == 401
        assert response.json()["code"] == "INVALID_SESSION_TOKEN"
        assert _is_cleared(response.headers.get_list("set-cookie"), _multi_name(token))


# --- revoke -----------------------------------------------------------------------------


async def test_revoke_removes_non_active_session_and_clears_its_cookie():
    async with make_client(multi_session_auth()) as client:
        first = (await _sign_up(client)).json()
        await _sign_up(client, email="second@example.com")  # now active

        response = await client.post(
            "/api/auth/multi-session/revoke", json={"sessionToken": first["token"]}
        )
        assert response.status_code == 200
        assert response.json() == {"status": True}
        assert _is_cleared(response.headers.get_list("set-cookie"), _multi_name(first["token"]))

        listing = (await client.get("/api/auth/multi-session/list-device-sessions")).json()
        assert len(listing) == 1
        assert listing[0]["user"]["email"] == "second@example.com"
        # the still-active (second) session is untouched
        assert (await client.get("/api/auth/get-session")).json()["user"]["email"] == (
            "second@example.com"
        )


async def test_revoke_active_session_promotes_next_valid_session():
    async with make_client(multi_session_auth()) as client:
        await _sign_up(client)
        second = (await _sign_up(client, email="second@example.com")).json()  # now active

        response = await client.post(
            "/api/auth/multi-session/revoke", json={"sessionToken": second["token"]}
        )
        assert response.status_code == 200
        set_cookies = response.headers.get_list("set-cookie")
        main_cookie = next(c for c in set_cookies if c.startswith("better-auth.session_token="))
        assert "Max-Age=0" not in main_cookie  # promoted, not cleared

        assert (await client.get("/api/auth/get-session")).json()["user"]["email"] == (
            SIGNUP["email"]
        )


async def test_revoke_only_active_session_clears_main_cookie():
    async with make_client(multi_session_auth()) as client:
        data = (await _sign_up(client)).json()

        response = await client.post(
            "/api/auth/multi-session/revoke", json={"sessionToken": data["token"]}
        )
        assert response.status_code == 200
        set_cookies = response.headers.get_list("set-cookie")
        assert _is_cleared(set_cookies, "better-auth.session_token")
        assert (await client.get("/api/auth/get-session")).json() is None


async def test_revoke_requires_active_session():
    async with make_client(multi_session_auth()) as client:
        response = await client.post(
            "/api/auth/multi-session/revoke", json={"sessionToken": "whatever"}
        )
        assert response.status_code == 401
        assert response.json()["code"] == "UNAUTHORIZED"


async def test_revoke_binds_to_signed_cookie_value_not_body_token():
    """Security: `revoke` must act on the token proven by the signed cookie *value*
    found at the request-derived cookie name, never on the body's claimed token —
    the signature covers the value, not the cookie's name."""
    auth = multi_session_auth()
    async with make_client(auth) as caller_client, make_client(auth) as other_client:
        caller_signup = await _sign_up(caller_client, email="caller@example.com")
        caller = caller_signup.json()
        caller_multi_name = _multi_name(caller["token"])
        caller_signed_value = _cookie_value(
            caller_signup.headers.get_list("set-cookie"), caller_multi_name
        )
        assert caller_signed_value is not None

        other = (await _sign_up(other_client, email="other@example.com")).json()

        # Caller's own cookies, PLUS a cookie NAMED after the other user's token but
        # holding the CALLER's own validly-signed value.
        caller_cookie_header = "; ".join(f"{k}={v}" for k, v in dict(caller_client.cookies).items())
        forged_entry = f"{_multi_name(other['token'])}={caller_signed_value}"
        crafted_headers = {"cookie": f"{caller_cookie_header}; {forged_entry}"}

        response = await caller_client.post(
            "/api/auth/multi-session/revoke",
            json={"sessionToken": other["token"]},
            headers=crafted_headers,
        )
        assert response.status_code == 200

        # the OTHER user's session must be completely untouched
        other_after = await other_client.get("/api/auth/get-session")
        assert other_after.json()["user"]["email"] == "other@example.com"
        assert other_after.json()["session"]["token"] == other["token"]


# --- sign-out cleanup hook ---------------------------------------------------------------


async def test_sign_out_revokes_all_device_sessions_and_clears_their_cookies():
    auth = multi_session_auth()
    async with make_client(auth) as client:
        first = (await _sign_up(client)).json()
        second = (await _sign_up(client, email="second@example.com")).json()

        response = await client.post("/api/auth/sign-out")
        assert response.status_code == 200
        set_cookies = response.headers.get_list("set-cookie")
        assert _is_cleared(set_cookies, _multi_name(first["token"]))
        assert _is_cleared(set_cookies, _multi_name(second["token"]))
        assert await auth.adapter.find_many("session") == []


async def test_sign_out_ignores_forged_multi_session_cookie():
    """A cookie whose signature doesn't verify must be left alone entirely (never
    cleared, never used to delete a session) -- matches the TS regression test for
    a forged `_multi-` cookie planted under another user's token."""
    auth = multi_session_auth()
    async with make_client(auth) as attacker_client, make_client(auth) as victim_client:
        await _sign_up(attacker_client, email="attacker@example.com")
        victim = (await _sign_up(victim_client, email="victim@example.com")).json()

        forged_name = _multi_name(victim["token"])
        attacker_cookie_header = "; ".join(
            f"{k}={v}" for k, v in dict(attacker_client.cookies).items()
        )
        crafted_headers = {
            "cookie": f"{attacker_cookie_header}; {forged_name}={victim['token']}.fake-signature"
        }

        await attacker_client.post("/api/auth/sign-out", headers=crafted_headers)

        victim_after = await victim_client.get("/api/auth/get-session")
        assert victim_after.json()["user"]["email"] == "victim@example.com"


# --- over-cap eviction -------------------------------------------------------------------


async def test_over_cap_sign_in_does_not_get_a_device_cookie():
    async with make_client(multi_session_auth(maximum_sessions=2)) as client:
        await _sign_up(client, email="one@example.com")
        await _sign_up(client, email="two@example.com")
        await _sign_up(client, email="three@example.com")

        listing = (await client.get("/api/auth/multi-session/list-device-sessions")).json()
        assert len(listing) == 2
        assert "three@example.com" not in {item["user"]["email"] for item in listing}

        # third user's own primary session is still perfectly valid -- just not
        # enumerable as a device session (no cookie slot left under the cap)
        current = await client.get("/api/auth/get-session")
        assert current.json()["user"]["email"] == "three@example.com"


# --- same-user re-sign-in replaces the stale device cookie -------------------------------


async def test_same_user_resign_in_replaces_old_device_cookie():
    async with make_client(multi_session_auth()) as client:
        first = (await _sign_up(client)).json()
        response = await _sign_in(client)
        second = response.json()
        assert second["token"] != first["token"]

        set_cookies = response.headers.get_list("set-cookie")
        assert _is_cleared(set_cookies, _multi_name(first["token"]))

        listing = (await client.get("/api/auth/multi-session/list-device-sessions")).json()
        assert len(listing) == 1
        assert listing[0]["session"]["token"] == second["token"]
