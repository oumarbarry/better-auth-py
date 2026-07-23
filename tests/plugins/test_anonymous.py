"""anonymous plugin — throwaway anonymous user/session, auto-link + cleanup on a
real sign-in.

Verified against TS `packages/better-auth/src/plugins/anonymous/index.ts` and
`anon.test.ts`.
"""

from __future__ import annotations

from datetime import timedelta

import pytest

from better_auth import EmailAndPassword, EmailVerification
from better_auth.adapters.base import Where
from better_auth.crypto import sign_value
from better_auth.plugins_ext.anonymous import ERROR_CODES, AnonymousPlugin
from better_auth.session import cookie_name, create_session, utcnow
from better_auth.types import APIError, AuthRequest, AuthResponse, Ctx
from conftest import SIGNUP, make_auth, make_client, sign_up


def anon_auth(**kwargs):
    return make_auth(plugins=[AnonymousPlugin(**kwargs)])


def _anon_plugin(auth) -> AnonymousPlugin:
    return next(p for p in auth.plugins if isinstance(p, AnonymousPlugin))


# --- sign-in/anonymous ------------------------------------------------------------


async def test_sign_in_anonymously_creates_user_and_session():
    async with make_client(anon_auth()) as client:
        response = await client.post("/api/auth/sign-in/anonymous")
        assert response.status_code == 200
        body = response.json()
        assert body["token"]
        assert body["user"]["isAnonymous"] is True
        assert body["user"]["name"] == "Anonymous"
        assert body["user"]["email"].startswith("temp@")
        assert body["user"]["email"].endswith(".com")

        session = (await client.get("/api/auth/get-session")).json()
        assert session["user"]["isAnonymous"] is True


async def test_email_domain_name_changes_temp_email_shape():
    async with make_client(anon_auth(email_domain_name="example.com")) as client:
        response = await client.post("/api/auth/sign-in/anonymous")
        email = response.json()["user"]["email"]
        assert email.startswith("temp-")
        assert email.endswith("@example.com")


async def test_isanonymous_defaults_false_for_a_regular_user():
    # sign_up_email's response body reflects the hand-built pre-write dict, not a
    # DB round-trip, so the schema-injected default is only visible on a real read
    # (get-session) — same surface the TS test itself asserts through.
    async with make_client(anon_auth()) as client:
        await sign_up(client)
        session = (await client.get("/api/auth/get-session")).json()
        assert session["user"]["isAnonymous"] is False


async def test_generate_name_sync():
    auth = anon_auth(generate_name=lambda ctx: "i-am-anonymous")
    async with make_client(auth) as client:
        response = await client.post("/api/auth/sign-in/anonymous")
        assert response.json()["user"]["name"] == "i-am-anonymous"


async def test_generate_name_async():
    async def gen_name(ctx):
        return "i-am-async-anonymous"

    auth = anon_auth(generate_name=gen_name)
    async with make_client(auth) as client:
        response = await client.post("/api/auth/sign-in/anonymous")
        assert response.json()["user"]["name"] == "i-am-async-anonymous"


async def test_generate_random_email_sync():
    auth = anon_auth(generate_random_email=lambda: "custom-1@example.com")
    async with make_client(auth) as client:
        response = await client.post("/api/auth/sign-in/anonymous")
        assert response.json()["user"]["email"] == "custom-1@example.com"


async def test_generate_random_email_async():
    async def gen_email():
        return "custom-2@example.com"

    auth = anon_auth(generate_random_email=gen_email)
    async with make_client(auth) as client:
        response = await client.post("/api/auth/sign-in/anonymous")
        assert response.json()["user"]["email"] == "custom-2@example.com"


async def test_generate_random_email_invalid_raises_sync():
    auth = anon_auth(generate_random_email=lambda: "not-an-email")
    async with make_client(auth) as client:
        response = await client.post("/api/auth/sign-in/anonymous")
        assert response.status_code == 400
        assert response.json()["code"] == "INVALID_EMAIL_FORMAT"
        assert response.json()["message"] == ERROR_CODES["INVALID_EMAIL_FORMAT"]


async def test_generate_random_email_invalid_raises_async():
    async def gen_email():
        return "still-not-an-email"

    auth = anon_auth(generate_random_email=gen_email)
    async with make_client(auth) as client:
        response = await client.post("/api/auth/sign-in/anonymous")
        assert response.status_code == 400
        assert response.json()["message"] == ERROR_CODES["INVALID_EMAIL_FORMAT"]


async def test_first_anonymous_sign_in_allowed_then_subsequent_rejected():
    async with make_client(anon_auth()) as client:
        first = await client.post("/api/auth/sign-in/anonymous")
        assert first.status_code == 200

        second = await client.post("/api/auth/sign-in/anonymous")
        assert second.status_code == 400
        assert second.json()["code"] == "ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY"
        assert (
            second.json()["message"]
            == ERROR_CODES["ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY"]
        )


# --- link on real sign-in / email verification -------------------------------------


async def test_link_on_email_sign_in_deletes_previous_anon_user():
    events = []

    async def on_link_account(data):
        events.append(data)

    auth = anon_auth(on_link_account=on_link_account)
    async with make_client(auth) as setup_client:
        await sign_up(setup_client)  # ada@example.com exists, unrelated cookie jar

    async with make_client(auth) as client:
        anon = await client.post("/api/auth/sign-in/anonymous")
        anon_user_id = anon.json()["user"]["id"]

        signin = await client.post("/api/auth/sign-in/email", json=SIGNUP)
        assert signin.status_code == 200

    assert len(events) == 1
    assert events[0]["anonymous_user"]["user"]["id"] == anon_user_id
    assert events[0]["new_user"]["user"]["email"] == "ada@example.com"
    assert await auth.adapter.find_one("user", [Where("id", anon_user_id)]) is None


async def test_on_link_account_fires_on_email_verification_of_anon_user():
    """https://github.com/better-auth/better-auth/issues/9485 (anon.test.ts)."""
    events = []
    captured: dict[str, str] = {}

    async def on_link_account(data):
        events.append(data)

    async def send_verification_email(user, url, token):
        captured["token"] = token

    auth = make_auth(
        plugins=[AnonymousPlugin(on_link_account=on_link_account)],
        email_and_password=EmailAndPassword(enabled=True, require_email_verification=True),
        email_verification=EmailVerification(
            auto_sign_in_after_verification=True,
            send_verification_email=send_verification_email,
        ),
    )
    async with make_client(auth) as client:
        anon = await client.post("/api/auth/sign-in/anonymous")
        assert anon.status_code == 200

        signup = await client.post(
            "/api/auth/sign-up/email",
            json={"name": "New User", "email": "newuser@example.com", "password": "password123"},
        )
        assert signup.status_code == 200
        assert signup.json()["token"] is None  # no session yet: verification required

        verify = await client.get("/api/auth/verify-email", params={"token": captured["token"]})
        assert verify.status_code == 200

    assert len(events) == 1
    assert events[0]["anonymous_user"]["user"]["isAnonymous"] is True
    assert events[0]["new_user"]["user"]["email"] == "newuser@example.com"


# --- cleanup safeguards (direct after-hook invocation, mirrors anon.test.ts) -------


async def _seed_anon_user_and_ctx(auth, *, path: str) -> tuple[dict, Ctx]:
    anon_user = await auth.internal.create_user(
        {"email": "temp@x.com", "emailVerified": False, "isAnonymous": True, "name": "Anonymous"}
    )
    assert anon_user is not None
    seed_request = AuthRequest(method="POST", path="/sign-in/anonymous")
    anon_session, _cookies = await create_session(
        auth, anon_user["id"], seed_request, user=anon_user
    )
    signed = sign_value(auth.secret, anon_session["token"])
    cookie_header = {"cookie": f"{cookie_name(auth)}={signed}"}
    request = AuthRequest(method="POST", path=path, headers=cookie_header)
    ctx = Ctx(auth=auth, request=request)
    ctx.response = AuthResponse(headers=[("set-cookie", f"{cookie_name(auth)}=new-value")])
    return anon_user, ctx


async def test_cleanup_safeguard_skips_delete_when_new_session_still_anonymous():
    auth = anon_auth()
    anon_user, ctx = await _seed_anon_user_and_ctx(auth, path="/sign-in/anonymous")
    ctx.new_session = {
        "session": {"token": "new-token"},
        "user": {"id": "other-anon", "isAnonymous": True},
    }

    hook = _anon_plugin(auth).hooks().after[0]
    await hook.handler(ctx)

    assert await auth.adapter.find_one("user", [Where("id", anon_user["id"])]) is not None


async def test_cleanup_deletes_previous_anon_user_when_linking_new_account():
    auth = anon_auth()
    anon_user, ctx = await _seed_anon_user_and_ctx(auth, path="/sign-in/email")
    ctx.new_session = {
        "session": {"token": "linked-token"},
        "user": {"id": "linked-user", "isAnonymous": False},
    }

    hook = _anon_plugin(auth).hooks().after[0]
    await hook.handler(ctx)

    assert await auth.adapter.find_one("user", [Where("id", anon_user["id"])]) is None
    assert await auth.adapter.find_many("session", [Where("userId", anon_user["id"])]) == []


async def test_cleanup_skips_delete_when_same_user():
    auth = anon_auth()
    anon_user, ctx = await _seed_anon_user_and_ctx(auth, path="/sign-in/email")
    ctx.new_session = {
        "session": {"token": "t"},
        "user": {"id": anon_user["id"], "isAnonymous": False},
    }

    hook = _anon_plugin(auth).hooks().after[0]
    await hook.handler(ctx)

    assert await auth.adapter.find_one("user", [Where("id", anon_user["id"])]) is not None


async def test_cleanup_skips_delete_when_disabled():
    auth = anon_auth(disable_delete_anonymous_user=True)
    anon_user, ctx = await _seed_anon_user_and_ctx(auth, path="/sign-in/email")
    ctx.new_session = {
        "session": {"token": "t"},
        "user": {"id": "linked-user", "isAnonymous": False},
    }

    hook = _anon_plugin(auth).hooks().after[0]
    await hook.handler(ctx)

    assert await auth.adapter.find_one("user", [Where("id", anon_user["id"])]) is not None


async def test_after_hook_reraises_when_sign_in_anonymous_has_no_new_session():
    """Defensive branch mirrored from TS (only reachable via a synthetic ctx like this
    one; the real endpoint always gates this before a response is ever built)."""
    auth = anon_auth()
    _anon_user, ctx = await _seed_anon_user_and_ctx(auth, path="/sign-in/anonymous")
    ctx.new_session = None

    hook = _anon_plugin(auth).hooks().after[0]
    with pytest.raises(APIError) as exc_info:
        await hook.handler(ctx)
    assert exc_info.value.code == "ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY"


async def test_after_hook_noop_on_unrelated_path_without_session_cookie():
    auth = anon_auth()
    request = AuthRequest(method="GET", path="/sign-in/anonymous")
    ctx = Ctx(auth=auth, request=request)
    ctx.response = AuthResponse(body={"ok": True})  # no set-cookie header at all

    hook = _anon_plugin(auth).hooks().after[0]
    result = await hook.handler(ctx)
    assert result is None


# --- delete-anonymous-user ----------------------------------------------------------


async def test_delete_anonymous_user_success_clears_cookie_and_removes_user():
    auth = anon_auth()
    async with make_client(auth) as client:
        anon = await client.post("/api/auth/sign-in/anonymous")
        user_id = anon.json()["user"]["id"]

        response = await client.post("/api/auth/delete-anonymous-user")
        assert response.status_code == 200
        assert response.json() == {"success": True}
        cleared = response.headers.get_list("set-cookie")
        assert any("Max-Age=0" in c for c in cleared)

    assert await auth.adapter.find_one("user", [Where("id", user_id)]) is None


async def test_delete_anonymous_user_accepts_old_but_valid_session():
    # TS sensitiveSessionMiddleware is an authoritative (cache-bypassing) session
    # read, NOT a freshness gate — a stale-but-valid session may still delete itself.
    auth = anon_auth()
    async with make_client(auth) as client:
        anon = await client.post("/api/auth/sign-in/anonymous")
        user_id = anon.json()["user"]["id"]
        token = anon.json()["token"]
        stale = utcnow() - timedelta(days=2)  # well past the default fresh_age (1 day)
        await auth.adapter.update("session", [Where("token", token)], {"createdAt": stale})

        response = await client.post("/api/auth/delete-anonymous-user")
        assert response.status_code == 200
        assert response.json() == {"success": True}
    assert await auth.adapter.find_one("user", [Where("id", user_id)]) is None


async def test_delete_anonymous_user_disabled():
    auth = anon_auth(disable_delete_anonymous_user=True)
    async with make_client(auth) as client:
        await client.post("/api/auth/sign-in/anonymous")
        response = await client.post("/api/auth/delete-anonymous-user")
        assert response.status_code == 400
        assert response.json()["code"] == "DELETE_ANONYMOUS_USER_DISABLED"


async def test_delete_anonymous_user_rejects_non_anonymous_user():
    auth = anon_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        response = await client.post("/api/auth/delete-anonymous-user")
        assert response.status_code == 403
        assert response.json()["code"] == "USER_IS_NOT_ANONYMOUS"


async def test_delete_anonymous_user_requires_session():
    async with make_client(anon_auth()) as client:
        response = await client.post("/api/auth/delete-anonymous-user")
        assert response.status_code == 401


# --- schema -------------------------------------------------------------------------


def test_schema_is_merged_and_includes_isanonymous():
    auth = anon_auth()
    assert "isAnonymous" in auth.schema["user"]
    field = auth.schema["user"]["isAnonymous"]
    assert field.type == "boolean"
    assert field.required is False
    assert field.input is False
    assert field.default is False


def test_error_codes_surface_on_auth_instance():
    auth = anon_auth()
    assert auth.error_codes["ANONYMOUS_USERS_CANNOT_SIGN_IN_AGAIN_ANONYMOUSLY"] == (
        "Anonymous users cannot sign in again anonymously"
    )
