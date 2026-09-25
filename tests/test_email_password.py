from datetime import timedelta

from better_auth import EmailAndPassword
from better_auth.crypto import generate_id
from better_auth.oauth import GitHub
from better_auth.session import utcnow
from conftest import SIGNUP, make_auth, make_client, sign_up


async def test_sign_up_returns_token_and_user(client):
    data = await sign_up(client)
    assert data["token"] and len(data["token"]) == 32
    user = data["user"]
    assert user["email"] == "ada@example.com"
    assert user["name"] == "Ada Lovelace"
    assert user["emailVerified"] is False
    assert "better-auth.session_token" in client.cookies


async def test_sign_up_normalizes_email(client):
    data = await sign_up(client, email="ADA@Example.COM")
    assert data["user"]["email"] == "ada@example.com"


async def test_sign_up_duplicate_email(client):
    await sign_up(client)
    response = await client.post("/api/auth/sign-up/email", json=SIGNUP)
    assert response.status_code == 422
    assert response.json()["code"] == "USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL"


async def test_sign_up_disabled_via_disable_sign_up():
    # `disableSignUp` blocks /sign-up/email specifically (EMAIL_PASSWORD_SIGN_UP_DISABLED),
    # distinct from `enabled=False` disabling the whole feature (EMAIL_PASSWORD_DISABLED
    # on e.g. /sign-in/email) — sign-up.ts's check ORs both conditions into the same code.
    auth = make_auth(email_and_password=EmailAndPassword(enabled=True, disable_sign_up=True))
    async with make_client(auth) as client:
        response = await client.post("/api/auth/sign-up/email", json=SIGNUP)
        assert response.status_code == 400
        assert response.json()["code"] == "EMAIL_PASSWORD_SIGN_UP_DISABLED"


async def test_sign_up_duplicate_email_enumeration_protection_require_verification():
    # sign-up.ts:235 — when requireEmailVerification is set, a duplicate sign-up
    # gets a fabricated user (200, token:null) instead of a 422, so an attacker
    # can't use /sign-up/email to enumerate registered addresses.
    auth = make_auth(
        email_and_password=EmailAndPassword(enabled=True, require_email_verification=True)
    )
    async with make_client(auth) as client:
        await client.post("/api/auth/sign-up/email", json=SIGNUP)
        response = await client.post("/api/auth/sign-up/email", json=SIGNUP)
        assert response.status_code == 200
        data = response.json()
        assert data["token"] is None
        assert data["user"]["email"] == SIGNUP["email"]
        assert data["user"]["name"] == SIGNUP["name"]
        assert data["user"]["emailVerified"] is False
        assert data["user"]["id"]  # a fresh synthetic id, not the real user's
        # the real (unverified) user is untouched — sign-in still blocks on
        # EMAIL_NOT_VERIFIED, not e.g. INVALID_EMAIL_OR_PASSWORD from a corrupted account
        real = await client.post("/api/auth/sign-in/email", json=SIGNUP)
        assert real.status_code == 403
        assert real.json()["code"] == "EMAIL_NOT_VERIFIED"


async def test_sign_up_duplicate_email_enumeration_protection_no_auto_sign_in():
    # Same protection kicks in when autoSignIn is disabled, even without
    # requireEmailVerification (sign-up.ts:235's OR condition).
    auth = make_auth(email_and_password=EmailAndPassword(enabled=True, auto_sign_in=False))
    async with make_client(auth) as client:
        await client.post("/api/auth/sign-up/email", json=SIGNUP)
        response = await client.post("/api/auth/sign-up/email", json=SIGNUP)
        assert response.status_code == 200
        assert response.json()["token"] is None


async def test_sign_up_invalid_email(client):
    response = await client.post(
        "/api/auth/sign-up/email", json={**SIGNUP, "email": "not-an-email"}
    )
    assert response.status_code == 400
    assert response.json()["code"] == "INVALID_EMAIL"


async def test_sign_in_invalid_email(client, monkeypatch):
    # sign-in.ts:484 (v1.6.29): the email format is checked before any lookup or hashing.
    from better_auth import crypto

    def no_scrypt(*_: object) -> bytes:
        raise AssertionError("scrypt must not run for a malformed email")

    monkeypatch.setattr(crypto, "_scrypt", no_scrypt)
    response = await client.post(
        "/api/auth/sign-in/email", json={"email": "not-an-email", "password": "s3cret-password"}
    )
    assert response.status_code == 400
    assert response.json() == {"code": "INVALID_EMAIL", "message": "Invalid email"}


async def test_sign_up_password_length(client):
    response = await client.post("/api/auth/sign-up/email", json={**SIGNUP, "password": "short"})
    assert response.status_code == 400
    assert response.json()["code"] == "PASSWORD_TOO_SHORT"

    response = await client.post("/api/auth/sign-up/email", json={**SIGNUP, "password": "x" * 200})
    assert response.json()["code"] == "PASSWORD_TOO_LONG"


async def test_sign_up_ignores_email_verified_from_body(client):
    data = await sign_up(client, emailVerified=True)
    assert data["user"]["emailVerified"] is False


async def test_sign_in_and_get_session(client):
    await sign_up(client)
    client.cookies.clear()

    response = await client.post(
        "/api/auth/sign-in/email",
        json={"email": SIGNUP["email"], "password": SIGNUP["password"]},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["redirect"] is False
    assert body["token"]
    assert body["user"]["email"] == SIGNUP["email"]

    session = (await client.get("/api/auth/get-session")).json()
    assert session["user"]["email"] == SIGNUP["email"]
    assert session["session"]["token"] == body["token"]


async def test_sign_in_with_callback_url(client):
    await sign_up(client)
    response = await client.post(
        "/api/auth/sign-in/email",
        json={**SIGNUP, "callbackURL": "/dashboard"},
    )
    body = response.json()
    assert body["redirect"] is True
    assert body["url"] == "/dashboard"


async def test_sign_in_wrong_password(client):
    await sign_up(client)
    response = await client.post(
        "/api/auth/sign-in/email",
        json={"email": SIGNUP["email"], "password": "wrong-password"},
    )
    assert response.status_code == 401
    assert response.json()["code"] == "INVALID_EMAIL_OR_PASSWORD"


async def test_sign_in_unknown_email_same_error(client):
    response = await client.post(
        "/api/auth/sign-in/email",
        json={"email": "ghost@example.com", "password": "whatever-123"},
    )
    assert response.status_code == 401
    assert response.json()["code"] == "INVALID_EMAIL_OR_PASSWORD"


async def test_sign_out(client):
    await sign_up(client)
    response = await client.post("/api/auth/sign-out")
    assert response.json() == {"success": True}
    assert (await client.get("/api/auth/get-session")).json() is None


async def test_sign_out_without_session(client):
    # sign-out.ts:77-166: no session cookie is still a successful, local sign-out
    response = await client.post("/api/auth/sign-out")
    assert response.status_code == 200
    assert response.json() == {"success": True}


async def test_sign_out_expires_the_session_cookies(client):
    # deleteSessionCookie (cookies/index.ts:517-555): token, cache and dont_remember
    await sign_up(client)
    response = await client.post("/api/auth/sign-out")
    expired = {
        c.split("=", 1)[0] for c in response.headers.get_list("set-cookie") if "Max-Age=0" in c
    }
    assert expired == {
        "better-auth.session_token",
        "better-auth.session_data",
        "better-auth.dont_remember",
    }


class _LogoutProvider(GitHub):
    """A provider with RP-initiated logout (TS ``createEndSessionURL``)."""

    calls: list[dict] = []

    async def create_end_session_url(
        self, *, id_token=None, post_logout_redirect_uri=None, state=None
    ):
        self.calls.append({"id_token": id_token, "post": post_logout_redirect_uri, "state": state})
        return f"https://idp.example/logout?id_token_hint={id_token}"


async def _logout_client_setup(auth, client):
    data = await sign_up(client)
    now = utcnow()
    for provider_id, id_token, age in (("github", "old-token", 60), ("github", "new-token", 0)):
        await auth.adapter.create(
            "account",
            {
                "id": generate_id(),
                "userId": data["user"]["id"],
                "providerId": provider_id,
                "accountId": id_token,
                "idToken": id_token,
                "createdAt": now,
                "updatedAt": now - timedelta(seconds=age),
            },
        )


async def test_sign_out_returns_the_provider_logout_url():
    # sign-out.ts:101-165 (430c89549): newest account of a provider with logout support
    _LogoutProvider.calls = []
    auth = make_auth(social_providers={"github": _LogoutProvider(client_id="c", client_secret="s")})
    async with make_client(auth) as client:
        await _logout_client_setup(auth, client)
        response = await client.post(
            "/api/auth/sign-out", json={"callbackURL": "/bye", "state": "xyz"}
        )
    url = "https://idp.example/logout?id_token_hint=new-token"
    assert response.status_code == 200
    assert response.json() == {"success": True, "url": url, "redirect": True}
    assert response.headers["location"] == url
    assert _LogoutProvider.calls == [
        {"id_token": "new-token", "post": "http://testserver/bye", "state": "xyz"}
    ]


async def test_sign_out_provider_logout_without_redirect():
    auth = make_auth(social_providers={"github": _LogoutProvider(client_id="c", client_secret="s")})
    async with make_client(auth) as client:
        await _logout_client_setup(auth, client)
        response = await client.post("/api/auth/sign-out", json={"disableRedirect": True})
    assert response.json()["redirect"] is False
    assert "location" not in response.headers


async def test_sign_out_rejects_an_untrusted_callback_url():
    auth = make_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        response = await client.post(
            "/api/auth/sign-out", json={"callbackURL": "https://evil.example/bye"}
        )
    assert response.status_code == 403
    assert response.json()["code"] == "INVALID_CALLBACK_URL"


async def test_protected_dependency(client):
    assert (await client.get("/protected")).status_code == 401
    await sign_up(client)
    response = await client.get("/protected")
    assert response.status_code == 200
    assert response.json() == {"email": SIGNUP["email"]}


async def test_optional_session_dependency(client):
    assert (await client.get("/maybe")).json() == {"authenticated": False}
    await sign_up(client)
    assert (await client.get("/maybe")).json() == {"authenticated": True}


async def test_bearer_token(auth, client):
    data = await sign_up(client)
    async with make_client(auth) as fresh:
        response = await fresh.get(
            "/protected", headers={"authorization": f"Bearer {data['token']}"}
        )
        assert response.status_code == 200


async def test_change_password(client):
    await sign_up(client)
    response = await client.post(
        "/api/auth/change-password",
        json={"currentPassword": SIGNUP["password"], "newPassword": "new-password-123"},
    )
    assert response.status_code == 200

    client.cookies.clear()
    old = await client.post("/api/auth/sign-in/email", json=SIGNUP)
    assert old.status_code == 401
    new = await client.post(
        "/api/auth/sign-in/email",
        json={"email": SIGNUP["email"], "password": "new-password-123"},
    )
    assert new.status_code == 200


async def test_change_password_wrong_current(client):
    await sign_up(client)
    response = await client.post(
        "/api/auth/change-password",
        json={"currentPassword": "nope-nope-nope", "newPassword": "new-password-123"},
    )
    assert response.status_code == 400
    assert response.json()["code"] == "INVALID_PASSWORD"


async def test_change_password_revoke_other_sessions(auth, client):
    await sign_up(client)
    async with make_client(auth) as other:
        await other.post("/api/auth/sign-in/email", json=SIGNUP)
        assert (await other.get("/api/auth/get-session")).json() is not None

        response = await client.post(
            "/api/auth/change-password",
            json={
                "currentPassword": SIGNUP["password"],
                "newPassword": "new-password-123",
                "revokeOtherSessions": True,
            },
        )
        assert response.json()["token"]
        assert (await other.get("/api/auth/get-session")).json() is None
    assert (await client.get("/api/auth/get-session")).json() is not None


async def test_update_user(client):
    await sign_up(client)
    response = await client.post("/api/auth/update-user", json={"name": "Grace Hopper"})
    assert response.json() == {"status": True}
    session = (await client.get("/api/auth/get-session")).json()
    assert session["user"]["name"] == "Grace Hopper"


async def test_ok_endpoint(client):
    response = await client.get("/api/auth/ok")
    assert response.json() == {"ok": True}


async def test_unknown_route(client):
    response = await client.get("/api/auth/does-not-exist")
    assert response.status_code == 404


# --- credential identity (internal-adapter.ts:1182-1191, sign-in.ts:527-547) -----------


async def test_sign_in_ignores_a_credential_account_keyed_to_another_id():
    auth = make_auth()
    async with make_client(auth) as client:
        data = await sign_up(client)
        from better_auth.adapters.base import Where

        await auth.adapter.update(
            "account",
            [Where("userId", data["user"]["id"]), Where("providerId", "credential")],
            {"accountId": "ada@example.com"},
        )
        client.cookies.clear()
        response = await client.post("/api/auth/sign-in/email", json=SIGNUP)
    assert response.status_code == 401
    assert response.json()["code"] == "INVALID_EMAIL_OR_PASSWORD"


async def test_set_password_fills_a_passwordless_credential_account():
    # update-user.ts:343-350 (v1.7.6)
    from better_auth.adapters.base import Where

    auth = make_auth()
    async with make_client(auth) as client:
        data = await sign_up(client)
        where = [Where("userId", data["user"]["id"]), Where("providerId", "credential")]
        await auth.adapter.update("account", where, {"password": None})
        response = await client.post(
            "/api/auth/set-password", json={"newPassword": "another-password-1"}
        )
        assert response.json() == {"status": True}
        accounts = await auth.adapter.find_many("account", where)
    assert len(accounts) == 1 and accounts[0]["password"]


async def test_set_password_when_already_set():
    auth = make_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        response = await client.post(
            "/api/auth/set-password", json={"newPassword": "another-password-1"}
        )
    assert response.status_code == 400
    assert response.json() == {
        "code": "PASSWORD_ALREADY_SET",
        "message": "User already has a password set",
    }


# --- sign-up gate rejections (sign-up.ts:238-365, v1.7.6) -------------------------------


def _rejecting_hooks(result):
    async def before(user, ctx):
        if isinstance(result, Exception):
            raise result
        return result

    return {"user": {"create": {"before": before}}}


async def test_sign_up_gate_rejection_hidden_behind_generic_response():
    from better_auth.types import APIError

    auth = make_auth(
        email_and_password=EmailAndPassword(enabled=True, require_email_verification=True),
        database_hooks=_rejecting_hooks(APIError(403, "blocked_domain", "Blocked")),
    )
    async with make_client(auth) as client:
        response = await client.post("/api/auth/sign-up/email", json=SIGNUP)
    assert response.status_code == 200
    assert response.json()["token"] is None
    assert response.json()["user"]["email"] == SIGNUP["email"]
    assert await auth.adapter.find_many("account", []) == []


async def test_sign_up_gate_rejection_surfaces_without_generic_mode():
    from better_auth.types import APIError

    auth = make_auth(database_hooks=_rejecting_hooks(APIError(403, "blocked_domain", "Blocked")))
    async with make_client(auth) as client:
        response = await client.post("/api/auth/sign-up/email", json=SIGNUP)
    assert response.status_code == 403
    assert response.json()["code"] == "blocked_domain"


async def test_sign_up_aborted_by_a_hook_fails_to_create_user():
    auth = make_auth(database_hooks=_rejecting_hooks(False))
    async with make_client(auth) as client:
        response = await client.post("/api/auth/sign-up/email", json=SIGNUP)
    assert response.status_code == 400
    assert response.json() == {"code": "FAILED_TO_CREATE_USER", "message": "Failed to create user"}
    assert await auth.adapter.find_many("account", []) == []
