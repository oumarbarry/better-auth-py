from better_auth import EmailAndPassword
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
    response = await client.post("/api/auth/sign-out")
    assert response.status_code == 400
    assert response.json()["code"] == "FAILED_TO_GET_SESSION"


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
