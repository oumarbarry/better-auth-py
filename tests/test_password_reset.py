from urllib.parse import parse_qs, urlsplit

from better_auth import EmailAndPassword
from conftest import SIGNUP, make_auth, make_client, sign_up


def reset_auth(**email_password_overrides):
    sent: list[tuple[dict, str, str]] = []

    async def send_reset_password(user, url, token):
        sent.append((user, url, token))

    auth = make_auth(
        email_and_password=EmailAndPassword(
            enabled=True, send_reset_password=send_reset_password, **email_password_overrides
        )
    )
    return auth, sent


async def test_full_reset_flow():
    auth, sent = reset_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        response = await client.post(
            "/api/auth/request-password-reset",
            json={"email": SIGNUP["email"], "redirectTo": "/reset"},
        )
        assert response.json() == {"status": True}
        user, url, token = sent[0]
        assert user["email"] == SIGNUP["email"]
        assert token in url

        # email-link landing redirects to the app with the token
        landing = await client.get(f"/api/auth/reset-password/{token}?callbackURL=%2Freset")
        assert landing.status_code == 302
        assert f"token={token}" in landing.headers["location"]

        response = await client.post(
            "/api/auth/reset-password",
            json={"newPassword": "brand-new-password", "token": token},
        )
        assert response.json() == {"status": True}

        client.cookies.clear()
        assert (await client.post("/api/auth/sign-in/email", json=SIGNUP)).status_code == 401
        good = await client.post(
            "/api/auth/sign-in/email",
            json={"email": SIGNUP["email"], "password": "brand-new-password"},
        )
        assert good.status_code == 200


async def test_unknown_email_gets_constant_response():
    auth, sent = reset_auth()
    async with make_client(auth) as client:
        response = await client.post(
            "/api/auth/request-password-reset", json={"email": "ghost@example.com"}
        )
        assert response.json() == {"status": True}
        assert sent == []


async def test_token_is_single_use():
    auth, sent = reset_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        await client.post("/api/auth/request-password-reset", json={"email": SIGNUP["email"]})
        token = sent[0][2]
        first = await client.post(
            "/api/auth/reset-password", json={"newPassword": "brand-new-password", "token": token}
        )
        assert first.status_code == 200
        second = await client.post(
            "/api/auth/reset-password", json={"newPassword": "other-password-1", "token": token}
        )
        assert second.status_code == 400
        assert second.json()["code"] == "INVALID_TOKEN"


async def test_invalid_token_rejected():
    auth, _sent = reset_auth()
    async with make_client(auth) as client:
        response = await client.post(
            "/api/auth/reset-password",
            json={"newPassword": "whatever-password", "token": "bogus"},
        )
        assert response.status_code == 400


async def test_reset_revokes_sessions_when_configured():
    auth, sent = reset_auth(revoke_sessions_on_password_reset=True)
    async with make_client(auth) as client:
        await sign_up(client)
        await client.post("/api/auth/request-password-reset", json={"email": SIGNUP["email"]})
        await client.post(
            "/api/auth/reset-password",
            json={"newPassword": "brand-new-password", "token": sent[0][2]},
        )
        assert (await client.get("/api/auth/get-session")).json() is None


async def test_forget_password_alias():
    auth, sent = reset_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        response = await client.post("/api/auth/forget-password", json={"email": SIGNUP["email"]})
        assert response.json() == {"status": True}
        assert len(sent) == 1


async def test_not_configured():
    auth = make_auth()  # no send_reset_password
    async with make_client(auth) as client:
        await sign_up(client)
        response = await client.post(
            "/api/auth/request-password-reset", json={"email": SIGNUP["email"]}
        )
        assert response.status_code == 400


async def test_reset_url_shape():
    auth, sent = reset_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        await client.post(
            "/api/auth/request-password-reset",
            json={"email": SIGNUP["email"], "redirectTo": "/account/reset"},
        )
        _user, url, token = sent[0]
        parts = urlsplit(url)
        assert parts.path == f"/api/auth/reset-password/{token}"
        assert parse_qs(parts.query)["callbackURL"] == ["/account/reset"]


async def test_reset_token_goes_through_verification_storage():
    # TS 1.6.29 password.ts:127/297: create/consumeVerificationValue, so the reset token
    # honors verification.storeIdentifier (the stored identifier is hashed here).
    from better_auth import Where
    from better_auth.internal_adapter import VerificationOptions

    sent: list[tuple] = []

    async def send_reset_password(user, url, token):
        sent.append((user, url, token))

    auth = make_auth(
        email_and_password=EmailAndPassword(enabled=True, send_reset_password=send_reset_password),
        verification=VerificationOptions(store_identifier="hashed"),
    )
    async with make_client(auth) as client:
        await sign_up(client)
        await client.post("/api/auth/request-password-reset", json={"email": SIGNUP["email"]})
        token = sent[0][2]
        plain = f"reset-password:{token}"
        assert await auth.adapter.find_one("verification", [Where("identifier", plain)]) is None
        response = await client.post(
            "/api/auth/reset-password", json={"newPassword": "brand-new-password", "token": token}
        )
        assert response.status_code == 200, response.text


async def test_reset_link_with_unknown_token_redirects_with_invalid_token():
    # password.ts:212-228: the landing route checks the token before forwarding it
    auth, _sent = reset_auth()
    async with make_client(auth) as client:
        landing = await client.get("/api/auth/reset-password/nope?callbackURL=%2Freset%23form")
    assert landing.status_code == 302
    assert landing.headers["location"] == "http://testserver/reset?error=INVALID_TOKEN#form"


async def test_reset_link_with_expired_token_redirects_with_invalid_token():
    auth, sent = reset_auth(reset_password_token_expires_in=-1)
    async with make_client(auth) as client:
        await sign_up(client)
        await client.post("/api/auth/request-password-reset", json={"email": SIGNUP["email"]})
        token = sent[0][2]
        landing = await client.get(f"/api/auth/reset-password/{token}?callbackURL=%2Freset")
    assert landing.headers["location"] == "http://testserver/reset?error=INVALID_TOKEN"


async def test_reset_link_with_valid_token_forwards_it():
    auth, sent = reset_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        await client.post("/api/auth/request-password-reset", json={"email": SIGNUP["email"]})
        token = sent[0][2]
        landing = await client.get(f"/api/auth/reset-password/{token}?callbackURL=%2Freset%3Fa%3D1")
    assert landing.headers["location"] == f"http://testserver/reset?a=1&token={token}"


async def test_reset_password_for_a_deleted_user():
    # password.ts:299-303 (v1.7.6): the user must still exist
    from better_auth.adapters.base import Where

    auth, sent = reset_auth()
    async with make_client(auth) as client:
        data = await sign_up(client)
        await client.post("/api/auth/request-password-reset", json={"email": SIGNUP["email"]})
        await auth.adapter.delete_many("user", [Where("id", data["user"]["id"])])
        response = await client.post(
            "/api/auth/reset-password",
            json={"newPassword": "brand-new-password", "token": sent[0][2]},
        )
    assert response.status_code == 400
    assert response.json() == {"code": "USER_NOT_FOUND", "message": "User not found"}
    assert await auth.adapter.find_many("account", [Where("providerId", "credential")]) != []
