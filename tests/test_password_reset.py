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
