from urllib.parse import parse_qs, urlsplit

from better_auth import EmailAndPassword, EmailVerification
from conftest import SIGNUP, make_auth, make_client, sign_up


def verification_auth(**verification_overrides):
    sent: list[tuple[dict, str, str]] = []

    async def send_verification_email(user, url, token):
        sent.append((user, url, token))

    auth = make_auth(
        email_and_password=EmailAndPassword(enabled=True, require_email_verification=True),
        email_verification=EmailVerification(
            send_verification_email=send_verification_email, **verification_overrides
        ),
    )
    return auth, sent


async def test_sign_up_requires_verification():
    auth, sent = verification_auth()
    async with make_client(auth) as client:
        data = await sign_up(client)
        assert data["token"] is None  # no session until verified
        assert len(sent) == 1
        assert (await client.get("/api/auth/get-session")).json() is None


async def test_sign_in_blocked_and_resends_email():
    auth, sent = verification_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        response = await client.post("/api/auth/sign-in/email", json=SIGNUP)
        assert response.status_code == 403
        assert response.json()["code"] == "EMAIL_NOT_VERIFIED"
        assert len(sent) == 2  # sign-up + sign-in attempt


async def test_verify_email_flow():
    auth, sent = verification_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        _user, url, token = sent[0]
        query = parse_qs(urlsplit(url).query)
        assert query["token"] == [token]

        response = await client.get(f"/api/auth/verify-email?token={token}&callbackURL=%2Fwelcome")
        assert response.status_code == 302
        assert response.headers["location"] == "http://testserver/welcome"

        signed_in = await client.post("/api/auth/sign-in/email", json=SIGNUP)
        assert signed_in.status_code == 200
        assert signed_in.json()["user"]["emailVerified"] is True


async def test_verify_email_token_single_use():
    auth, sent = verification_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        token = sent[0][2]
        assert (await client.get(f"/api/auth/verify-email?token={token}")).status_code == 200
        assert (await client.get(f"/api/auth/verify-email?token={token}")).status_code == 400


async def test_invalid_token_redirects_with_error():
    auth, _sent = verification_auth()
    async with make_client(auth) as client:
        response = await client.get("/api/auth/verify-email?token=bogus&callbackURL=%2Fwelcome")
        assert response.status_code == 302
        assert "error=invalid_token" in response.headers["location"]


async def test_auto_sign_in_after_verification():
    auth, sent = verification_auth(auto_sign_in_after_verification=True)
    async with make_client(auth) as client:
        await sign_up(client)
        token = sent[0][2]
        await client.get(f"/api/auth/verify-email?token={token}")
        session = (await client.get("/api/auth/get-session")).json()
        assert session is not None
        assert session["user"]["emailVerified"] is True


async def test_send_verification_email_endpoint():
    auth, sent = verification_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        response = await client.post(
            "/api/auth/send-verification-email", json={"email": SIGNUP["email"]}
        )
        assert response.json() == {"status": True}
        assert len(sent) == 2

        missing = await client.post(
            "/api/auth/send-verification-email", json={"email": "ghost@example.com"}
        )
        assert missing.status_code == 400
        assert missing.json()["code"] == "USER_NOT_FOUND"
