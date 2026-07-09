from better_auth import RateLimit
from conftest import SIGNUP, make_auth, make_client, sign_up


async def test_untrusted_origin_rejected(client):
    response = await client.post(
        "/api/auth/sign-up/email", json=SIGNUP, headers={"origin": "http://evil.example"}
    )
    assert response.status_code == 403
    assert response.json()["code"] == "INVALID_ORIGIN"


async def test_base_url_origin_allowed(client):
    response = await client.post(
        "/api/auth/sign-up/email", json=SIGNUP, headers={"origin": "http://testserver"}
    )
    assert response.status_code == 200


async def test_extra_trusted_origin():
    auth = make_auth(trusted_origins=["http://app.example.com"])
    async with make_client(auth) as client:
        response = await client.post(
            "/api/auth/sign-up/email", json=SIGNUP, headers={"origin": "http://app.example.com"}
        )
        assert response.status_code == 200


async def test_untrusted_callback_url_rejected(client):
    await sign_up(client)
    response = await client.post(
        "/api/auth/sign-in/email", json={**SIGNUP, "callbackURL": "http://evil.example/steal"}
    )
    assert response.status_code == 403
    assert response.json()["code"] == "INVALID_CALLBACK_URL"


async def test_protocol_relative_callback_url_rejected(client):
    await sign_up(client)
    response = await client.post(
        "/api/auth/sign-in/email", json={**SIGNUP, "callbackURL": "//evil.example/steal"}
    )
    assert response.status_code == 403


async def test_rate_limit_special_rule_on_sign_in():
    auth = make_auth(rate_limit=RateLimit(enabled=True))
    async with make_client(auth) as client:
        payload = {"email": "ghost@example.com", "password": "wrong-password"}
        for _ in range(3):  # special rule: 3 per 10s on /sign-in*
            assert (await client.post("/api/auth/sign-in/email", json=payload)).status_code == 401
        limited = await client.post("/api/auth/sign-in/email", json=payload)
        assert limited.status_code == 429
        assert "x-retry-after" in limited.headers


async def test_rate_limit_disabled_by_default(client):
    for _ in range(5):
        response = await client.post(
            "/api/auth/sign-in/email",
            json={"email": "ghost@example.com", "password": "wrong-password"},
        )
        assert response.status_code == 401


async def test_secret_too_short_rejected():
    import pytest

    with pytest.raises(ValueError):
        make_auth(secret="short")


async def test_error_page(client):
    response = await client.get("/api/auth/error?error=state_mismatch")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "state_mismatch" in response.text


async def test_error_page_escapes_html(client):
    response = await client.get("/api/auth/error?error=<script>alert(1)</script>")
    assert "<script>" not in response.text
