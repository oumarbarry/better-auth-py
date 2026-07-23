"""bearer plugin — response-side (`set-auth-token` + expose-headers) and
`requireSignature` request-side gating. Request-side raw/signed reading otherwise
already works via core `session.read_token` (session.py:60).

Verified against TS `packages/better-auth/src/plugins/bearer/index.ts` and
`bearer.test.ts`.
"""

from __future__ import annotations

from better_auth.plugins_ext.bearer import BearerPlugin
from conftest import make_auth, make_client, sign_up


def bearer_auth(**kwargs):
    return make_auth(plugins=[BearerPlugin(**kwargs)])


async def test_sign_up_sets_set_auth_token_header():
    async with make_client(bearer_auth()) as client:
        response = await client.post(
            "/api/auth/sign-up/email",
            json={"name": "Ada", "email": "ada@example.com", "password": "s3cret-password"},
        )
        assert response.status_code == 200
        token = response.headers.get("set-auth-token")
        assert token is not None
        assert "." in token  # signed cookie value (token.signature)
        exposed = response.headers.get("access-control-expose-headers", "")
        assert "set-auth-token" in [h.strip() for h in exposed.split(",")]


async def test_no_set_auth_token_when_no_session_created():
    async with make_client(bearer_auth()) as client:
        response = await client.get("/api/auth/get-session")
        assert response.status_code == 200
        assert response.json() is None
        assert "set-auth-token" not in response.headers


async def test_set_auth_token_not_set_when_session_cookie_cleared_on_sign_out():
    async with make_client(bearer_auth()) as client:
        await sign_up(client)
        response = await client.post("/api/auth/sign-out")
        assert response.status_code == 200
        # sign-out clears the session cookie (Max-Age=0) -> bearer must not echo it
        assert "set-auth-token" not in response.headers


async def test_get_session_via_signed_bearer_token():
    async with make_client(bearer_auth()) as client:
        signup = await client.post(
            "/api/auth/sign-up/email",
            json={"name": "Ada", "email": "ada@example.com", "password": "s3cret-password"},
        )
        signed = signup.headers["set-auth-token"]
        client.cookies.clear()
        response = await client.get(
            "/api/auth/get-session", headers={"Authorization": f"Bearer {signed}"}
        )
        assert response.status_code == 200
        assert response.json()["user"]["email"] == "ada@example.com"


async def test_get_session_via_raw_unsigned_token_default_allows_it():
    async with make_client(bearer_auth()) as client:  # require_signature=False (default)
        data = await sign_up(client)
        raw_token = data["token"]
        client.cookies.clear()
        response = await client.get(
            "/api/auth/get-session", headers={"Authorization": f"Bearer {raw_token}"}
        )
        assert response.status_code == 200
        assert response.json()["user"]["email"] == "ada@example.com"


async def test_require_signature_blocks_raw_unsigned_token():
    async with make_client(bearer_auth(require_signature=True)) as client:
        data = await sign_up(client)
        raw_token = data["token"]
        client.cookies.clear()
        response = await client.get(
            "/api/auth/get-session", headers={"Authorization": f"Bearer {raw_token}"}
        )
        assert response.status_code == 200
        assert response.json() is None  # raw token rejected -> unauthenticated


async def test_require_signature_still_allows_signed_token():
    async with make_client(bearer_auth(require_signature=True)) as client:
        signup = await client.post(
            "/api/auth/sign-up/email",
            json={"name": "Ada", "email": "ada@example.com", "password": "s3cret-password"},
        )
        signed = signup.headers["set-auth-token"]
        client.cookies.clear()
        response = await client.get(
            "/api/auth/get-session", headers={"Authorization": f"Bearer {signed}"}
        )
        assert response.status_code == 200
        assert response.json()["user"]["email"] == "ada@example.com"


async def test_valid_cookie_wins_even_if_authorization_header_invalid():
    async with make_client(bearer_auth()) as client:
        await sign_up(client)  # client keeps the valid session cookie
        response = await client.get(
            "/api/auth/get-session", headers={"Authorization": "Bearer invalid.token"}
        )
        assert response.status_code == 200
        assert response.json()["user"]["email"] == "ada@example.com"


async def test_invalid_bearer_header_alone_is_unauthenticated():
    async with make_client(bearer_auth()) as client:
        response = await client.get(
            "/api/auth/get-session", headers={"Authorization": "Bearer invalid.token"}
        )
        assert response.status_code == 200
        assert response.json() is None


async def test_bearer_scheme_is_case_insensitive_and_tolerates_whitespace():
    async with make_client(bearer_auth()) as client:
        signup = await client.post(
            "/api/auth/sign-up/email",
            json={"name": "Ada", "email": "ada@example.com", "password": "s3cret-password"},
        )
        signed = signup.headers["set-auth-token"]
        client.cookies.clear()
        for scheme in ("bearer", "BEARER", "BeArEr", "Bearer "):
            response = await client.get(
                "/api/auth/get-session", headers={"Authorization": f"{scheme} {signed}"}
            )
            assert response.status_code == 200
            assert response.json()["user"]["email"] == "ada@example.com"


async def test_url_decoded_and_raw_encoded_signed_token_both_work():
    from urllib.parse import unquote

    async with make_client(bearer_auth()) as client:
        signup = await client.post(
            "/api/auth/sign-up/email",
            json={"name": "Ada", "email": "ada@example.com", "password": "s3cret-password"},
        )
        signed = signup.headers["set-auth-token"]
        client.cookies.clear()
        for candidate in (signed, unquote(signed)):
            response = await client.get(
                "/api/auth/get-session", headers={"Authorization": f"Bearer {candidate}"}
            )
            assert response.status_code == 200
            assert response.json()["user"]["email"] == "ada@example.com"
