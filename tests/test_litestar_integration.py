"""Litestar integration parity with the FastAPI one (tests/conftest.py's app + client).

Same behaviors, Litestar client: cookie round-trip, session/require_session dependencies,
multiple Set-Cookie headers, custom base_path mount, 404 passthrough for non-auth routes.
"""

from __future__ import annotations

from typing import Any

import pytest
from litestar import Litestar, get
from litestar.di import NamedDependency, Provide
from litestar.testing import AsyncTestClient, RequestFactory

from better_auth import BetterAuth
from better_auth.integrations.litestar import (
    BetterAuthLitestar,
    _to_auth_request,
    _to_response,
)
from better_auth.types import AuthResponse
from conftest import SIGNUP, make_auth


def make_app(auth: BetterAuth) -> Litestar:
    ba = BetterAuthLitestar(auth)

    @get("/protected", dependencies={"result": Provide(ba.require_session)})
    async def protected(result: NamedDependency[dict[str, Any]]) -> dict[str, str]:
        return {"email": result["user"]["email"]}

    @get("/maybe", dependencies={"result": Provide(ba.session)})
    async def maybe(result: NamedDependency[dict[str, Any] | None]) -> dict[str, bool]:
        return {"authenticated": result is not None}

    return Litestar(route_handlers=[ba.router, protected, maybe])


@pytest.fixture
def auth() -> BetterAuth:
    return make_auth()


def make_client(auth: BetterAuth) -> AsyncTestClient:
    # Real browsers always send Origin on cross-state POSTs and the CSRF check requires it;
    # default it to the base URL, exactly as tests/conftest.py does for the FastAPI client.
    client: AsyncTestClient = AsyncTestClient(app=make_app(auth), base_url="http://testserver")
    client.headers.update({"origin": "http://testserver"})
    return client


@pytest.fixture
async def client(auth: BetterAuth):
    async with make_client(auth) as client:
        yield client


async def sign_up(client: AsyncTestClient, **overrides: Any) -> Any:
    response = await client.post("/api/auth/sign-up/email", json={**SIGNUP, **overrides})
    assert response.status_code == 200, response.text
    return response.json()


async def test_sign_up_sets_session_cookie(client):
    response = await client.post("/api/auth/sign-up/email", json=SIGNUP)
    assert response.status_code == 200
    assert response.json()["user"]["email"] == SIGNUP["email"]
    cookies = response.headers.get_list("set-cookie")
    assert any(cookie.startswith("better-auth.session_token=") for cookie in cookies)
    assert "better-auth.session_token" in client.cookies


async def test_get_session_with_cookie(client):
    await sign_up(client)
    response = await client.get("/api/auth/get-session")
    assert response.status_code == 200
    assert response.json()["user"]["email"] == SIGNUP["email"]


async def test_get_session_anonymous_is_null(client):
    response = await client.get("/api/auth/get-session")
    assert response.status_code == 200
    assert response.json() is None


async def test_require_session_dependency_401_then_200(client):
    response = await client.get("/protected")
    assert response.status_code == 401
    assert response.json()["detail"] == "Not authenticated"

    await sign_up(client)
    response = await client.get("/protected")
    assert response.status_code == 200
    assert response.json() == {"email": SIGNUP["email"]}


async def test_optional_session_dependency(client):
    assert (await client.get("/maybe")).json() == {"authenticated": False}
    await sign_up(client)
    assert (await client.get("/maybe")).json() == {"authenticated": True}


async def test_multiple_set_cookie_headers(client):
    """sign-out clears both the session and the dont_remember cookie: two Set-Cookie headers."""
    await sign_up(client)
    response = await client.post("/api/auth/sign-out")
    assert response.status_code == 200
    cookies = response.headers.get_list("set-cookie")
    assert len(cookies) >= 2
    names = {cookie.split("=", 1)[0] for cookie in cookies}
    assert {"better-auth.session_token", "better-auth.dont_remember"} <= names


async def test_query_params_reach_the_handler(client):
    """?disableRedirect drives an endpoint branch, so query translation must survive."""
    response = await client.get("/api/auth/error?error=invalid")
    assert response.status_code == 200
    assert "invalid" in response.text


async def test_custom_base_path_mount():
    auth = make_auth(base_path="/auth")
    async with make_client(auth) as client:
        assert (await client.post("/auth/sign-up/email", json=SIGNUP)).status_code == 200
        assert (await client.get("/api/auth/get-session")).status_code == 404


async def test_non_auth_routes_pass_through(client):
    assert (await client.get("/nope")).status_code == 404
    assert (await client.get("/maybe")).status_code == 200


def test_to_response_redirect():
    response = _to_response(
        AuthResponse(redirect_to="https://example.com/cb", headers=[("set-cookie", "a=1")])
    )
    headers = dict(response.encode_headers())
    assert response.status_code == 302
    assert headers[b"location"] == b"https://example.com/cb"
    assert headers[b"set-cookie"] == b"a=1"


def test_to_response_media_type_body_is_sent_as_is():
    response = _to_response(AuthResponse(status=200, body="<h1>hi</h1>", media_type="text/html"))
    assert response.body == b"<h1>hi</h1>"
    assert dict(response.encode_headers())[b"content-type"].startswith(b"text/html")


def test_to_response_json_body_is_dumped():
    response = _to_response(AuthResponse(status=201, body={"a": 1}))
    assert response.status_code == 201
    assert response.body == b'{"a":1}'
    assert dict(response.encode_headers())[b"content-type"] == b"application/json"


def test_to_auth_request_prefers_forwarded_ip():
    request = RequestFactory().get(
        "/api/auth/get-session", headers={"X-Forwarded-For": "203.0.113.7, 10.0.0.1"}
    )
    auth_request = _to_auth_request(request, "/get-session", b"")
    assert auth_request.client_ip == "203.0.113.7"
    assert auth_request.headers["x-forwarded-for"] == "203.0.113.7, 10.0.0.1"
    assert auth_request.path == "/get-session"
