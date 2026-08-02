"""Flask integration parity with the FastAPI/Litestar ones (tests/conftest.py's auth).

Same behaviors, Flask's sync test client: cookie round-trip, session/require_session
helpers, multiple Set-Cookie headers, custom base_path mount, 404 passthrough, plus
the loop-persistence regression test for the WSGI→async bridge.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from flask import Flask
from flask import request as flask_request
from flask.testing import FlaskClient
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool

from better_auth import BetterAuth
from better_auth.adapters.sqlalchemy import SQLAlchemyAdapter
from better_auth.integrations.flask import (
    BetterAuthFlask,
    _to_auth_request,
    _to_response,
)
from better_auth.types import AuthResponse
from conftest import SIGNUP, make_auth


def make_app(auth: BetterAuth) -> Flask:
    ba = BetterAuthFlask(auth)
    app = Flask(__name__)
    app.register_blueprint(ba.blueprint)

    @app.get("/protected")
    def protected() -> dict[str, str]:
        result = ba.require_session()
        return {"email": result["user"]["email"]}

    @app.get("/maybe")
    def maybe() -> dict[str, bool]:
        return {"authenticated": ba.session() is not None}

    return app


def make_client(app: Flask) -> FlaskClient:
    # Real browsers always send Origin on cross-state POSTs and the CSRF check requires it;
    # default it to the base URL, exactly as tests/conftest.py does for the FastAPI client.
    client = app.test_client()
    client.environ_base["HTTP_ORIGIN"] = "http://testserver"
    return client


@pytest.fixture
def auth() -> BetterAuth:
    return make_auth()


@pytest.fixture
def client(auth: BetterAuth) -> FlaskClient:
    return make_client(make_app(auth))


def sign_up(client: FlaskClient, **overrides: Any) -> Any:
    response = client.post("/api/auth/sign-up/email", json={**SIGNUP, **overrides})
    assert response.status_code == 200, response.text
    return response.json


def test_sign_up_sets_session_cookie(client):
    response = client.post("/api/auth/sign-up/email", json=SIGNUP)
    assert response.status_code == 200
    assert response.json["user"]["email"] == SIGNUP["email"]
    cookies = response.headers.getlist("Set-Cookie")
    assert any(cookie.startswith("better-auth.session_token=") for cookie in cookies)
    assert client.get_cookie("better-auth.session_token") is not None


def test_get_session_with_cookie(client):
    sign_up(client)
    response = client.get("/api/auth/get-session")
    assert response.status_code == 200
    assert response.json["user"]["email"] == SIGNUP["email"]


def test_get_session_anonymous_is_null(client):
    response = client.get("/api/auth/get-session")
    assert response.status_code == 200
    assert response.json is None


def test_require_session_401_then_200(client):
    # Flask's abort() renders Werkzeug's HTML error page, not the JSON `detail`
    # bodies of the FastAPI/Litestar layers — status and message text still match.
    response = client.get("/protected")
    assert response.status_code == 401
    assert "Not authenticated" in response.text

    sign_up(client)
    response = client.get("/protected")
    assert response.status_code == 200
    assert response.json == {"email": SIGNUP["email"]}


def test_optional_session(client):
    assert client.get("/maybe").json == {"authenticated": False}
    sign_up(client)
    assert client.get("/maybe").json == {"authenticated": True}


def test_multiple_set_cookie_headers(client):
    """sign-out clears both the session and the dont_remember cookie: two Set-Cookie headers."""
    sign_up(client)
    response = client.post("/api/auth/sign-out")
    assert response.status_code == 200
    cookies = response.headers.getlist("Set-Cookie")
    assert len(cookies) >= 2
    names = {cookie.split("=", 1)[0] for cookie in cookies}
    assert {"better-auth.session_token", "better-auth.dont_remember"} <= names


def test_query_params_reach_the_handler(client):
    response = client.get("/api/auth/error?error=invalid")
    assert response.status_code == 200
    assert "invalid" in response.text


def test_custom_base_path_mount():
    client = make_client(make_app(make_auth(base_path="/auth")))
    assert client.post("/auth/sign-up/email", json=SIGNUP).status_code == 200
    assert client.get("/api/auth/get-session").status_code == 404


def test_non_auth_routes_pass_through(client):
    assert client.get("/nope").status_code == 404
    assert client.get("/maybe").status_code == 200
    # unknown path under the mount reaches the core, which answers its own 404
    assert client.get("/api/auth/definitely-not-a-route").status_code == 404


def test_loop_persists_across_requests():
    """Two sequential DB-touching requests on one app with the async SQLAlchemy adapter.

    Regression guard for the WSGI→async bridge: the core caches an httpx.AsyncClient
    and async DB drivers hold loop-bound pools, so every call must run on ONE
    persistent loop, never a fresh one per request (asyncio.run). aiosqlite happens
    to be loop-agnostic (its futures bind per-call), so the e2e round-trip alone
    would not catch the bad bridge — the loop-identity assertions below do.
    """

    async def running_loop() -> asyncio.AbstractEventLoop:
        return asyncio.get_running_loop()

    engine = create_async_engine("sqlite+aiosqlite://", poolclass=StaticPool)
    adapter = SQLAlchemyAdapter(engine)
    auth = make_auth(adapter=adapter)
    ba = BetterAuthFlask(auth)
    ba._run(adapter.create_tables())
    app = Flask(__name__)
    app.register_blueprint(ba.blueprint)
    client = make_client(app)
    try:
        first_loop = ba._run(running_loop())
        assert client.post("/api/auth/sign-up/email", json=SIGNUP).status_code == 200
        response = client.get("/api/auth/get-session")
        assert response.status_code == 200
        session = response.json
        assert session is not None
        assert session["user"]["email"] == SIGNUP["email"]
        assert ba._run(running_loop()) is first_loop is ba._loop
    finally:
        ba._run(engine.dispose())


def test_to_response_redirect():
    response = _to_response(
        AuthResponse(redirect_to="https://example.com/cb", headers=[("set-cookie", "a=1")])
    )
    assert response.status_code == 302
    assert response.headers["location"] == "https://example.com/cb"
    assert response.headers.getlist("Set-Cookie") == ["a=1"]


def test_to_response_media_type_body_is_sent_as_is():
    response = _to_response(AuthResponse(status=200, body="<h1>hi</h1>", media_type="text/html"))
    assert response.get_data() == b"<h1>hi</h1>"
    assert response.headers["content-type"].startswith("text/html")


def test_to_response_json_body_is_dumped():
    response = _to_response(AuthResponse(status=201, body={"a": 1}))
    assert response.status_code == 201
    assert response.get_data() == b'{"a":1}'
    assert response.headers["content-type"] == "application/json"


def test_to_auth_request_prefers_forwarded_ip():
    app = Flask(__name__)
    context = app.test_request_context(
        "/api/auth/get-session", headers={"X-Forwarded-For": "203.0.113.7, 10.0.0.1"}
    )
    with context:
        auth_request = _to_auth_request(flask_request, "/get-session", b"")
    assert auth_request.client_ip == "203.0.113.7"
    assert auth_request.headers["x-forwarded-for"] == "203.0.113.7, 10.0.0.1"
    assert auth_request.path == "/get-session"


def test_to_auth_request_query_last_value_wins():
    """Werkzeug's args.to_dict() keeps the FIRST value; the port's semantics are last-wins."""
    app = Flask(__name__)
    with app.test_request_context("/api/auth/x?a=1&a=2&b=only"):
        auth_request = _to_auth_request(flask_request, "/x", b"")
    assert auth_request.query == {"a": "2", "b": "only"}
