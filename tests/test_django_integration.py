"""Django integration parity with the FastAPI/Litestar/Flask ones (tests/conftest.py's auth).

Same behaviors, Django's sync test client: cookie round-trip, session/require_session
helpers, multiple Set-Cookie headers, custom base_path mount, 404 passthrough, 405 on
other methods, plus the loop-persistence regression test for the WSGI→async bridge.

Django needs configured settings before the test client runs; the module-level
``settings.configure`` guard below is the standard pattern for testing a Django lib
without a project. ``ROOT_URLCONF`` is any object with a ``urlpatterns`` attribute,
so each test installs its own tiny urlconf instead of a shared module.
"""

from __future__ import annotations

import asyncio
from typing import Any

import django
import pytest
from django.conf import settings

if not settings.configured:
    settings.configure(DEBUG=False, ALLOWED_HOSTS=["testserver"], MIDDLEWARE=[])
    django.setup()

from django.http import HttpRequest, HttpResponse, JsonResponse
from django.test import Client, RequestFactory
from django.urls import path
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool

from better_auth import BetterAuth
from better_auth.adapters.sqlalchemy import SQLAlchemyAdapter
from better_auth.integrations.django import (
    BetterAuthDjango,
    _to_auth_request,
    _to_response,
)
from better_auth.types import AuthResponse
from conftest import SIGNUP, make_auth


class _URLConf:
    """Stand-in for a urls.py module: Django only needs a ``urlpatterns`` attribute."""

    def __init__(self, urlpatterns: list[Any]) -> None:
        self.urlpatterns = urlpatterns


def make_app(auth: BetterAuth) -> BetterAuthDjango:
    ba = BetterAuthDjango(auth)

    def protected(request: HttpRequest) -> HttpResponse:
        result = ba.require_session(request)
        if isinstance(result, HttpResponse):
            return result
        return JsonResponse({"email": result["user"]["email"]})

    def maybe(request: HttpRequest) -> HttpResponse:
        return JsonResponse({"authenticated": ba.session(request) is not None})

    settings.ROOT_URLCONF = _URLConf([*ba.urls, path("protected", protected), path("maybe", maybe)])
    return ba


def make_client() -> Client:
    # Real browsers always send Origin on cross-state POSTs and the CSRF check requires it;
    # default it to the base URL, exactly as tests/conftest.py does for the FastAPI client.
    return Client(headers={"origin": "http://testserver"})


@pytest.fixture
def auth() -> BetterAuth:
    return make_auth()


@pytest.fixture
def client(auth: BetterAuth) -> Client:
    make_app(auth)
    return make_client()


def sign_up(client: Client, **overrides: Any) -> Any:
    response = client.post(
        "/api/auth/sign-up/email", {**SIGNUP, **overrides}, content_type="application/json"
    )
    assert response.status_code == 200, response.content
    return response.json()


def test_sign_up_sets_session_cookie(client):
    response = client.post("/api/auth/sign-up/email", SIGNUP, content_type="application/json")
    assert response.status_code == 200
    assert response.json()["user"]["email"] == SIGNUP["email"]
    morsel = response.cookies.get("better-auth.session_token")
    assert morsel is not None and morsel.value
    assert morsel["httponly"] is True
    assert client.cookies.get("better-auth.session_token") is not None


def test_get_session_with_cookie(client):
    sign_up(client)
    response = client.get("/api/auth/get-session")
    assert response.status_code == 200
    assert response.json()["user"]["email"] == SIGNUP["email"]


def test_get_session_anonymous_is_null(client):
    response = client.get("/api/auth/get-session")
    assert response.status_code == 200
    assert response.json() is None


def test_require_session_401_then_200(client):
    # require_session hands back the prepared 401 JsonResponse (Django has no
    # exception-to-401 mapping); body matches the FastAPI layer's `detail` shape.
    response = client.get("/protected")
    assert response.status_code == 401
    assert response.json() == {"detail": "Not authenticated"}

    sign_up(client)
    response = client.get("/protected")
    assert response.status_code == 200
    assert response.json() == {"email": SIGNUP["email"]}


def test_optional_session(client):
    assert client.get("/maybe").json() == {"authenticated": False}
    sign_up(client)
    assert client.get("/maybe").json() == {"authenticated": True}


def test_multiple_set_cookie_headers(client):
    """sign-out clears both the session and the dont_remember cookie: two Set-Cookie headers.

    HttpResponse carries them as two ``response.cookies`` morsels; every Django
    handler emits one Set-Cookie line per morsel (django/core/handlers/wsgi.py).
    """
    sign_up(client)
    # Django's client defaults to multipart encoding, which the core's JSON body
    # parsing rejects — send an (empty) JSON body like a real client would.
    response = client.post("/api/auth/sign-out", content_type="application/json")
    assert response.status_code == 200
    assert len(response.cookies) >= 2
    assert {"better-auth.session_token", "better-auth.dont_remember"} <= set(response.cookies)
    assert response.cookies["better-auth.session_token"]["max-age"] == "0"


def test_method_not_allowed(client):
    assert client.put("/api/auth/sign-up/email").status_code == 405


def test_query_params_reach_the_handler(client):
    response = client.get("/api/auth/error?error=invalid")
    assert response.status_code == 200
    assert b"invalid" in response.content


def test_custom_base_path_mount():
    make_app(make_auth(base_path="/auth"))
    client = make_client()
    response = client.post("/auth/sign-up/email", SIGNUP, content_type="application/json")
    assert response.status_code == 200
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
    ba = make_app(auth)
    ba._run(adapter.create_tables())
    client = make_client()
    try:
        first_loop = ba._run(running_loop())
        response = client.post("/api/auth/sign-up/email", SIGNUP, content_type="application/json")
        assert response.status_code == 200
        response = client.get("/api/auth/get-session")
        assert response.status_code == 200
        session = response.json()
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
    assert response["location"] == "https://example.com/cb"
    assert response.cookies["a"].value == "1"


def test_to_response_multiple_set_cookies_survive():
    """HttpResponse.headers overwrites duplicate keys, so raw Set-Cookie headers are
    parsed into ``response.cookies`` morsels — the one channel Django emits repeated."""
    response = _to_response(
        AuthResponse(
            status=200,
            body=None,
            headers=[
                ("set-cookie", "a=1; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800"),
                ("set-cookie", "b=2; Path=/"),
            ],
        )
    )
    assert response.cookies["a"].value == "1"
    assert response.cookies["a"]["httponly"] is True
    assert response.cookies["a"]["samesite"] == "Lax"
    assert response.cookies["a"]["max-age"] == "604800"
    assert response.cookies["b"].value == "2"
    assert response.cookies["b"]["path"] == "/"


def test_to_response_media_type_body_is_sent_as_is():
    response = _to_response(AuthResponse(status=200, body="<h1>hi</h1>", media_type="text/html"))
    assert response.content == b"<h1>hi</h1>"
    assert response["content-type"].startswith("text/html")


def test_to_response_json_body_is_dumped():
    response = _to_response(AuthResponse(status=201, body={"a": 1}))
    assert response.status_code == 201
    assert response.content == b'{"a":1}'
    assert response["content-type"] == "application/json"


def test_to_auth_request_prefers_forwarded_ip():
    request = RequestFactory().get(
        "/api/auth/get-session", headers={"x-forwarded-for": "203.0.113.7, 10.0.0.1"}
    )
    auth_request = _to_auth_request(request, "/get-session", b"")
    assert auth_request.client_ip == "203.0.113.7"
    assert auth_request.headers["x-forwarded-for"] == "203.0.113.7, 10.0.0.1"
    assert auth_request.path == "/get-session"


def test_to_auth_request_query_last_value_wins():
    """QueryDict[key] already returns the last value; `.lists()` makes last-wins explicit."""
    request = RequestFactory().get("/api/auth/x?a=1&a=2&b=only")
    auth_request = _to_auth_request(request, "/x", b"")
    assert auth_request.query == {"a": "2", "b": "only"}
