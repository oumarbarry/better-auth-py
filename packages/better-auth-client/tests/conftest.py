"""One in-process server (conftest-style make_auth, the 7 client-namespace plugins +
bearer), mounted twice: ASGITransport over the FastAPI app for AsyncAuthClient,
WSGITransport over the Flask app for AuthClient (a Flask instance IS a WSGI app).

Every fixture is parametrized-friendly: test bodies are written once and drive both
shells through the ``res`` awaiter.
"""

from __future__ import annotations

import inspect
from typing import Any

import pytest
from better_auth_client import AsyncAuthClient, AuthClient
from fastapi import FastAPI
from flask import Flask
from httpx import ASGITransport, WSGITransport

from better_auth import BetterAuth, EmailAndPassword, MemoryAdapter
from better_auth.integrations.fastapi import BetterAuthFastAPI
from better_auth.integrations.flask import BetterAuthFlask
from better_auth.plugins_ext import (
    AdminPlugin,
    ApiKeyPlugin,
    BearerPlugin,
    DeviceAuthorizationPlugin,
    EmailOTPPlugin,
    MagicLinkPlugin,
    OrganizationPlugin,
    TwoFactorPlugin,
)

SECRET = "test-secret-0123456789-abcdefghijklmnop"
BASE_URL = "http://testserver"


@pytest.fixture
def outbox() -> dict[str, Any]:
    """Captures what the server "sends": magic-link payloads and email OTPs."""
    return {}


@pytest.fixture
def auth(outbox: dict[str, Any]) -> BetterAuth:
    def send_magic_link(data: dict[str, Any]) -> None:
        outbox["magic_link"] = data

    def send_verification_otp(data: dict[str, Any], ctx: Any = None) -> None:
        outbox["otp"] = data

    return BetterAuth(
        secret=SECRET,
        base_url=BASE_URL,
        adapter=MemoryAdapter(),
        email_and_password=EmailAndPassword(enabled=True),
        plugins=[
            TwoFactorPlugin(),
            OrganizationPlugin(),
            AdminPlugin(),
            ApiKeyPlugin(),
            MagicLinkPlugin(send_magic_link=send_magic_link),
            EmailOTPPlugin(send_verification_otp=send_verification_otp),
            # interval "0s": poll-driven tests never sleep between polls
            DeviceAuthorizationPlugin(interval="0s"),
            # bearer plugin: emits set-auth-token, which the client captures
            BearerPlugin(),
        ],
    )


def make_fastapi_app(auth: BetterAuth) -> FastAPI:
    app = FastAPI()
    app.include_router(BetterAuthFastAPI(auth).router)
    return app


def make_flask_app(auth: BetterAuth) -> Flask:
    app = Flask(__name__)
    app.register_blueprint(BetterAuthFlask(auth).blueprint)
    return app


@pytest.fixture(params=["sync", "async"])
async def client_factory(request: pytest.FixtureRequest, auth: BetterAuth):
    """Callable minting clients bound to one shared server app (device-flow tests
    need a second, separately-authenticated client)."""
    created: list[AuthClient | AsyncAuthClient] = []

    if request.param == "sync":
        wsgi_app = make_flask_app(auth)

        def make() -> AuthClient | AsyncAuthClient:
            client = AuthClient(BASE_URL, transport=WSGITransport(app=wsgi_app))
            created.append(client)
            return client
    else:
        asgi_app = make_fastapi_app(auth)

        def make() -> AuthClient | AsyncAuthClient:
            client = AsyncAuthClient(BASE_URL, transport=ASGITransport(app=asgi_app))
            created.append(client)
            return client

    yield make

    for client in created:
        if isinstance(client, AuthClient):
            client.close()
        else:
            await client.aclose()


@pytest.fixture
def client(client_factory: Any) -> AuthClient | AsyncAuthClient:
    return client_factory()


@pytest.fixture
def res():
    """Awaits AsyncAuthClient results, passes AuthClient results through — one test
    body drives both shells."""

    async def _res(value: Any) -> Any:
        return await value if inspect.isawaitable(value) else value

    return _res
