from typing import Any

import pytest
from fastapi import Depends, FastAPI
from httpx import ASGITransport, AsyncClient

from better_auth import BetterAuth, EmailAndPassword, MemoryAdapter
from better_auth.integrations.fastapi import BetterAuthFastAPI

SECRET = "test-secret-0123456789-abcdefghijklmnop"


def make_auth(**overrides: Any) -> BetterAuth:
    options: dict[str, Any] = {
        "secret": SECRET,
        "base_url": "http://testserver",
        "adapter": MemoryAdapter(),
        "email_and_password": EmailAndPassword(enabled=True),
    }
    options.update(overrides)
    return BetterAuth(**options)


def make_app(auth: BetterAuth) -> FastAPI:
    app = FastAPI()
    integration = BetterAuthFastAPI(auth)
    app.include_router(integration.router)

    @app.get("/protected")
    async def protected(result: dict = Depends(integration.require_session)):
        return {"email": result["user"]["email"]}

    @app.get("/maybe")
    async def maybe(result: dict | None = Depends(integration.session)):
        return {"authenticated": result is not None}

    return app


def make_client(auth: BetterAuth) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=make_app(auth)), base_url="http://testserver")


@pytest.fixture
def auth() -> BetterAuth:
    return make_auth()


@pytest.fixture
async def client(auth: BetterAuth):
    async with make_client(auth) as client:
        yield client


SIGNUP = {"name": "Ada Lovelace", "email": "ada@example.com", "password": "s3cret-password"}


async def sign_up(client: AsyncClient, **overrides: Any) -> dict[str, Any]:
    response = await client.post("/api/auth/sign-up/email", json={**SIGNUP, **overrides})
    assert response.status_code == 200, response.text
    return response.json()
