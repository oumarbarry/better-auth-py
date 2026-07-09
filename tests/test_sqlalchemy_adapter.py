from datetime import timedelta, timezone

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool

from better_auth.adapters.base import Where
from better_auth.adapters.sqlalchemy import SQLAlchemyAdapter
from better_auth.session import utcnow
from conftest import SIGNUP, make_auth, make_client, sign_up


@pytest.fixture
async def sa_auth():
    engine = create_async_engine("sqlite+aiosqlite://", poolclass=StaticPool)
    adapter = SQLAlchemyAdapter(engine)
    auth = make_auth(adapter=adapter)  # init() runs in the constructor
    await adapter.create_tables()
    yield auth
    await engine.dispose()


async def test_full_flow_on_sqlalchemy(sa_auth):
    async with make_client(sa_auth) as client:
        data = await sign_up(client)
        assert data["token"]

        session = (await client.get("/api/auth/get-session")).json()
        assert session["user"]["email"] == SIGNUP["email"]
        assert session["user"]["emailVerified"] is False

        assert (await client.post("/api/auth/sign-out")).json() == {"success": True}
        assert (await client.get("/api/auth/get-session")).json() is None

        signin = await client.post("/api/auth/sign-in/email", json=SIGNUP)
        assert signin.status_code == 200


async def test_datetimes_round_trip_timezone_aware(sa_auth):
    async with make_client(sa_auth) as client:
        await sign_up(client)
    user = await sa_auth.adapter.find_one("user", [Where("email", SIGNUP["email"])])
    assert user["createdAt"].tzinfo == timezone.utc


async def test_where_operators(sa_auth):
    async with make_client(sa_auth) as client:
        await sign_up(client)
        await sign_up(client, email="second@example.com")

    users = await sa_auth.adapter.find_many("user")
    assert len(users) == 2
    subset = await sa_auth.adapter.find_many("user", [Where("email", [SIGNUP["email"]], "in")])
    assert len(subset) == 1
    recent = await sa_auth.adapter.find_many(
        "user", [Where("createdAt", utcnow() - timedelta(hours=1), "gt")]
    )
    assert len(recent) == 2
    none = await sa_auth.adapter.find_many("user", [Where("email", SIGNUP["email"], "ne")])
    assert len(none) == 1


async def test_update_and_delete(sa_auth):
    async with make_client(sa_auth) as client:
        await sign_up(client)
    updated = await sa_auth.adapter.update(
        "user", [Where("email", SIGNUP["email"])], {"name": "Renamed"}
    )
    assert updated["name"] == "Renamed"
    deleted = await sa_auth.adapter.delete_many("user", [Where("email", SIGNUP["email"])])
    assert deleted == 1
    assert await sa_auth.adapter.find_one("user", [Where("email", SIGNUP["email"])]) is None


async def test_create_tables_is_idempotent(sa_auth):
    await sa_auth.adapter.create_tables()
    await sa_auth.adapter.create_tables()
