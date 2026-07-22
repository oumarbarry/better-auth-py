"""Ported subset of better-auth's shared adapter test suite.

Runs against both MemoryAdapter and SQLAlchemyAdapter to prove parity for the
expanded contract (item 2), the transform layer (item 3), advanced.database
options (item 6) and transactions (item 8).
"""

from __future__ import annotations

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool

from better_auth.adapters.base import Where
from better_auth.adapters.memory import MemoryAdapter
from better_auth.adapters.sqlalchemy import SQLAlchemyAdapter
from better_auth.config import AdvancedDatabase
from better_auth.schema import CORE_SCHEMA, Field, merge_schema

# A tiny model with numeric fields for consume/increment tests.
_COUNTER_SCHEMA = {
    "counter": {
        "id": Field("string", required=True, unique=True),
        "key": Field("string", required=True, unique=True),
        "count": Field("number", required=True),
    }
}
_SCHEMA = merge_schema(CORE_SCHEMA, _COUNTER_SCHEMA)


async def _make(kind: str, advanced: AdvancedDatabase | None = None):
    if kind == "memory":
        adapter = MemoryAdapter(advanced=advanced)
        adapter.init(_SCHEMA)
        return adapter, None
    engine = create_async_engine("sqlite+aiosqlite://", poolclass=StaticPool)
    adapter = SQLAlchemyAdapter(engine, advanced=advanced)
    adapter.init(_SCHEMA)
    await adapter.create_tables()
    return adapter, engine


@pytest.fixture(params=["memory", "sqlalchemy"])
async def adapter(request):
    a, engine = await _make(request.param)
    yield a
    if engine is not None:
        await engine.dispose()


async def _user(adapter, **overrides):
    data = {"name": "Ada", "email": "ada@example.com"}
    data.update(overrides)
    return await adapter.create("user", data)


# --- transform layer (item 3) + generate_id (item 6) -------------------------


async def test_create_injects_id_when_absent(adapter):
    row = await _user(adapter)
    assert isinstance(row["id"], str) and len(row["id"]) == 32


async def test_create_applies_defaults(adapter):
    row = await _user(adapter)
    assert row["emailVerified"] is False
    assert row["createdAt"] is not None
    assert row["updatedAt"] is not None


async def test_create_keeps_supplied_id(adapter):
    row = await _user(adapter, id="custom-id-123")
    assert row["id"] == "custom-id-123"


async def test_update_bumps_updated_at(adapter):
    row = await _user(adapter)
    original = row["updatedAt"]
    updated = await adapter.update("user", [Where("id", row["id"])], {"name": "Grace"})
    assert updated["name"] == "Grace"
    assert updated["updatedAt"] >= original


# --- contract expansion (item 2) ---------------------------------------------


async def test_count(adapter):
    await _user(adapter, email="a@example.com")
    await _user(adapter, email="b@example.com")
    assert await adapter.count("user") == 2
    assert await adapter.count("user", [Where("email", "a@example.com")]) == 1


async def test_update_many_returns_affected(adapter):
    await _user(adapter, email="a@example.com", name="x")
    await _user(adapter, email="b@example.com", name="x")
    n = await adapter.update_many("user", [Where("name", "x")], {"name": "y"})
    assert n == 2


async def test_single_delete(adapter):
    await _user(adapter, email="a@example.com")
    await adapter.delete("user", [Where("email", "a@example.com")])
    assert await adapter.find_one("user", [Where("email", "a@example.com")]) is None


async def test_single_delete_empty_where_is_noop(adapter):
    await _user(adapter, email="a@example.com")
    await adapter.delete("user", [])
    assert await adapter.count("user") == 1


async def test_single_update_empty_where_returns_none(adapter):
    await _user(adapter, email="a@example.com", name="keep")
    result = await adapter.update("user", [], {"name": "changed"})
    assert result is None
    row = await adapter.find_one("user", [Where("email", "a@example.com")])
    assert row["name"] == "keep"


async def test_find_many_limit_offset_sort(adapter):
    for i in range(5):
        await _user(adapter, email=f"u{i}@example.com", name=f"name{i}")
    asc = await adapter.find_many(
        "user", limit=2, sort_by={"field": "name", "direction": "asc"}
    )
    assert [r["name"] for r in asc] == ["name0", "name1"]
    desc = await adapter.find_many(
        "user", limit=2, sort_by={"field": "name", "direction": "desc"}
    )
    assert [r["name"] for r in desc] == ["name4", "name3"]
    page2 = await adapter.find_many(
        "user", offset=2, limit=2, sort_by={"field": "name", "direction": "asc"}
    )
    assert [r["name"] for r in page2] == ["name2", "name3"]


async def test_default_find_many_limit():
    adapter, _engine = await _make("memory", AdvancedDatabase(default_find_many_limit=3))
    for i in range(10):
        await adapter.create("user", {"name": f"n{i}", "email": f"u{i}@x.com"})
    rows = await adapter.find_many("user")
    assert len(rows) == 3


async def test_operator_not_in(adapter):
    await _user(adapter, email="a@example.com")
    await _user(adapter, email="b@example.com")
    await _user(adapter, email="c@example.com")
    rows = await adapter.find_many(
        "user", [Where("email", ["a@example.com", "b@example.com"], "not_in")]
    )
    assert [r["email"] for r in rows] == ["c@example.com"]


async def test_operator_starts_with_ends_with(adapter):
    await _user(adapter, email="alice@example.com", name="Alice")
    await _user(adapter, email="bob@example.org", name="Bob")
    starts = await adapter.find_many("user", [Where("name", "Al", "starts_with")])
    assert [r["name"] for r in starts] == ["Alice"]
    ends = await adapter.find_many("user", [Where("email", ".org", "ends_with")])
    assert [r["email"] for r in ends] == ["bob@example.org"]


async def test_connector_or(adapter):
    await _user(adapter, email="a@example.com", name="A")
    await _user(adapter, email="b@example.com", name="B")
    await _user(adapter, email="c@example.com", name="C")
    rows = await adapter.find_many(
        "user",
        [
            Where("name", "A", connector="OR"),
            Where("name", "B", connector="OR"),
        ],
    )
    assert {r["name"] for r in rows} == {"A", "B"}


async def test_mode_insensitive(adapter):
    await _user(adapter, email="Ada@Example.com", name="Ada")
    row = await adapter.find_one(
        "user", [Where("email", "ada@example.com", mode="insensitive")]
    )
    assert row is not None and row["name"] == "Ada"


async def test_find_many_select(adapter):
    await _user(adapter, email="a@example.com", name="Ada")
    rows = await adapter.find_many("user", select=["email", "name"])
    assert set(rows[0].keys()) == {"email", "name"}


# --- consume_one / increment_one ---------------------------------------------


async def test_consume_one_returns_and_deletes(adapter):
    await adapter.create("counter", {"key": "k", "count": 1})
    row = await adapter.consume_one("counter", [Where("key", "k")])
    assert row is not None and row["key"] == "k"
    assert await adapter.consume_one("counter", [Where("key", "k")]) is None


async def test_increment_one_guarded(adapter):
    await adapter.create("counter", {"key": "k", "count": 5})
    row = await adapter.increment_one(
        "counter", [Where("key", "k")], increment={"count": -1}
    )
    assert row["count"] == 4
    # guard: only decrement while count > 0
    await adapter.update("counter", [Where("key", "k")], {"count": 0})
    blocked = await adapter.increment_one(
        "counter",
        [Where("key", "k"), Where("count", 0, "gt")],
        increment={"count": -1},
    )
    assert blocked is None


async def test_increment_one_requires_increment_or_set(adapter):
    await adapter.create("counter", {"key": "k", "count": 1})
    with pytest.raises(ValueError):
        await adapter.increment_one("counter", [Where("key", "k")], increment={})


# --- transactions (item 8) ---------------------------------------------------


async def test_transaction_commits(adapter):
    async def work(tx):
        await tx.create("user", {"name": "A", "email": "a@example.com"})
        await tx.create("user", {"name": "B", "email": "b@example.com"})

    await adapter.transaction(work)
    assert await adapter.count("user") == 2


async def test_transaction_rolls_back(adapter):
    await _user(adapter, email="keep@example.com")

    async def work(tx):
        await tx.create("user", {"name": "X", "email": "x@example.com"})
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        await adapter.transaction(work)
    assert await adapter.count("user") == 1
    assert await adapter.find_one("user", [Where("email", "x@example.com")]) is None
