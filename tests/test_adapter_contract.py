"""Ported subset of better-auth's shared adapter test suite.

Runs against both MemoryAdapter and SQLAlchemyAdapter to prove parity for the
expanded contract (item 2), the transform layer (item 3), advanced.database
options (item 6) and transactions (item 8).
"""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool

from better_auth.adapters.base import BaseAdapter, Where
from better_auth.adapters.memory import MemoryAdapter
from better_auth.adapters.sqlalchemy import SQLAlchemyAdapter
from better_auth.config import AdvancedDatabase
from better_auth.schema import CORE_SCHEMA, Field, merge_schema
from better_auth.types import BetterAuthError

# A tiny model with numeric fields for consume/increment tests.
_COUNTER_SCHEMA = {
    "counter": {
        "id": Field("string", required=True, unique=True),
        "key": Field("string", required=True, unique=True),
        "count": Field("number", required=True),
    }
}
_SCHEMA = merge_schema(CORE_SCHEMA, _COUNTER_SCHEMA)


class FallbackAdapter(MemoryAdapter):
    """A custom adapter without native atomic methods: exercises the shared fallbacks
    (TS core/src/db/adapter/atomic-fallback.ts, v1.7.6)."""

    consume_one = BaseAdapter.consume_one
    increment_one = BaseAdapter.increment_one


async def _make(kind: str, advanced: AdvancedDatabase | None = None):
    if kind in ("memory", "fallback"):
        adapter = (MemoryAdapter if kind == "memory" else FallbackAdapter)(advanced=advanced)
        adapter.init(_SCHEMA)
        return adapter, None
    engine = create_async_engine("sqlite+aiosqlite://", poolclass=StaticPool)
    adapter = SQLAlchemyAdapter(engine, advanced=advanced)
    adapter.init(_SCHEMA)
    await adapter.create_tables()
    return adapter, engine


@pytest.fixture(params=["memory", "fallback", "sqlalchemy"])
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
    asc = await adapter.find_many("user", limit=2, sort_by={"field": "name", "direction": "asc"})
    assert [r["name"] for r in asc] == ["name0", "name1"]
    desc = await adapter.find_many("user", limit=2, sort_by={"field": "name", "direction": "desc"})
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
    row = await adapter.find_one("user", [Where("email", "ada@example.com", mode="insensitive")])
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
    row = await adapter.increment_one("counter", [Where("key", "k")], increment={"count": -1})
    assert row["count"] == 4
    # guard: only decrement while count > 0
    await adapter.update("counter", [Where("key", "k")], {"count": 0})
    blocked = await adapter.increment_one(
        "counter",
        [Where("key", "k"), Where("count", 0, "gt")],
        increment={"count": -1},
    )
    assert blocked is None


async def test_increment_one_updates_only_the_selected_row(adapter):
    # TS core factory.ts incrementOne fallback (v1.6.29) pins the update to the row id.
    await adapter.create("counter", {"key": "a", "count": 1})
    await adapter.create("counter", {"key": "b", "count": 1})
    row = await adapter.increment_one("counter", [Where("count", 1)], increment={"count": 1})
    assert row is not None and row["count"] == 2
    assert sorted(r["count"] for r in await adapter.find_many("counter")) == [1, 2]


async def test_increment_one_requires_increment_or_set(adapter):
    # TS v1.7.6 factory.ts:1466
    await adapter.create("counter", {"key": "k", "count": 1})
    with pytest.raises(BetterAuthError, match="requires a non-empty `increment` or `set`"):
        await adapter.increment_one("counter", [Where("key", "k")], increment={})


async def test_increment_one_set_only_and_mixed(adapter):
    await adapter.create("counter", {"key": "k", "count": 1})
    row = await adapter.increment_one(
        "counter", [Where("key", "k")], increment={}, set={"count": 7}
    )
    assert row is not None and row["count"] == 7
    row = await adapter.increment_one(
        "counter", [Where("key", "k")], increment={"count": 2}, set={"key": "k2"}
    )
    assert row is not None and row["count"] == 9 and row["key"] == "k2"
    stored = await adapter.find_one("counter", [Where("key", "k2")])
    assert stored is not None and stored["count"] == 9


async def test_concurrent_increments_lose_nothing(adapter):
    # TS v1.7.6 atomic-fallback.ts:178: the counter value is part of the CAS guard, so
    # interleaved increments retry instead of overwriting each other.
    await adapter.create("counter", {"key": "k", "count": 0})
    await asyncio.gather(
        *(
            adapter.increment_one("counter", [Where("key", "k")], increment={"count": 1})
            for _ in range(4)
        )
    )
    row = await adapter.find_one("counter", [Where("key", "k")])
    assert row is not None and row["count"] == 4


async def test_concurrent_consumers_get_one_row(adapter):
    await adapter.create("counter", {"key": "k", "count": 1})
    results = await asyncio.gather(
        *(adapter.consume_one("counter", [Where("key", "k")]) for _ in range(3))
    )
    assert sum(r is not None for r in results) == 1


# --- shared atomic fallbacks (TS v1.7.6 core/src/db/adapter/atomic-fallback.ts) -------


async def _fallback() -> FallbackAdapter:
    adapter, _ = await _make("fallback")
    assert isinstance(adapter, FallbackAdapter)
    return adapter


async def test_fallback_consume_returns_none_when_a_concurrent_caller_won(monkeypatch):
    adapter = await _fallback()
    await adapter.create("counter", {"key": "k", "count": 1})
    real_find_one = adapter.find_one

    async def read_then_lose_race(*args, **kwargs):
        row = await real_find_one(*args, **kwargs)
        await adapter.delete_many("counter", [Where("key", "k")])
        return row

    monkeypatch.setattr(adapter, "find_one", read_then_lose_race)
    assert await adapter.consume_one("counter", [Where("key", "k")]) is None


async def test_fallback_consume_is_guarded_on_the_snapshot(monkeypatch):
    # atomic-fallback.ts:157: the delete is guarded on every scalar column of the read
    # snapshot, so a row changed between read and delete is left alone.
    adapter = await _fallback()
    await adapter.create("counter", {"key": "k", "count": 1})
    real_find_one = adapter.find_one

    async def read_then_row_changes(*args, **kwargs):
        row = await real_find_one(*args, **kwargs)
        await adapter.update_many("counter", [Where("key", "k")], {"count": 2})
        return row

    monkeypatch.setattr(adapter, "find_one", read_then_row_changes)
    assert await adapter.consume_one("counter", [Where("key", "k")]) is None
    assert await adapter.count("counter") == 1


async def test_fallback_consume_rejects_an_impossible_row_count(monkeypatch):
    adapter = await _fallback()
    await adapter.create("counter", {"key": "k", "count": 1})

    async def two_rows(*args, **kwargs):
        return 2

    monkeypatch.setattr(adapter, "delete_many", two_rows)
    with pytest.raises(BetterAuthError, match="affected row count of 0 or 1"):
        await adapter.consume_one("counter", [Where("key", "k")])


async def test_fallback_increment_retries_after_a_concurrent_write(monkeypatch):
    adapter = await _fallback()
    await adapter.create("counter", {"key": "k", "count": 1})
    real_find_one = adapter.find_one
    raced = []

    async def read_then_race_once(*args, **kwargs):
        row = await real_find_one(*args, **kwargs)
        if not raced:
            raced.append(True)
            await adapter.update_many("counter", [Where("key", "k")], {"count": 10})
        return row

    monkeypatch.setattr(adapter, "find_one", read_then_race_once)
    row = await adapter.increment_one("counter", [Where("key", "k")], increment={"count": 1})
    assert row is not None and row["count"] == 11
    stored = await real_find_one("counter", [Where("key", "k")])
    assert stored is not None and stored["count"] == 11


async def test_fallback_increment_gives_up_after_five_attempts(monkeypatch):
    adapter = await _fallback()
    await adapter.create("counter", {"key": "k", "count": 1})
    attempts = []

    async def always_lost(*args, **kwargs):
        attempts.append(1)
        return 0

    monkeypatch.setattr(adapter, "update_many", always_lost)
    with pytest.raises(BetterAuthError, match="could not complete an atomic increment"):
        await adapter.increment_one("counter", [Where("key", "k")], increment={"count": 1})
    assert len(attempts) == 5


async def test_fallback_increment_noop_skips_the_write(monkeypatch):
    # atomic-fallback.ts:216: a no-op takes effect at the read.
    adapter = await _fallback()
    await adapter.create("counter", {"key": "k", "count": 3})

    async def must_not_write(*args, **kwargs):
        raise AssertionError("no write expected")

    monkeypatch.setattr(adapter, "update_many", must_not_write)
    row = await adapter.increment_one(
        "counter", [Where("key", "k")], increment={"count": 0}, set={"count": 3}
    )
    assert row is not None and row["count"] == 3


async def test_fallback_increment_requires_numeric_counters():
    adapter = await _fallback()
    await adapter.create("counter", {"key": "k", "count": 1})
    await adapter.update_many("counter", [Where("key", "k")], {"count": "one"})
    with pytest.raises(BetterAuthError, match="finite numeric counter values"):
        await adapter.increment_one("counter", [Where("key", "k")], increment={"count": 1})


async def test_fallback_increment_only_leaves_updated_at_alone():
    # TS only runs transformInput (onUpdate) over `set`, never over bare increments.
    adapter = await _fallback()
    adapter.schema = merge_schema(
        adapter.schema,
        {"counter": {"updatedAt": Field("datetime", on_update=lambda: "bumped")}},
    )
    await adapter.create("counter", {"key": "k", "count": 1, "updatedAt": "original"})
    row = await adapter.increment_one("counter", [Where("key", "k")], increment={"count": 1})
    assert row is not None and row["updatedAt"] == "original"
    stored = await adapter.find_one("counter", [Where("key", "k")])
    assert stored is not None and stored["updatedAt"] == "original"


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


async def test_in_operator_matches_generated_mixed_case_ids(adapter):
    # regression: the memory adapter's case-sensitive "in"/"not_in" path lowercased
    # the ROW value (but not the query values), so generated mixed-case ids and
    # session tokens never matched
    u1 = await _user(adapter)
    u2 = await _user(adapter, email="b@example.com")
    rows = await adapter.find_many("user", [Where("id", [u1["id"], u2["id"]], "in")])
    assert {r["id"] for r in rows} == {u1["id"], u2["id"]}
    kept = await adapter.find_many("user", [Where("id", [u1["id"]], "not_in")])
    assert u1["id"] not in {r["id"] for r in kept}


# --- memory adapter transaction isolation (TS v1.7.6 memory-adapter.ts:40-120) --------


async def test_memory_failed_transaction_keeps_concurrent_writes():
    adapter, _ = await _make("memory")
    started = asyncio.Event()
    release = asyncio.Event()

    async def work(tx):
        await tx.create("user", {"name": "X", "email": "x@example.com"})
        started.set()
        await release.wait()
        raise RuntimeError("boom")

    task = asyncio.create_task(adapter.transaction(work))
    await started.wait()
    # the uncommitted write is invisible outside the transaction
    assert await adapter.find_one("user", [Where("email", "x@example.com")]) is None
    await _user(adapter, email="concurrent@example.com")
    release.set()
    with pytest.raises(RuntimeError):
        await task
    assert await adapter.find_one("user", [Where("email", "concurrent@example.com")])
    assert await adapter.find_one("user", [Where("email", "x@example.com")]) is None


async def test_memory_committed_transaction_merges_with_concurrent_writes():
    adapter, _ = await _make("memory")
    kept = await _user(adapter, email="kept@example.com", name="old")
    doomed = await _user(adapter, email="doomed@example.com")
    started = asyncio.Event()
    release = asyncio.Event()

    async def work(tx):
        await tx.create("user", {"name": "T", "email": "tx@example.com"})
        await tx.delete("user", [Where("id", doomed["id"])])
        started.set()
        await release.wait()

    task = asyncio.create_task(adapter.transaction(work))
    await started.wait()
    await _user(adapter, email="concurrent@example.com")
    await adapter.update("user", [Where("id", kept["id"])], {"name": "new"})
    release.set()
    await task
    emails = {r["email"] for r in await adapter.find_many("user")}
    assert emails == {"kept@example.com", "tx@example.com", "concurrent@example.com"}
    row = await adapter.find_one("user", [Where("id", kept["id"])])
    assert row is not None and row["name"] == "new"
