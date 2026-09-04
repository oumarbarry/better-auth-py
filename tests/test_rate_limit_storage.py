"""rateLimit table + storage backends (item 9, storage side only)."""

from __future__ import annotations

import json
from typing import Any

from better_auth.adapters.memory import MemoryAdapter
from better_auth.adapters.rate_limit import (
    DatabaseRateLimitStorage,
    MemoryRateLimitStorage,
    SecondaryRateLimitStorage,
)
from better_auth.schema import CORE_SCHEMA, merge_schema, rate_limit_model
from better_auth.secondary_storage import MemorySecondaryStorage


def _row(value: dict[str, Any] | None) -> dict[str, Any]:
    assert value is not None
    return value


# --- schema -------------------------------------------------------------------


def test_rate_limit_model_shape():
    fields = rate_limit_model()
    assert fields["key"].required and fields["key"].unique
    assert fields["count"].type == "number"
    assert fields["lastRequest"].type == "number" and fields["lastRequest"].bigint
    # lastRequest defaults to epoch milliseconds
    assert fields["lastRequest"].make_default() > 1_000_000_000_000


# --- backends -----------------------------------------------------------------


async def test_memory_backend_get_set():
    store = MemoryRateLimitStorage(window=10)
    assert await store.get("k") is None
    await store.set("k", {"key": "k", "count": 1, "lastRequest": 123})
    assert _row(await store.get("k"))["count"] == 1


async def test_database_backend_round_trips_via_adapter():
    adapter = MemoryAdapter()
    adapter.init(merge_schema(CORE_SCHEMA, {"rateLimit": rate_limit_model()}))
    store = DatabaseRateLimitStorage(adapter)

    await store.set("k", {"count": 1, "lastRequest": 100})
    row = _row(await store.get("k"))
    assert row["key"] == "k" and row["count"] == 1 and row["lastRequest"] == 100

    await store.set("k", {"count": 5, "lastRequest": 200}, update=True)
    assert _row(await store.get("k"))["count"] == 5
    assert await adapter.count("rateLimit") == 1  # update, not insert


async def test_secondary_backend_wire_format():
    ss = MemorySecondaryStorage()
    store = SecondaryRateLimitStorage(ss, window=10)
    await store.set("k", {"count": 2, "lastRequest": 999})
    # byte-compatible with the TS lib: compact {"count",...,"lastRequest"} JSON
    raw = await ss.get("k")
    assert raw == '{"count":2,"lastRequest":999}'
    assert json.loads(raw or "") == {"count": 2, "lastRequest": 999}
    assert ss.ttls["k"] == 10  # ttl = window
