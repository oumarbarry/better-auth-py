"""Rate-limiter algorithm: the rolling window, backend equivalence through the
limiter, and custom-rule precedence/skip. Storage backends in isolation are
covered by test_rate_limit_storage.py."""

from __future__ import annotations

import asyncio
import json
import logging
import math
import time
from typing import Any

from better_auth import RateLimit
from better_auth.adapters.base import Where
from better_auth.adapters.memory import MemoryAdapter
from better_auth.rate_limit import decide_consume
from better_auth.secondary_storage import MemorySecondaryStorage
from better_auth.types import AuthRequest
from conftest import make_auth

# --- pure window algorithm (decideConsume parity) -----------------------------


def test_fresh_key_opens_window_as_create():
    row, is_update, allowed, retry = decide_consume(None, 10, 3, 1000)
    assert allowed and retry is None
    assert row == {"count": 1, "lastRequest": 1000}
    assert is_update is False  # a fresh key is a create, not an update


def test_increment_within_window():
    row, is_update, allowed, _ = decide_consume({"count": 1, "lastRequest": 1000}, 10, 3, 2000)
    assert allowed and is_update is True
    assert row == {"count": 2, "lastRequest": 2000}


def test_blocked_at_max_reports_retry_after():
    _, _, allowed, retry = decide_consume({"count": 3, "lastRequest": 1000}, 10, 3, 5000)
    assert not allowed
    assert retry == math.ceil((1000 + 10_000 - 5000) / 1000)  # == 6


def test_window_boundary_resets_count():
    # TS v1.7.6 api/rate-limiter/index.ts:70: `timeSinceLastRequest >= windowInMs`
    row, _, allowed, _ = decide_consume({"count": 3, "lastRequest": 1000}, 10, 3, 11_000)
    assert allowed and row == {"count": 1, "lastRequest": 11_000}


def test_window_elapsed_resets_count():
    row, _, allowed, retry = decide_consume({"count": 3, "lastRequest": 1000}, 10, 3, 20_000)
    assert allowed and retry is None
    assert row == {"count": 1, "lastRequest": 20_000}


# --- backend equivalence through the limiter ----------------------------------


async def _drive(auth, n=4, path="/x"):
    results = []
    for _ in range(n):
        request = AuthRequest(method="POST", path=path, headers={}, client_ip="1.2.3.4")
        results.append(await auth._rate_limiter.check(request))
    return results


def _auth_with(storage, **extra):
    return make_auth(
        rate_limit=RateLimit(enabled=True, storage=storage, custom_rules={"/x": (100, 3)}),
        **extra,
    )


async def test_memory_backend_enforces_max():
    results = await _drive(_auth_with("memory"))
    assert [r is None for r in results] == [True, True, True, False]


async def test_database_backend_enforces_max():
    results = await _drive(_auth_with("database"))
    assert [r is None for r in results] == [True, True, True, False]


async def test_secondary_backend_enforces_max():
    auth = _auth_with("secondary-storage", secondary_storage=MemorySecondaryStorage())
    results = await _drive(auth)
    assert [r is None for r in results] == [True, True, True, False]


# --- custom rules -------------------------------------------------------------


async def test_custom_rule_false_skips_limiting():
    auth = make_auth(rate_limit=RateLimit(enabled=True, custom_rules={"/x": False}))
    results = await _drive(auth, n=10)
    assert all(r is None for r in results)  # never limited


async def test_custom_rule_wildcard_match():
    auth = make_auth(rate_limit=RateLimit(enabled=True, custom_rules={"/api/*": (100, 2)}))
    results = await _drive(auth, path="/api/thing")
    assert [r is None for r in results] == [True, True, False, False]


async def test_custom_rule_callable():
    def rule(request, defaults):
        return (100, 1)

    auth = make_auth(rate_limit=RateLimit(enabled=True, custom_rules={"/x": rule}))
    results = await _drive(auth)
    assert [r is None for r in results] == [True, False, False, False]


async def test_no_trusted_ip_shares_a_bucket():
    # no client IP -> fail closed on a shared per-path bucket (still enforced)
    auth = make_auth(rate_limit=RateLimit(enabled=True, custom_rules={"/x": (100, 2)}))
    results = []
    for _ in range(3):
        request = AuthRequest(method="POST", path="/x", headers={}, client_ip=None)
        results.append(await auth._rate_limiter.check(request))
    assert [r is None for r in results] == [True, True, False]


async def test_disabled_when_enabled_false():
    auth = make_auth(rate_limit=RateLimit(enabled=False, custom_rules={"/x": (100, 1)}))
    results = await _drive(auth, n=5)
    assert all(r is None for r in results)


# --- database writes are never fire-and-forget (TS 9ede8059b) -----------------


class _YieldingAdapter(MemoryAdapter):
    """MemoryAdapter that yields to the event loop mid-write and records completion,
    so a detached background write would be observable by the time `check` returns."""

    def __init__(self) -> None:
        super().__init__()
        self.completed: list[str] = []

    async def create(
        self,
        model: str,
        data: dict[str, Any],
        *,
        select: list[str] | None = None,
        force_allow_id: bool = False,
    ) -> dict[str, Any]:
        await asyncio.sleep(0)
        row = await super().create(model, data, select=select, force_allow_id=force_allow_id)
        self.completed.append(f"create:{model}")
        return row


async def test_database_rate_limit_writes_complete_before_check_returns():
    """TS 9ede8059b awaited the expired-row sweep instead of firing it off
    (`ctx.runInBackground` -> `runInBackgroundOrAwait`, api/rate-limiter/index.ts:224-236).

    The port has no background-task seam: the database backend awaits every write and
    the sweep inline. Pinned: `check` leaves no task running and no DB write in flight.
    """
    adapter = _YieldingAdapter()
    auth = make_auth(
        adapter=adapter,
        rate_limit=RateLimit(enabled=True, storage="database", custom_rules={"/x": (100, 3)}),
    )
    request = AuthRequest(method="POST", path="/x", headers={}, client_ip="1.2.3.4")
    tasks_before = asyncio.all_tasks()

    assert await auth._rate_limiter.check(request) is None

    assert adapter.completed == ["create:rateLimit"]  # the write landed inside check()
    assert asyncio.all_tasks() - tasks_before == set()  # nothing was detached
    assert await adapter.count("rateLimit") == 1


# --- atomic consume per backend (TS v1.7.6 api/rate-limiter/index.ts:133-320) --------


def _request(path: str = "/x") -> AuthRequest:
    return AuthRequest(method="POST", path=path, headers={}, client_ip="1.2.3.4")


async def test_database_backend_holds_the_limit_under_concurrency():
    auth = _auth_with("database")
    assert await auth._rate_limiter.check(_request()) is None  # opens the window
    results = await asyncio.gather(*(auth._rate_limiter.check(_request()) for _ in range(8)))
    assert sum(r is None for r in results) == 2  # max 3, one already spent
    row = await auth.adapter.find_one("rateLimit", [Where("key", "1.2.3.4|/x")])
    assert row is not None and row["count"] == 3


async def test_database_backend_prunes_expired_rows_on_window_reset():
    # index.ts:186-188 + :229: a window reset sweeps rows older than the longest window.
    auth = _auth_with("database")
    now = int(time.time() * 1000)
    await auth.adapter.create("rateLimit", {"key": "stale", "count": 1, "lastRequest": 1})
    await auth.adapter.create(
        "rateLimit", {"key": "1.2.3.4|/x", "count": 3, "lastRequest": now - 101_000}
    )
    assert await auth._rate_limiter.check(_request()) is None  # window elapsed: reset
    assert await auth.adapter.find_one("rateLimit", [Where("key", "stale")]) is None
    row = await auth.adapter.find_one("rateLimit", [Where("key", "1.2.3.4|/x")])
    assert row is not None and row["count"] == 1


async def test_secondary_backend_stores_a_plain_counter_with_a_fixed_ttl():
    # index.ts:290: `increment(key, window)`, allowed while count <= max, retry = window.
    ss = MemorySecondaryStorage()
    auth = _auth_with("secondary-storage", secondary_storage=ss)
    results = await _drive(auth)
    assert results == [None, None, None, 100]
    assert await ss.get("1.2.3.4|/x") == "4"
    assert ss.ttls["1.2.3.4|/x"] is not None and 99 <= ss.ttls["1.2.3.4|/x"] <= 100


class _KVWithoutIncrement:
    def __init__(self) -> None:
        self.data: dict[str, str] = {}

    async def get(self, key: str) -> str | None:
        return self.data.get(key)

    async def set(self, key: str, value: str, ttl: int | None = None) -> None:
        self.data[key] = value

    async def delete(self, key: str) -> None:
        self.data.pop(key, None)


async def test_secondary_backend_without_increment_falls_back_with_a_warning(caplog, monkeypatch):
    monkeypatch.setattr("better_auth.adapters.rate_limit._legacy_warned", False)
    ss = _KVWithoutIncrement()
    auth = _auth_with("secondary-storage", secondary_storage=ss)
    with caplog.at_level(logging.WARNING, logger="better_auth"):
        results = await _drive(auth)
    assert [r is None for r in results] == [True, True, True, False]
    assert json.loads(ss.data["1.2.3.4|/x"])["count"] == 3
    assert sum("best-effort" in r.getMessage() for r in caplog.records) == 1


async def test_custom_storage_consume_is_used():
    calls: list[tuple[str, dict[str, int]]] = []

    class Store:
        async def consume(self, key: str, rule: dict[str, int]) -> dict[str, Any]:
            calls.append((key, rule))
            return {"allowed": len(calls) < 2, "retryAfter": 7 if len(calls) >= 2 else None}

    auth = make_auth(
        rate_limit=RateLimit(enabled=True, custom_storage=Store(), custom_rules={"/x": (100, 3)})
    )
    assert await _drive(auth, n=2) == [None, 7]
    assert calls[0] == ("1.2.3.4|/x", {"window": 100, "max": 3})


async def test_custom_storage_with_get_set_still_works(caplog, monkeypatch):
    monkeypatch.setattr("better_auth.adapters.rate_limit._legacy_warned", False)

    class Store:
        def __init__(self) -> None:
            self.rows: dict[str, dict[str, Any]] = {}

        async def get(self, key: str) -> dict[str, Any] | None:
            return self.rows.get(key)

        async def set(self, key: str, value: dict[str, Any], update: bool = False) -> None:
            self.rows[key] = value

    auth = make_auth(
        rate_limit=RateLimit(enabled=True, custom_storage=Store(), custom_rules={"/x": (100, 3)})
    )
    with caplog.at_level(logging.WARNING, logger="better_auth"):
        results = await _drive(auth)
    assert [r is None for r in results] == [True, True, True, False]
    assert any("best-effort" in r.getMessage() for r in caplog.records)


async def test_secondary_backend_restarts_a_legacy_json_counter():
    # A counter written before the plain-integer format makes `increment` fail (Redis INCR
    # on a non-integer raises). The key is dropped and the window restarts.
    ss = MemorySecondaryStorage()
    await ss.set("1.2.3.4|/x", '{"count":3,"lastRequest":1}', 100)
    auth = _auth_with("secondary-storage", secondary_storage=ss)
    results = await _drive(auth)
    assert results == [None, None, None, 100]
    assert await ss.get("1.2.3.4|/x") == "4"
