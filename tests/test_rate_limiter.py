"""Rate-limiter algorithm: the rolling window, backend equivalence through the
limiter, and custom-rule precedence/skip. Storage backends in isolation are
covered by test_rate_limit_storage.py."""

from __future__ import annotations

import asyncio
import math
from typing import Any

from better_auth import RateLimit
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

    N/A here, by construction: the port has no background-task seam — `RateLimiter.check`
    (rate_limit.py:171-192) awaits every storage call inline, and the sweep itself lives
    inside TS's atomic `createDatabaseStorageWrapper`, which the port replaced wholesale
    with the uniform read-decide-write path (ponytail note, rate_limit.py:13-15). Pinned:
    `check` leaves no task running and no DB write in flight.
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
