"""Rate-limiter algorithm (gap item 14): the rolling window, backend equivalence
through the limiter, and custom-rule precedence/skip. Storage backends in isolation
are covered by test_rate_limit_storage.py."""

from __future__ import annotations

import math

from better_auth import RateLimit
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
