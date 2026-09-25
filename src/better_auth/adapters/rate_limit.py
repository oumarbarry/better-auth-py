"""Rate-limit storage backends (mirrors better-auth's ``BetterAuthRateLimitStorage``).

Each backend records one request and decides it in a single ``consume(key, rule)`` step
(TS v1.7.6 api/rate-limiter/index.ts:133-320), so concurrent requests cannot all pass a
stale read. ``rule`` is ``{"window": seconds, "max": requests}``; the result is
``{"allowed": bool, "retryAfter": seconds | None}``. The rule precedence and request keying
live in ``rate_limit.py``.

A database row is ``{"key": str, "count": int, "lastRequest": int}`` where ``lastRequest``
is epoch milliseconds (the ``rateLimit`` table's ``bigint``). A secondary-storage counter
is a plain integer string written by ``SecondaryStorage.increment``, whose TTL is set once
when the key is created. The older ``get``/``set`` methods stay for custom code that used
them.
"""

from __future__ import annotations

import json
import logging
import math
import time
from typing import Any, Protocol

from .base import BaseAdapter, Where

logger = logging.getLogger("better_auth")

RATE_LIMIT_MODEL = "rateLimit"

#: in-process store ceiling, so a flood of distinct keys cannot grow it without bound
MEMORY_STORE_MAX_ENTRIES = 100_000

Rule = dict[str, int]
Decision = dict[str, Any]


class RateLimitStorage(Protocol):
    async def consume(self, key: str, rule: Rule) -> Decision: ...


def _now_ms() -> int:
    return int(time.time() * 1000)


def retry_after(last_request: int, window: int, now_ms: int | None = None) -> int:
    now = _now_ms() if now_ms is None else now_ms
    return math.ceil((last_request + window * 1000 - now) / 1000)


def decide_consume(
    data: dict[str, Any] | None, window: int, maximum: int, now_ms: int
) -> tuple[dict[str, Any], bool, bool, int | None]:
    """One rolling-window step (TS ``decideConsume``, index.ts:50).

    Returns ``(next_row, is_update, allowed, retry_after)``. ``next_row`` carries the
    new ``{count, lastRequest}``; ``is_update`` is False only when opening a fresh key.
    """
    if not data:
        return {"count": 1, "lastRequest": now_ms}, False, True, None
    if now_ms - data["lastRequest"] >= window * 1000:
        return {"count": 1, "lastRequest": now_ms}, True, True, None
    if data["count"] >= maximum:
        return data, True, False, retry_after(data["lastRequest"], window, now_ms)
    return {"count": data["count"] + 1, "lastRequest": now_ms}, True, True, None


_legacy_warned = False


async def legacy_consume(storage: Any, key: str, rule: Rule) -> Decision:
    """Non-atomic read-decide-write for a storage without an atomic ``consume`` (a custom
    ``get``/``set`` storage, or a secondary storage without ``increment``). TS 1.6 did the
    same (``legacyConsume``); TS 1.7 refuses such storages. Kept so they keep working,
    with one warning, since concurrent requests can pass the check together."""
    global _legacy_warned
    if not _legacy_warned:
        _legacy_warned = True
        logger.warning(
            "Rate limiting is best-effort: the configured storage has no atomic "
            "`consume`, so concurrent requests may bypass the limit. Provide a storage "
            "that implements `consume` for strict enforcement."
        )
    data = await storage.get(key)
    next_row, is_update, allowed, wait = decide_consume(
        data, rule["window"], rule["max"], _now_ms()
    )
    if not allowed:
        return {"allowed": False, "retryAfter": wait}
    await storage.set(key, {"key": key, **next_row}, is_update)
    return {"allowed": True, "retryAfter": None}


class MemoryRateLimitStorage:
    """In-process store; an entry lives for the window of the rule that last wrote it."""

    def __init__(self, window: int = 10) -> None:
        self._window = window
        #: key -> (row, expires_at epoch ms); dict order is insertion order
        self._store: dict[str, tuple[dict[str, Any], int]] = {}

    def _prune(self, now: int) -> None:
        for key in [k for k, (_, expires_at) in self._store.items() if now >= expires_at]:
            del self._store[key]
        # ponytail: O(n) sweep per request, same as TS pruneMemoryStore (index.ts:23)
        for key in list(self._store)[: max(len(self._store) - MEMORY_STORE_MAX_ENTRIES, 0)]:
            del self._store[key]

    async def consume(self, key: str, rule: Rule) -> Decision:
        # TS index.ts:308: atomic because nothing awaits between the read and the write.
        now = _now_ms()
        self._prune(now)
        entry = self._store.get(key)
        current = entry[0] if entry and now < entry[1] else None
        next_row, _, allowed, wait = decide_consume(current, rule["window"], rule["max"], now)
        if allowed:
            self._store[key] = ({**next_row, "key": key}, now + rule["window"] * 1000)
        return {"allowed": allowed, "retryAfter": wait}

    async def get(self, key: str) -> dict[str, Any] | None:
        entry = self._store.get(key)
        if entry is None or _now_ms() >= entry[1]:
            self._store.pop(key, None)
            return None
        return entry[0]

    async def set(self, key: str, value: dict[str, Any], update: bool = False) -> None:
        self._store[key] = (value, _now_ms() + self._window * 1000)


class DatabaseRateLimitStorage:
    """Rows in the ``rateLimit`` table, updated through guarded ``increment_one``
    (TS ``createDatabaseStorageWrapper``, index.ts:115)."""

    def __init__(self, adapter: BaseAdapter, longest_window: int = 0) -> None:
        self._adapter = adapter
        #: longest configured window, the expired-row sweep horizon (index.ts:120)
        self._longest_window = longest_window

    async def get(self, key: str) -> dict[str, Any] | None:
        rows = await self._adapter.find_many(RATE_LIMIT_MODEL, [Where("key", key)], limit=1)
        return rows[0] if rows else None

    async def set(self, key: str, value: dict[str, Any], update: bool = False) -> None:
        if update:
            await self._adapter.update_many(
                RATE_LIMIT_MODEL,
                [Where("key", key)],
                {"count": value["count"], "lastRequest": value["lastRequest"]},
            )
        else:
            await self._adapter.create(
                RATE_LIMIT_MODEL,
                {"key": key, "count": value["count"], "lastRequest": value["lastRequest"]},
            )

    async def consume(self, key: str, rule: Rule) -> Decision:
        window = rule["window"]
        horizon = max(self._longest_window, window)
        window_ms = window * 1000
        data = await self.get(key)
        now = _now_ms()
        allowed: Decision = {"allowed": True, "retryAfter": None}

        # Fresh key: open the window only by creating the row, so one concurrent opener
        # wins and the others re-read and are counted (index.ts:148).
        if data is None:
            try:
                await self._adapter.create(
                    RATE_LIMIT_MODEL, {"key": key, "count": 1, "lastRequest": now}
                )
                return allowed
            except Exception:
                if await self.get(key) is None:
                    raise
                return await self.consume(key, rule)

        # Window elapsed: reset, guarded on the window so a concurrent increment in the
        # new window is not clobbered (index.ts:172).
        if now - data["lastRequest"] >= window_ms:
            reset = await self._adapter.increment_one(
                RATE_LIMIT_MODEL,
                [Where("key", key), Where("lastRequest", data["lastRequest"], "lte")],
                increment={},
                set={"count": 1, "lastRequest": now},
            )
            if reset is None:
                return await self.consume(key, rule)
            await self._delete_expired_rows(now - horizon * 1000)
            return allowed

        # Within the window and under the max: guarded on both (index.ts:196).
        incremented = await self._adapter.increment_one(
            RATE_LIMIT_MODEL,
            [
                Where("key", key),
                Where("lastRequest", now - window_ms, "gt"),
                Where("count", rule["max"], "lt"),
            ],
            increment={"count": 1},
            set={"lastRequest": now},
        )
        if incremented is not None:
            return allowed

        # Guard missed: the window rolled or the max was reached; re-read and re-decide.
        fresh = await self.get(key)
        if fresh is None or now - fresh["lastRequest"] >= window_ms:
            return await self.consume(key, rule)
        return {"allowed": False, "retryAfter": retry_after(fresh["lastRequest"], window)}

    async def _delete_expired_rows(self, cutoff: int) -> None:
        """Best-effort sweep bounding table growth; failures are logged (index.ts:229)."""
        try:
            await self._adapter.delete_many(RATE_LIMIT_MODEL, [Where("lastRequest", cutoff, "lt")])
        except Exception:
            logger.exception("Error pruning rate limit rows")


class SecondaryRateLimitStorage:
    """Counters in a ``SecondaryStorage`` (Redis/KV) through its atomic ``increment``,
    in the TS storage format: a plain integer whose TTL is the window, set when the key
    is created and never extended (index.ts:280)."""

    def __init__(self, secondary_storage: Any, window: int = 10) -> None:
        self._ss = secondary_storage
        self._window = window

    async def consume(self, key: str, rule: Rule) -> Decision:
        increment = getattr(self._ss, "increment", None)
        if increment is None:
            return await legacy_consume(self, key, rule)
        try:
            count = await increment(key, rule["window"])
        except Exception:
            # A counter from the older JSON format is not an integer, so INCR fails on it.
            # Drop it and restart the window once; a second failure propagates.
            await self._ss.delete(key)
            count = await increment(key, rule["window"])
        if count <= rule["max"]:
            return {"allowed": True, "retryAfter": None}
        return {"allowed": False, "retryAfter": rule["window"]}

    # legacy JSON format, used only by a store without ``increment``
    async def get(self, key: str) -> dict[str, Any] | None:
        raw = await self._ss.get(key)
        return json.loads(raw) if raw else None

    async def set(self, key: str, value: dict[str, Any], update: bool = False) -> None:
        await self._ss.set(key, json.dumps(value, separators=(",", ":")), self._window)
