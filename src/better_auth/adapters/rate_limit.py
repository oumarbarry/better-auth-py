"""Rate-limit storage backends — the *storage side only* (mirrors better-auth's
``BetterAuthRateLimitStorage`` get/set). The limiter algorithm (window decision,
``consume``) is a separate concern (W1-F); this just persists ``{key, count, lastRequest}``
rows across three backends so the future limiter can plug into any of them.

A row is a plain dict ``{"key": str, "count": int, "lastRequest": int}`` where
``lastRequest`` is epoch milliseconds (matches the ``rateLimit`` table's ``bigint``).
"""

from __future__ import annotations

import json
import time
from typing import Any, Protocol

from .base import BaseAdapter, Where

RATE_LIMIT_MODEL = "rateLimit"


class RateLimitStorage(Protocol):
    async def get(self, key: str) -> dict[str, Any] | None: ...
    async def set(self, key: str, value: dict[str, Any], update: bool = False) -> None: ...


class MemoryRateLimitStorage:
    """In-process store with a per-key TTL (the rolling window in seconds)."""

    def __init__(self, window: int = 10) -> None:
        self._window = window
        self._store: dict[str, tuple[dict[str, Any], float]] = {}

    async def get(self, key: str) -> dict[str, Any] | None:
        entry = self._store.get(key)
        if entry is None:
            return None
        data, expires_at = entry
        if time.monotonic() >= expires_at:
            del self._store[key]
            return None
        return data

    async def set(self, key: str, value: dict[str, Any], update: bool = False) -> None:
        self._store[key] = (value, time.monotonic() + self._window)


class DatabaseRateLimitStorage:
    """Persists rows in the ``rateLimit`` table via the DB adapter."""

    def __init__(self, adapter: BaseAdapter) -> None:
        self._adapter = adapter

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


class SecondaryRateLimitStorage:
    """Persists ``{"count", "lastRequest"}`` JSON in a ``SecondaryStorage`` (Redis/KV).

    Wire format is byte-compatible with the TS lib's secondary-storage rate limiter.
    """

    def __init__(self, secondary_storage: Any, window: int = 10) -> None:
        self._ss = secondary_storage
        self._window = window

    async def get(self, key: str) -> dict[str, Any] | None:
        raw = await self._ss.get(key)
        return json.loads(raw) if raw else None

    async def set(self, key: str, value: dict[str, Any], update: bool = False) -> None:
        await self._ss.set(
            key,
            json.dumps(value, separators=(",", ":")),
            self._window,
        )
