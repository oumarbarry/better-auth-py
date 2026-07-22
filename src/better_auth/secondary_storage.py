"""Secondary storage: a plain KV interface (mirrors better-auth's ``SecondaryStorage``).

Sessions (and, elsewhere, rate-limit counters and single-use tokens) can live in a KV
store such as Redis instead of the SQL database. The wire format the internal adapter
writes is byte-compatible with the TypeScript library, so a Python app and a TS app can
share one store. No schema, no models — just string keys and string values.
"""

from __future__ import annotations

import time
from typing import Protocol, runtime_checkable


@runtime_checkable
class SecondaryStorage(Protocol):
    """KV contract. ``get_and_delete`` / ``increment`` are optional (checked at runtime)."""

    async def get(self, key: str) -> str | None: ...
    async def set(self, key: str, value: str, ttl: int | None = None) -> None: ...
    async def delete(self, key: str) -> None: ...


class MemorySecondaryStorage:
    """In-memory ``SecondaryStorage`` for tests and single-process dev.

    ``ttls`` records the ttl (seconds) passed to the last ``set`` per key, so tests can
    assert TTL behaviour without reaching into wall-clock timing.
    """

    def __init__(self) -> None:
        self._store: dict[str, tuple[str, float | None]] = {}
        self.ttls: dict[str, int | None] = {}

    def _expired(self, key: str) -> bool:
        item = self._store.get(key)
        if item is None:
            return True
        _, expires_at = item
        return expires_at is not None and time.monotonic() > expires_at

    async def get(self, key: str) -> str | None:
        if self._expired(key):
            self._store.pop(key, None)
            return None
        return self._store[key][0]

    async def set(self, key: str, value: str, ttl: int | None = None) -> None:
        expires_at = time.monotonic() + ttl if ttl is not None else None
        self._store[key] = (value, expires_at)
        self.ttls[key] = ttl

    async def delete(self, key: str) -> None:
        self._store.pop(key, None)
        self.ttls.pop(key, None)

    async def get_and_delete(self, key: str) -> str | None:
        """Atomic read-and-delete for single-use credentials (single-process only)."""
        value = await self.get(key)
        if value is not None:
            await self.delete(key)
        return value

    async def increment(self, key: str, ttl: int | None = None) -> int:
        """Atomic counter; ``ttl`` is applied only when the counter is first created."""
        if self._expired(key):
            self._store.pop(key, None)
            await self.set(key, "1", ttl)
            return 1
        count = int(self._store[key][0]) + 1
        _, expires_at = self._store[key]
        remaining = None if expires_at is None else max(int(expires_at - time.monotonic()), 0)
        self._store[key] = (str(count), expires_at)
        self.ttls[key] = remaining
        return count
