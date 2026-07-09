"""In-memory adapter for development and tests."""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from typing import Any

from .base import BaseAdapter, Where

_OPS: dict[str, Callable[[Any, Any], bool]] = {
    "eq": lambda a, b: a == b,
    "ne": lambda a, b: a != b,
    "in": lambda a, b: a in b,
    "contains": lambda a, b: isinstance(a, str) and b in a,
    "gt": lambda a, b: a is not None and a > b,
    "gte": lambda a, b: a is not None and a >= b,
    "lt": lambda a, b: a is not None and a < b,
    "lte": lambda a, b: a is not None and a <= b,
}


def _matches(row: dict[str, Any], where: list[Where] | None) -> bool:
    return all(_OPS[c.operator](row.get(c.field), c.value) for c in where or [])


class MemoryAdapter(BaseAdapter):
    def __init__(self) -> None:
        self._store: dict[str, list[dict[str, Any]]] = defaultdict(list)

    async def create(self, model: str, data: dict[str, Any]) -> dict[str, Any]:
        self._store[model].append(dict(data))
        return dict(data)

    async def find_one(self, model: str, where: list[Where]) -> dict[str, Any] | None:
        return next((dict(r) for r in self._store[model] if _matches(r, where)), None)

    async def find_many(self, model: str, where: list[Where] | None = None) -> list[dict[str, Any]]:
        return [dict(r) for r in self._store[model] if _matches(r, where)]

    async def update(
        self, model: str, where: list[Where], data: dict[str, Any]
    ) -> dict[str, Any] | None:
        for row in self._store[model]:
            if _matches(row, where):
                row.update(data)
                return dict(row)
        return None

    async def delete_many(self, model: str, where: list[Where]) -> int:
        rows = self._store[model]
        kept = [r for r in rows if not _matches(r, where)]
        deleted = len(rows) - len(kept)
        self._store[model] = kept
        return deleted
