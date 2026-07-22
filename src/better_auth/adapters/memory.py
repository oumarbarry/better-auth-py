"""In-memory adapter for development and tests."""

from __future__ import annotations

import copy
from collections import defaultdict
from collections.abc import Awaitable, Callable
from typing import Any

from ..config import AdvancedDatabase
from .base import BaseAdapter, SortBy, Where


def _lower(value: Any) -> Any:
    return value.lower() if isinstance(value, str) else value


def _eval(row: dict[str, Any], clause: Where) -> bool:
    a: Any = row.get(clause.field)
    b: Any = clause.value
    op = clause.operator
    insensitive = clause.mode == "insensitive"

    if op in ("in", "not_in"):
        if not isinstance(b, (list, tuple, set)):
            raise ValueError(f"operator {op!r} requires an array value")
        values = [_lower(v) for v in b] if insensitive else list(b)
        found = _lower(a) in values
        return found if op == "in" else not found
    if op in ("contains", "starts_with", "ends_with"):
        if not (isinstance(a, str) and isinstance(b, str)):
            return False
        aa = a.lower() if insensitive else a
        bb = b.lower() if insensitive else b
        if op == "contains":
            return bb in aa
        if op == "starts_with":
            return aa.startswith(bb)
        return aa.endswith(bb)
    if op == "eq":
        if b is None:
            return a is None
        return _lower(a) == _lower(b) if insensitive else a == b
    if op == "ne":
        return _lower(a) != _lower(b) if insensitive else a != b
    if op == "gt":
        return a is not None and a > b
    if op == "gte":
        return a is not None and a >= b
    if op == "lt":
        return a is not None and a < b
    if op == "lte":
        return a is not None and a <= b
    raise ValueError(f"Unsupported operator {op!r}")


def _matches(row: dict[str, Any], where: list[Where] | None) -> bool:
    if not where:
        return True
    result = _eval(row, where[0])
    for clause in where:
        clause_result = _eval(row, clause)
        result = result or clause_result if clause.connector == "OR" else result and clause_result
    return result


def _sort_key(value: Any) -> tuple[int, Any]:
    # None sorts first (matches TS null ordering); coerce to string for mixed types.
    if value is None:
        return (0, "")
    return (1, value)


class MemoryAdapter(BaseAdapter):
    def __init__(self, advanced: AdvancedDatabase | None = None) -> None:
        super().__init__(advanced)
        self._store: dict[str, list[dict[str, Any]]] = defaultdict(list)

    async def create(
        self,
        model: str,
        data: dict[str, Any],
        *,
        select: list[str] | None = None,
        force_allow_id: bool = False,
    ) -> dict[str, Any]:
        row = self._in(model, data, "create")
        self._store[model].append(dict(row))
        return self._out(model, dict(row), select)

    async def find_one(
        self, model: str, where: list[Where], *, select: list[str] | None = None
    ) -> dict[str, Any] | None:
        for r in self._store[model]:
            if _matches(r, where):
                return self._out(model, dict(r), select)
        return None

    async def find_many(
        self,
        model: str,
        where: list[Where] | None = None,
        *,
        limit: int | None = None,
        sort_by: SortBy | None = None,
        offset: int | None = None,
        select: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        rows = [dict(r) for r in self._store[model] if _matches(r, where)]
        if sort_by is not None:
            rows.sort(
                key=lambda r: _sort_key(r.get(sort_by["field"])),
                reverse=sort_by.get("direction") == "desc",
            )
        if offset is not None:
            rows = rows[offset:]
        rows = rows[: self._limit(limit)]
        return [self._out(model, r, select) for r in rows]

    async def update(
        self, model: str, where: list[Where], data: dict[str, Any]
    ) -> dict[str, Any] | None:
        if not where:  # fail-closed: bulk writes must use update_many
            return None
        row = self._in(model, data, "update")
        for stored in self._store[model]:
            if _matches(stored, where):
                stored.update(row)
                return self._out(model, dict(stored))
        return None

    async def update_many(self, model: str, where: list[Where], data: dict[str, Any]) -> int:
        row = self._in(model, data, "update")
        affected = 0
        for stored in self._store[model]:
            if _matches(stored, where):
                stored.update(row)
                affected += 1
        return affected

    async def delete(self, model: str, where: list[Where]) -> None:
        if not where:  # fail-closed
            return
        rows = self._store[model]
        for i, r in enumerate(rows):
            if _matches(r, where):
                del rows[i]
                return

    async def delete_many(self, model: str, where: list[Where]) -> int:
        rows = self._store[model]
        kept = [r for r in rows if not _matches(r, where)]
        deleted = len(rows) - len(kept)
        self._store[model] = kept
        return deleted

    async def count(self, model: str, where: list[Where] | None = None) -> int:
        return sum(1 for r in self._store[model] if _matches(r, where))

    async def transaction(self, callback: Callable[[BaseAdapter], Awaitable[Any]]) -> Any:
        snapshot = copy.deepcopy(dict(self._store))
        try:
            return await callback(self)
        except Exception:
            self._store = defaultdict(list, {k: v for k, v in snapshot.items()})
            raise
