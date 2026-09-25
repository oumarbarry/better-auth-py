"""Database adapter interface: generic CRUD over named models, like better-auth adapters.

Rows are plain dicts with camelCase keys matching better_auth.schema. Plugins can define
their own models without adapter changes.
"""

from __future__ import annotations

import math
from collections.abc import Awaitable, Callable
from datetime import datetime
from typing import Any

from ..config import AdvancedDatabase
from ..schema import Schema
from ..types import BetterAuthError
from .transform import Caps, transform_input, transform_output

SortBy = dict[str, str]  # {"field": ..., "direction": "asc" | "desc"}


class Where:
    """A single condition.

    operator: eq | ne | in | not_in | contains | starts_with | ends_with | gt | gte | lt | lte
    connector: how this clause joins the running result — "AND" (default) or "OR".
    mode: "sensitive" (default) or "insensitive" (case-insensitive string match).
    """

    __slots__ = ("connector", "field", "mode", "operator", "value")

    def __init__(
        self,
        field: str,
        value: Any,
        operator: str = "eq",
        connector: str = "AND",
        mode: str = "sensitive",
    ):
        self.field = field
        self.value = value
        self.operator = operator
        self.connector = connector
        self.mode = mode


class BaseAdapter:
    #: what this backend stores natively; overridden per adapter
    CAPS = Caps()

    schema: Schema
    advanced: AdvancedDatabase

    def __init__(self, advanced: AdvancedDatabase | None = None) -> None:
        self.schema = {}
        self.advanced = advanced or AdvancedDatabase()

    def init(self, schema: Schema) -> None:
        """Called once by BetterAuth with the merged (core + plugins) schema."""
        self.schema = schema

    # --- transform helpers (item 3) ---------------------------------------------------

    def _in(self, model: str, data: dict[str, Any], action: str) -> dict[str, Any]:
        return transform_input(data, model, self.schema, action, self.advanced, self.CAPS)

    def _out(
        self, model: str, row: dict[str, Any], select: list[str] | None = None
    ) -> dict[str, Any]:
        result = transform_output(row, model, self.schema, self.CAPS, select)
        assert result is not None  # row is non-None, so the projection is too
        return result

    def _limit(self, limit: int | None) -> int:
        return limit if limit is not None else self.advanced.default_find_many_limit

    # --- raw CRUD (implemented by subclasses) -----------------------------------------

    async def create(
        self,
        model: str,
        data: dict[str, Any],
        *,
        select: list[str] | None = None,
        force_allow_id: bool = False,
    ) -> dict[str, Any]:
        raise NotImplementedError

    async def find_one(
        self, model: str, where: list[Where], *, select: list[str] | None = None
    ) -> dict[str, Any] | None:
        raise NotImplementedError

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
        raise NotImplementedError

    async def update(
        self, model: str, where: list[Where], data: dict[str, Any]
    ) -> dict[str, Any] | None:
        raise NotImplementedError

    async def update_many(self, model: str, where: list[Where], data: dict[str, Any]) -> int:
        raise NotImplementedError

    async def delete(self, model: str, where: list[Where]) -> None:
        raise NotImplementedError

    async def delete_many(self, model: str, where: list[Where]) -> int:
        raise NotImplementedError

    async def count(self, model: str, where: list[Where] | None = None) -> int:
        raise NotImplementedError

    async def transaction(self, callback: Callable[[BaseAdapter], Awaitable[Any]]) -> Any:
        raise NotImplementedError

    async def check_schema(self) -> None:
        """Raise ``SchemaMismatchError`` when the store cannot hold what Better Auth writes
        (TS v1.7.6 ``ctx.checkSchema``). Adapters that cannot introspect skip it."""

    # --- atomic primitives ---------------------------------------------------------------
    #
    # Adapters override these with a native atomic statement when the store has one
    # (MemoryAdapter, SQLAlchemyAdapter on RETURNING dialects). The shared fallbacks
    # below port TS v1.7.6 core/src/db/adapter/atomic-fallback.ts: read a snapshot, then
    # mutate it with a write guarded on that snapshot, and trust the write only when the
    # adapter reports exactly one affected row. They need no transaction.

    async def consume_one(self, model: str, where: list[Where]) -> dict[str, Any] | None:
        """Atomically delete one matching row and return it (single-use credentials).

        Under concurrent calls exactly one caller gets the row; the others get None.
        """
        row = await self.find_one(model, where)
        if row is None:
            return None
        # atomic-fallback.ts:157: guard the snapshot with AND predicates.
        name = type(self).__name__
        guard = _snapshot_guard(name, row, [*row, *(c.field for c in where)], where)
        return row if _changed_one(name, await self.delete_many(model, guard)) else None

    async def increment_one(
        self,
        model: str,
        where: list[Where],
        increment: dict[str, Any] | None = None,
        set: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Atomic ``field = field + delta`` on one row; ``where`` is selector *and* guard.

        ``set`` assigns absolute values in the same write. Returns the updated row, or
        None when the guard matched no row.
        """
        increment = check_increment(increment, set)
        name = type(self).__name__
        # atomic-fallback.ts:178: compare-and-swap on the snapshot value of every field
        # the call reads or writes, retried a bounded number of times.
        fields = [*(c.field for c in where), *increment, *(set or {})]
        # TS applies onUpdate defaults only through a given `set` (factory.ts:1494);
        # update_many would add them for a bare increment, so pin them to the snapshot.
        pinned = (
            []
            if set is not None
            else [
                field
                for field, spec in self.schema.get(model, {}).items()
                if spec.on_update is not None and field not in increment
            ]
        )
        for _ in range(_MAX_ATTEMPTS):
            row = await self.find_one(model, where)
            if row is None:
                return None
            update: dict[str, Any] = dict(set or {})
            for field_name, delta in increment.items():
                current = row.get(field_name)
                if current is None:
                    current = 0
                if isinstance(current, bool) or not isinstance(current, (int, float)):
                    raise BetterAuthError(
                        f'Adapter "{name}" must return finite numeric counter '
                        "values or null for atomic increments."
                    )
                nxt = current + delta
                if not math.isfinite(nxt) or (delta != 0 and nxt == current):
                    raise BetterAuthError(
                        f'Adapter "{name}" cannot represent the requested counter increment safely.'
                    )
                update[field_name] = nxt
            if all(row.get(k, _MISSING) == v for k, v in update.items()):
                return row  # a no-op takes effect at the read
            guard = _snapshot_guard(name, row, [*fields, *pinned], where)
            write = {**update, **{field: row.get(field) for field in pinned}}
            if _changed_one(name, await self.update_many(model, guard, write)):
                # a second read could observe another writer's result instead of ours
                return {**row, **update}
        raise BetterAuthError(
            f'Adapter "{name}" could not complete an atomic increment due to '
            "contention. Retry the operation or implement incrementOne natively."
        )


_MAX_ATTEMPTS = 5
_MISSING = object()


def check_increment(increment: dict[str, Any] | None, set: dict[str, Any] | None) -> dict[str, Any]:
    """TS v1.7.6 factory.ts:1466 and atomic-fallback.ts:mutationSchema."""
    if not increment and not set:
        raise BetterAuthError(
            "incrementOne requires a non-empty `increment` or `set`; both were empty."
        )
    increment = increment or {}
    for delta in increment.values():
        if isinstance(delta, bool) or not isinstance(delta, (int, float)):
            raise BetterAuthError(
                "incrementOne requires finite increments and a set object for the atomic fallback."
            )
    return increment


def _is_scalar(value: Any) -> bool:
    return value is None or isinstance(value, (str, int, float, bool, datetime))


def _snapshot_guard(
    adapter: str, row: dict[str, Any], fields: list[str], where: list[Where]
) -> list[Where]:
    """``where`` plus the row id plus ``field == snapshot`` for every scalar field
    (atomic-fallback.ts:117). An OR selector is dropped in favor of the id so the
    guard never widens."""
    if row.get("id") is None:
        raise BetterAuthError(f'Adapter "{adapter}" must return the row id for atomic fallbacks.')
    has_or = any(c.connector == "OR" for c in where)
    guard = [Where("id", row["id"])] if has_or else [*where, Where("id", row["id"])]
    for field in dict.fromkeys(fields):
        if field == "id":
            continue
        value = row.get(field)
        if not _is_scalar(value):
            if has_or and any(c.field == field for c in where):
                raise BetterAuthError(
                    f'Adapter "{adapter}" must implement native atomic methods for OR '
                    "predicates on structured values."
                )
            continue
        guard.append(Where(field, value))
    return guard


def _changed_one(adapter: str, count: int) -> bool:
    if count not in (0, 1):
        raise BetterAuthError(
            f'Adapter "{adapter}" must return an affected row count of 0 or 1 from an '
            "atomic fallback."
        )
    return count == 1
