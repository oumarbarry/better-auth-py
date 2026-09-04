"""Database adapter interface: generic CRUD over named models, like better-auth adapters.

Rows are plain dicts with camelCase keys matching better_auth.schema. Plugins can define
their own models without adapter changes.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from ..config import AdvancedDatabase
from ..schema import Schema
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

    # --- derived, atomic-ish primitives (shared via transaction) ----------------------

    async def consume_one(self, model: str, where: list[Where]) -> dict[str, Any] | None:
        """Atomically delete-and-return one matching row (single-use credential primitive)."""

        async def _cb(tx: BaseAdapter) -> dict[str, Any] | None:
            rows = await tx.find_many(model, where, limit=1)
            if not rows:
                return None
            row = rows[0]
            await tx.delete(model, [Where("id", row["id"])])
            return row

        return await self.transaction(_cb)

    async def increment_one(
        self,
        model: str,
        where: list[Where],
        increment: dict[str, Any] | None = None,
        set: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Atomic ``field = field + delta`` with ``where`` as selector *and* CAS guard."""
        if not increment and not set:
            raise ValueError("increment_one requires a non-empty `increment` or `set`")

        async def _cb(tx: BaseAdapter) -> dict[str, Any] | None:
            rows = await tx.find_many(model, where, limit=1)
            if not rows:
                return None
            row = rows[0]
            update: dict[str, Any] = dict(set or {})
            for field_name, delta in (increment or {}).items():
                update[field_name] = (row.get(field_name) or 0) + delta
            # re-apply `where` (incl. guard) as compare-and-swap
            affected = await tx.update_many(model, where, update)
            if affected == 0:
                return None
            return {**row, **update}

        return await self.transaction(_cb)
