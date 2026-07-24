"""SQLAlchemy adapter (async). Tables are generated from the merged schema.

Install with: ``pip install better-auth-py[sqlalchemy]``.

Datetimes are stored as naive UTC (portable across SQLite/Postgres/MySQL) and always
returned timezone-aware (UTC). JSON and array fields are stored as JSON strings (matching
better-auth's ``supportsJSON:false``/``supportsArrays:false`` backends).
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from contextlib import asynccontextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    and_,
    func,
    or_,
)
from sqlalchemy import (
    select as sa_select,
)
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine
from sqlalchemy.sql import ColumnElement

from ..config import AdvancedDatabase
from ..schema import Field, Schema
from .base import BaseAdapter, SortBy, Where
from .transform import Caps


def _col_type(spec: Field) -> Any:
    t = spec.type
    if t == "string":
        return String(255)
    if t in ("text", "json", "string[]", "number[]"):
        return Text()
    if t == "number":
        return BigInteger() if spec.bigint else Integer()
    if t == "boolean":
        return Boolean()
    if t == "datetime":
        return DateTime()
    raise ValueError(f"Unknown field type {t!r}")


def _to_storage(value: Any) -> Any:
    if isinstance(value, datetime) and value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def _from_storage(value: Any) -> Any:
    if isinstance(value, datetime) and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


class SQLAlchemyAdapter(BaseAdapter):
    # SQLAlchemy handles booleans/dates natively; JSON/arrays are stored as JSON strings.
    CAPS = Caps(booleans=True, dates=True, json=False, arrays=False)

    def __init__(
        self,
        engine: AsyncEngine,
        metadata: MetaData | None = None,
        advanced: AdvancedDatabase | None = None,
    ):
        super().__init__(advanced)
        self.engine = engine
        self.metadata = metadata or MetaData()
        self._tables: dict[str, Table] = {}
        self._active: ContextVar[AsyncConnection | None] = ContextVar("_active", default=None)

    def init(self, schema: Schema) -> None:
        super().init(schema)
        for model, fields in schema.items():
            if model in self._tables:
                continue
            columns: list[Column] = []
            for name, spec in fields.items():
                args: list[Any] = [_col_type(spec)]
                if spec.references is not None:
                    ref = spec.references
                    on_delete = ref.on_delete.upper() if ref.on_delete else None
                    args.append(ForeignKey(f"{ref.model}.{ref.field}", ondelete=on_delete))
                columns.append(
                    Column(
                        name,
                        *args,
                        primary_key=name == "id",
                        nullable=not spec.required,
                        unique=spec.unique and name != "id",
                        index=spec.index,
                    )
                )
            self._tables[model] = Table(model, self.metadata, *columns)

    async def create_tables(self) -> None:
        """Create missing tables (dev convenience — use real migrations in production)."""
        async with self.engine.begin() as conn:
            await conn.run_sync(self.metadata.create_all)

    # --- connection sharing (item 8: transactions) ------------------------------------

    @asynccontextmanager
    async def _connection(self, write: bool):
        active = self._active.get()
        if active is not None:
            yield active
        elif write:
            async with self.engine.begin() as conn:
                yield conn
        else:
            async with self.engine.connect() as conn:
                yield conn

    async def transaction(self, callback: Callable[[BaseAdapter], Awaitable[Any]]) -> Any:
        if self._active.get() is not None:
            return await callback(self)  # already inside a transaction
        async with self.engine.begin() as conn:
            token = self._active.set(conn)
            try:
                return await callback(self)
            finally:
                self._active.reset(token)

    # --- query building ---------------------------------------------------------------

    def _table(self, model: str) -> Table:
        try:
            return self._tables[model]
        except KeyError:
            raise KeyError(f"Unknown model {model!r} — was the adapter initialized?") from None

    @staticmethod
    def _clause(table: Table, c: Where) -> ColumnElement:
        col = table.c[c.field]
        op = c.operator
        insensitive = c.mode == "insensitive"
        if op in ("in", "not_in"):
            if not isinstance(c.value, (list, tuple, set)):
                raise ValueError(f"operator {op!r} requires an array value")
            values = [_to_storage(v) for v in c.value]
            if insensitive:
                lowered = [v.lower() for v in values]
                return (
                    func.lower(col).notin_(lowered)
                    if op == "not_in"
                    else func.lower(col).in_(lowered)
                )
            return col.notin_(values) if op == "not_in" else col.in_(values)

        value = _to_storage(c.value)
        if op == "eq":
            return func.lower(col) == value.lower() if insensitive else col == value
        if op == "ne":
            return func.lower(col) != value.lower() if insensitive else col != value
        if op == "contains":
            return col.ilike(f"%{value}%") if insensitive else col.contains(value)
        if op == "starts_with":
            return col.ilike(f"{value}%") if insensitive else col.startswith(value)
        if op == "ends_with":
            return col.ilike(f"%{value}") if insensitive else col.endswith(value)
        if op == "gt":
            return col > value
        if op == "gte":
            return col >= value
        if op == "lt":
            return col < value
        if op == "lte":
            return col <= value
        raise ValueError(f"Unsupported operator {op!r}")

    def _condition(self, table: Table, where: list[Where] | None) -> ColumnElement | None:
        if not where:
            return None
        result = self._clause(table, where[0])
        for c in where:
            expr = self._clause(table, c)
            result = or_(result, expr) if c.connector == "OR" else and_(result, expr)
        return result

    def _row(self, model: str, row: Any, select: list[str] | None) -> dict[str, Any]:
        native = {key: _from_storage(value) for key, value in row._mapping.items()}
        return self._out(model, native, select)

    # --- CRUD -------------------------------------------------------------------------

    async def create(
        self,
        model: str,
        data: dict[str, Any],
        *,
        select: list[str] | None = None,
        force_allow_id: bool = False,
    ) -> dict[str, Any]:
        table = self._table(model)
        row = self._in(model, data, "create")
        values = {k: _to_storage(v) for k, v in row.items()}
        async with self._connection(write=True) as conn:
            await conn.execute(table.insert().values(**values))
        return self._out(model, {k: _from_storage(v) for k, v in row.items()}, select)

    async def find_one(
        self, model: str, where: list[Where], *, select: list[str] | None = None
    ) -> dict[str, Any] | None:
        table = self._table(model)
        stmt = table.select().limit(1)
        cond = self._condition(table, where)
        if cond is not None:
            stmt = stmt.where(cond)
        async with self._connection(write=False) as conn:
            row = (await conn.execute(stmt)).first()
        return self._row(model, row, select) if row is not None else None

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
        table = self._table(model)
        stmt = table.select()
        cond = self._condition(table, where)
        if cond is not None:
            stmt = stmt.where(cond)
        if sort_by is not None:
            col = table.c[sort_by["field"]]
            stmt = stmt.order_by(col.desc() if sort_by.get("direction") == "desc" else col.asc())
        if offset is not None:
            stmt = stmt.offset(offset)
        stmt = stmt.limit(self._limit(limit))
        async with self._connection(write=False) as conn:
            rows = (await conn.execute(stmt)).all()
        return [self._row(model, r, select) for r in rows]

    async def update(
        self, model: str, where: list[Where], data: dict[str, Any]
    ) -> dict[str, Any] | None:
        if not where:  # fail-closed: bulk writes must use update_many
            return None
        table = self._table(model)
        row = self._in(model, data, "update")
        values = {k: _to_storage(v) for k, v in row.items()}
        cond = self._condition(table, where)
        stmt = table.update().values(**values)
        if cond is not None:
            stmt = stmt.where(cond)
        async with self._connection(write=True) as conn:
            await conn.execute(stmt)
        return await self.find_one(model, self._refind(where, row))

    async def update_many(self, model: str, where: list[Where], data: dict[str, Any]) -> int:
        table = self._table(model)
        row = self._in(model, data, "update")
        values = {k: _to_storage(v) for k, v in row.items()}
        cond = self._condition(table, where)
        stmt = table.update().values(**values)
        if cond is not None:
            stmt = stmt.where(cond)
        async with self._connection(write=True) as conn:
            result = await conn.execute(stmt)
        return int(result.rowcount or 0)

    @staticmethod
    def _refind(where: list[Where], data: dict[str, Any]) -> list[Where]:
        # if an updated column was part of the lookup, look it up by its new value
        return [
            Where(c.field, data[c.field]) if c.operator == "eq" and c.field in data else c
            for c in where
        ]

    async def delete(self, model: str, where: list[Where]) -> None:
        if not where:  # fail-closed
            return
        table = self._table(model)
        cond = self._condition(table, where)
        # single delete: bound to one row via a subquery on the primary key
        pk = table.c["id"]
        inner = sa_select(pk).where(cond).limit(1) if cond is not None else sa_select(pk).limit(1)
        stmt = table.delete().where(pk.in_(inner))
        async with self._connection(write=True) as conn:
            await conn.execute(stmt)

    async def delete_many(self, model: str, where: list[Where]) -> int:
        table = self._table(model)
        cond = self._condition(table, where)
        stmt = table.delete()
        if cond is not None:
            stmt = stmt.where(cond)
        async with self._connection(write=True) as conn:
            result = await conn.execute(stmt)
        return int(result.rowcount or 0)

    async def count(self, model: str, where: list[Where] | None = None) -> int:
        table = self._table(model)
        stmt = sa_select(func.count()).select_from(table)
        cond = self._condition(table, where)
        if cond is not None:
            stmt = stmt.where(cond)
        async with self._connection(write=False) as conn:
            return int((await conn.execute(stmt)).scalar() or 0)
