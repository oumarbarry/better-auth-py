"""SQLAlchemy adapter (async). Tables are generated from the merged schema.

Install with: ``pip install better-auth-py[sqlalchemy]``.

Datetimes are stored as naive UTC (portable across SQLite/Postgres/MySQL) and always
returned timezone-aware (UTC).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, MetaData, String, Table, Text, and_
from sqlalchemy.ext.asyncio import AsyncEngine
from sqlalchemy.sql import ColumnElement

from ..schema import Schema
from .base import BaseAdapter, Where

_TYPES = {
    "string": lambda: String(255),
    "text": lambda: Text(),
    "boolean": lambda: Boolean(),
    "datetime": lambda: DateTime(),
}


def _to_storage(value: Any) -> Any:
    if isinstance(value, datetime) and value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def _from_storage(value: Any) -> Any:
    if isinstance(value, datetime) and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


class SQLAlchemyAdapter(BaseAdapter):
    def __init__(self, engine: AsyncEngine, metadata: MetaData | None = None):
        self.engine = engine
        self.metadata = metadata or MetaData()
        self._tables: dict[str, Table] = {}

    def init(self, schema: Schema) -> None:
        for model, fields in schema.items():
            if model in self._tables:
                continue
            columns: list[Column] = []
            for name, spec in fields.items():
                args: list[Any] = [_TYPES[spec.type]()]
                if spec.references:
                    ref_model, ref_col = spec.references.split(".")
                    args.append(ForeignKey(f"{ref_model}.{ref_col}"))
                columns.append(
                    Column(
                        name,
                        *args,
                        primary_key=name == "id",
                        nullable=not spec.required,
                        unique=spec.unique and name != "id",
                    )
                )
            self._tables[model] = Table(model, self.metadata, *columns)

    async def create_tables(self) -> None:
        """Create missing tables (dev convenience — use real migrations in production)."""
        async with self.engine.begin() as conn:
            await conn.run_sync(self.metadata.create_all)

    def _table(self, model: str) -> Table:
        try:
            return self._tables[model]
        except KeyError:
            raise KeyError(f"Unknown model {model!r} — was the adapter initialized?") from None

    def _condition(self, table: Table, where: list[Where] | None) -> ColumnElement | None:
        if not where:
            return None
        parts = []
        for c in where:
            col = table.c[c.field]
            value = _to_storage(c.value)
            if c.operator == "eq":
                parts.append(col == value)
            elif c.operator == "ne":
                parts.append(col != value)
            elif c.operator == "in":
                parts.append(col.in_([_to_storage(v) for v in c.value]))
            elif c.operator == "contains":
                parts.append(col.contains(c.value))
            elif c.operator == "gt":
                parts.append(col > value)
            elif c.operator == "gte":
                parts.append(col >= value)
            elif c.operator == "lt":
                parts.append(col < value)
            elif c.operator == "lte":
                parts.append(col <= value)
            else:
                raise ValueError(f"Unsupported operator {c.operator!r}")
        return and_(*parts)

    @staticmethod
    def _row(row: Any) -> dict[str, Any]:
        return {key: _from_storage(value) for key, value in row._mapping.items()}

    async def create(self, model: str, data: dict[str, Any]) -> dict[str, Any]:
        table = self._table(model)
        values = {k: _to_storage(v) for k, v in data.items()}
        async with self.engine.begin() as conn:
            await conn.execute(table.insert().values(**values))
        return dict(data)

    async def find_one(self, model: str, where: list[Where]) -> dict[str, Any] | None:
        table = self._table(model)
        stmt = table.select().limit(1)
        cond = self._condition(table, where)
        if cond is not None:
            stmt = stmt.where(cond)
        async with self.engine.connect() as conn:
            row = (await conn.execute(stmt)).first()
        return self._row(row) if row is not None else None

    async def find_many(self, model: str, where: list[Where] | None = None) -> list[dict[str, Any]]:
        table = self._table(model)
        stmt = table.select()
        cond = self._condition(table, where)
        if cond is not None:
            stmt = stmt.where(cond)
        async with self.engine.connect() as conn:
            rows = (await conn.execute(stmt)).all()
        return [self._row(r) for r in rows]

    async def update(
        self, model: str, where: list[Where], data: dict[str, Any]
    ) -> dict[str, Any] | None:
        table = self._table(model)
        cond = self._condition(table, where)
        values = {k: _to_storage(v) for k, v in data.items()}
        stmt = table.update().values(**values)
        if cond is not None:
            stmt = stmt.where(cond)
        async with self.engine.begin() as conn:
            await conn.execute(stmt)
        return await self.find_one(model, self._refind(where, data))

    @staticmethod
    def _refind(where: list[Where], data: dict[str, Any]) -> list[Where]:
        # if an updated column was part of the lookup, look it up by its new value
        return [
            Where(c.field, data[c.field]) if c.operator == "eq" and c.field in data else c
            for c in where
        ]

    async def delete_many(self, model: str, where: list[Where]) -> int:
        table = self._table(model)
        cond = self._condition(table, where)
        stmt = table.delete()
        if cond is not None:
            stmt = stmt.where(cond)
        async with self.engine.begin() as conn:
            result = await conn.execute(stmt)
        return int(result.rowcount or 0)
