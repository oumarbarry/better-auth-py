"""Database adapter interface: generic CRUD over named models, like better-auth adapters.

Rows are plain dicts with camelCase keys matching better_auth.schema. Plugins can define
their own models without adapter changes.
"""

from __future__ import annotations

from typing import Any

from ..schema import Schema


class Where:
    """A single condition. operator: eq | ne | in | contains | gt | gte | lt | lte."""

    __slots__ = ("field", "operator", "value")

    def __init__(self, field: str, value: Any, operator: str = "eq"):
        self.field = field
        self.value = value
        self.operator = operator


class BaseAdapter:
    def init(self, schema: Schema) -> None:
        """Called once by BetterAuth with the merged (core + plugins) schema."""

    async def create(self, model: str, data: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError

    async def find_one(self, model: str, where: list[Where]) -> dict[str, Any] | None:
        raise NotImplementedError

    async def find_many(self, model: str, where: list[Where] | None = None) -> list[dict[str, Any]]:
        raise NotImplementedError

    async def update(
        self, model: str, where: list[Where], data: dict[str, Any]
    ) -> dict[str, Any] | None:
        raise NotImplementedError

    async def delete_many(self, model: str, where: list[Where]) -> int:
        raise NotImplementedError
