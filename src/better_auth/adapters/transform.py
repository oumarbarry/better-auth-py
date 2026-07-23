"""Adapter input/output transform pipeline (mirrors better-auth's createAdapterFactory).

Keeps adapters thin: id injection, default/onUpdate application and capability-flag type
coercion happen here, so a `CustomAdapter` only stores/reads raw rows.

Deviation from TS (noted): TS strips a caller-supplied ``id`` unless ``forceAllowId``. This
port keeps a supplied ``id`` and only *generates* one when absent — the Python endpoints
generate ids inline and depend on them, and there is no internal-adapter seam this wave to
move that responsibility. ``force_allow_id`` is accepted for signature parity.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any

from ..config import AdvancedDatabase
from ..crypto import generate_id
from ..schema import Field, Schema


class Caps:
    """What a backend stores natively; ``False`` means the transform serializes for it."""

    def __init__(
        self,
        *,
        booleans: bool = True,
        dates: bool = True,
        json: bool = True,
        arrays: bool = True,
    ) -> None:
        self.booleans = booleans
        self.dates = dates
        self.json = json
        self.arrays = arrays


def resolve_generated_id(model: str, advanced: AdvancedDatabase) -> str | None:
    """Return an id for a new row, or ``None`` to let the DB generate it."""
    gen = advanced.generate_id
    if gen is False or gen == "serial":
        # ponytail: "serial" (numeric auto-increment) needs Integer PK + FK coercion,
        # not wired this wave — treat like DB-generated (None). Upgrade under numeric-id.
        return None
    if gen == "uuid":
        return str(uuid.uuid4())
    if not isinstance(gen, (bool, str)):
        return gen(model)
    return generate_id()


def _coerce_input(value: Any, field: Field, caps: Caps) -> Any:
    if value is None:
        return None
    if not caps.booleans and isinstance(value, bool):
        return 1 if value else 0
    if not caps.dates and field.type == "datetime" and isinstance(value, datetime):
        return value.isoformat()
    if not caps.json and field.type == "json" and not isinstance(value, str):
        return json.dumps(value)
    if not caps.arrays and field.type in ("string[]", "number[]") and isinstance(value, list):
        return json.dumps(value)
    return value


def _coerce_output(value: Any, field: Field, caps: Caps) -> Any:
    if value is None:
        return None
    if not caps.booleans and field.type == "boolean" and isinstance(value, int):
        return value == 1
    if not caps.dates and field.type == "datetime" and isinstance(value, str):
        return datetime.fromisoformat(value)
    if not caps.json and field.type == "json" and isinstance(value, str):
        return json.loads(value)
    if not caps.arrays and field.type in ("string[]", "number[]") and isinstance(value, str):
        return json.loads(value)
    return value


def transform_input(
    data: dict[str, Any],
    model: str,
    schema: Schema,
    action: str,
    advanced: AdvancedDatabase,
    caps: Caps,
) -> dict[str, Any]:
    """Inject id (on create), apply defaults/onUpdate, and coerce values for storage."""
    fields = schema[model]
    out: dict[str, Any] = dict(data)

    if action == "create" and "id" not in out:
        generated = resolve_generated_id(model, advanced)
        if generated is not None:
            out["id"] = generated

    for name, field in fields.items():
        if name == "id":
            continue
        if name in out:
            value = out[name]
            if action == "create" and value is None and field.required and field.has_default():
                value = field.make_default()
            # field transform.input (factory.ts:254): normalize the value, then coerce
            if field.transform_input is not None:
                value = field.transform_input(value)
            out[name] = _coerce_input(value, field, caps)
            continue
        if action == "create" and field.has_default():
            out[name] = _coerce_input(field.make_default(), field, caps)
        elif action == "update" and field.on_update is not None:
            out[name] = _coerce_input(field.on_update(), field, caps)
    return out


def transform_output(
    row: dict[str, Any] | None,
    model: str,
    schema: Schema,
    caps: Caps,
    select: list[str] | None = None,
) -> dict[str, Any] | None:
    """Coerce stored values back to Python types and apply ``select`` projection."""
    if row is None:
        return None
    fields = schema.get(model, {})
    out: dict[str, Any] = {}
    for key, value in row.items():
        if select and key not in select:
            continue
        field = fields.get(key)
        out[key] = _coerce_output(value, field, caps) if field is not None else value
    return out
