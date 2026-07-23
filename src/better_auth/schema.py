"""Core database schema, mirroring better-auth's user/session/account/verification tables.

Field names are camelCase on purpose: they match better-auth's default column names, so a
Python app can share a database with a TypeScript better-auth app.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


def _now() -> datetime:
    return datetime.now(timezone.utc)


# Sentinel for "no default configured" (distinct from an explicit ``default=None``).
class _Unset:
    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return "UNSET"


UNSET: Any = _Unset()


@dataclass(frozen=True)
class Reference:
    """A structured foreign-key reference (mirrors better-auth's ``references``)."""

    model: str
    field: str = "id"
    on_delete: str | None = None  # e.g. "cascade"


@dataclass(frozen=True)
class Field:
    #: "string" | "text" | "number" | "boolean" | "datetime" | "json" | "string[]" | "number[]"
    #: (``text`` is a Python-only alias for a non-sortable long string; it maps to the same
    #: column TS's ``string`` produces so a shared DB round-trips.)
    type: str
    required: bool = False
    unique: bool = False
    references: Reference | None = None
    #: whether the field is returned to callers (``returned: false`` hides tokens/passwords)
    returned: bool = True
    #: whether the field may be set from client input (``input: false`` rejects client values)
    input: bool = True
    #: static default applied on create when the value is absent (``UNSET`` = none)
    default: Any = UNSET
    #: callable default applied on create when the value is absent (e.g. ``_now``)
    default_factory: Callable[[], Any] | None = None
    #: callable re-applied on every update when the value is absent (e.g. ``updatedAt``)
    on_update: Callable[[], Any] | None = None
    #: override the storage column name (defaults to the field key)
    field_name: str | None = None
    #: hint that the column is sorted/filtered on (varchar vs text at DDL time in TS)
    sortable: bool = False
    #: create an index on the column
    index: bool = False
    #: store as a 64-bit integer
    bigint: bool = False

    def has_default(self) -> bool:
        return self.default is not UNSET or self.default_factory is not None

    def make_default(self) -> Any:
        if self.default_factory is not None:
            return self.default_factory()
        return self.default


Schema = dict[str, dict[str, Field]]

_USER_REF = Reference("user", "id", on_delete="cascade")

CORE_SCHEMA: Schema = {
    "user": {
        "id": Field("string", required=True, unique=True),
        "name": Field("string", required=True, sortable=True),
        "email": Field("string", required=True, unique=True, sortable=True),
        "emailVerified": Field("boolean", required=True, default=False, input=False),
        "image": Field("string"),
        "createdAt": Field("datetime", required=True, default_factory=_now),
        "updatedAt": Field("datetime", required=True, default_factory=_now, on_update=_now),
    },
    "session": {
        "id": Field("string", required=True, unique=True),
        "expiresAt": Field("datetime", required=True),
        "token": Field("string", required=True, unique=True),
        "ipAddress": Field("string"),
        "userAgent": Field("string"),
        "userId": Field("string", required=True, references=_USER_REF, index=True),
        "createdAt": Field("datetime", required=True, default_factory=_now),
        "updatedAt": Field("datetime", required=True, default_factory=_now, on_update=_now),
    },
    "account": {
        "id": Field("string", required=True, unique=True),
        "accountId": Field("string", required=True),
        "providerId": Field("string", required=True),
        "userId": Field("string", required=True, references=_USER_REF, index=True),
        "accessToken": Field("text", returned=False),
        "refreshToken": Field("text", returned=False),
        "idToken": Field("text", returned=False),
        "accessTokenExpiresAt": Field("datetime", returned=False),
        "refreshTokenExpiresAt": Field("datetime", returned=False),
        "scope": Field("string"),
        "password": Field("string", returned=False),
        "createdAt": Field("datetime", required=True, default_factory=_now),
        "updatedAt": Field("datetime", required=True, default_factory=_now, on_update=_now),
    },
    "verification": {
        "id": Field("string", required=True, unique=True),
        "identifier": Field("string", required=True, index=True),
        "value": Field("text", required=True),
        "expiresAt": Field("datetime", required=True),
        "createdAt": Field("datetime", required=True, default_factory=_now),
        "updatedAt": Field("datetime", required=True, default_factory=_now, on_update=_now),
    },
}


def rate_limit_model() -> dict[str, Field]:
    """The ``rateLimit`` table — emitted only when rate-limit storage is ``database``.

    ponytail: kept out of CORE_SCHEMA (TS emits it conditionally); merge it in when
    the DB-backed rate limiter is wired.
    """
    return {
        "id": Field("string", required=True, unique=True),
        "key": Field("string", required=True, unique=True),
        "count": Field("number", required=True),
        "lastRequest": Field("number", required=True, bigint=True, default_factory=_epoch_ms),
    }


def _epoch_ms() -> int:
    return int(_now().timestamp() * 1000)


def merge_schema(base: Schema, *extensions: Schema) -> Schema:
    """Merge plugin schemas into the core schema (new models or extra fields)."""
    merged: Schema = {model: dict(fields) for model, fields in base.items()}
    for extension in extensions:
        for model, fields in extension.items():
            merged.setdefault(model, {})
            merged[model].update(fields)
    return merged


# --- parse layer (mirrors better-auth's db/schema.ts filterOutputFields/parseAccountOutput) ---


def filter_output_fields(row: dict[str, Any], fields: dict[str, Field]) -> dict[str, Any]:
    """Drop ``returned: false`` fields from an output row (e.g. tokens, passwords)."""
    hidden = {name for name, spec in fields.items() if not spec.returned}
    return {key: value for key, value in row.items() if key not in hidden}


def parse_input_data(
    data: dict[str, Any], fields: dict[str, Field], action: str = "create"
) -> dict[str, Any]:
    """Schema-driven input allowlist (mirrors better-auth's ``parseInputData``).

    Only keys declared in ``fields`` pass through; unknown keys are dropped. A field
    with ``input=False`` is rejected (``FIELD_NOT_ALLOWED``) if the caller tries to
    set a truthy value (its default is applied instead on ``create``). Defaults and
    ``required`` are enforced only on ``create``.

    ``fields`` is the *input* schema — the configured ``additionalFields`` plus
    plugin-contributed fields, NOT the core columns (TS ``getFields(mode:"input")``
    starts from an empty core schema). So with nothing configured this returns ``{}``,
    which is exactly why a generic route like ``/update-session`` then reports
    "No fields to update".
    """
    from .types import APIError

    parsed: dict[str, Any] = {}
    for key, spec in fields.items():
        if key in data:
            if spec.input is False:
                if spec.has_default() and action != "update":
                    parsed[key] = spec.make_default()
                    continue
                if data[key]:
                    raise APIError(400, "FIELD_NOT_ALLOWED", f"{key} is not allowed to be set")
                continue
            parsed[key] = data[key]
            continue
        if spec.has_default() and action == "create":
            parsed[key] = spec.make_default()
            continue
        if spec.required and action == "create":
            raise APIError(400, "MISSING_FIELD", f"{key} is required")
    return parsed


def parse_user_output(user: dict[str, Any], fields: dict[str, Field]) -> dict[str, Any]:
    """Emit only returnable user fields (schema + configured additionalFields)."""
    return filter_output_fields(user, fields)


def parse_session_output(session: dict[str, Any], fields: dict[str, Field]) -> dict[str, Any]:
    """Emit only returnable session fields (schema + configured additionalFields)."""
    return filter_output_fields(session, fields)


def parse_account_output(
    account: dict[str, Any], fields: dict[str, Field] | None = None
) -> dict[str, Any]:
    """Strip tokens + password from an account row before returning it to callers.

    ``fields`` defaults to the core account schema; pass the merged schema (with
    plugin/additional fields) to honour their ``returned`` flags too.
    """
    return filter_output_fields(account, fields if fields is not None else CORE_SCHEMA["account"])
