"""Core database schema, mirroring better-auth's user/session/account/verification tables.

Field names are camelCase on purpose: they match better-auth's default column names, so a
Python app can share a database with a TypeScript better-auth app.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Field:
    type: str  # "string" | "text" | "boolean" | "datetime"
    required: bool = False
    unique: bool = False
    references: str | None = None  # e.g. "user.id"


Schema = dict[str, dict[str, Field]]

CORE_SCHEMA: Schema = {
    "user": {
        "id": Field("string", required=True, unique=True),
        "name": Field("string", required=True),
        "email": Field("string", required=True, unique=True),
        "emailVerified": Field("boolean", required=True),
        "image": Field("string"),
        "createdAt": Field("datetime", required=True),
        "updatedAt": Field("datetime", required=True),
    },
    "session": {
        "id": Field("string", required=True, unique=True),
        "expiresAt": Field("datetime", required=True),
        "token": Field("string", required=True, unique=True),
        "ipAddress": Field("string"),
        "userAgent": Field("string"),
        "userId": Field("string", required=True, references="user.id"),
        "createdAt": Field("datetime", required=True),
        "updatedAt": Field("datetime", required=True),
    },
    "account": {
        "id": Field("string", required=True, unique=True),
        "accountId": Field("string", required=True),
        "providerId": Field("string", required=True),
        "userId": Field("string", required=True, references="user.id"),
        "accessToken": Field("text"),
        "refreshToken": Field("text"),
        "idToken": Field("text"),
        "accessTokenExpiresAt": Field("datetime"),
        "refreshTokenExpiresAt": Field("datetime"),
        "scope": Field("string"),
        "password": Field("string"),
        "createdAt": Field("datetime", required=True),
        "updatedAt": Field("datetime", required=True),
    },
    "verification": {
        "id": Field("string", required=True, unique=True),
        "identifier": Field("string", required=True),
        "value": Field("text", required=True),
        "expiresAt": Field("datetime", required=True),
        "createdAt": Field("datetime", required=True),
        "updatedAt": Field("datetime", required=True),
    },
}


def merge_schema(base: Schema, *extensions: Schema) -> Schema:
    """Merge plugin schemas into the core schema (new models or extra fields)."""
    merged: Schema = {model: dict(fields) for model, fields in base.items()}
    for extension in extensions:
        for model, fields in extension.items():
            merged.setdefault(model, {})
            merged[model].update(fields)
    return merged
