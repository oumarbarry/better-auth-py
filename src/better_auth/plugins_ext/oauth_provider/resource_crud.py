"""SERVER_ONLY admin CRUD for OAuth protected resources.

Port of TS ``packages/oauth-provider/src/oauthResource/`` (v1.7.6, d2a79bae7): the
``resourceBodySchema`` (index.ts:20) and the handlers (endpoints.ts). Every handler routes
through :func:`assert_resource_privileges`; mutations drop the resource cache entry.
"""

from __future__ import annotations

import inspect
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import unquote

from ...adapters.base import Where
from ...session import utcnow
from ...types import APIError, AuthResponse, Ctx
from .resources import JWS_ALGORITHMS, assert_identifier_valid, invalidate_resource_cache
from .utils import OAuthError

_UNIQUE_VIOLATION = re.compile(r"unique|duplicate", re.IGNORECASE)
_MAX_SAFE_INT = 2**53 - 1

#: Fields an update may write, in TS order (endpoints.ts:224). ``identifier`` is the key.
_UPDATE_FIELDS = (
    "name",
    "accessTokenTtl",
    "refreshTokenTtl",
    "signingAlgorithm",
    "signingKeyId",
    "allowedScopes",
    "customClaims",
    "dpopBoundAccessTokensRequired",
    "disabled",
    "metadata",
)


async def _maybe_await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


def _now() -> datetime:
    return datetime.fromtimestamp(utcnow().timestamp(), tz=timezone.utc)


# --- body schema (index.ts:20), rendered like better-call's fromError ------------------


def _received(value: Any) -> str:
    """zod's parsed type name for the ``received`` part of an issue."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    return "object"


def _type_issue(expected: str, value: Any) -> str:
    return f"Invalid input: expected {expected}, received {_received(value)}"


def _ttl_issues(value: Any) -> list[str]:
    """``z.number().int().positive()``: the int check aborts, the safe range does not."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return [_type_issue("number", value)]
    if isinstance(value, float) and not value.is_integer():
        return ["Invalid input: expected int, received number"]
    if value > _MAX_SAFE_INT:
        return [f"Too big: expected int to be <={_MAX_SAFE_INT}"]
    issues = []
    if value < -_MAX_SAFE_INT:
        issues.append(f"Too small: expected int to be >=-{_MAX_SAFE_INT}")
    if value <= 0:
        issues.append("Too small: expected number to be >0")
    return issues


def _field_issues(key: str, value: Any) -> list[tuple[str, str]]:
    """(path, message) issues for one present body field."""
    nullable = key not in ("identifier", "name", "dpopBoundAccessTokensRequired", "disabled")
    if value is None and nullable:
        return []
    if key == "identifier":
        if not isinstance(value, str):
            return [(key, _type_issue("string", value))]
        if not value:
            return [(key, "Too small: expected string to have >=1 characters")]
        return []
    if key in ("name", "signingKeyId"):
        return [] if isinstance(value, str) else [(key, _type_issue("string", value))]
    if key in ("accessTokenTtl", "refreshTokenTtl"):
        return [(key, message) for message in _ttl_issues(value)]
    if key == "signingAlgorithm":
        if value in JWS_ALGORITHMS:
            return []
        options = "|".join(f'"{alg}"' for alg in JWS_ALGORITHMS)
        return [(key, f"Invalid option: expected one of {options}")]
    if key == "allowedScopes":
        if not isinstance(value, list):
            return [(key, _type_issue("array", value))]
        return [
            (f"{key}.{i}", _type_issue("string", item))
            for i, item in enumerate(value)
            if not isinstance(item, str)
        ]
    if key in ("customClaims", "metadata"):
        return [] if isinstance(value, dict) else [(key, _type_issue("record", value))]
    # dpopBoundAccessTokensRequired, disabled
    return [] if isinstance(value, bool) else [(key, _type_issue("boolean", value))]


def validate_resource_body(body: Any, *, create: bool) -> dict[str, Any]:
    """Validate the body against ``resourceBodySchema`` (``.required({identifier})`` on
    create) and strip unknown keys. Raises better-call's ``VALIDATION_ERROR``."""
    body = body if isinstance(body, dict) else {}
    issues: list[tuple[str, str]] = []
    for key in ("identifier", *_UPDATE_FIELDS):
        if key in body:
            issues.extend(_field_issues(key, body[key]))
        elif key == "identifier" and create:
            issues.append((key, "Invalid input: expected nonoptional, received undefined"))
    if issues:
        message = "; ".join(f"[body.{path}] {text}" for path, text in issues)
        raise APIError(400, "VALIDATION_ERROR", message)
    return {k: v for k, v in body.items() if k == "identifier" or k in _UPDATE_FIELDS}


# --- helpers (endpoints.ts:38-100) ------------------------------------------------------


async def assert_resource_privileges(
    ctx: Ctx,
    session: dict[str, Any] | None,
    opts: Any,
    action: str,
    resource_id: str | None = None,
) -> None:
    """TS ``assertResourcePrivileges``: UNAUTHORIZED without a session, BAD_REQUEST without
    headers, else UNAUTHORIZED when ``resource_privileges`` returns a falsy value. Without
    the callback any signed-in session may manage resources, as in TS."""
    if session is None:
        raise APIError(401, "UNAUTHORIZED")
    if not ctx.request.headers:
        raise APIError(400, "BAD_REQUEST")
    privileges = getattr(opts, "resource_privileges", None)
    if privileges is None:
        return
    allowed = await _maybe_await(
        privileges(
            {
                "headers": ctx.request.headers,
                "action": action,
                "session": session.get("session"),
                "user": session.get("user"),
                "resourceId": resource_id,
            }
        )
    )
    if not allowed:
        raise APIError(401, "UNAUTHORIZED")


_MALFORMED_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")


def decode_path_param(value: str) -> str:
    """TS ``decodePathParam``: ``decodeURIComponent``, or the raw value when it throws (a
    malformed escape or invalid UTF-8)."""
    if _MALFORMED_ESCAPE.search(value):
        return value
    try:
        return unquote(value, errors="strict")
    except UnicodeDecodeError:
        return value


def _resource_not_found(identifier: str) -> OAuthError:
    return OAuthError(404, "not_found", f"resource {identifier} not found")


async def _find_resource(ctx: Ctx, identifier: str) -> dict[str, Any] | None:
    return await ctx.adapter.find_one("oauthResource", [Where("identifier", identifier)])


def _resource_row(data: dict[str, Any], now: datetime) -> dict[str, Any]:
    """TS ``buildResourceRow`` (endpoints.ts:102): the seed path's defaults."""
    identifier = data["identifier"]
    return {
        "identifier": identifier,
        "name": data.get("name") if data.get("name") is not None else identifier,
        "accessTokenTtl": data.get("accessTokenTtl"),
        "refreshTokenTtl": data.get("refreshTokenTtl"),
        "signingAlgorithm": data.get("signingAlgorithm"),
        "signingKeyId": data.get("signingKeyId"),
        "allowedScopes": data.get("allowedScopes"),
        "customClaims": data.get("customClaims"),
        "dpopBoundAccessTokensRequired": data.get("dpopBoundAccessTokensRequired") or False,
        "disabled": data.get("disabled") or False,
        "policyVersion": 1,
        "metadata": data.get("metadata"),
        "createdAt": now,
        "updatedAt": now,
    }


# --- endpoints ------------------------------------------------------------------------


async def create_resource_endpoint(ctx: Ctx, opts: Any) -> AuthResponse:
    """POST /admin/oauth2/resources (endpoints.ts:121)."""
    data = validate_resource_body(ctx.body(), create=True)
    session = await ctx.get_session()
    await assert_resource_privileges(ctx, session, opts, "create")
    identifier = data["identifier"]
    await assert_identifier_valid(opts, identifier)
    duplicate = OAuthError(400, "invalid_request", f"resource {identifier} already exists")
    # ponytail: TS relies on the unique index alone; adapters that do not enforce it (the
    # memory adapter) need this pre-check. The unique catch below still covers the race.
    if await _find_resource(ctx, identifier):
        raise duplicate
    try:
        created = await ctx.adapter.create("oauthResource", _resource_row(data, _now()))
    except Exception as exc:
        if _UNIQUE_VIOLATION.search(str(exc)):
            raise duplicate from exc
        raise
    if not created:
        raise OAuthError(400, "invalid_request", f"resource {identifier} could not be created")
    invalidate_resource_cache(created["identifier"])
    return AuthResponse(status=201, body=created)


async def list_resources_endpoint(ctx: Ctx, opts: Any) -> list[dict[str, Any]]:
    """GET /admin/oauth2/resources (endpoints.ts:167)."""
    session = await ctx.get_session()
    await assert_resource_privileges(ctx, session, opts, "list")
    return await ctx.adapter.find_many("oauthResource", []) or []


async def get_resource_endpoint(ctx: Ctx, opts: Any, identifier: str) -> dict[str, Any]:
    """GET /admin/oauth2/resources/:identifier (endpoints.ts:179)."""
    identifier = decode_path_param(identifier)
    session = await ctx.get_session()
    await assert_resource_privileges(ctx, session, opts, "read", identifier)
    row = await _find_resource(ctx, identifier)
    if not row:
        raise _resource_not_found(identifier)
    return row


async def update_resource_endpoint(ctx: Ctx, opts: Any, identifier: str) -> dict[str, Any]:
    """PATCH /admin/oauth2/resources/:identifier (endpoints.ts:199). Only the fields present
    in the body are written; an explicit null clears a policy column."""
    body = validate_resource_body(ctx.body(), create=False)
    identifier = decode_path_param(identifier)
    session = await ctx.get_session()
    await assert_resource_privileges(ctx, session, opts, "update", identifier)
    if not await _find_resource(ctx, identifier):
        raise _resource_not_found(identifier)
    update: dict[str, Any] = {"updatedAt": _now()}
    update.update({k: body[k] for k in _UPDATE_FIELDS if k in body})
    await ctx.adapter.update("oauthResource", [Where("identifier", identifier)], update)
    invalidate_resource_cache(identifier)
    # Re-read so the response reflects the persisted row (endpoints.ts:251).
    refreshed = await _find_resource(ctx, identifier)
    if not refreshed:
        raise _resource_not_found(identifier)
    return refreshed


async def delete_resource_endpoint(ctx: Ctx, opts: Any, identifier: str) -> dict[str, Any]:
    """DELETE /admin/oauth2/resources/:identifier (endpoints.ts:266)."""
    identifier = decode_path_param(identifier)
    session = await ctx.get_session()
    await assert_resource_privileges(ctx, session, opts, "delete", identifier)
    if not await _find_resource(ctx, identifier):
        raise _resource_not_found(identifier)
    await ctx.adapter.delete("oauthResource", [Where("identifier", identifier)])
    invalidate_resource_cache(identifier)
    return {"deleted": True}


async def link_client_resource_endpoint(
    ctx: Ctx, opts: Any, identifier: str, client_id: str
) -> dict[str, Any]:
    """POST /admin/oauth2/resources/:identifier/clients/:client_id (endpoints.ts:305).
    Idempotent: an existing pair answers ``{linked, alreadyLinked}``."""
    session = await ctx.get_session()
    resource_id = decode_path_param(identifier)
    client_id = decode_path_param(client_id)
    await assert_resource_privileges(ctx, session, opts, "link", resource_id)
    if not await _find_resource(ctx, resource_id):
        raise _resource_not_found(resource_id)
    if not await ctx.adapter.find_one("oauthClient", [Where("clientId", client_id)]):
        raise OAuthError(404, "not_found", f"client {client_id} not found")
    pair = [Where("clientId", client_id), Where("resourceId", resource_id)]
    already = {"linked": True, "alreadyLinked": True}
    # ponytail: the schema cannot declare TS's (clientId, resourceId) unique index, so the
    # pair is checked first. Two concurrent links on a SQL adapter can still both insert;
    # unlink deletes every copy and lookups dedupe. Add the composite index to the schema
    # model to close the race.
    if await ctx.adapter.find_one("oauthClientResource", pair):
        return already
    try:
        await ctx.adapter.create(
            "oauthClientResource",
            {"clientId": client_id, "resourceId": resource_id, "createdAt": _now()},
        )
    except Exception as exc:
        if _UNIQUE_VIOLATION.search(str(exc)):
            return already
        raise
    return {"linked": True}


async def unlink_client_resource_endpoint(
    ctx: Ctx, opts: Any, identifier: str, client_id: str
) -> dict[str, Any]:
    """DELETE /admin/oauth2/resources/:identifier/clients/:client_id (endpoints.ts:365).
    Always succeeds, even when the pair does not exist."""
    session = await ctx.get_session()
    resource_id = decode_path_param(identifier)
    client_id = decode_path_param(client_id)
    await assert_resource_privileges(ctx, session, opts, "unlink", resource_id)
    await ctx.adapter.delete_many(
        "oauthClientResource",
        [Where("clientId", client_id), Where("resourceId", resource_id)],
    )
    return {"unlinked": True}
