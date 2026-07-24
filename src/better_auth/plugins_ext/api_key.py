"""api-key plugin — mint / verify / manage long-lived API keys (database mode).

Ported from TS ``packages/api-key/src/`` at v1.6.23 (``index.ts``, ``schema.ts``,
``error-codes.ts``, ``rate-limit.ts``, ``routes/*.ts``, ``org-authorization.ts``).

Cross-runtime storage compatibility is a hard requirement: the ``apikey`` table uses the
exact camelCase column names and the ``key`` column is ``default_key_hasher(prefix+random)``
= base64url-nopad SHA-256, byte-identical to the TS ``defaultKeyHasher``. A row written by
the TS plugin verifies here and vice-versa.

Scope: ``storage:"database"`` only. ``secondary-storage`` / ``customStorage`` raise
``NotImplementedError`` at construction (the TS ``adapter.ts`` ~800-LOC layer, whose
secondary-only quota path is explicitly non-atomic, is deferred). The concurrency
guarantees the tests assert (single-winner remaining, rate-limit, refill) rest on the
guarded compare-and-swap ``increment_one`` primitive against the authoritative DB row.

Port-surface notes (this port is HTTP-dispatch-only, no ``auth.api.*`` surface):
- ``verify`` and ``delete-all-expired-api-keys`` are TS ``serverOnly`` — here they are
  plugin methods (``verify_api_key`` / ``delete_all_expired_api_keys``), never mounted as
  HTTP routes, mirroring the one-time-token precedent for server-only functionality.
- create / update distinguish TS "client" (``ctx.request`` set) from "server" calls. The
  HTTP routes always run the client path (rejecting server-only props / ``userId``); the
  ``create_api_key`` / ``update_api_key`` methods run the server path.
"""

from __future__ import annotations

import contextlib
import json
import math
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Any

from ..access_control import role as make_role
from ..adapters.base import Where
from ..crypto import default_key_hasher, generate_random_string
from ..plugins import HookSet, Plugin, PluginHook, Route
from ..schema import Field, Schema
from ..session import get_session, utcnow
from ..types import APIError, AuthResponse, Ctx

# --- error codes (verbatim from error-codes.ts) --------------------------------------

API_KEY_ERROR_CODES: dict[str, str] = {
    "INVALID_METADATA_TYPE": "metadata must be an object or undefined",
    "REFILL_AMOUNT_AND_INTERVAL_REQUIRED": (
        "refillAmount is required when refillInterval is provided"
    ),
    "REFILL_INTERVAL_AND_AMOUNT_REQUIRED": (
        "refillInterval is required when refillAmount is provided"
    ),
    "USER_BANNED": "User is banned",
    "UNAUTHORIZED_SESSION": "Unauthorized or invalid session",
    "KEY_NOT_FOUND": "API Key not found",
    "KEY_DISABLED": "API Key is disabled",
    "KEY_EXPIRED": "API Key has expired",
    "USAGE_EXCEEDED": "API Key has reached its usage limit",
    "KEY_NOT_RECOVERABLE": "API Key is not recoverable",
    "EXPIRES_IN_IS_TOO_SMALL": "The expiresIn is smaller than the predefined minimum value.",
    "EXPIRES_IN_IS_TOO_LARGE": "The expiresIn is larger than the predefined maximum value.",
    "INVALID_REMAINING": "The remaining count is either too large or too small.",
    "INVALID_PREFIX_LENGTH": "The prefix length is either too large or too small.",
    "INVALID_NAME_LENGTH": "The name length is either too large or too small.",
    "METADATA_DISABLED": "Metadata is disabled.",
    "RATE_LIMIT_EXCEEDED": "Rate limit exceeded.",
    "NO_VALUES_TO_UPDATE": "No values to update.",
    "KEY_DISABLED_EXPIRATION": "Custom key expiration values are disabled.",
    "INVALID_API_KEY": "Invalid API key.",
    "INVALID_USER_ID_FROM_API_KEY": "The user id from the API key is invalid.",
    "INVALID_REFERENCE_ID_FROM_API_KEY": "The reference id from the API key is invalid.",
    "INVALID_API_KEY_GETTER_RETURN_TYPE": (
        "API Key getter returned an invalid key type. Expected string."
    ),
    "SERVER_ONLY_PROPERTY": (
        "The property you're trying to set can only be set from the server auth instance only."
    ),
    "FAILED_TO_UPDATE_API_KEY": "Failed to update API key",
    "NAME_REQUIRED": "API Key name is required.",
    "ORGANIZATION_ID_REQUIRED": "Organization ID is required for organization-owned API keys.",
    "USER_NOT_MEMBER_OF_ORGANIZATION": (
        "You are not a member of the organization that owns this API key."
    ),
    "INSUFFICIENT_API_KEY_PERMISSIONS": (
        "You do not have permission to perform this action on organization API keys."
    ),
    "NO_DEFAULT_API_KEY_CONFIGURATION_FOUND": "No default api-key configuration found.",
    "ORGANIZATION_PLUGIN_REQUIRED": (
        "Organization plugin is required for organization-owned API keys. "
        "Please install and configure the organization plugin."
    ),
}

# generateRandomString(length, "a-z", "A-Z") — 52-char alphabet, no digits/-_ (index.ts:129).
_KEY_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
_DAY_MS = 1000 * 60 * 60 * 24


class _RateLimitedError(APIError):
    """Rate-limit deny (custom TS code ``RATE_LIMITED`` + ``details.tryAgainIn``). The port's
    ``APIError`` has no ``details`` slot; ``try_again_in`` rides on the exception and is
    surfaced only in the verify wrapper's ``error`` object (spec reconciliation, default (b)).
    The bare before-hook 429 drops it (tests assert status, not body)."""

    def __init__(self, message: str, try_again_in: int):
        super().__init__(429, "RATE_LIMITED", message)
        self.try_again_in = try_again_in


# --- config normalization (types.ts + index.ts:68-108) -------------------------------


@dataclass
class _Config:
    config_id: str | None = None
    api_key_headers: str | list[str] = "x-api-key"
    disable_key_hashing: bool = False
    default_key_length: int = 64
    default_prefix: str | None = None
    maximum_prefix_length: int = 32
    minimum_prefix_length: int = 1
    maximum_name_length: int = 32
    minimum_name_length: int = 1
    require_name: bool = False
    enable_metadata: bool = False
    enable_session_for_api_keys: bool = False
    references: str = "user"
    storage: str = "database"
    # nested
    should_store_start: bool = True
    starting_characters_length: int = 6
    default_expires_in: int | None = None
    disable_custom_expires_time: bool = False
    min_expires_in: int = 1
    max_expires_in: int = 365
    rate_limit_enabled: bool = True
    rate_limit_time_window: int = _DAY_MS
    rate_limit_max: int = 10
    default_permissions: Any = None
    custom_key_generator: Any = None
    custom_api_key_getter: Any = None
    custom_api_key_validator: Any = None


def _normalize(raw: dict[str, Any] | None) -> _Config:
    raw = dict(raw or {})
    storage = raw.get("storage", "database")
    if storage != "database" or raw.get("custom_storage") is not None:
        raise NotImplementedError(
            "api-key plugin (this port) supports storage='database' only; "
            "secondary-storage / customStorage are deferred (see gap 08 items 13-15)."
        )
    starting = raw.get("starting_characters_config") or {}
    expiration = raw.get("key_expiration") or {}
    rate_limit = raw.get("rate_limit") or {}
    permissions = raw.get("permissions") or {}
    return _Config(
        config_id=raw.get("config_id"),
        api_key_headers=raw.get("api_key_headers", "x-api-key"),
        disable_key_hashing=raw.get("disable_key_hashing", False),
        default_key_length=raw.get("default_key_length") or 64,
        default_prefix=raw.get("default_prefix"),
        maximum_prefix_length=raw.get("maximum_prefix_length", 32),
        minimum_prefix_length=raw.get("minimum_prefix_length", 1),
        maximum_name_length=raw.get("maximum_name_length", 32),
        minimum_name_length=raw.get("minimum_name_length", 1),
        require_name=raw.get("require_name", False),
        enable_metadata=raw.get("enable_metadata", False),
        enable_session_for_api_keys=raw.get("enable_session_for_api_keys", False),
        references=raw.get("references", "user"),
        storage=storage,
        should_store_start=starting.get("should_store", True),
        starting_characters_length=starting.get("characters_length", 6),
        default_expires_in=expiration.get("default_expires_in"),
        disable_custom_expires_time=expiration.get("disable_custom_expires_time", False),
        min_expires_in=expiration.get("min_expires_in", 1),
        max_expires_in=expiration.get("max_expires_in", 365),
        rate_limit_enabled=rate_limit.get("enabled", True),
        rate_limit_time_window=rate_limit.get("time_window", _DAY_MS),
        rate_limit_max=rate_limit.get("max_requests", 10),
        default_permissions=permissions.get("default_permissions"),
        custom_key_generator=raw.get("custom_key_generator"),
        custom_api_key_getter=raw.get("custom_api_key_getter"),
        custom_api_key_validator=raw.get("custom_api_key_validator"),
    )


def _is_default_config_id(config_id: str | None) -> bool:
    return not config_id or config_id == "default"


def _config_id_matches(key_config_id: str | None, expected: str | None) -> bool:
    if _is_default_config_id(key_config_id) and _is_default_config_id(expected):
        return True
    return key_config_id == expected


# --- rate-limit decision (rate-limit.ts, pure, no writes) ----------------------------


@dataclass
class _Decision:
    type: str
    last_request: datetime | None = None
    now: datetime | None = None
    window_start: datetime | None = None
    max: int | None = None
    message: str | None = None
    try_again_in: int = 0


def _evaluate_rate_limit(api_key: dict[str, Any], opts: _Config) -> _Decision:
    now = utcnow()
    last_request = api_key.get("lastRequest")
    window_ms = api_key.get("rateLimitTimeWindow")
    max_requests = api_key.get("rateLimitMax")

    if opts.rate_limit_enabled is False:
        return _Decision("skip", last_request=now)
    if api_key.get("rateLimitEnabled") is False:
        return _Decision("skip", last_request=now)
    if window_ms is None or max_requests is None:
        return _Decision("skip", last_request=None)
    if last_request is None:
        return _Decision("start", now=now)

    delta_ms = (now - last_request).total_seconds() * 1000
    window_start = now - timedelta(milliseconds=window_ms)
    if delta_ms > window_ms:
        return _Decision("reset", now=now, window_start=window_start)
    if api_key.get("requestCount", 0) >= max_requests:
        return _Decision(
            "deny",
            message=API_KEY_ERROR_CODES["RATE_LIMIT_EXCEEDED"],
            try_again_in=math.ceil(window_ms - delta_ms),
        )
    return _Decision("increment", now=now, max=max_requests, window_start=window_start)


# --- module-level expired-sweep throttle (routes/index.ts:98) ------------------------

_last_checked: datetime | None = None


async def _delete_all_expired(ctx: Ctx, bypass: bool = False) -> None:
    global _last_checked
    now = utcnow()
    if (
        _last_checked is not None
        and not bypass
        and (now - _last_checked).total_seconds() * 1000 < 10000
    ):
        return
    _last_checked = now
    with contextlib.suppress(Exception):  # fire-and-forget parity (routes/index.ts:128)
        await ctx.adapter.delete_many(
            "apikey",
            [Where("expiresAt", now, "lt"), Where("expiresAt", None, "ne")],
        )


# --- helpers -------------------------------------------------------------------------


def _parse_metadata(value: Any) -> dict[str, Any] | None:
    """Defensive parse-on-read (spec: no legacy double-stringify heal, tolerate shapes)."""
    if value is None:
        return None
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (ValueError, TypeError):
            return None
    return None


def _parse_permissions(value: Any) -> dict[str, Any] | None:
    if not value:
        return None
    if isinstance(value, dict):
        return value
    try:
        return json.loads(value)
    except (ValueError, TypeError):
        return None


def _strip_key(row: dict[str, Any]) -> dict[str, Any]:
    out = {k: v for k, v in row.items() if k != "key"}
    out["metadata"] = _parse_metadata(row.get("metadata"))
    out["permissions"] = _parse_permissions(row.get("permissions"))
    return out


# --- plugin --------------------------------------------------------------------------


class ApiKeyPlugin(Plugin):
    id = "api-key"
    error_codes = API_KEY_ERROR_CODES

    def __init__(self, config: dict[str, Any] | list[dict[str, Any]] | None = None, *,
                 schema: Schema | None = None) -> None:
        raws: list[dict[str, Any] | None]
        if isinstance(config, list):
            if config and not all(c.get("config_id") for c in config):
                raise ValueError(
                    "config_id is required for each API key configuration in the api-key plugin."
                )
            ids = [c.get("config_id") for c in config]
            if len(set(ids)) != len(ids):
                raise ValueError(
                    "config_id must be unique for each API key configuration in the api-key plugin."
                )
            raws = list(config)
        else:
            raws = [config]

        self._configs: list[_Config] = [_normalize(r) for r in raws]

        single = self._configs[0] if len(self._configs) == 1 else None
        default_rate_max = single.rate_limit_max if single else 10
        default_window = single.rate_limit_time_window if single else _DAY_MS
        self.schema: Schema = _build_schema(default_rate_max, default_window)
        if schema:
            for model, fields in schema.items():
                self.schema.setdefault(model, {}).update(fields)

    # --- config resolution (routes/index.ts:45) ------------------------------------

    def _resolve_config(self, config_id: str | None) -> _Config:
        def default_config() -> _Config:
            for c in self._configs:
                if not c.config_id or c.config_id == "default":
                    # clone with config_id forced to "default" (TS spreads {...c, configId})
                    return replace(c, config_id="default")
            raise APIError(
                400,
                "NO_DEFAULT_API_KEY_CONFIGURATION_FOUND",
                API_KEY_ERROR_CODES["NO_DEFAULT_API_KEY_CONFIGURATION_FOUND"],
            )

        if not config_id:
            return default_config()
        for c in self._configs:
            if c.config_id == config_id:
                return c
        return default_config()

    # --- routes (HTTP client surface) ----------------------------------------------

    def routes(self) -> list[Route]:
        return [
            ("POST", "/api-key/create", self._route_create),
            ("GET", "/api-key/get", self._route_get),
            ("POST", "/api-key/update", self._route_update),
            ("POST", "/api-key/delete", self._route_delete),
            ("GET", "/api-key/list", self._route_list),
        ]

    def hooks(self) -> HookSet:
        return HookSet(before=[PluginHook(self._session_matcher, self._session_hook)])

    # --- key generation + hashing (Area 4) -----------------------------------------

    async def _generate_key(self, opts: _Config, prefix: str | None) -> str:
        if opts.custom_key_generator is not None:
            result = opts.custom_key_generator(
                {"length": opts.default_key_length, "prefix": prefix}
            )
            if hasattr(result, "__await__"):
                result = await result
            return result
        random = generate_random_string(opts.default_key_length, _KEY_ALPHABET)
        return f"{prefix or ''}{random}"

    @staticmethod
    def _hash(opts: _Config, full_key: str) -> str:
        return full_key if opts.disable_key_hashing else default_key_hasher(full_key)

    # --- create (create-api-key.ts) ------------------------------------------------

    async def create_api_key(self, ctx: Ctx, **body: Any) -> dict[str, Any]:
        """Server surface: mint a key (may set server-only props + userId)."""
        return await self._create(ctx, body, server=True)

    async def _route_create(self, ctx: Ctx) -> AuthResponse:
        return AuthResponse(body=await self._create(ctx, ctx.body(), server=False))

    async def _create(self, ctx: Ctx, body: dict[str, Any], *, server: bool) -> dict[str, Any]:
        opts = self._resolve_config(body.get("configId"))
        session_result, _ = await get_session(ctx.auth, ctx.request, disable_cache=True)
        session_user = session_result["user"] if session_result else None
        is_client = not server

        remaining = body.get("remaining")
        using_server_only = (
            remaining is not None
            or body.get("refillAmount") is not None
            or body.get("refillInterval") is not None
            or body.get("rateLimitMax") is not None
            or body.get("rateLimitTimeWindow") is not None
            or body.get("rateLimitEnabled") is not None
            or body.get("permissions") is not None
        )
        if is_client and using_server_only:
            raise APIError(400, "SERVER_ONLY_PROPERTY", API_KEY_ERROR_CODES["SERVER_ONLY_PROPERTY"])
        if is_client and body.get("userId") is not None:
            raise APIError(401, "UNAUTHORIZED_SESSION", API_KEY_ERROR_CODES["UNAUTHORIZED_SESSION"])

        # reference resolution
        references = opts.references or "user"
        if references == "organization":
            org_id = body.get("organizationId")
            if not org_id:
                raise APIError(
                    400, "ORGANIZATION_ID_REQUIRED",
                    API_KEY_ERROR_CODES["ORGANIZATION_ID_REQUIRED"],
                )
            user_id = (session_user or {}).get("id") or body.get("userId")
            if not user_id:
                raise APIError(
                    401, "UNAUTHORIZED_SESSION", API_KEY_ERROR_CODES["UNAUTHORIZED_SESSION"]
                )
            await self._check_org_permission(ctx, user_id, org_id, "create")
            reference_id = org_id
        elif is_client:
            if not session_user or not session_user.get("id"):
                raise APIError(
                    401, "UNAUTHORIZED_SESSION", API_KEY_ERROR_CODES["UNAUTHORIZED_SESSION"]
                )
            reference_id = session_user["id"]
        else:
            ctx_user_id = body.get("userId")
            session_user_id = (session_user or {}).get("id")
            if not session_user_id and not ctx_user_id:
                raise APIError(
                    401, "UNAUTHORIZED_SESSION", API_KEY_ERROR_CODES["UNAUTHORIZED_SESSION"]
                )
            if session_user and ctx_user_id and session_user_id != ctx_user_id:
                raise APIError(
                    401, "UNAUTHORIZED_SESSION", API_KEY_ERROR_CODES["UNAUTHORIZED_SESSION"]
                )
            reference_id = session_user_id or ctx_user_id

        # validation gates
        metadata = body.get("metadata")
        if metadata is not None:
            if opts.enable_metadata is False:
                raise APIError(400, "METADATA_DISABLED", API_KEY_ERROR_CODES["METADATA_DISABLED"])
            if not isinstance(metadata, dict):
                raise APIError(
                    400, "INVALID_METADATA_TYPE", API_KEY_ERROR_CODES["INVALID_METADATA_TYPE"]
                )

        refill_amount = body.get("refillAmount")
        refill_interval = body.get("refillInterval")
        if refill_amount and not refill_interval:
            raise APIError(
                400, "REFILL_AMOUNT_AND_INTERVAL_REQUIRED",
                API_KEY_ERROR_CODES["REFILL_AMOUNT_AND_INTERVAL_REQUIRED"],
            )
        if refill_interval and not refill_amount:
            raise APIError(
                400, "REFILL_INTERVAL_AND_AMOUNT_REQUIRED",
                API_KEY_ERROR_CODES["REFILL_INTERVAL_AND_AMOUNT_REQUIRED"],
            )

        expires_in = body.get("expiresIn")
        if expires_in:
            if opts.disable_custom_expires_time is True:
                raise APIError(
                    400, "KEY_DISABLED_EXPIRATION",
                    API_KEY_ERROR_CODES["KEY_DISABLED_EXPIRATION"],
                )
            days = expires_in / (60 * 60 * 24)
            if opts.min_expires_in > days:
                raise APIError(
                    400, "EXPIRES_IN_IS_TOO_SMALL",
                    API_KEY_ERROR_CODES["EXPIRES_IN_IS_TOO_SMALL"],
                )
            if opts.max_expires_in < days:
                raise APIError(
                    400, "EXPIRES_IN_IS_TOO_LARGE",
                    API_KEY_ERROR_CODES["EXPIRES_IN_IS_TOO_LARGE"],
                )

        prefix = body.get("prefix")
        if prefix and (
            len(prefix) < opts.minimum_prefix_length or len(prefix) > opts.maximum_prefix_length
        ):
            raise APIError(
                400, "INVALID_PREFIX_LENGTH", API_KEY_ERROR_CODES["INVALID_PREFIX_LENGTH"]
            )

        name = body.get("name")
        if name:
            if len(name) < opts.minimum_name_length or len(name) > opts.maximum_name_length:
                raise APIError(
                    400, "INVALID_NAME_LENGTH", API_KEY_ERROR_CODES["INVALID_NAME_LENGTH"]
                )
        elif opts.require_name:
            raise APIError(400, "NAME_REQUIRED", API_KEY_ERROR_CODES["NAME_REQUIRED"])

        await _delete_all_expired(ctx)

        full_key = await self._generate_key(opts, prefix or opts.default_prefix)
        hashed = self._hash(opts, full_key)
        start = full_key[: opts.starting_characters_length] if opts.should_store_start else None

        # permissions (body -> JSON string, else config default)
        default_perms = opts.default_permissions
        if callable(default_perms):
            default_perms = default_perms(reference_id, ctx)
            if hasattr(default_perms, "__await__"):
                default_perms = await default_perms
        body_perms = body.get("permissions")
        if body_perms:
            permissions_str: str | None = json.dumps(body_perms)
        elif default_perms:
            permissions_str = json.dumps(default_perms)
        else:
            permissions_str = None

        now = utcnow()
        if expires_in:
            expires_at: datetime | None = now + timedelta(seconds=expires_in)
        elif opts.default_expires_in:
            expires_at = now + timedelta(seconds=opts.default_expires_in)
        else:
            expires_at = None

        rate_limit_enabled = body.get("rateLimitEnabled")
        data: dict[str, Any] = {
            "configId": opts.config_id or "default",
            "createdAt": now,
            "updatedAt": now,
            "name": name,
            "prefix": prefix or opts.default_prefix,
            "start": start,
            "key": hashed,
            "enabled": True,
            "expiresAt": expires_at,
            "referenceId": reference_id,
            "lastRefillAt": None,
            "lastRequest": None,
            "rateLimitMax": body.get("rateLimitMax") if body.get("rateLimitMax") is not None
            else opts.rate_limit_max,
            "rateLimitTimeWindow": body.get("rateLimitTimeWindow")
            if body.get("rateLimitTimeWindow") is not None else opts.rate_limit_time_window,
            "remaining": remaining,
            "refillAmount": refill_amount,
            "refillInterval": refill_interval,
            "rateLimitEnabled": rate_limit_enabled if rate_limit_enabled is not None
            else opts.rate_limit_enabled,
            "requestCount": 0,
            "permissions": permissions_str,
        }
        if metadata is not None:
            data["metadata"] = metadata  # adapter transform_input stringifies

        row = await ctx.adapter.create("apikey", data, force_allow_id=False)
        result = {k: v for k, v in row.items()}
        result["key"] = full_key
        result["metadata"] = metadata if metadata is not None else None
        result["permissions"] = _parse_permissions(row.get("permissions"))
        return result

    # --- verify (verify-api-key.ts) ------------------------------------------------

    async def verify_api_key(
        self, ctx: Ctx, *, key: str, config_id: str | None = None,
        permissions: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Server-only. Wrapped response: never raises to the caller."""
        lookup_opts = self._resolve_config(config_id)

        if config_id is not None and lookup_opts.custom_api_key_validator is not None:
            valid = lookup_opts.custom_api_key_validator({"ctx": ctx, "key": key})
            if hasattr(valid, "__await__"):
                valid = await valid
            if not valid:
                return {
                    "valid": False,
                    "error": {"message": API_KEY_ERROR_CODES["INVALID_API_KEY"],
                              "code": "KEY_NOT_FOUND"},
                    "key": None,
                }

        try:
            row, _opts = await self._validate_api_key(
                ctx, key, lookup_opts=lookup_opts, permissions=permissions,
                expected_config_id=config_id, run_custom_validator=config_id is None,
            )
        except _RateLimitedError as e:
            return {
                "valid": False,
                "error": {"message": e.message, "code": e.code, "tryAgainIn": e.try_again_in},
                "key": None,
            }
        except APIError as e:
            return {
                "valid": False,
                "error": {"message": e.message, "code": e.code},
                "key": None,
            }
        return {"valid": True, "error": None, "key": _strip_key(row)}

    async def _validate_api_key(
        self, ctx: Ctx, key: str, *, lookup_opts: _Config,
        permissions: dict[str, Any] | None = None,
        expected_config_id: str | None = None, run_custom_validator: bool = False,
    ) -> tuple[dict[str, Any], _Config]:
        hashed = key if lookup_opts.disable_key_hashing else default_key_hasher(key)
        api_key = await ctx.adapter.find_one("apikey", [Where("key", hashed)])
        if api_key is None:
            raise APIError(401, "INVALID_API_KEY", API_KEY_ERROR_CODES["INVALID_API_KEY"])

        if expected_config_id is not None and not _config_id_matches(
            api_key.get("configId"), expected_config_id
        ):
            raise APIError(401, "INVALID_API_KEY", API_KEY_ERROR_CODES["INVALID_API_KEY"])

        opts = self._resolve_config(api_key.get("configId"))

        if run_custom_validator and opts.custom_api_key_validator is not None:
            valid = opts.custom_api_key_validator({"ctx": ctx, "key": key})
            if hasattr(valid, "__await__"):
                valid = await valid
            if not valid:
                raise APIError(401, "KEY_NOT_FOUND", API_KEY_ERROR_CODES["KEY_NOT_FOUND"])

        if api_key.get("enabled") is False:
            raise APIError(401, "KEY_DISABLED", API_KEY_ERROR_CODES["KEY_DISABLED"])

        if api_key.get("expiresAt") and utcnow() > api_key["expiresAt"]:
            await ctx.adapter.delete("apikey", [Where("id", api_key["id"])])
            raise APIError(401, "KEY_EXPIRED", API_KEY_ERROR_CODES["KEY_EXPIRED"])

        if permissions:
            key_perms = _parse_permissions(api_key.get("permissions"))
            if not key_perms:
                raise APIError(401, "KEY_NOT_FOUND", API_KEY_ERROR_CODES["KEY_NOT_FOUND"])
            if not make_role(key_perms).authorize(permissions).get("success"):
                raise APIError(401, "KEY_NOT_FOUND", API_KEY_ERROR_CODES["KEY_NOT_FOUND"])

        if api_key.get("remaining") == 0 and api_key.get("refillAmount") is None:
            await ctx.adapter.delete("apikey", [Where("id", api_key["id"])])
            raise APIError(429, "USAGE_EXCEEDED", API_KEY_ERROR_CODES["USAGE_EXCEEDED"])

        new_row = await self._claim_usage_db(ctx, api_key, opts)
        return new_row, opts

    async def _claim_usage_db(
        self, ctx: Ctx, api_key: dict[str, Any], opts: _Config
    ) -> dict[str, Any]:
        row = api_key
        if api_key.get("remaining") is not None:
            row = await self._consume_remaining(ctx, api_key)
        row = await self._consume_rate_limit(ctx, row, opts)

        final = await ctx.adapter.update(
            "apikey", [Where("id", row["id"])], {"updatedAt": utcnow()}
        )
        if final is None:
            # row deleted concurrently (revoked mid-verify): do not re-cache a gone key.
            raise APIError(401, "INVALID_API_KEY", API_KEY_ERROR_CODES["INVALID_API_KEY"])
        return final

    async def _consume_remaining(self, ctx: Ctx, api_key: dict[str, Any]) -> dict[str, Any]:
        now = utcnow()
        refill_interval = api_key.get("refillInterval")
        refill_amount = api_key.get("refillAmount")
        if refill_interval and refill_amount:
            last: datetime = api_key.get("lastRefillAt") or api_key["createdAt"]
            if (now - last).total_seconds() * 1000 > refill_interval:
                refilled = await ctx.adapter.increment_one(
                    "apikey",
                    [Where("id", api_key["id"]),
                     Where("lastRefillAt", api_key.get("lastRefillAt"))],
                    set={"remaining": refill_amount - 1, "lastRefillAt": now},
                )
                if refilled is not None:
                    return refilled
                # lost the refill CAS: fall through to guarded decrement.

        decremented = await ctx.adapter.increment_one(
            "apikey",
            [Where("id", api_key["id"]), Where("remaining", 0, "gt")],
            increment={"remaining": -1},
        )
        if decremented is None:
            raise APIError(429, "USAGE_EXCEEDED", API_KEY_ERROR_CODES["USAGE_EXCEEDED"])
        return decremented

    async def _consume_rate_limit(
        self, ctx: Ctx, api_key: dict[str, Any], opts: _Config
    ) -> dict[str, Any]:
        decision = _evaluate_rate_limit(api_key, opts)

        if decision.type == "deny":
            raise _RateLimitedError(decision.message or "", decision.try_again_in)

        if decision.type == "skip":
            if decision.last_request is None:
                return api_key
            updated = await ctx.adapter.update(
                "apikey", [Where("id", api_key["id"])], {"lastRequest": decision.last_request}
            )
            return updated or api_key

        if decision.type == "increment":
            incremented = await ctx.adapter.increment_one(
                "apikey",
                [
                    Where("id", api_key["id"]),
                    Where("lastRequest", decision.window_start, "gt"),
                    Where("requestCount", decision.max, "lt"),
                ],
                increment={"requestCount": 1},
                set={"lastRequest": decision.now},
            )
            if incremented is not None:
                return incremented
            fresh = await ctx.adapter.find_one("apikey", [Where("id", api_key["id"])])
            if fresh is None:
                raise APIError(401, "INVALID_API_KEY", API_KEY_ERROR_CODES["INVALID_API_KEY"])
            return await self._consume_rate_limit(ctx, fresh, opts)

        # start / reset: guarded conditional set of requestCount=1.
        if decision.type == "reset":
            window_guard = Where("lastRequest", decision.window_start, "lte")
        else:
            window_guard = Where("lastRequest", None, "eq")
        started = await ctx.adapter.increment_one(
            "apikey",
            [Where("id", api_key["id"]), window_guard],
            set={"requestCount": 1, "lastRequest": decision.now},
        )
        if started is not None:
            return started
        fresh = await ctx.adapter.find_one("apikey", [Where("id", api_key["id"])])
        if fresh is None:
            raise APIError(401, "INVALID_API_KEY", API_KEY_ERROR_CODES["INVALID_API_KEY"])
        return await self._consume_rate_limit(ctx, fresh, opts)

    # --- get / update / delete / list ----------------------------------------------

    async def _lookup_and_own(
        self, ctx: Ctx, key_id: str, config_id: str | None, user_id: str, action: str
    ) -> tuple[dict[str, Any], _Config]:
        """Fetch by id, config-scope gate, then ownership gate (user or org)."""
        lookup_opts = self._resolve_config(config_id)
        api_key = await ctx.adapter.find_one("apikey", [Where("id", key_id)])
        if api_key is None:
            raise APIError(404, "KEY_NOT_FOUND", API_KEY_ERROR_CODES["KEY_NOT_FOUND"])
        if not _config_id_matches(api_key.get("configId"), lookup_opts.config_id):
            raise APIError(404, "KEY_NOT_FOUND", API_KEY_ERROR_CODES["KEY_NOT_FOUND"])
        opts = self._resolve_config(api_key.get("configId"))
        if (opts.references or "user") == "organization":
            await self._check_org_permission(ctx, user_id, api_key["referenceId"], action)
        elif api_key["referenceId"] != user_id:
            raise APIError(404, "KEY_NOT_FOUND", API_KEY_ERROR_CODES["KEY_NOT_FOUND"])
        return api_key, opts

    async def _route_get(self, ctx: Ctx) -> AuthResponse:
        session = await ctx.require_session()
        query = ctx.request.query
        api_key, _ = await self._lookup_and_own(
            ctx, query.get("id", ""), query.get("configId"), session["user"]["id"], "read"
        )
        await _delete_all_expired(ctx)
        return AuthResponse(body=_strip_key(api_key))

    async def _route_update(self, ctx: Ctx) -> AuthResponse:
        return AuthResponse(body=await self._update(ctx, ctx.body(), server=False))

    async def update_api_key(self, ctx: Ctx, **body: Any) -> dict[str, Any]:
        return await self._update(ctx, body, server=True)

    async def _update(self, ctx: Ctx, body: dict[str, Any], *, server: bool) -> dict[str, Any]:
        session_result, _ = await get_session(ctx.auth, ctx.request, disable_cache=True)
        session_user = session_result["user"] if session_result else None
        is_client = not server

        if session_user and session_user.get("id"):
            user_id = session_user["id"]
        elif not is_client:
            user_id = body.get("userId")
        else:
            user_id = None
        if not user_id:
            raise APIError(401, "UNAUTHORIZED_SESSION", API_KEY_ERROR_CODES["UNAUTHORIZED_SESSION"])
        if session_user and body.get("userId") and session_user["id"] != body["userId"]:
            raise APIError(401, "UNAUTHORIZED_SESSION", API_KEY_ERROR_CODES["UNAUTHORIZED_SESSION"])

        if is_client and (
            body.get("refillAmount") is not None
            or body.get("refillInterval") is not None
            or body.get("rateLimitMax") is not None
            or body.get("rateLimitTimeWindow") is not None
            or body.get("rateLimitEnabled") is not None
            or body.get("remaining") is not None
            or body.get("permissions") is not None
        ):
            raise APIError(400, "SERVER_ONLY_PROPERTY", API_KEY_ERROR_CODES["SERVER_ONLY_PROPERTY"])

        api_key, opts = await self._lookup_and_own(
            ctx, body.get("keyId", ""), body.get("configId"), user_id, "update"
        )

        new_values: dict[str, Any] = {}
        if "name" in body and body["name"] is not None:
            name = body["name"]
            if len(name) < opts.minimum_name_length or len(name) > opts.maximum_name_length:
                raise APIError(
                    400, "INVALID_NAME_LENGTH", API_KEY_ERROR_CODES["INVALID_NAME_LENGTH"]
                )
            new_values["name"] = name
        if body.get("enabled") is not None:
            new_values["enabled"] = body["enabled"]
        if "expiresIn" in body:
            expires_in = body["expiresIn"]
            if opts.disable_custom_expires_time is True:
                raise APIError(
                    400, "KEY_DISABLED_EXPIRATION",
                    API_KEY_ERROR_CODES["KEY_DISABLED_EXPIRATION"],
                )
            if expires_in is not None:
                days = expires_in / (60 * 60 * 24)
                if days < opts.min_expires_in:
                    raise APIError(
                        400, "EXPIRES_IN_IS_TOO_SMALL",
                        API_KEY_ERROR_CODES["EXPIRES_IN_IS_TOO_SMALL"],
                    )
                if days > opts.max_expires_in:
                    raise APIError(
                        400, "EXPIRES_IN_IS_TOO_LARGE",
                        API_KEY_ERROR_CODES["EXPIRES_IN_IS_TOO_LARGE"],
                    )
            new_values["expiresAt"] = (
                utcnow() + timedelta(seconds=expires_in) if expires_in else None
            )
        if body.get("metadata") is not None and opts.enable_metadata is True:
            if not isinstance(body["metadata"], dict):
                raise APIError(
                    400, "INVALID_METADATA_TYPE", API_KEY_ERROR_CODES["INVALID_METADATA_TYPE"]
                )
            new_values["metadata"] = body["metadata"]
        if body.get("remaining") is not None:
            new_values["remaining"] = body["remaining"]
        if body.get("refillAmount") is not None or body.get("refillInterval") is not None:
            if body.get("refillAmount") is not None and body.get("refillInterval") is None:
                raise APIError(
                    400, "REFILL_AMOUNT_AND_INTERVAL_REQUIRED",
                    API_KEY_ERROR_CODES["REFILL_AMOUNT_AND_INTERVAL_REQUIRED"],
                )
            if body.get("refillInterval") is not None and body.get("refillAmount") is None:
                raise APIError(
                    400, "REFILL_INTERVAL_AND_AMOUNT_REQUIRED",
                    API_KEY_ERROR_CODES["REFILL_INTERVAL_AND_AMOUNT_REQUIRED"],
                )
            new_values["refillAmount"] = body.get("refillAmount")
            new_values["refillInterval"] = body.get("refillInterval")
        if body.get("rateLimitEnabled") is not None:
            new_values["rateLimitEnabled"] = body["rateLimitEnabled"]
        if body.get("rateLimitTimeWindow") is not None:
            new_values["rateLimitTimeWindow"] = body["rateLimitTimeWindow"]
        if body.get("rateLimitMax") is not None:
            new_values["rateLimitMax"] = body["rateLimitMax"]
        if body.get("permissions") is not None:
            new_values["permissions"] = json.dumps(body["permissions"])

        if not new_values:
            raise APIError(400, "NO_VALUES_TO_UPDATE", API_KEY_ERROR_CODES["NO_VALUES_TO_UPDATE"])

        try:
            result = await ctx.adapter.update("apikey", [Where("id", api_key["id"])], new_values)
        except Exception as e:  # storage error -> 500 with raw message (delete/update-api-key.ts)
            raise APIError(500, "INTERNAL_SERVER_ERROR", str(e)) from e
        new_row = result or api_key
        await _delete_all_expired(ctx)
        return _strip_key(new_row)

    async def _route_delete(self, ctx: Ctx) -> AuthResponse:
        session = await ctx.require_session()
        if session["user"].get("banned") is True:
            raise APIError(401, "USER_BANNED", API_KEY_ERROR_CODES["USER_BANNED"])
        body = ctx.body()
        api_key, _opts = await self._lookup_and_own(
            ctx, body.get("keyId", ""), body.get("configId"), session["user"]["id"], "delete"
        )
        try:
            await ctx.adapter.delete("apikey", [Where("id", api_key["id"])])
        except Exception as e:
            raise APIError(500, "INTERNAL_SERVER_ERROR", str(e)) from e
        await _delete_all_expired(ctx)
        return AuthResponse(body={"success": True})

    async def _route_list(self, ctx: Ctx) -> AuthResponse:
        session = await ctx.require_session()
        query = ctx.request.query
        config_id = query.get("configId")
        organization_id = query.get("organizationId")
        limit = int(query["limit"]) if query.get("limit") else None
        offset = int(query["offset"]) if query.get("offset") else None

        if organization_id:
            await self._check_org_permission(
                ctx, session["user"]["id"], organization_id, "read"
            )
        reference_id = organization_id or session["user"]["id"]
        expected_ref_type = "organization" if organization_id else "user"

        rows = await ctx.adapter.find_many("apikey", [Where("referenceId", reference_id)])

        def keep(row: dict[str, Any]) -> bool:
            key_cfg = self._config_for_key(row.get("configId"))
            ref_type = (key_cfg.references or "user") if key_cfg else "user"
            if ref_type != expected_ref_type or row["referenceId"] != reference_id:
                return False
            return not (config_id and not _config_id_matches(row.get("configId"), config_id))

        filtered = [r for r in rows if keep(r)]
        total = len(filtered)
        if offset is not None:
            filtered = filtered[offset:]
        if limit is not None:
            filtered = filtered[:limit]

        await _delete_all_expired(ctx)
        return AuthResponse(
            body={
                "apiKeys": [_strip_key(r) for r in filtered],
                "total": total,
                "limit": limit,
                "offset": offset,
            }
        )

    def _config_for_key(self, key_config_id: str | None) -> _Config | None:
        for c in self._configs:
            if _is_default_config_id(key_config_id):
                if _is_default_config_id(c.config_id):
                    return c
            elif c.config_id == key_config_id:
                return c
        return None

    async def delete_all_expired_api_keys(self, ctx: Ctx) -> dict[str, Any]:
        """Server-only. Bypass the 10s throttle; catch internally."""
        try:
            await _delete_all_expired(ctx, bypass=True)
        except Exception as e:  # pragma: no cover
            return {"success": False, "error": str(e)}
        return {"success": True, "error": None}

    # --- org authorization (org-authorization.ts) ----------------------------------

    async def _check_org_permission(
        self, ctx: Ctx, user_id: str, organization_id: str, action: str
    ) -> dict[str, Any]:
        from .organization import OrganizationPlugin, has_permission

        org_plugin = next(
            (p for p in ctx.auth.plugins if isinstance(p, OrganizationPlugin)), None
        )
        if org_plugin is None:
            raise APIError(
                500, "ORGANIZATION_PLUGIN_REQUIRED",
                API_KEY_ERROR_CODES["ORGANIZATION_PLUGIN_REQUIRED"],
            )
        member = await ctx.adapter.find_one(
            "member",
            [Where("userId", user_id), Where("organizationId", organization_id)],
        )
        if member is None:
            raise APIError(
                403, "USER_NOT_MEMBER_OF_ORGANIZATION",
                API_KEY_ERROR_CODES["USER_NOT_MEMBER_OF_ORGANIZATION"],
            )

        try:
            ok = await has_permission(
                role=member["role"],
                permissions={"apiKey": [action]},
                options=org_plugin,
                organization_id=organization_id,
                ctx=ctx,
                allow_creator_all_permissions=True,
            )
        except Exception:
            ok = False
        if not ok:
            raise APIError(
                403, "INSUFFICIENT_API_KEY_PERMISSIONS",
                API_KEY_ERROR_CODES["INSUFFICIENT_API_KEY_PERMISSIONS"],
            )
        return member

    # --- /get-session session-mock before-hook (index.ts:165) ----------------------

    def _get_key_from_config(self, ctx: Ctx, config: _Config) -> str | None:
        if config.custom_api_key_getter is not None:
            return config.custom_api_key_getter(ctx)
        headers = config.api_key_headers
        if isinstance(headers, list):
            for header in headers:
                value = ctx.request.headers.get(header.lower())
                if value:
                    return value
            return None
        return ctx.request.headers.get(headers.lower())

    def _find_key_and_config(self, ctx: Ctx) -> tuple[str, _Config] | None:
        for config in self._configs:
            if not config.enable_session_for_api_keys:
                continue
            key = self._get_key_from_config(ctx, config)
            if key:
                return key, config
        return None

    def _session_matcher(self, ctx: Ctx) -> bool:
        return self._find_key_and_config(ctx) is not None

    async def _session_hook(self, ctx: Ctx) -> AuthResponse | None:
        found = self._find_key_and_config(ctx)
        if found is None:
            return None
        key, config = found

        if not isinstance(key, str):
            raise APIError(
                400, "INVALID_API_KEY_GETTER_RETURN_TYPE",
                API_KEY_ERROR_CODES["INVALID_API_KEY_GETTER_RETURN_TYPE"],
            )
        if len(key) < config.default_key_length:
            raise APIError(403, "INVALID_API_KEY", API_KEY_ERROR_CODES["INVALID_API_KEY"])
        if config.custom_api_key_validator is not None:
            valid = config.custom_api_key_validator({"ctx": ctx, "key": key})
            if hasattr(valid, "__await__"):
                valid = await valid
            if not valid:
                raise APIError(403, "INVALID_API_KEY", API_KEY_ERROR_CODES["INVALID_API_KEY"])

        api_key, _opts = await self._validate_api_key(
            ctx, key, lookup_opts=config, expected_config_id=config.config_id,
            run_custom_validator=False,
        )
        await _delete_all_expired(ctx)

        if (config.references or "user") != "user":
            raise APIError(
                401, "INVALID_REFERENCE_ID_FROM_API_KEY",
                API_KEY_ERROR_CODES["INVALID_REFERENCE_ID_FROM_API_KEY"],
            )
        user = await ctx.adapter.find_one("user", [Where("id", api_key["referenceId"])])
        if user is None:
            raise APIError(
                401, "INVALID_REFERENCE_ID_FROM_API_KEY",
                API_KEY_ERROR_CODES["INVALID_REFERENCE_ID_FROM_API_KEY"],
            )

        now = utcnow()
        expires_at = api_key.get("expiresAt") or (
            now + timedelta(seconds=ctx.auth.session_options.expires_in)
        )
        session = {
            "user": user,
            "session": {
                "id": api_key["id"],
                "token": key,
                "userId": api_key["referenceId"],
                "userAgent": ctx.request.headers.get("user-agent"),
                "ipAddress": ctx.request.client_ip,
                "createdAt": now,
                "updatedAt": now,
                "expiresAt": expires_at,
            },
        }
        ctx._session = session
        ctx._session_loaded = True

        if ctx.request.path == "/get-session":
            return AuthResponse(
                body=session,
                headers=[("cache-control", "no-store"), ("pragma", "no-cache")],
            )
        return None


# --- schema (schema.ts, 21 columns, camelCase) ---------------------------------------


def _build_schema(default_rate_limit_max: int, default_time_window: int) -> Schema:
    return {
        "apikey": {
            "configId": Field("string", required=True, default="default", input=False, index=True),
            "name": Field("string", required=False, input=False),
            "start": Field("string", required=False, input=False),
            "referenceId": Field("string", required=True, input=False, index=True),
            "prefix": Field("string", required=False, input=False),
            "key": Field("string", required=True, input=False, index=True),
            "refillInterval": Field("number", required=False, input=False),
            "refillAmount": Field("number", required=False, input=False),
            "lastRefillAt": Field("datetime", required=False, input=False),
            "enabled": Field("boolean", required=False, input=False, default=True),
            "rateLimitEnabled": Field("boolean", required=False, input=False, default=True),
            "rateLimitTimeWindow": Field(
                "number", required=False, input=False, default=default_time_window
            ),
            "rateLimitMax": Field(
                "number", required=False, input=False, default=default_rate_limit_max
            ),
            "requestCount": Field("number", required=False, input=False, default=0),
            "remaining": Field("number", required=False, input=False),
            "lastRequest": Field("datetime", required=False, input=False),
            "expiresAt": Field("datetime", required=False, input=False),
            "createdAt": Field("datetime", required=True, input=False),
            "updatedAt": Field("datetime", required=True, input=False),
            "permissions": Field("string", required=False, input=False),
            "metadata": Field("string", required=False, input=True, transform_input=json.dumps),
        }
    }
