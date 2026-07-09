"""Framework-agnostic HTTP primitives shared by the core and integrations."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime
from http.cookies import SimpleCookie
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .auth import BetterAuth


class APIError(Exception):
    """Error surfaced to the client as ``{"message": ..., "code": ...}`` with `status`."""

    def __init__(self, status: int, code: str, message: str | None = None):
        self.status = status
        self.code = code
        self.message = message or code.replace("_", " ").capitalize()
        super().__init__(self.message)


def json_default(value: Any) -> str:
    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    raise TypeError(f"Object of type {type(value).__name__} is not JSON serializable")


def dump_json(body: Any) -> bytes:
    return json.dumps(body, default=json_default, separators=(",", ":")).encode()


@dataclass
class AuthRequest:
    """A request stripped of the mount prefix (``path`` starts at e.g. ``/sign-in/email``)."""

    method: str
    path: str
    headers: dict[str, str] = field(default_factory=dict)  # lower-cased keys
    query: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    client_ip: str | None = None

    def cookies(self) -> dict[str, str]:
        raw = self.headers.get("cookie", "")
        if not raw:
            return {}
        jar: SimpleCookie = SimpleCookie()
        jar.load(raw)
        return {name: morsel.value for name, morsel in jar.items()}

    def json(self) -> dict[str, Any]:
        if not self.body:
            return {}
        try:
            data = json.loads(self.body)
        except ValueError:
            raise APIError(400, "INVALID_BODY", "Invalid JSON body") from None
        if not isinstance(data, dict):
            raise APIError(400, "INVALID_BODY", "Expected a JSON object")
        return data


@dataclass
class AuthResponse:
    """What every endpoint handler returns; integrations translate it to their framework."""

    status: int = 200
    body: Any = None
    headers: list[tuple[str, str]] = field(default_factory=list)
    redirect_to: str | None = None
    #: None means JSON; anything else (e.g. "text/html") sends `body` as-is
    media_type: str | None = None

    def set_cookie(self, value: str) -> None:
        self.headers.append(("set-cookie", value))


@dataclass
class Ctx:
    """Per-request context handed to endpoint handlers and plugin hooks."""

    auth: BetterAuth
    request: AuthRequest
    params: dict[str, str] = field(default_factory=dict)
    _body: dict[str, Any] | None = None
    _session: Any = None
    _session_loaded: bool = False

    @property
    def adapter(self):
        return self.auth.adapter

    def body(self) -> dict[str, Any]:
        if self._body is None:
            self._body = self.request.json()
        return self._body

    async def get_session(self) -> dict[str, Any] | None:
        """Return ``{"session": ..., "user": ...}`` for the request cookie, or None."""
        if not self._session_loaded:
            self._session = await self.auth.load_session(self.request)
            self._session_loaded = True
        return self._session

    async def require_session(self) -> dict[str, Any]:
        result = await self.get_session()
        if result is None:
            raise APIError(401, "UNAUTHORIZED", "Not authenticated")
        return result
