"""BetterAuth: configuration, routing and request dispatch."""

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable, Mapping
from typing import Any
from urllib.parse import urlsplit

import httpx

from .adapters.base import BaseAdapter
from .adapters.memory import MemoryAdapter
from .config import EmailAndPassword, EmailVerification, RateLimit, SessionOptions
from .endpoints import ROUTES
from .oauth import OAuthProvider
from .plugins import Plugin
from .schema import CORE_SCHEMA, Schema, merge_schema
from .session import get_session as _get_session
from .types import APIError, AuthRequest, AuthResponse, Ctx

logger = logging.getLogger("better_auth")

# better-auth's default special rate-limit rules: (window seconds, max requests)
_SPECIAL_RATE_RULES: list[tuple[Callable[[str], bool], tuple[int, int]]] = [
    (
        lambda p: p.startswith(("/sign-in", "/sign-up", "/change-password", "/change-email")),
        (10, 3),
    ),
    (
        lambda p: (
            p in ("/request-password-reset", "/send-verification-email")
            or p.startswith("/forget-password")
        ),
        (60, 3),
    ),
]


class BetterAuth:
    """The auth instance. Mount it with an integration (e.g. better_auth.integrations.fastapi)
    or call :meth:`handle` with an :class:`~better_auth.types.AuthRequest` directly."""

    def __init__(
        self,
        *,
        secret: str,
        adapter: BaseAdapter | None = None,
        base_url: str = "http://localhost:8000",
        base_path: str = "/api/auth",
        email_and_password: EmailAndPassword | None = None,
        email_verification: EmailVerification | None = None,
        social_providers: Mapping[str, OAuthProvider] | None = None,
        session: SessionOptions | None = None,
        rate_limit: RateLimit | None = None,
        trusted_origins: list[str] | None = None,
        plugins: list[Plugin] | None = None,
        hooks: dict[str, Callable[..., Awaitable[None]]] | None = None,
        http_client: httpx.AsyncClient | None = None,
        cookie_prefix: str = "better-auth",
        use_secure_cookies: bool | None = None,
        skip_state_cookie_check: bool = False,
    ):
        if not secret or len(secret) < 32:
            raise ValueError(
                "secret must be at least 32 characters — generate one with"
                " `openssl rand -base64 32`"
            )
        self.secret = secret
        self.base_url = base_url.rstrip("/")
        stripped = base_path.strip("/")
        self.base_path = f"/{stripped}" if stripped else ""
        self.email_and_password = email_and_password or EmailAndPassword()
        self.email_verification = email_verification or EmailVerification()
        self.session_options = session or SessionOptions()
        self.rate_limit = rate_limit or RateLimit()
        self.trusted_origins = [origin.rstrip("/") for origin in trusted_origins or []]
        self.plugins = list(plugins or [])
        self.hooks = dict(hooks or {})
        self.cookie_prefix = cookie_prefix
        self.use_secure_cookies = (
            use_secure_cookies
            if use_secure_cookies is not None
            else self.base_url.startswith("https://")
        )
        self.skip_state_cookie_check = skip_state_cookie_check

        self.social_providers = dict(social_providers or {})
        for provider_id, provider in self.social_providers.items():
            if not provider.provider_id:
                provider.provider_id = provider_id

        self.schema: Schema = merge_schema(CORE_SCHEMA, *(p.schema for p in self.plugins))
        self.adapter = adapter if adapter is not None else MemoryAdapter()
        self.adapter.init(self.schema)

        self._http = http_client
        self._rate_buckets: dict[str, tuple[float, int]] = {}
        self._routes: list[tuple[str, tuple[str, ...], Any]] = []
        for method, path, handler in [
            *ROUTES,
            *(route for plugin in self.plugins for route in plugin.routes()),
        ]:
            self._routes.append((method, tuple(path.strip("/").split("/")), handler))

    # --- helpers ----------------------------------------------------------------------

    @property
    def http(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=10)
        return self._http

    async def run_hook(self, name: str, *args: Any) -> None:
        hook = self.hooks.get(name)
        if hook is not None:
            await hook(*args)

    def _allowed_origins(self) -> set[str]:
        origins = {self._origin(self.base_url)}
        origins.update(self._origin(origin) for origin in self.trusted_origins)
        origins.discard("")
        return origins

    @staticmethod
    def _origin(url: str) -> str:
        parts = urlsplit(url)
        return f"{parts.scheme}://{parts.netloc}" if parts.scheme and parts.netloc else ""

    def is_trusted_url(self, url: str) -> bool:
        """Relative paths and URLs on the base/trusted origins are allowed redirect targets."""
        if url.startswith("/") and not url.startswith("//"):
            return True
        return self._origin(url) in self._allowed_origins()

    def ensure_trusted_url(self, url: str) -> None:
        if not self.is_trusted_url(url):
            raise APIError(403, "INVALID_CALLBACK_URL", "Callback URL is not trusted")

    async def load_session(self, request: AuthRequest) -> dict[str, Any] | None:
        """``{"session": ..., "user": ...}`` for the request, or None. Used by integrations."""
        result, _cookies = await _get_session(self, request)
        return result

    # --- dispatch ---------------------------------------------------------------------

    async def handle(self, request: AuthRequest) -> AuthResponse:
        try:
            return await self._dispatch(request)
        except APIError as error:
            return AuthResponse(
                status=error.status, body={"code": error.code, "message": error.message}
            )
        except Exception:
            logger.exception("better-auth error handling %s %s", request.method, request.path)
            return AuthResponse(status=500, body={"message": "Internal Server Error"})

    async def _dispatch(self, request: AuthRequest) -> AuthResponse:
        request.path = "/" + request.path.strip("/")

        retry_after = self._check_rate_limit(request)
        if retry_after is not None:
            return AuthResponse(
                status=429,
                body={"message": "Too many requests. Please try again later."},
                headers=[("x-retry-after", str(retry_after))],
            )
        self._check_origin(request)

        match = self._match(request.method, request.path)
        if match is None:
            return AuthResponse(status=404, body={"message": "Not Found"})
        handler, params = match

        ctx = Ctx(auth=self, request=request, params=params)
        for plugin in self.plugins:
            short_circuit = await plugin.before(ctx)
            if short_circuit is not None:
                return short_circuit

        result = await handler(ctx)
        response = result if isinstance(result, AuthResponse) else AuthResponse(body=result)

        for plugin in self.plugins:
            replacement = await plugin.after(ctx, response)
            if replacement is not None:
                response = replacement
        return response

    def _match(self, method: str, path: str) -> tuple[Any, dict[str, str]] | None:
        parts = tuple(path.strip("/").split("/"))
        for route_method, segments, handler in self._routes:
            if route_method != method or len(segments) != len(parts):
                continue
            params: dict[str, str] = {}
            for segment, part in zip(segments, parts, strict=True):
                if segment.startswith("{") and segment.endswith("}"):
                    params[segment[1:-1]] = part
                elif segment != part:
                    break
            else:
                return handler, params
        return None

    def _check_origin(self, request: AuthRequest) -> None:
        """Reject state-changing requests from untrusted browser origins (CSRF)."""
        if request.method == "GET":
            return
        origin = request.headers.get("origin")
        if not origin:  # non-browser clients (no Origin header) pass through
            return
        if origin.rstrip("/") not in self._allowed_origins():
            raise APIError(403, "INVALID_ORIGIN", "Origin not trusted")

    def _check_rate_limit(self, request: AuthRequest) -> int | None:
        """Returns seconds to wait when limited, else None. Fixed window, in-memory."""
        limit = self.rate_limit
        if not limit.enabled:
            return None
        window, maximum = limit.window, limit.max
        for matches, rule in _SPECIAL_RATE_RULES:
            if matches(request.path):
                window, maximum = rule
                break
        custom = limit.custom_rules.get(request.path)
        if custom is not None:
            window, maximum = custom

        key = f"{request.client_ip or 'no-ip'}-{request.path}"
        now = time.time()
        start, count = self._rate_buckets.get(key, (now, 0))
        if now - start >= window:
            start, count = now, 0
        count += 1
        self._rate_buckets[key] = (start, count)
        if count > maximum:
            return max(1, int(window - (now - start)))
        return None
