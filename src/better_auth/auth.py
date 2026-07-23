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
from .config import (
    AccountOptions,
    EmailAndPassword,
    EmailVerification,
    RateLimit,
    SessionOptions,
    UserOptions,
)
from .endpoints import ROUTES
from .internal_adapter import InternalAdapter
from .oauth import OAuthProvider
from .plugins import Plugin
from .schema import (
    CORE_SCHEMA,
    Field,
    Schema,
    filter_output_fields,
    merge_schema,
    parse_input_data,
)
from .secondary_storage import SecondaryStorage
from .session import get_session as _get_session
from .types import APIError, AuthRequest, AuthResponse, Ctx

#: A request hook (``options.hooks.before``/``after``): ``async (ctx) -> AuthResponse | None``.
RequestHook = Callable[[Ctx], Awaitable[AuthResponse | None]]

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


def _path_matches(pattern: str, path: str) -> bool:
    """Middleware path match: exact, or prefix when ``pattern`` ends in ``/**``."""
    if pattern.endswith("/**"):
        prefix = pattern[:-3]
        return path == prefix or path.startswith(prefix + "/")
    return pattern == path


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
        user: UserOptions | None = None,
        account: AccountOptions | None = None,
        rate_limit: RateLimit | None = None,
        trusted_origins: list[str] | None = None,
        plugins: list[Plugin] | None = None,
        hooks: Mapping[str, RequestHook] | None = None,
        database_hooks: dict[str, Any] | None = None,
        secondary_storage: SecondaryStorage | None = None,
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
        self.user = user or UserOptions()
        self.account = account or AccountOptions()
        self.rate_limit = rate_limit or RateLimit()
        self.trusted_origins = [origin.rstrip("/") for origin in trusted_origins or []]
        self.plugins = list(plugins or [])
        #: request middleware — ``{"before": fn(ctx), "after": fn(ctx)}`` (TS ``options.hooks``).
        self.hooks: Mapping[str, RequestHook] = dict(hooks or {})
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

        # Output schema: core columns + configured additionalFields + plugin fields.
        # Later sources win on collision (TS getFields order: core < additional < plugin).
        additional: Schema = {
            "user": dict(self.user.additional_fields),
            "session": dict(self.session_options.additional_fields),
            "account": dict(self.account.additional_fields),
        }
        self.schema: Schema = merge_schema(
            CORE_SCHEMA, additional, *(p.schema for p in self.plugins)
        )
        # Input schema per model: additionalFields + plugin fields only (NOT core columns),
        # so generic write routes (e.g. /update-session) only accept configured fields.
        self._input_fields: dict[str, dict[str, Field]] = {
            model: merge_schema(
                {model: additional[model]}, *(p.schema for p in self.plugins)
            ).get(model, {})
            for model in ("user", "session", "account")
        }

        # $ERROR_CODES surfaced on the instance for typed client errors.
        self.error_codes: dict[str, str] = {}
        for plugin in self.plugins:
            self.error_codes.update(plugin.error_codes)

        self.secondary_storage = secondary_storage
        self.database_hooks = database_hooks
        self.adapter = adapter if adapter is not None else MemoryAdapter()
        self.adapter.init(self.schema)
        #: the domain seam every core write routes through so databaseHooks fire.
        self.internal = InternalAdapter(
            self.adapter,
            secondary_storage=secondary_storage,
            database_hooks=database_hooks,
            session_expires_in=self.session_options.expires_in,
        )

        self._http = http_client
        self._rate_buckets: dict[str, tuple[float, int]] = {}
        self._routes: list[tuple[str, tuple[str, ...], Any]] = []
        for method, path, handler in [
            *ROUTES,
            *(route for plugin in self.plugins for route in plugin.routes()),
        ]:
            self._routes.append((method, tuple(path.strip("/").split("/")), handler))

        for plugin in self.plugins:  # TS init(ctx): may mutate options/state in place
            plugin.init(self)

    # --- helpers ----------------------------------------------------------------------

    @property
    def http(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=10)
        return self._http

    # --- output/input parsing (schema-driven; mirrors db/schema.ts parse*) -------------

    def parse_user_output(self, user: dict[str, Any]) -> dict[str, Any]:
        return filter_output_fields(user, self.schema["user"])

    def parse_session_output(self, session: dict[str, Any]) -> dict[str, Any]:
        return filter_output_fields(session, self.schema["session"])

    def parse_account_output(self, account: dict[str, Any]) -> dict[str, Any]:
        return filter_output_fields(account, self.schema["account"])

    def parse_session_input(self, data: dict[str, Any], action: str = "update") -> dict[str, Any]:
        """Allowlist a session-write body to configured input fields (drops core columns
        and unknown keys). Empty result means the caller sent nothing writable."""
        return parse_input_data(data, self._input_fields["session"], action)

    def parse_user_input(self, data: dict[str, Any], action: str = "update") -> dict[str, Any]:
        return parse_input_data(data, self._input_fields["user"], action)

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

        # --- onRequest phase: rate limit -> plugin.on_request ---------------------------
        retry_after = self._check_rate_limit(request)
        if retry_after is not None:
            return AuthResponse(
                status=429,
                body={"message": "Too many requests. Please try again later."},
                headers=[("x-retry-after", str(retry_after))],
            )

        ctx = Ctx(auth=self, request=request)
        for plugin in self.plugins:
            short_circuit = await plugin.on_request(ctx)
            if short_circuit is not None:
                return short_circuit

        self._check_origin(request)

        match = self._match(request.method, request.path)
        if match is None:
            return AuthResponse(status=404, body={"message": "Not Found"})
        handler, params = match
        ctx.params = params

        # --- path-scoped plugin middlewares (TS router middleware) ----------------------
        for plugin in self.plugins:
            for mw in plugin.middlewares():
                if _path_matches(mw.path, request.path):
                    result = await mw.handler(ctx)
                    if isinstance(result, AuthResponse):
                        return result

        # --- before-hooks: user hooks first, then plugin hooks (TS getHooks order) ------
        short = await self._run_before_hooks(ctx)
        if short is not None:
            return short

        result = await handler(ctx)
        response = result if isinstance(result, AuthResponse) else AuthResponse(body=result)
        ctx.response = response

        # --- after-hooks: user hooks first, then plugin hooks ---------------------------
        response = await self._run_after_hooks(ctx, response)

        # --- onResponse phase -----------------------------------------------------------
        for plugin in self.plugins:
            replacement = await plugin.on_response(ctx, response)
            if replacement is not None:
                response = replacement
                ctx.response = response
        return response

    async def _run_before_hooks(self, ctx: Ctx) -> AuthResponse | None:
        user_before = self.hooks.get("before")
        if user_before is not None:
            short = await user_before(ctx)
            if short is not None:
                return short
        for plugin in self.plugins:
            short = await plugin.before(ctx)  # global (always-matched) hook
            if short is not None:
                return short
            for hook in plugin.hooks().before:
                if hook.matcher(ctx):
                    short = await hook.handler(ctx)
                    if isinstance(short, AuthResponse):
                        return short
        return None

    async def _run_after_hooks(self, ctx: Ctx, response: AuthResponse) -> AuthResponse:
        user_after = self.hooks.get("after")
        if user_after is not None:
            replacement = await user_after(ctx)
            if isinstance(replacement, AuthResponse):
                response = replacement
                ctx.response = response
        for plugin in self.plugins:
            for hook in plugin.hooks().after:
                if hook.matcher(ctx):
                    replacement = await hook.handler(ctx)
                    if isinstance(replacement, AuthResponse):
                        response = replacement
                        ctx.response = response
            replacement = await plugin.after(ctx, response)  # global (always-matched) hook
            if replacement is not None:
                response = replacement
                ctx.response = response
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
        # plugin rateLimit[] rules (first match wins) override default/special
        for plugin in self.plugins:
            matched = next(
                (r for r in plugin.rate_limit() if r.path_matcher(request.path)), None
            )
            if matched is not None:
                window, maximum = matched.window, matched.max
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
