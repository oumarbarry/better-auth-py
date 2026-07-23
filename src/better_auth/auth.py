"""BetterAuth: configuration, routing and request dispatch."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable, Mapping
from typing import Any
from urllib.parse import urlsplit

import httpx

from .adapters.base import BaseAdapter
from .adapters.memory import MemoryAdapter
from .config import (
    AccountOptions,
    CrossSubDomainCookies,
    EmailAndPassword,
    EmailVerification,
    OnAPIError,
    RateLimit,
    SessionOptions,
    UserOptions,
)
from .crypto import hash_password
from .endpoints import ROUTES
from .internal_adapter import InternalAdapter
from .oauth import OAuthProvider
from .origin import check_origin, matches_origin_pattern
from .plugins import Plugin
from .rate_limit import RateLimiter
from .schema import (
    CORE_SCHEMA,
    Field,
    Schema,
    filter_output_fields,
    merge_schema,
    parse_input_data,
    rate_limit_model,
)
from .secondary_storage import SecondaryStorage
from .session import get_session as _get_session
from .types import APIError, AuthRequest, AuthResponse, Ctx

#: A request hook (``options.hooks.before``/``after``): ``async (ctx) -> AuthResponse | None``.
RequestHook = Callable[[Ctx], Awaitable[AuthResponse | None]]

logger = logging.getLogger("better_auth")


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
        trusted_origins: list[str] | Callable[[Any], Any] | None = None,
        plugins: list[Plugin] | None = None,
        hooks: Mapping[str, RequestHook] | None = None,
        database_hooks: dict[str, Any] | None = None,
        secondary_storage: SecondaryStorage | None = None,
        http_client: httpx.AsyncClient | None = None,
        cookie_prefix: str = "better-auth",
        use_secure_cookies: bool | None = None,
        skip_state_cookie_check: bool = False,
        on_api_error: OnAPIError | None = None,
        disabled_paths: list[str] | None = None,
        skip_trailing_slashes: bool = False,
        disable_csrf_check: bool | None = None,
        disable_origin_check: bool | list[str] = False,
        cross_sub_domain_cookies: CrossSubDomainCookies | None = None,
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
        #: list of origin patterns (wildcards allowed) or a callable(request) -> list
        if callable(trusted_origins):
            self._trusted_origins: Any = trusted_origins
        else:
            self._trusted_origins = [o.rstrip("/") for o in trusted_origins or []]
        self.on_api_error = on_api_error or OnAPIError()
        self.disabled_paths = {"/" + p.strip("/") for p in disabled_paths or []}
        self.skip_trailing_slashes = skip_trailing_slashes
        self._disable_csrf_check_set = disable_csrf_check is not None
        self.disable_csrf_check = bool(disable_csrf_check)
        self.disable_origin_check = disable_origin_check
        self.cross_sub_domain_cookies = cross_sub_domain_cookies or CrossSubDomainCookies()
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
        # DB-backed rate limiting needs the `rateLimit` table in the adapter's schema.
        if self.rate_limit.storage == "database":
            self.schema = merge_schema(self.schema, {"rateLimit": rate_limit_model()})
        # Input schema per model: additionalFields + plugin fields only (NOT core columns),
        # so generic write routes (e.g. /update-session) only accept configured fields.
        self._input_fields: dict[str, dict[str, Field]] = {
            model: merge_schema({model: additional[model]}, *(p.schema for p in self.plugins)).get(
                model, {}
            )
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
        self._rate_limiter = RateLimiter(self)
        # Plugin routes FIRST so a plugin can shadow a same-(method,path) core route
        # (``_match`` returns the first match; e.g. custom-session overrides GET
        # /get-session). Unrelated core routes are unaffected.
        self._routes: list[tuple[str, tuple[str, ...], Any]] = []
        for method, path, handler in [
            *(route for plugin in self.plugins for route in plugin.routes()),
            *ROUTES,
        ]:
            self._routes.append((method, tuple(path.strip("/").split("/")), handler))

        #: async ``(password, path) -> None`` checks run before every password hash
        #: (may raise APIError to reject, e.g. haveibeenpwned). Plugins append in init().
        self.password_checks: list[Callable[[str, str], Awaitable[None]]] = []

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

    @property
    def cookie_domain(self) -> str | None:
        """Cookie ``Domain`` when cross-subdomain cookies are enabled, else None."""
        cfg = self.cross_sub_domain_cookies
        if not cfg.enabled:
            return None
        return cfg.domain or (urlsplit(self.base_url).hostname or None)

    def _sync_trusted_origins(self) -> list[str]:
        """Base origin + static configured origins (callable form is resolved async in
        the router middleware; the sync redirect-guard uses the static list only)."""
        origins: list[str] = []
        parts = urlsplit(self.base_url)
        if parts.scheme and parts.netloc:
            origins.append(f"{parts.scheme}://{parts.netloc}")
        if not callable(self._trusted_origins):
            origins.extend(self._trusted_origins)
        return origins

    def is_trusted_url(self, url: str) -> bool:
        """Relative paths and URLs matching a base/trusted origin (wildcards honoured)."""
        return any(
            matches_origin_pattern(url, o, allow_relative=True)
            for o in self._sync_trusted_origins()
        )

    def ensure_trusted_url(self, url: str) -> None:
        if not self.is_trusted_url(url):
            raise APIError(403, "INVALID_CALLBACK_URL", "Callback URL is not trusted")

    async def load_session(self, request: AuthRequest) -> dict[str, Any] | None:
        """``{"session": ..., "user": ...}`` for the request, or None. Used by integrations."""
        result, _cookies = await _get_session(self, request)
        return result

    async def hash_password_checked(self, password: str, path: str) -> str:
        """Run every registered ``password_checks`` (may raise APIError to reject a
        weak/compromised password), then hash. Every core hash call site routes through
        this one seam so a plugin (e.g. haveibeenpwned) can gate all of them by
        appending a check in ``init``."""
        for check in self.password_checks:
            await check(password, path)
        return hash_password(password)

    # --- dispatch ---------------------------------------------------------------------

    async def handle(self, request: AuthRequest) -> AuthResponse:
        try:
            return await self._dispatch(request)
        except APIError as error:
            return await self._on_api_error(request, error, error.status, error.code, error.message)
        except Exception as exc:
            logger.exception("better-auth error handling %s %s", request.method, request.path)
            return await self._on_api_error(
                request, exc, 500, "INTERNAL_SERVER_ERROR", "Internal Server Error"
            )

    async def _on_api_error(
        self, request: AuthRequest, error: Exception, status: int, code: str, message: str
    ) -> AuthResponse:
        """options.onAPIError: run the on_error hook, optionally re-raise (throw)."""
        cfg = self.on_api_error
        if cfg.on_error is not None:
            try:
                await cfg.on_error(error, request)
            except Exception:
                logger.exception("onAPIError.on_error hook raised")
        if cfg.throw:
            raise error
        if status == 500:
            return AuthResponse(status=500, body={"code": code, "message": message})
        return AuthResponse(status=status, body={"code": code, "message": message})

    async def _dispatch(self, request: AuthRequest) -> AuthResponse:
        # A trailing slash on a non-root path is significant unless skipTrailingSlashes
        # (TS default false: `/ok/` != `/ok`). The normalized path (trailing stripped) is
        # what disabledPaths/rate-limit/origin key on, mirroring TS normalizePathname.
        had_trailing_slash = len(request.path) > 1 and request.path.rstrip().endswith("/")
        request.path = "/" + request.path.strip("/")

        # --- onRequest phase: disabledPaths -> rate limit -> plugin.on_request -----------
        if request.path in self.disabled_paths:
            return AuthResponse(status=404, body={"message": "Not Found"})

        retry_after = await self._rate_limiter.check(request)
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

        await check_origin(self, ctx)

        match = self._match(request.method, request.path)
        if match is None or (had_trailing_slash and not self.skip_trailing_slashes):
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
