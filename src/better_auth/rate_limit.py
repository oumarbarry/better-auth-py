"""Rate limiter — the TS window algorithm (``api/rate-limiter/index.ts``) over the
storage backends in ``adapters/rate_limit.py``.

A counter row is ``{count, lastRequest}`` where ``lastRequest`` is epoch ms. The window
is rolling: a key resets to ``count=1`` once ``window`` seconds have elapsed since its
last request; within the window it increments until ``max`` and then blocks with a
``X-Retry-After`` computed from ``lastRequest``.

Rule precedence (first match wins, later stages override): default ``{window, max}`` →
special rules (sign-in/up etc.) → plugin ``rate_limit[]`` rules → ``custom_rules``
(exact or ``*`` wildcard; a callable or ``False`` to skip).

ponytail: uses the read-decide-write path (TS ``legacyConsume``) uniformly for all
backends rather than per-backend atomic ``consume`` — correct for a single process;
add an atomic primitive if a multi-worker deployment needs strict enforcement.

The client IP is resolved via ``ip.get_request_ip`` from the configured
``advanced.ipAddress`` headers (TS ``getIp``); ``disable_ip_tracking`` skips per-IP
limiting entirely.
"""

from __future__ import annotations

import fnmatch
import inspect
import math
import os
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

from .adapters.rate_limit import (
    DatabaseRateLimitStorage,
    MemoryRateLimitStorage,
    SecondaryRateLimitStorage,
)
from .ip import get_request_ip

if TYPE_CHECKING:
    from .auth import BetterAuth
    from .types import AuthRequest

#: shared per-path bucket when no client IP can be resolved — fail closed (still limit)
#: rather than letting a client drop the IP header to bypass the limit.
NO_TRUSTED_IP = "no-trusted-ip"

# better-auth default special rules: (path matcher, (window seconds, max requests)).
_SPECIAL_RULES: list[tuple[Callable[[str], bool], tuple[int, int]]] = [
    (
        lambda p: p.startswith(("/sign-in", "/sign-up", "/change-password", "/change-email")),
        (10, 3),
    ),
    (
        lambda p: (
            p in ("/request-password-reset", "/send-verification-email")
            or p.startswith("/forget-password")
            or p in ("/email-otp/send-verification-otp", "/email-otp/request-password-reset")
        ),
        (60, 3),
    ),
]


def _retry_after(last_request: int, window: int, now_ms: int) -> int:
    return math.ceil((last_request + window * 1000 - now_ms) / 1000)


def decide_consume(
    data: dict[str, Any] | None, window: int, maximum: int, now_ms: int
) -> tuple[dict[str, Any], bool, bool, int | None]:
    """One rolling-window step (TS ``decideConsume``).

    Returns ``(next_row, is_update, allowed, retry_after)``. ``next_row`` carries the
    new ``{count, lastRequest}``; ``is_update`` is False only when opening a fresh key.
    """
    window_ms = window * 1000
    if not data:
        return {"count": 1, "lastRequest": now_ms}, False, True, None
    if now_ms - data["lastRequest"] > window_ms:
        return {"count": 1, "lastRequest": now_ms}, True, True, None
    if data["count"] >= maximum:
        return data, True, False, _retry_after(data["lastRequest"], window, now_ms)
    return {"count": data["count"] + 1, "lastRequest": now_ms}, True, True, None


class RateLimiter:
    """Per-request atomic-ish rate-limit check keyed on client IP + normalized path."""

    def __init__(self, auth: BetterAuth) -> None:
        self.auth = auth
        self._memory: MemoryRateLimitStorage | None = None

    def _is_enabled(self) -> bool:
        enabled = self.auth.rate_limit.enabled
        if enabled is not None:
            return enabled
        # None → production-only default (mirrors TS NODE_ENV/BETTER_AUTH_ENV === production)
        env = os.environ.get("BETTER_AUTH_ENV") or os.environ.get("NODE_ENV")
        return env == "production"

    def _storage(self, window: int) -> Any:
        cfg = self.auth.rate_limit
        if cfg.custom_storage is not None:
            return cfg.custom_storage
        if cfg.storage == "database":
            return DatabaseRateLimitStorage(self.auth.adapter)
        if cfg.storage == "secondary-storage":
            if self.auth.secondary_storage is None:
                raise ValueError(
                    "rate_limit.storage='secondary-storage' requires a secondary_storage backend"
                )
            return SecondaryRateLimitStorage(self.auth.secondary_storage, window=window)
        # memory (default): one shared store; TTL follows the current rule's window so a
        # key survives at least its whole window before eviction (else the count resets early).
        if self._memory is None:
            self._memory = MemoryRateLimitStorage(window=window)
        self._memory._window = window  # ponytail: rule window per set; single shared store
        return self._memory

    async def _resolve(self, request: AuthRequest) -> tuple[str, int, int] | None:
        """``(key, window, max)`` for this request, or None to skip rate limiting."""
        cfg = self.auth.rate_limit
        path = request.path
        window, maximum = cfg.window, cfg.max

        for matcher, (w, m) in _SPECIAL_RULES:
            if matcher(path):
                window, maximum = w, m
                break

        for plugin in self.auth.plugins:
            matched = next((r for r in plugin.rate_limit() if r.path_matcher(path)), None)
            if matched is not None:
                window, maximum = matched.window, matched.max
                break

        custom = await self._resolve_custom(request, path, window, maximum)
        if custom is False:  # rule (or callable) was False -> skip rate limiting entirely
            return None
        if isinstance(custom, tuple):
            window, maximum = custom

        ip = get_request_ip(request, self.auth.ip_address)
        if ip is None and self.auth.ip_address.disable_ip_tracking:
            # IP tracking explicitly disabled; per-IP rate limiting does not apply.
            return None
        # Fail closed when no IP resolves: a shared per-path bucket still enforces the
        # limit rather than letting a client drop the header to bypass it.
        return f"{ip or NO_TRUSTED_IP}|{path}", window, maximum

    async def _resolve_custom(
        self, request: AuthRequest, path: str, window: int, maximum: int
    ) -> tuple[int, int] | bool | None:
        """Custom-rule override for ``path``: a ``(window, max)`` tuple, ``False`` (skip —
        the rule was ``False`` or a callable returned it), or None (no matching rule)."""
        rules = self.auth.rate_limit.custom_rules
        match = next(
            (p for p in rules if (fnmatch.fnmatchcase(path, p) if "*" in p else p == path)),
            None,
        )
        if match is None:
            return None
        rule = rules[match]
        if callable(rule):
            result = rule(request, {"window": window, "max": maximum})
            if inspect.isawaitable(result):
                result = await result
            rule = result
        if rule is False:
            return False
        if not rule:
            return None
        if isinstance(rule, dict):
            return rule["window"], rule["max"]
        return rule[0], rule[1]  # (window, max) tuple

    async def check(self, request: AuthRequest) -> int | None:
        """Seconds to wait when the request is rate-limited, else None."""
        if not self._is_enabled():
            return None
        config = await self._resolve(request)
        if config is None:
            return None
        key, window, maximum = config

        storage = self._storage(window)
        data = await storage.get(key)
        now_ms = int(time.time() * 1000)
        next_row, is_update, allowed, retry_after = decide_consume(data, window, maximum, now_ms)
        if not allowed:
            return retry_after if retry_after is not None else window
        await storage.set(key, next_row, is_update)
        return None
