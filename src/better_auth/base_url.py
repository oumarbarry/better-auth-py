"""Dynamic ``base_url`` resolution — a port of better-auth's ``utils/url.ts``
(``getHostFromSource``/``getProtocolFromSource``/``matchesHostPattern``/
``resolveDynamicBaseURL``) plus the ``allowedHosts`` → trusted-origins expansion
from ``context/helpers.ts:108-133``.

TS clones the whole ``AuthContext`` per request (``resolveRequestContext``). The port
instead binds the resolved origin to a :class:`~contextvars.ContextVar` for the duration
of the request (:func:`bind_base_url`), which ``BetterAuth.base_url`` reads — every
existing ``auth.base_url`` call site becomes per-request without changing, and each
asyncio task gets its own copy of the context.
"""

from __future__ import annotations

import re
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar

from .config import DynamicBaseURL
from .origin import _get_origin, _wildcard_to_regex

#: The origin resolved for the in-flight request (``None`` outside one).
_CURRENT_BASE_URL: ContextVar[str | None] = ContextVar("better_auth_base_url", default=None)

# validateProxyHeader host denylist (url.ts:99-108) — checked before the shape allowlist.
_SUSPICIOUS_HOST = re.compile(r"\.\.|\0|\s|^\.|[<>'\"]|javascript:|file:|data:", re.IGNORECASE)
# ...then the header must look like a hostname, IPv4, bracketed IPv6 or localhost (url.ts:114-129).
_HOST_SHAPE = re.compile(
    r"^(?:"
    r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*"
    r"|(?:\d{1,3}\.){3}\d{1,3}"
    r"|\[[0-9a-fA-F:]+\]"
    r"|localhost"
    r")(?::[0-9]{1,5})?$",
    re.IGNORECASE,
)


def validate_proxy_header(header: str, kind: str) -> bool:
    """Whether a ``host``/``proto`` header value is safe to trust (url.ts:91-140)."""
    if not header or not header.strip():
        return False
    if kind == "proto":
        return header in ("http", "https")
    if kind == "host":
        return not _SUSPICIOUS_HOST.search(header) and bool(_HOST_SHAPE.match(header))
    return False


def _is_loopback_for_dev_scheme(host: str) -> bool:
    """url.ts:19-30 — port/brackets stripped, then the loopback names."""
    hostname = re.sub(r":\d+$", "", host).strip("[]").lower()
    return (
        hostname == "localhost"
        or hostname.endswith(".localhost")
        or hostname == "::1"
        or hostname.startswith("127.")
    )


def get_host_from_source(headers: Mapping[str, str], trusted_proxy_headers: bool) -> str | None:
    """``x-forwarded-host`` (only when trusted) then ``host``, each validated (url.ts:273-300).

    ponytail: TS also falls back to the request URL's host; ``AuthRequest`` carries no
    absolute URL, so headers are the only source here.
    """
    if trusted_proxy_headers:
        forwarded = headers.get("x-forwarded-host")
        if forwarded and validate_proxy_header(forwarded, "host"):
            return forwarded
    host = headers.get("host")
    if host and validate_proxy_header(host, "host"):
        return host
    return None


def get_protocol_from_source(
    headers: Mapping[str, str],
    config_protocol: str | None,
    trusted_proxy_headers: bool,
) -> str:
    """Config protocol → trusted ``x-forwarded-proto`` → loopback ``http`` → ``https``
    (url.ts:307-345)."""
    if config_protocol in ("http", "https"):
        return config_protocol
    if trusted_proxy_headers:
        forwarded = headers.get("x-forwarded-proto")
        if forwarded and validate_proxy_header(forwarded, "proto"):
            return forwarded
    host = get_host_from_source(headers, trusted_proxy_headers)
    if host and _is_loopback_for_dev_scheme(host):
        return "http"
    return "https"


def _normalize_host(value: str) -> str:
    return re.sub(r"^https?://", "", value).split("/")[0].lower()


def matches_host_pattern(host: str, pattern: str) -> bool:
    """Host vs. allowed-host pattern (url.ts:361-386). Wildcards reuse the
    ``trustedOrigins`` matcher, so ``*`` crosses dots (``*.vercel.app`` matches
    ``a.b.vercel.app``)."""
    if not host or not pattern:
        return False
    normalized_host = _normalize_host(host)
    normalized_pattern = _normalize_host(pattern)
    if "*" in normalized_pattern or "?" in normalized_pattern:
        return bool(_wildcard_to_regex(normalized_pattern).match(normalized_host))
    return normalized_host == normalized_pattern


def resolve_dynamic_base_url(
    config: DynamicBaseURL, headers: Mapping[str, str], trusted_proxy_headers: bool
) -> str:
    """The origin for this request (url.ts:398-438).

    ponytail: TS appends ``basePath`` here; the port keeps ``base_url`` an origin and
    composes ``base_url + base_path`` at each call site, so nothing is appended.
    """
    host = get_host_from_source(headers, trusted_proxy_headers)
    if not host:
        if config.fallback:
            return config.fallback.rstrip("/")
        raise ValueError(
            "Could not determine host from request headers. "
            "Please provide a fallback URL in your baseURL config."
        )
    if any(matches_host_pattern(host, pattern) for pattern in config.allowed_hosts):
        protocol = get_protocol_from_source(headers, config.protocol, trusted_proxy_headers)
        return f"{protocol}://{host}"
    if config.fallback:
        return config.fallback.rstrip("/")
    raise ValueError(
        f'Host "{host}" is not in the allowed hosts list. '
        f"Allowed hosts: {', '.join(config.allowed_hosts)}. "
        "Add this host to your allowedHosts config or provide a fallback URL."
    )


def expand_trusted_origins(config: DynamicBaseURL) -> list[str]:
    """Every allowed host as an origin, plus the fallback's (helpers.ts:108-133)."""
    origins: list[str] = []
    protocol = config.protocol
    for host in config.allowed_hosts:
        if "://" in host:
            origins.append(host)
            continue
        if protocol in (None, "https", "auto"):
            origins.append(f"https://{host}")
        if protocol in ("http", "auto") or _is_loopback_for_dev_scheme(host):
            origins.append(f"http://{host}")
    if config.fallback:
        fallback_origin = _get_origin(config.fallback)
        if fallback_origin:
            origins.append(fallback_origin)
    return origins


@contextmanager
def bind_base_url(
    config: DynamicBaseURL | None, headers: Mapping[str, str], trusted_proxy_headers: bool
) -> Iterator[None]:
    """Bind the request-resolved origin for the duration of the block (no-op for a
    static ``base_url``). Mirrors TS's per-request ``AuthContext`` clone."""
    if config is None:
        yield
        return
    token = _CURRENT_BASE_URL.set(resolve_dynamic_base_url(config, headers, trusted_proxy_headers))
    try:
        yield
    finally:
        _CURRENT_BASE_URL.reset(token)
