"""CSRF / trusted-origin checking — a faithful port of better-auth's
``api/middlewares/origin-check.ts`` + ``auth/trusted-origins.ts``.

Covers: ``Origin``→``Referer`` fallback, ``MISSING_OR_NULL_ORIGIN`` when cookies are
present, Fetch-Metadata ``CROSS_SITE_NAVIGATION_LOGIN_BLOCKED`` on first-login forms,
wildcard (``*.domain.com``) + callable ``trusted_origins``, and per-URL validation of
``callbackURL``/``redirectTo``/``errorCallbackURL``/``newUserCallbackURL`` with the exact
TS error codes.
"""

from __future__ import annotations

import inspect
import re
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from .types import APIError, Ctx

if TYPE_CHECKING:
    from .auth import BetterAuth

# matchesOriginPattern relative-path allowlist (trusted-origins.ts:22).
_RELATIVE_RE = re.compile(r"^/(?!/|\\|%2f|%5c)[\w\-.+/@]*(?:\?[\w\-.+/=&%@]*)?$", re.IGNORECASE)

_FORM_CSRF_PREFIXES = ("/sign-in", "/sign-up")


def _get_origin(url: str) -> str | None:
    """``scheme://host[:port]`` for http(s) URLs, else None (non-web schemes → browser 'null')."""
    parts = urlsplit(url)
    if parts.scheme in ("http", "https") and parts.netloc:
        return f"{parts.scheme}://{parts.netloc}"
    return None


def _get_protocol(url: str) -> str | None:
    parts = urlsplit(url)
    return f"{parts.scheme}:" if parts.scheme else None


def _get_host(url: str) -> str | None:
    parts = urlsplit(url)
    return parts.netloc or None


def _wildcard_to_regex(pattern: str) -> re.Pattern[str]:
    """Glob → regex, mirroring wildcard-match with the default ``/`` separator:
    ``**`` spans separators, ``*`` matches a run of non-separator chars, ``?`` one."""
    out = ["^"]
    i = 0
    while i < len(pattern):
        char = pattern[i]
        if char == "*":
            if i + 1 < len(pattern) and pattern[i + 1] == "*":
                out.append(".*")
                i += 2
                continue
            out.append(r"[^/\\]*")
        elif char == "?":
            out.append(r"[^/\\]")
        else:
            out.append(re.escape(char))
        i += 1
    out.append("$")
    return re.compile("".join(out))


def matches_origin_pattern(url: str, pattern: str, allow_relative: bool = False) -> bool:
    """Whether ``url`` matches an origin ``pattern`` (trusted-origins.ts)."""
    if url.startswith("/"):
        return bool(allow_relative and _RELATIVE_RE.match(url))

    if "*" in pattern or "?" in pattern:
        if "://" in pattern:
            return bool(_wildcard_to_regex(pattern).match(_get_origin(url) or url))
        host = _get_host(url)
        return bool(host and _wildcard_to_regex(pattern).match(host))

    protocol = _get_protocol(url)
    if protocol in ("http:", "https:") or protocol is None:
        return pattern == _get_origin(url)
    return url.startswith(pattern)


async def resolve_trusted_origins(auth: BetterAuth, request) -> list[str]:
    """Base-URL origin + configured origins (+ callable form, which may be async)."""
    origins: list[str] = []
    base = _get_origin(auth.base_url)
    if base:
        origins.append(base)
    configured = auth._trusted_origins
    if callable(configured):
        result = configured(request)
        if inspect.isawaitable(result):
            result = await result
        origins.extend(o for o in (result or []) if o)
    else:
        origins.extend(configured)
    return origins


async def is_trusted_origin(auth: BetterAuth, request, url: str, *, allow_relative: bool) -> bool:
    origins = await resolve_trusted_origins(auth, request)
    return any(matches_origin_pattern(url, o, allow_relative) for o in origins)


_URL_ERROR_CODES = {
    "origin": "INVALID_ORIGIN",
    "callbackURL": "INVALID_CALLBACK_URL",
    "redirectURL": "INVALID_REDIRECT_URL",
    "errorCallbackURL": "INVALID_ERROR_CALLBACK_URL",
    "newUserCallbackURL": "INVALID_NEW_USER_CALLBACK_URL",
}


async def _validate_url(auth: BetterAuth, request, url, label: str) -> None:
    if not url:
        return
    # A JSON array/object body yields a non-string here — reject as a controlled 400.
    if not isinstance(url, str):
        raise APIError(400, "BAD_REQUEST", f"Invalid {label}: expected a string")
    if not await is_trusted_origin(auth, request, url, allow_relative=label != "origin"):
        raise APIError(403, _URL_ERROR_CODES[label], f"Invalid {label}")


async def _validate_origin(auth: BetterAuth, ctx: Ctx, force: bool = False) -> None:
    request = ctx.request
    headers = request.headers
    origin_header = headers.get("origin") or headers.get("referer") or ""
    use_cookies = "cookie" in headers

    if auth.disable_csrf_check:
        return
    # backward-compat: disableOriginCheck === True (ONLY — never a path array) used to
    # also disable CSRF. A list means "skip these paths", not "disable CSRF globally".
    if auth.disable_origin_check is True and not auth._disable_csrf_check_set:
        return
    # per-path skip (True or a matching path in the list) — mirrors TS shouldSkipOriginCheck
    if _should_skip_origin_check(auth, request.path):
        return
    if not (force or use_cookies):
        return
    if not origin_header or origin_header == "null":
        raise APIError(403, "MISSING_OR_NULL_ORIGIN", "Missing or null origin")
    if not await is_trusted_origin(auth, request, origin_header, allow_relative=False):
        raise APIError(403, "INVALID_ORIGIN", "Origin not trusted")


async def _validate_form_csrf(auth: BetterAuth, ctx: Ctx) -> None:
    """Fetch-Metadata first-login protection (origin-check.ts:296)."""
    if auth.disable_csrf_check:
        return
    # backward-compat couples only to disableOriginCheck === True, never a path array.
    if auth.disable_origin_check is True and not auth._disable_csrf_check_set:
        return
    headers = ctx.request.headers
    if "cookie" in headers:
        return await _validate_origin(auth, ctx)

    site = (headers.get("sec-fetch-site") or "").strip()
    mode = (headers.get("sec-fetch-mode") or "").strip()
    dest = (headers.get("sec-fetch-dest") or "").strip()
    if site or mode or dest:
        if site == "cross-site" and mode == "navigate":
            raise APIError(
                403,
                "CROSS_SITE_NAVIGATION_LOGIN_BLOCKED",
                "Cross-site navigation login blocked",
            )
        return await _validate_origin(auth, ctx, force=True)

    # No Fetch Metadata: a present Origin/Referer is still evidence of cross-site intent.
    if headers.get("origin") or headers.get("referer"):
        return await _validate_origin(auth, ctx, force=True)


def _should_skip_origin_check(auth: BetterAuth, path: str) -> bool:
    skip = auth.disable_origin_check
    if skip is True:
        return True
    if isinstance(skip, (list, tuple)):
        return any(path == p.rstrip("/") or path.startswith(p.rstrip("/") + "/") for p in skip)
    return False


async def check_origin(auth: BetterAuth, ctx: Ctx) -> None:
    """Router ``/**`` origin/CSRF check for state-changing requests (origin-check.ts:66)."""
    request = ctx.request
    if request.method in ("GET", "OPTIONS", "HEAD"):
        return

    await _validate_origin(auth, ctx)

    # form-CSRF (Fetch Metadata) for first-login endpoints
    if request.path.startswith(_FORM_CSRF_PREFIXES):
        await _validate_form_csrf(auth, ctx)

    if _should_skip_origin_check(auth, request.path):
        return

    body = ctx.body() if request.body else {}
    query = request.query
    await _validate_url(
        auth, request, body.get("callbackURL") or query.get("callbackURL"), "callbackURL"
    )
    await _validate_url(auth, request, body.get("redirectTo"), "redirectURL")
    await _validate_url(auth, request, body.get("errorCallbackURL"), "errorCallbackURL")
    await _validate_url(auth, request, body.get("newUserCallbackURL"), "newUserCallbackURL")
