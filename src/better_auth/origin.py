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
from urllib.parse import parse_qsl, unquote, urlsplit

from .types import APIError, Ctx

if TYPE_CHECKING:
    from .auth import BetterAuth

# trusted-origins.ts:4-6 (v1.7.6)
_CONTROL_CHARACTER = re.compile(r"[\x00-\x1f\x7f-\x9f]")
_ENCODED_PATH_SEPARATOR = re.compile(r"%2[fF]|%5[cC]")
_MALFORMED_PERCENT = re.compile(r"%(?![0-9a-fA-F]{2})")

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


def _normalize_path(path: str) -> str:
    """trusted-origins.ts:14-30: percent-decode, then resolve ``.``/``..`` segments."""
    decoded = path
    if not _MALFORMED_PERCENT.search(path):  # decodeURIComponent throws on these
        try:
            decoded = unquote(path, errors="strict")
        except UnicodeDecodeError:
            decoded = path
    segments: list[str] = []
    for segment in decoded.split("/"):
        if segment == "..":
            if segments:
                segments.pop()
        elif segment not in (".", ""):
            segments.append(segment)
    return "/" + "/".join(segments) if segments else ""


def _parse_custom_scheme_origin(value: str) -> tuple[str, str, str] | None:
    """``(scheme, authority, path)`` by plain string ops (trusted-origins.ts:45-73)."""
    if _CONTROL_CHARACTER.search(value):
        return None
    scheme_end = value.find(":")
    if scheme_end <= 0:
        return None
    scheme = value[:scheme_end].lower()
    rest = value[scheme_end + 1 :]
    authority = ""
    if rest.startswith("//"):
        rest = rest[2:]
        end = re.search(r"[/?#]", rest)
        authority, rest = (rest, "") if end is None else (rest[: end.start()], rest[end.start() :])
    path_end = re.search(r"[?#]", rest)
    path = _normalize_path(rest if path_end is None else rest[: path_end.start()])
    return scheme, authority.lower(), path


def _is_safe_relative_url(value: str) -> bool:
    """trusted-origins.ts:80-105. The trailing ``new URL(value, origin).origin`` recheck
    can only fail for ``//`` or ``\\`` prefixes and C0 controls, all rejected here first,
    so a value that reaches the end is a same-origin path."""
    if (
        not value.startswith("/")
        or value.startswith("//")
        or "\\" in value
        or _CONTROL_CHARACTER.search(value)
    ):
        return False
    path_end = re.search(r"[?#]", value)
    path = value if path_end is None else value[: path_end.start()]
    return not _ENCODED_PATH_SEPARATOR.search(path)


def matches_origin_pattern(url: str, pattern: str, allow_relative: bool = False) -> bool:
    """Whether ``url`` matches an origin ``pattern`` (trusted-origins.ts:116-165, v1.7.6)."""
    if url.startswith("/"):
        return allow_relative and _is_safe_relative_url(url)

    if "*" in pattern or "?" in pattern:
        if "://" in pattern:
            return bool(_wildcard_to_regex(pattern).match(_get_origin(url) or url))
        host = _get_host(url)
        return bool(host and _wildcard_to_regex(pattern).match(host))

    protocol = _get_protocol(url)
    if protocol in ("http:", "https:") or protocol is None:
        return pattern == _get_origin(url)
    # Custom schemes: same scheme, the exact authority when the pattern pins one, and
    # the pattern path or a path beneath it (trusted-origins.ts:143-164).
    parsed = _parse_custom_scheme_origin(url)
    parsed_pattern = _parse_custom_scheme_origin(pattern)
    if parsed is None or parsed_pattern is None or parsed[0] != parsed_pattern[0]:
        return False
    if parsed_pattern[1] and parsed[1] != parsed_pattern[1]:
        return False
    if not parsed_pattern[2]:
        return True
    return parsed[2] == parsed_pattern[2] or parsed[2].startswith(parsed_pattern[2] + "/")


async def resolve_trusted_origins(auth: BetterAuth, request) -> list[str]:
    """Base-URL origin + configured origins (+ callable form, which may be async)."""
    # helpers.ts:108-133 — a dynamic baseURL contributes every allowed host (wildcards
    # included, matched by matches_origin_pattern) plus the fallback origin, in place of
    # the single resolved origin.
    origins: list[str] = list(auth._dynamic_origins)
    if not origins:
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


def _request_origin(auth: BetterAuth, request) -> str | None:
    """The origin the request was sent to (TS ``getBaseURL(undefined, basePath, request,
    false, trustedProxyHeaders)`` then ``getOrigin``, utils/url.ts:142-188): trusted
    ``x-forwarded-host`` + ``x-forwarded-proto`` first, else the request URL."""
    from .base_url import validate_proxy_header

    headers = request.headers
    host = headers.get("x-forwarded-host")
    proto = headers.get("x-forwarded-proto")
    if (
        host
        and proto
        and auth.trusted_proxy_headers
        and validate_proxy_header(proto, "proto")
        and validate_proxy_header(host, "host")
    ):
        return _get_origin(f"{proto}://{host}")
    return _get_origin(request.url) if request.url else None


async def _validate_origin(auth: BetterAuth, ctx: Ctx, force: bool = False) -> None:
    request = ctx.request
    headers = request.headers
    origin = headers.get("origin")
    origin_header = origin or headers.get("referer") or ""
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
    # origin-check.ts:253-269 (c8dcfa57e): a same-origin form sent with `no-referrer`
    # carries `Origin: null`; Fetch Metadata lets the request target stand in for it.
    inferred = None
    if origin == "null" and headers.get("sec-fetch-site") == "same-origin":
        inferred = _request_origin(auth, request)
    origin_to_validate = inferred or origin_header
    if not origin_to_validate or origin_to_validate == "null":
        raise APIError(403, "MISSING_OR_NULL_ORIGIN", "Missing or null Origin")
    if not await is_trusted_origin(auth, request, origin_to_validate, allow_relative=False):
        raise APIError(403, "INVALID_ORIGIN", "Invalid origin")


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
                "Cross-site navigation login blocked. This request appears to be a CSRF attack.",
            )
        return await _validate_origin(auth, ctx, force=True)

    # No Fetch Metadata: a present Origin/Referer is still evidence of cross-site intent.
    if headers.get("origin") or headers.get("referer"):
        return await _validate_origin(auth, ctx, force=True)


#: Public seam for endpoints that force form-CSRF validation themselves (TS
#: ``formCsrfMiddleware``, origin-check.ts:296) — e.g. plugins_ext/email_otp.py.
validate_form_csrf = _validate_form_csrf


def _should_skip_origin_check(auth: BetterAuth, path: str) -> bool:
    skip = auth.disable_origin_check
    if skip is True:
        return True
    if isinstance(skip, (list, tuple)):
        return any(path == p.rstrip("/") or path.startswith(p.rstrip("/") + "/") for p in skip)
    return False


def _body_for_origin_check(ctx: Ctx) -> dict[str, object]:
    """TS parses the body per content-type, so a form-encoded POST (e.g. an OAuth
    ``response_mode=form_post`` callback) simply has no ``callbackURL`` — it must not
    die with INVALID_BODY here. Parse forms; keep strict JSON errors for JSON."""
    request = ctx.request
    if not request.body:
        return {}
    content_type = (request.headers.get("content-type") or "").split(";")[0].strip().lower()
    if content_type == "application/x-www-form-urlencoded":
        return dict(parse_qsl(request.body.decode("utf-8", "replace")))
    return ctx.body()


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

    body = _body_for_origin_check(ctx)
    query = request.query
    await _validate_url(
        auth, request, body.get("callbackURL") or query.get("callbackURL"), "callbackURL"
    )
    await _validate_url(auth, request, body.get("redirectTo"), "redirectURL")
    await _validate_url(auth, request, body.get("errorCallbackURL"), "errorCallbackURL")
    await _validate_url(auth, request, body.get("newUserCallbackURL"), "newUserCallbackURL")
