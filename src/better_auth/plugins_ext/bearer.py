"""bearer — accept ``Authorization: Bearer <token>`` and expose the session token via
``set-auth-token`` on responses.

Port of TS ``packages/better-auth/src/plugins/bearer/index.ts``.

Request-side raw/signed ``Authorization: Bearer`` reading already lives in core
(``session.read_token``, ``session.py:60``) — it accepts either the signed cookie
value or the raw session token directly. This plugin adds the two things core does
not do: (a) the response-side ``set-auth-token`` header + Access-Control-Expose-Headers
merge (TS ``hooks.after``), and (b) ``require_signature`` — core has no gate against a
raw/unsigned token, so the before-hook must sanitize the request before core sees it
(TS ``hooks.before``).
"""

from __future__ import annotations

from ..crypto import sign_value, unsign_value
from ..plugins import HookSet, Plugin, PluginHook, add_expose_headers
from ..session import cookie_name
from ..types import AuthResponse, Ctx

_BEARER_SCHEME = "bearer "


def _has_authorization(ctx: Ctx) -> bool:
    return bool(ctx.request.headers.get("authorization"))


def _session_cookie_value(response: AuthResponse, name: str) -> str | None:
    """The session cookie's value from ``response``'s Set-Cookie headers, or None if
    absent or its Max-Age is 0 (a cleared cookie, e.g. sign-out — TS checks
    ``sessionCookie["max-age"] === 0``)."""
    for key, raw in response.headers:
        if key.lower() != "set-cookie":
            continue
        cookie_part, *attrs = raw.split(";")
        cname, _, cvalue = cookie_part.partition("=")
        if cname.strip() != name:
            continue
        for attr in attrs:
            attr_name, _, attr_value = attr.strip().partition("=")
            if attr_name.strip().lower() == "max-age" and attr_value.strip() == "0":
                return None
        return cvalue
    return None


class BearerPlugin(Plugin):
    id = "bearer"

    def __init__(self, require_signature: bool = False) -> None:
        self.require_signature = require_signature

    def hooks(self) -> HookSet:
        return HookSet(
            before=[PluginHook(matcher=_has_authorization, handler=self._before)],
            after=[PluginHook(matcher=lambda ctx: True, handler=self._after)],
        )

    async def _before(self, ctx: Ctx) -> None:
        """Mirrors TS's exact decision tree: a ``.``-containing token is already a
        signed value; otherwise (unless ``require_signature``) sign it. Verify the
        HMAC either way — an invalid signature falls through unauthenticated. On
        success, inject the (re-canonicalized) signed value as the session cookie on
        the request so downstream session loading finds it; a pre-existing valid
        cookie is untouched either way (cookie lookup wins over the header in core's
        ``read_token``, so an invalid header never displaces a valid cookie)."""
        authorization = ctx.request.headers.get("authorization", "")
        if authorization[: len(_BEARER_SCHEME)].lower() != _BEARER_SCHEME:
            return None
        token = authorization[len(_BEARER_SCHEME) :].strip()
        if not token:
            return None

        if "." in token:
            signed = token
        elif self.require_signature:
            # core's read_token() falls back to treating a bearer value as the raw
            # session token itself when it isn't a validly-signed one (session.py:73);
            # require_signature must prevent that fallback from authenticating, so
            # strip the header rather than merely no-op-ing here.
            ctx.request.headers.pop("authorization", None)
            return None
        else:
            signed = sign_value(ctx.auth.secret, token)

        raw = unsign_value(ctx.auth.secret, signed)
        if raw is None:
            return None  # invalid signature -> fall through unauthenticated

        # Re-sign the verified value so the injected cookie is always in this port's
        # canonical (percent-encoded) form, regardless of how the client encoded the
        # incoming token (TS: `token.includes("%") ? tryDecode(token) : token`).
        canonical = sign_value(ctx.auth.secret, raw)
        name = cookie_name(ctx.auth)
        existing = ctx.request.headers.get("cookie", "")
        ctx.request.headers["cookie"] = (
            f"{existing}; {name}={canonical}" if existing else f"{name}={canonical}"
        )
        return None

    async def _after(self, ctx: Ctx) -> None:
        response = ctx.response
        if not isinstance(response, AuthResponse):
            return None
        value = _session_cookie_value(response, cookie_name(ctx.auth))
        if value is None:
            return None
        response.headers.append(("set-auth-token", value))
        add_expose_headers(response, "set-auth-token")
        return None
