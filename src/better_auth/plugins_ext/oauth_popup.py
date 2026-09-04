"""oauth-popup — popup-based social OAuth.

Port of TS ``packages/better-auth/src/plugins/oauth-popup/``. The popup navigates
top-level to ``/oauth-popup/start`` (first-party to the auth origin), the server sets the
state + opener-marker cookies and redirects to the provider; on the OAuth callback this
plugin swaps the redirect for a server-rendered HTML page whose inline script
``postMessage``s the session token (or error) back to ``window.opener`` and closes the
popup. **Pair with the ``bearer`` plugin** — the token is handed back for cross-site use.

The completion ``<script>`` is a fixed string whose sha256 is pinned in the response CSP.
:data:`OAUTH_POPUP_COMPLETE_SCRIPT` reproduces the TS script byte-for-byte (verified by
``test_script_sha256_is_pinned_in_csp_hash`` against the TS-pinned hash), so the CSP hash
below is reused verbatim from TS.

``ponytail`` notes:
- The Python OAuth layer has no ``setOAuthState``/``generateGenericState``; state is a
  verification row + signed CSRF cookie (``oauth.flow``). ``/oauth-popup/start`` writes
  that row directly (it needs ``requestSignUp`` + INTERNAL_STATE_KEYS stripping) and sets
  the shared ``_state_cookie`` so the normal ``/callback`` and ``/oauth2/callback`` routes
  consume it unchanged.
- ``additionalData`` is stored NESTED under ``additionalData`` (this port's convention,
  matching generic-oauth) with INTERNAL_STATE_KEYS stripped — nesting already keeps an
  injected ``link``/``callbackURL`` out of the keys the callback reads.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import timedelta
from typing import Any
from urllib.parse import parse_qs, urlsplit

from ..crypto import generate_id, generate_random_string, sign_value, unsign_value
from ..oauth.flow import STATE_EXPIRES_IN, _absolute_url, _state_cookie
from ..oauth.machinery import build_authorization_url
from ..plugins import HookSet, Plugin, PluginHook, Route
from ..session import build_cookie, clear_cookie, cookie_name, utcnow
from ..types import APIError, AuthResponse, Ctx

logger = logging.getLogger("better_auth")

# --- constants (TS constants.ts) ---------------------------------------------------------

#: postMessage ``type`` the completion page posts to its opener.
OAUTH_POPUP_MESSAGE_TYPE = "better-auth:oauth-popup"
#: DOM id of the inert JSON data block the completion page reads.
OAUTH_POPUP_DATA_ELEMENT_ID = "better-auth-oauth-popup"
#: Signed cookie carrying the opener origin/nonce from sign-in to callback.
POPUP_MARKER_COOKIE = "oauth_popup"
#: localStorage key the popup session token is persisted under.
POPUP_TOKEN_STORAGE_KEY = "better-auth.popup_token"

# --- error codes (exact TS strings, error-codes.ts) --------------------------------------

OAUTH_POPUP_ERROR_CODES: dict[str, str] = {
    "POPUP_SIGN_IN_FAILED": "Popup sign-in failed",
    "POPUP_BLOCKED": "Sign-in popup was blocked by the browser",
    "POPUP_CLOSED": "Sign-in popup was closed before completing",
    "POPUP_TIMEOUT": "Sign-in popup timed out",
}

# --- state keys mirrored so additionalData cannot inject them (state.ts stateDataSchema) --

INTERNAL_STATE_KEYS = frozenset(
    {
        "callbackURL",
        "codeVerifier",
        "errorURL",
        "newUserURL",
        "expiresAt",
        "oauthState",
        "link",
        "requestSignUp",
    }
)

# --- the CSP-pinned completion script (byte-for-byte from index.ts) ----------------------

#: The completion-page script. Reproduced EXACTLY from TS ``OAUTH_POPUP_COMPLETE_SCRIPT``
#: (literal tabs + LF newlines) so its sha256 matches :data:`OAUTH_POPUP_SCRIPT_CSP_HASH`.
#: The element id is interpolated via ``json.dumps`` exactly like TS's
#: ``${JSON.stringify(OAUTH_POPUP_DATA_ELEMENT_ID)}``.
OAUTH_POPUP_COMPLETE_SCRIPT = (
    "(function () {\n"
    f"\tvar el = document.getElementById({json.dumps(OAUTH_POPUP_DATA_ELEMENT_ID)});\n"
    "\tif (!el) return;\n"
    "\tvar payload;\n"
    "\ttry {\n"
    '\t\tpayload = JSON.parse(el.textContent || "");\n'
    "\t} catch (e) {\n"
    "\t\treturn;\n"
    "\t}\n"
    "\tvar target = window.opener || window.parent;\n"
    "\tif (target && target !== window) {\n"
    "\t\ttry {\n"
    "\t\t\ttarget.postMessage(\n"
    "\t\t\t\t{\n"
    "\t\t\t\t\ttype: payload.type,\n"
    "\t\t\t\t\tnonce: payload.nonce,\n"
    "\t\t\t\t\ttoken: payload.token,\n"
    "\t\t\t\t\tredirectTo: payload.redirectTo,\n"
    "\t\t\t\t\terror: payload.error,\n"
    "\t\t\t\t},\n"
    "\t\t\t\tpayload.targetOrigin,\n"
    "\t\t\t);\n"
    "\t\t} catch (e) {}\n"
    "\t}\n"
    "\twindow.close();\n"
    "})();\n"
)

#: sha256 of :data:`OAUTH_POPUP_COMPLETE_SCRIPT`, pinned in the completion CSP (TS constant).
OAUTH_POPUP_SCRIPT_CSP_HASH = "sha256-tIo2K8VBC9SnhvdZ+9GsGkQoZm+jm/JcxL+d+i8b8KQ="

_INLINE_ESCAPE = re.compile("[<\u2028\u2029]")
_warned_missing_bearer = False


def _inline_json(value: Any) -> str:
    """Escapes ``</script>`` and the JS line separators (U+2028/U+2029) for embedding in
    a script element — TS ``inlineJSON``. Compact separators mirror ``JSON.stringify``."""
    text = json.dumps(value, separators=(",", ":"), ensure_ascii=False)
    return _INLINE_ESCAPE.sub(lambda m: f"\\u{ord(m.group(0)):04x}", text)


def _has_bearer(auth: Any) -> bool:
    return any(getattr(p, "id", None) == "bearer" for p in auth.plugins)


def render_completion(ctx: Ctx, popup_origin: str, message: dict[str, Any]) -> AuthResponse:
    """Render the page that posts the outcome (token or error) to the opener. ``popup_origin``
    must be trusted — validated at ``/oauth-popup/start`` and preserved in the signed marker
    cookie the callback reads. ``message`` is the already-clean payload (no ``None`` values)."""
    global _warned_missing_bearer
    if message.get("token") and not _warned_missing_bearer and not _has_bearer(ctx.auth):
        _warned_missing_bearer = True
        logger.warning(
            "OAuth popup hands the session token back via postMessage, but the `bearer` "
            "plugin is not registered, so an embedded (cross-site iframe) app cannot "
            "authenticate with it. Add BearerPlugin() to your auth `plugins`."
        )

    data = {"type": OAUTH_POPUP_MESSAGE_TYPE, "targetOrigin": popup_origin, **message}
    html = (
        "<!doctype html>\n"
        "<html>\n"
        '<head><meta charset="utf-8"><title>Completing sign-in</title></head>\n'
        "<body>\n"
        f'<script type="application/json" id="{OAUTH_POPUP_DATA_ELEMENT_ID}">'
        f"{_inline_json(data)}</script>\n"
        f"<script>{OAUTH_POPUP_COMPLETE_SCRIPT}</script>\n"
        "</body>\n"
        "</html>"
    )
    return AuthResponse(
        status=200,
        body=html,
        media_type="text/html; charset=utf-8",
        headers=[
            (
                "content-security-policy",
                f"default-src 'none'; script-src '{OAUTH_POPUP_SCRIPT_CSP_HASH}'; base-uri 'none'",
            ),
            # The page carries the session token, so keep it out of any cache.
            ("cache-control", "no-store"),
            ("pragma", "no-cache"),
        ],
    )


def _session_token_from(response: AuthResponse, name: str) -> str | None:
    """First non-empty ``name`` cookie value from ``response``'s Set-Cookie headers — this is
    the signed session token ``create_session`` just wrote, handed back via postMessage."""
    for key, raw in response.headers:
        if key.lower() != "set-cookie":
            continue
        cookie_part = raw.split(";", 1)[0]
        cname, _, cvalue = cookie_part.partition("=")
        if cname.strip() == name and cvalue:
            return cvalue
    return None


class OAuthPopupPlugin(Plugin):
    """Server plugin for popup-based OAuth. The client navigates the popup to
    ``/oauth-popup/start``; on the OAuth callback this plugin swaps the redirect for a page
    that posts the session token (or error) back to the opener. Pair with ``BearerPlugin``.
    Takes no options (TS ``oauthPopup()``)."""

    id = "oauth-popup"
    error_codes = OAUTH_POPUP_ERROR_CODES

    def routes(self) -> list[Route]:
        return [("GET", "/oauth-popup/start", self._start)]

    def hooks(self) -> HookSet:
        return HookSet(after=[PluginHook(matcher=self._is_callback, handler=self._after)])

    # --- GET /oauth-popup/start ----------------------------------------------------------

    async def _start(self, ctx: Ctx) -> AuthResponse:
        from ..origin import is_trusted_origin

        query = ctx.request.query
        popup_origin = query.get("popupOrigin", "")
        # The opener must be trusted before we postMessage anything to it; if not, we can't
        # safely relay, so reject hard.
        if not await is_trusted_origin(ctx.auth, ctx.request, popup_origin, allow_relative=False):
            logger.error(
                "OAuth popup origin is not a trusted origin. Add %s to trustedOrigins.",
                popup_origin,
            )
            raise APIError(403, "INVALID_ORIGIN", "Invalid origin")

        popup_nonce = query.get("popupNonce") or ""

        # Once the opener is trusted, relay start-stage failures to it as a completion error
        # page (so it isn't left waiting for a timeout).
        def fail(code: str, description: str | None = None) -> AuthResponse:
            error = {"code": code}
            if description:
                error["description"] = description
            return render_completion(ctx, popup_origin, {"nonce": popup_nonce, "error": error})

        # originCheckMiddleware skips GET, so mirror its trusted-origin check on the redirect
        # URLs here, relaying the failure to the opener rather than throwing.
        async def validate_redirect(url: str | None, code: str) -> AuthResponse | None:
            if not url or await is_trusted_origin(ctx.auth, ctx.request, url, allow_relative=True):
                return None
            logger.error("Invalid redirect URL: %s", url)
            return fail(code, f"Untrusted URL: {url}")

        invalid = (
            await validate_redirect(query.get("callbackURL"), "invalid_callback_url")
            or await validate_redirect(query.get("errorCallbackURL"), "invalid_error_callback_url")
            or await validate_redirect(
                query.get("newUserCallbackURL"), "invalid_new_user_callback_url"
            )
        )
        if invalid is not None:
            return invalid

        # Built-in social AND generic-oauth providers both register into social_providers.
        provider = ctx.auth.social_providers.get(query.get("provider") or "")
        if provider is None:
            return fail("provider_not_found", f"Unknown provider: {query.get('provider')}")

        callback_url = query.get("callbackURL") or ctx.auth.base_url

        try:
            code_verifier = generate_random_string(128)
            state = await self._store_state(ctx, callback_url, code_verifier, query)
            url = await self._authorization_url(ctx, provider, state, code_verifier, query)
        except Exception as error:
            logger.error("OAuth popup failed to start: %s", error)
            return fail("popup_sign_in_failed", "Failed to start the OAuth flow.")

        response = AuthResponse(redirect_to=url)
        response.set_cookie(_state_cookie(ctx, state))
        # Remember the opener so the callback's completion page can post to it.
        marker = sign_value(
            ctx.auth.secret,
            json.dumps({"popupOrigin": popup_origin, "popupNonce": popup_nonce}),
        )
        response.set_cookie(build_cookie(ctx.auth, marker, 10 * 60, POPUP_MARKER_COOKIE))
        return response

    async def _store_state(
        self, ctx: Ctx, callback_url: str, code_verifier: str, query: dict[str, str]
    ) -> str:
        """Write the CSRF state row (verification table) and return the ``state`` token. Shape
        matches what ``/callback`` and ``/oauth2/callback`` read (``oauth.flow``)."""
        raw_additional = query.get("additionalData")
        parsed: dict[str, Any] = {}
        if raw_additional:
            try:
                loaded = json.loads(raw_additional)
                if isinstance(loaded, dict):
                    parsed = loaded
            except ValueError:
                parsed = {}
        additional_data = {k: v for k, v in parsed.items() if k not in INTERNAL_STATE_KEYS}

        state = generate_random_string(32)
        now = utcnow()
        value: dict[str, Any] = {
            "callbackURL": callback_url,
            "codeVerifier": code_verifier,
            "errorURL": query.get("errorCallbackURL"),
            "newUserURL": query.get("newUserCallbackURL"),
            "expiresAt": int(now.timestamp() * 1000) + 10 * 60 * 1000,
        }
        if query.get("requestSignUp") == "true":
            value["requestSignUp"] = True
        if additional_data:
            value["additionalData"] = additional_data
        await ctx.adapter.create(
            "verification",
            {
                "id": generate_id(),
                "identifier": state,
                "value": json.dumps(value),
                "expiresAt": now + timedelta(seconds=STATE_EXPIRES_IN),
                "createdAt": now,
                "updatedAt": now,
            },
        )
        return state

    async def _authorization_url(
        self, ctx: Ctx, provider: Any, state: str, code_verifier: str, query: dict[str, str]
    ) -> str:
        """Provider authorization URL. Generic-oauth providers resolve their endpoint via
        discovery and callback under ``/oauth2/callback`` (their registered provider carries a
        ``generic`` config but no ``authorization_endpoint``); built-in social providers build
        it themselves and callback under ``/callback``."""
        base = f"{ctx.auth.base_url}{ctx.auth.base_path}"
        scopes = query["scopes"].split(",") if query.get("scopes") else None
        generic = getattr(provider, "generic", None)
        if generic is not None:
            auth_endpoint = generic.authorization_url
            if not auth_endpoint and generic.discovery_url:
                from .generic_oauth import _discover

                doc = await _discover(
                    ctx.auth.http, generic.discovery_url, generic.discovery_headers
                )
                auth_endpoint = doc.get("authorization_endpoint")
            if not auth_endpoint:
                raise APIError(400, "INVALID_OAUTH_CONFIGURATION", "Invalid OAuth configuration")
            merged = [*(scopes or []), *(generic.scopes or [])]
            return build_authorization_url(
                authorization_endpoint=auth_endpoint,
                client_id=generic.client_id,
                state=state,
                redirect_uri=generic.redirect_uri
                or f"{base}/oauth2/callback/{provider.provider_id}",
                scopes=list(dict.fromkeys(merged)) or None,
                response_type=generic.response_type or "code",
                code_verifier=code_verifier if generic.pkce else None,
                prompt=generic.prompt,
                access_type=generic.access_type,
                response_mode=generic.response_mode,
            )
        return provider.authorization_url(
            state=state,
            redirect_uri=provider.redirect_uri or f"{base}/callback/{provider.provider_id}",
            code_verifier=code_verifier,
            extra_scopes=scopes,
        )

    # --- after /callback/* and /oauth2/callback/* ----------------------------------------

    @staticmethod
    def _is_callback(ctx: Ctx) -> bool:
        path = ctx.request.path or ""
        return path.startswith("/callback/") or path.startswith("/oauth2/callback/")

    async def _after(self, ctx: Ctx) -> AuthResponse | None:
        response = ctx.response
        if not isinstance(response, AuthResponse):
            return None
        redirect_to = response.redirect_to
        if not redirect_to:
            return None  # not a redirect -> nothing to swap

        raw = ctx.request.cookies().get(cookie_name(ctx.auth, POPUP_MARKER_COOKIE))
        marker = unsign_value(ctx.auth.secret, raw) if raw else None
        if not marker:
            return None  # not a popup flow -> keep the redirect
        try:
            parsed = json.loads(marker)
            popup_origin = parsed["popupOrigin"]
            popup_nonce = parsed.get("popupNonce") or ""
        except (ValueError, KeyError, TypeError):
            return None

        # The session token is the cookie create_session just wrote; post it back to the
        # opener. No token -> the callback errored.
        token = _session_token_from(response, cookie_name(ctx.auth))
        if token:
            completion = render_completion(
                ctx,
                popup_origin,
                {"nonce": popup_nonce, "token": token, "redirectTo": redirect_to},
            )
        else:
            params = parse_qs(urlsplit(_absolute_url(ctx, redirect_to)).query)
            error = params.get("error", [None])[0]
            if not error:
                return None  # unrecognized outcome -> keep the redirect
            err: dict[str, Any] = {"code": error}
            description = params.get("error_description", [None])[0]
            if description:
                err["description"] = description
            completion = render_completion(ctx, popup_origin, {"nonce": popup_nonce, "error": err})

        # The callback's session cookies must ride along on the completion response (swapping
        # the redirect would otherwise drop them).
        for key, val in response.headers:
            if key.lower() == "set-cookie":
                completion.set_cookie(val)
        # Clear the opener marker on the completion response.
        completion.set_cookie(clear_cookie(ctx.auth, POPUP_MARKER_COOKIE))
        return completion
