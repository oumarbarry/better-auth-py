"""oauth-proxy — complete social OAuth from preview/branch deployments.

Port of TS ``packages/better-auth/src/plugins/oauth-proxy/`` (``index.ts`` + ``utils.ts``).
Preview/branch deployments get a rotating URL that an OAuth provider (which only whitelists
ONE production ``redirect_uri``) will not accept. This plugin routes the provider callback
through the fixed **production** deployment: production runs the code→token→userInfo
exchange, encrypts the resulting profile under a **shared secret**, and 302s it back to the
preview's ``/oauth-proxy-callback``, which creates the user/session locally.

The plugin is ALL hooks plus one endpoint (the proxy callback); it adds no schema.

Flow (database state strategy — the only one this port has):

1. ``before /sign-in/social|/sign-in/oauth2`` (preview): rewrite ``callbackURL`` to
   ``{currentOrigin}{basePath}/oauth-proxy-callback?callbackURL={original}`` so the eventual
   redirect lands back on the preview.
2. ``after`` sign-in (preview): read the freshly-written ``verification`` row, re-encrypt its
   value under the **proxy key** (``opts.secret ?? auth.secret``), wrap it in an
   ``OAuthProxyStatePackage`` and replace the provider URL's ``state`` param with it — so
   production (which does not share the preview's ``BETTER_AUTH_SECRET``) can read it back.
3. ``before /callback/:provider`` (production): decrypt the ``state`` as a package; if it is
   a proxy package, do the exchange, build the encrypted ``PassthroughPayload`` and 302 to
   the preview's proxy callback with a ``profile`` param. If it cannot decrypt (regular
   state / mismatched secrets) → fall through to the normal callback (fail closed).
4. ``GET /oauth-proxy-callback`` (preview): origin-check ``callbackURL`` (open-redirect
   guard), decrypt+validate the profile (required fields, replay window, consume the OAuth
   state), then ``handle_oauth_user_info`` → session → redirect.
5. ``after /callback/:provider``: unwrap a same-origin proxy redirect back to the original
   destination (defensive; only reached when the before hook fell through).

``ponytail`` notes (deliberate divergences from TS, with reasons):
- **No ``baseURL`` override.** TS mutates the per-request ``ctx.context.baseURL`` to
  production so the authorization ``redirect_uri`` points at production. Python's
  ``BetterAuth`` is a single shared instance and ``base_url`` is read for redirect_uri,
  cookie domain, trusted-origin anchoring, etc.; mutating it per-request would be a
  concurrency hazard AND would make ``sign_in_social``'s ``ensure_trusted_url`` reject the
  preview-origin proxy ``callbackURL`` (it anchors trust on ``base_url``). Instead, set each
  provider's ``redirect_uri`` to the production callback — production's own callback exchange
  already uses its ``base_url``, so the two match. Upgrade path: a per-request redirect_uri
  seam in ``oauth/flow.py`` (out of scope for a plugin-only port).
- **Database state strategy only** — the Python OAuth layer stores state as a verification
  row (TS's stateless ``cookie`` strategy is not ported), so the ``after`` sign-in hook has
  only the DB branch.
"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

from ..adapters.base import Where
from ..crypto import symmetric_decrypt, symmetric_encrypt
from ..oauth.flow import (
    OAuthLinkError,
    _absolute_url,
    _callback_params,
    _error_redirect,
    handle_oauth_user_info,
)
from ..oauth.models import OAuthTokens, OAuthUserInfo
from ..oauth.providers import ProviderConfig
from ..origin import is_trusted_origin
from ..plugins import HookSet, Plugin, PluginHook, Route
from ..session import create_session, utcnow
from ..types import APIError, AuthResponse, Ctx, json_default

logger = logging.getLogger("better_auth")

DEFAULT_MAX_AGE = 60  # seconds — TS `opts?.maxAge ?? 60`


# --- url helpers (utils.ts) ---------------------------------------------------------------


def _strip_trailing_slash(url: str | None) -> str:
    return url.rstrip("/") if url else ""


def _get_origin(url: str | None) -> str | None:
    """``scheme://host[:port]`` for http(s) URLs, else None (TS ``getOrigin``)."""
    if not url:
        return None
    parts = urlsplit(url)
    if parts.scheme in ("http", "https") and parts.netloc:
        return f"{parts.scheme}://{parts.netloc}"
    return None


def _vendor_base_url() -> str | None:
    """Base URL from vendor env vars (TS ``getVendorBaseURL``). Vercel/Netlify/Render expose a
    URL; AWS/GCP/Azure expose a bare function name (ignored later by the ``getOrigin`` gate)."""
    vercel = os.environ.get("VERCEL_URL")
    return (
        (f"https://{vercel}" if vercel else None)
        or os.environ.get("NETLIFY_URL")
        or os.environ.get("RENDER_URL")
        or os.environ.get("AWS_LAMBDA_FUNCTION_NAME")
        or os.environ.get("GOOGLE_CLOUD_FUNCTION_NAME")
        or os.environ.get("AZURE_FUNCTION_NAME")
    )


def _request_origin(ctx: Ctx) -> str | None:
    """The server's own origin for this request, reconstructed from the ``Host`` header
    (+ ``X-Forwarded-Proto`` / the base_url scheme). This stands in for TS ``ctx.request.url``:
    it is the host the request arrived on, NOT the client page's Origin header."""
    host = ctx.request.headers.get("host")
    if not host:
        return None
    proto = ctx.request.headers.get("x-forwarded-proto")
    if not proto:
        proto = "https" if ctx.auth.base_url.startswith("https") else "http"
    return f"{proto}://{host}"


def _parse_dt(value: Any) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


def _set_query_param(url: str, key: str, value: str) -> str:
    """``URLSearchParams.set`` equivalent: replace/append ``key`` on ``url``'s query."""
    parts = urlsplit(url)
    pairs = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k != key]
    pairs.append((key, value))
    return parts._replace(query=urlencode(pairs)).geturl()


class OAuthProxyPlugin(Plugin):
    """Proxy social-OAuth callbacks through a production deployment (TS ``oAuthProxy``).

    Options mirror ``OAuthProxyOptions``:

    :param current_url: The current deployment URL. Trusted as-is. When omitted, resolved from
        the (trusted) request origin, then a vendor env URL, then ``base_url``.
    :param production_url: The fixed production URL; a request already on this origin is not
        proxied. Defaults to ``BETTER_AUTH_URL`` / ``base_url``.
    :param max_age: Max age (seconds) of an encrypted profile before it is rejected as a
        replay. Default 60.
    :param secret: A dedicated proxy secret used **instead of** ``auth.secret`` for all proxy
        encryption. Must be shared across every environment in the flow.
    """

    id = "oauth-proxy"

    def __init__(
        self,
        *,
        current_url: str | None = None,
        production_url: str | None = None,
        max_age: int = DEFAULT_MAX_AGE,
        secret: str | None = None,
    ) -> None:
        self.current_url = current_url
        self.production_url = production_url
        self.max_age = max_age
        self.secret = secret

    # --- wiring --------------------------------------------------------------------------

    def routes(self) -> list[Route]:
        return [("GET", "/oauth-proxy-callback", self._proxy_callback)]

    def hooks(self) -> HookSet:
        return HookSet(
            before=[
                PluginHook(matcher=self._is_sign_in, handler=self._before_sign_in),
                PluginHook(matcher=self._is_callback, handler=self._before_callback),
            ],
            after=[
                PluginHook(matcher=self._is_sign_in, handler=self._after_sign_in),
                PluginHook(matcher=self._is_callback, handler=self._after_callback),
            ],
        )

    @staticmethod
    def _is_sign_in(ctx: Ctx) -> bool:
        path = ctx.request.path or ""
        return path.startswith("/sign-in/social") or path.startswith("/sign-in/oauth2")

    @staticmethod
    def _is_callback(ctx: Ctx) -> bool:
        return (ctx.request.path or "").startswith("/callback/")

    # --- resolution (utils.ts) -----------------------------------------------------------

    def _encryption_key(self, ctx: Ctx) -> str:
        """The proxy key — ``opts.secret`` overrides the global secret (TS ``getEncryptionKey``)."""
        return self.secret or ctx.auth.secret

    def _check_skip_proxy(self, ctx: Ctx) -> bool:
        """Whether to skip proxying (TS ``checkSkipProxy``): the ``x-skip-oauth-proxy`` header,
        or a request already on the production origin."""
        if ctx.request.headers.get("x-skip-oauth-proxy"):
            return True
        production_url = (
            self.production_url or os.environ.get("BETTER_AUTH_URL") or ctx.auth.base_url
        )
        if not production_url:
            return False
        current_url = self.current_url or _request_origin(ctx) or _vendor_base_url()
        if not current_url:
            return False
        return _get_origin(production_url) == _get_origin(current_url)

    async def _resolve_current_origin(self, ctx: Ctx) -> str:
        """The receiver origin for the encrypted replay (TS ``resolveCurrentURL``).

        Security: a request-derived origin is honoured ONLY when it is an explicitly trusted
        origin — otherwise an attacker controlling the ``Host`` header could point the replay
        at themselves. An explicit ``current_url`` and the vendor/base URLs are developer
        configured and trusted as-is.
        """
        if self.current_url:
            return _get_origin(self.current_url) or self.current_url
        origin = _request_origin(ctx)
        if origin and await is_trusted_origin(ctx.auth, ctx.request, origin, allow_relative=False):
            return origin
        vendor = _vendor_base_url()
        vendor_origin = _get_origin(vendor) if vendor else None
        if vendor_origin:
            return vendor_origin
        return _get_origin(ctx.auth.base_url) or ctx.auth.base_url

    # --- before /sign-in: rewrite callbackURL --------------------------------------------

    async def _before_sign_in(self, ctx: Ctx) -> AuthResponse | None:
        if self._check_skip_proxy(ctx):
            return None
        current_origin = await self._resolve_current_origin(ctx)
        body = ctx.body()
        original_callback = body.get("callbackURL") or ctx.auth.base_url
        base_path = ctx.auth.base_path or "/api/auth"
        body["callbackURL"] = (
            f"{_strip_trailing_slash(current_origin)}{base_path}"
            f"/oauth-proxy-callback?callbackURL={quote(original_callback, safe='')}"
        )
        return None

    # --- after /sign-in: encrypt the state package ---------------------------------------

    async def _after_sign_in(self, ctx: Ctx) -> AuthResponse | None:
        if self._check_skip_proxy(ctx):
            return None
        response = ctx.response
        if not isinstance(response, AuthResponse) or not isinstance(response.body, dict):
            return None
        provider_url = response.body.get("url")
        if not isinstance(provider_url, str):
            return None
        parts = urlsplit(provider_url)
        query_pairs = parse_qsl(parts.query, keep_blank_values=True)
        original_state = next((v for k, v in query_pairs if k == "state"), None)
        if not original_state:
            return None
        try:
            row = await ctx.adapter.find_one("verification", [Where("identifier", original_state)])
            plaintext_state = row["value"] if row else None
            if not plaintext_state:
                logger.warning("No OAuth state found for proxy")
                return None
            key = self._encryption_key(ctx)
            # Re-encrypt the plaintext state under the proxy key, wrap it so production reads
            # it back with that same key (production lacks this env's BETTER_AUTH_SECRET).
            package = {
                "state": original_state,
                "stateCookie": symmetric_encrypt(key, plaintext_state),
                "isOAuthProxy": True,
            }
            encrypted_package = symmetric_encrypt(key, json.dumps(package))
            new_query = [(k, encrypted_package if k == "state" else v) for k, v in query_pairs]
            response.body["url"] = parts._replace(query=urlencode(new_query)).geturl()
        except Exception as error:  # fall through to a non-proxied flow on any failure
            logger.error("Failed to prepare OAuth proxy state: %s", error)
        return None

    # --- before /callback (production): passthrough --------------------------------------

    async def _before_callback(self, ctx: Ctx) -> AuthResponse | None:
        params = _callback_params(ctx)  # query + form body (Apple form_post)
        state = params.get("state")
        if not state or not isinstance(state, str):
            return None

        key = self._encryption_key(ctx)
        try:
            package = json.loads(symmetric_decrypt(key, state))
        except Exception:
            # Regular (non-proxy) state, or a proxy package under a different secret. Fall
            # through to the normal callback (fail closed) — see the shared-secret docs.
            logger.debug("OAuth proxy: could not decrypt state package, falling back")
            return None
        if not (
            isinstance(package, dict)
            and package.get("isOAuthProxy")
            and package.get("state")
            and package.get("stateCookie")
        ):
            logger.warning("Invalid OAuth proxy state package")
            return None

        try:
            state_data = json.loads(symmetric_decrypt(key, package["stateCookie"]))
        except Exception as error:
            logger.error("Failed to decrypt OAuth proxy state cookie: %s", error)
            return None

        error_url = state_data.get("errorURL")

        # State-binding check (no-op for the DB strategy, which carries no `oauthState`).
        oauth_state = state_data.get("oauthState")
        if oauth_state is not None and oauth_state != package["state"]:
            logger.error("OAuth proxy state binding mismatch")
            return _error_redirect(ctx, "state_mismatch", error_url)

        error = params.get("error")
        if error:
            return _error_redirect(ctx, error, error_url)
        code = params.get("code")
        if not code:
            logger.warning("OAuth callback missing authorization code")
            return _error_redirect(ctx, "no_code", error_url)

        provider = ctx.auth.social_providers.get(ctx.params.get("provider", ""))
        if provider is None:
            logger.warning("OAuth provider not found")
            return _error_redirect(ctx, "oauth_provider_not_found", error_url)

        redirect_uri = f"{ctx.auth.base_url}{ctx.auth.base_path}/callback/{provider.provider_id}"
        try:
            tokens = await provider.exchange(
                ctx.auth.http,
                code=code,
                redirect_uri=redirect_uri,
                code_verifier=state_data.get("codeVerifier"),
            )
        except Exception as error:
            logger.error("Failed to validate authorization code: %s", error)
            return _error_redirect(ctx, "invalid_code", error_url)

        try:
            info = await provider.fetch_user(tokens, ctx.auth.http)
        except Exception:
            info = None
        if info is None:
            logger.error("Unable to get user info from provider")
            return _error_redirect(ctx, "unable_to_get_user_info", error_url)
        if not info.email:
            logger.error("Provider did not return email")
            return _error_redirect(ctx, "email_not_found", error_url)

        # stateData.callbackURL is the rewritten proxy URL; the ORIGINAL destination is its
        # embedded `callbackURL` query param.
        proxy_callback = state_data.get("callbackURL") or ""
        inner = dict(parse_qsl(urlsplit(proxy_callback).query)).get("callbackURL")
        final_callback = inner or proxy_callback

        payload: dict[str, Any] = {
            "userInfo": {
                "id": str(info.id),
                "email": info.email,
                "name": info.name or "",
                "image": info.image,
                "emailVerified": info.email_verified,
            },
            "account": {
                "providerId": provider.provider_id,
                "accountId": str(info.id),
                "accessToken": tokens.access_token,
                "refreshToken": tokens.refresh_token,
                "idToken": tokens.id_token,
                "accessTokenExpiresAt": tokens.access_token_expires_at,
                "refreshTokenExpiresAt": tokens.refresh_token_expires_at,
                "scope": ",".join(tokens.scopes) if tokens.scopes else None,
            },
            "state": package["state"],
            "callbackURL": final_callback,
            "newUserURL": state_data.get("newUserURL"),
            "errorURL": state_data.get("errorURL"),
            "disableSignUp": (
                provider.disable_implicit_sign_up and not state_data.get("requestSignUp")
            )
            or provider.disable_sign_up,
            "timestamp": int(time.time() * 1000),
        }
        encrypted_payload = symmetric_encrypt(key, json.dumps(payload, default=json_default))
        return AuthResponse(
            redirect_to=_set_query_param(proxy_callback, "profile", encrypted_payload)
        )

    # --- GET /oauth-proxy-callback (preview): decrypt + create session -------------------

    async def _proxy_callback(self, ctx: Ctx) -> AuthResponse:
        # originCheck((ctx) => ctx.query.callbackURL): open-redirect guard on the receiver.
        # GET requests skip the global CSRF/origin check, so validate here (relative allowed).
        query_callback = ctx.request.query.get("callbackURL")
        if query_callback and not await is_trusted_origin(
            ctx.auth, ctx.request, query_callback, allow_relative=True
        ):
            raise APIError(403, "INVALID_CALLBACK_URL", "Invalid callbackURL")

        key = self._encryption_key(ctx)
        encrypted_profile = ctx.request.query.get("profile")
        if not encrypted_profile:
            logger.error("OAuth proxy callback missing profile data")
            return _error_redirect(ctx, "missing_profile", None)

        try:
            decrypted = symmetric_decrypt(key, encrypted_profile)
        except Exception as error:
            logger.error("Failed to decrypt OAuth proxy profile: %s", error)
            return _error_redirect(ctx, "invalid_profile", None)
        try:
            payload = json.loads(decrypted)
        except Exception as error:
            logger.error("Failed to parse OAuth proxy payload: %s", error)
            return _error_redirect(ctx, "invalid_payload", None)

        timestamp = payload.get("timestamp") if isinstance(payload, dict) else None
        if not (
            isinstance(payload, dict)
            and isinstance(timestamp, (int, float))
            and not isinstance(timestamp, bool)
            and payload.get("userInfo")
            and payload.get("account")
            and payload.get("state")
            and payload.get("callbackURL")
        ):
            logger.error("Failed to parse OAuth proxy payload")
            return _error_redirect(ctx, "invalid_payload", None)

        error_url = payload.get("errorURL")

        # Replay window: allow up to 10s of future skew (TS clock-skew tolerance).
        age = (time.time() * 1000 - timestamp) / 1000
        if age > self.max_age or age < -10:
            logger.error("OAuth proxy payload expired or invalid (age: %ss)", age)
            return _error_redirect(ctx, "payload_expired", error_url)

        if not await self._consume_state(ctx, payload["state"]):
            return _error_redirect(ctx, "state_mismatch", error_url)

        account = payload["account"]
        provider = ctx.auth.social_providers.get(account["providerId"]) or ProviderConfig(
            client_id="", provider_id=account["providerId"]
        )
        user_info = payload["userInfo"]
        info = OAuthUserInfo(
            id=str(user_info["id"]),
            email=user_info.get("email"),
            name=user_info.get("name") or "",
            image=user_info.get("image"),
            email_verified=bool(user_info.get("emailVerified")),
        )
        scope = account.get("scope")
        tokens = OAuthTokens(
            access_token=account.get("accessToken"),
            refresh_token=account.get("refreshToken"),
            id_token=account.get("idToken"),
            scope=scope,
            scopes=scope.split(",") if scope else [],
            access_token_expires_at=_parse_dt(account.get("accessTokenExpiresAt")),
            refresh_token_expires_at=_parse_dt(account.get("refreshTokenExpiresAt")),
        )
        try:
            user_id, is_register = await handle_oauth_user_info(
                ctx, provider, info, tokens, disable_sign_up=bool(payload.get("disableSignUp"))
            )
        except OAuthLinkError as err:
            return _error_redirect(ctx, err.code, error_url)

        _session, cookies = await create_session(ctx.auth, user_id, ctx.request, ctx=ctx)
        final = (
            (payload.get("newUserURL") or payload["callbackURL"])
            if is_register
            else payload["callbackURL"]
        )
        response = AuthResponse(redirect_to=_absolute_url(ctx, final))
        for cookie in cookies:
            response.set_cookie(cookie)
        return response

    async def _consume_state(self, ctx: Ctx, state: str) -> bool:
        """Consume the OAuth state row (TS ``parseGenericState`` with ``skipStateCookieCheck``):
        the row must exist (was issued by this env's sign-in) and not be expired; consuming it
        deletes it. Missing/expired → False → ``state_mismatch``."""
        row = await ctx.adapter.find_one("verification", [Where("identifier", state)])
        if row is None:
            logger.warning("OAuth proxy state missing or invalid")
            return False
        await ctx.adapter.delete_many("verification", [Where("identifier", state)])
        expires_at = row.get("expiresAt")
        return expires_at is None or expires_at > utcnow()

    # --- after /callback: unwrap same-origin proxy redirects -----------------------------

    async def _after_callback(self, ctx: Ctx) -> AuthResponse | None:
        response = ctx.response
        if not isinstance(response, AuthResponse):
            return None
        location = response.redirect_to
        if (
            not location
            or "/oauth-proxy-callback?callbackURL" not in location
            or not location.startswith("http")
        ):
            return None
        production_url = self.production_url or ctx.auth.base_url
        if _get_origin(location) == _get_origin(production_url):
            inner = dict(parse_qsl(urlsplit(location).query)).get("callbackURL")
            if inner:
                response.redirect_to = inner  # unwrap to the original destination
            return None
        logger.warning("OAuth proxy: cross-origin callback reached after hook unexpectedly")
        return None
