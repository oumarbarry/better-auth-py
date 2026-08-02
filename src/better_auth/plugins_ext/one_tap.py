"""one-tap plugin — Google One Tap sign-in.

Verifies a Google One Tap ID token (posted by the browser after Google Identity
Services resolves a credential) and signs the user in through the same
find/register/link decision tree the redirect OAuth flow uses.

Verified against TS ``packages/better-auth/src/plugins/one-tap`` (index.ts, client.ts,
one-tap.test.ts) at v1.6.23. TS depends on ``@better-auth/core/social-providers``'s
``verifyGoogleIdToken``/``isGoogleHostedDomainAllowed`` and ``handleOAuthUserInfo``
(``oauth2/link-account.ts``); this port reuses the Wave-2 Python equivalents instead of
reimplementing JWKS verification or the linking policy:
  - ``oauth.verify.verify_id_token`` — JWKS fetch/cache + RS256/ES256 verification.
  - ``oauth.providers.Google`` — Google's JWKS URI + accepted issuers (constants).
  - ``oauth.flow.handle_oauth_user_info`` — the shared find/register/link decision tree.

``ponytail`` notes:
  - ``isGoogleHostedDomainAllowed`` has no Python port — Wave 2 never wired a dedicated
    ``hd`` field onto ``Google`` (only the generic ``authorize_params`` escape hatch), so
    there's nothing to reuse. Re-implemented here as a 6-line pure function rather than
    touching shared provider code (out of this plugin's file-ownership scope). The
    "configured hd" it checks is read from ``google_provider.authorize_params.get("hd")``
    — the existing per-provider extra-params mechanism (see ``Reddit``/``Roblox``), also
    how a caller would send `hd` as an authorize-URL hint today.
  - A fresh ``Google(client_id=audience)`` is built per request instead of reusing the
    registered social-provider instance, and passed to ``handle_oauth_user_info``: TS
    builds an inline ``{providerId: "google", accountId: sub}`` literal rather than the
    registered provider config, so e.g. ``overrideUserInfoOnSignIn`` on a real
    ``socialProviders.google`` config can't leak into One Tap's linking decision.
"""

from __future__ import annotations

from typing import Any

from ..adapters.base import Where
from ..oauth.flow import OAuthLinkError, handle_oauth_user_info
from ..oauth.models import OAuthTokens, OAuthUserInfo
from ..oauth.providers import Google
from ..oauth.verify import verify_id_token
from ..plugins import Plugin, Route
from ..session import create_session
from ..types import APIError, AuthResponse, Ctx

#: TS ``verifyGoogleIdToken``'s ``GOOGLE_ID_TOKEN_MAX_AGE`` — an extra hardening check
#: beyond `exp`: reject a token whose `iat` is older than this, even if not yet expired.
_GOOGLE_ID_TOKEN_MAX_AGE = 3600  # "1h"


def _hd_allowed(configured: str | None, token_hd: Any) -> bool:
    """TS ``isGoogleHostedDomainAllowed``. ``"*"`` accepts any Workspace hd; unset accepts all."""
    if not configured:
        return True
    if not isinstance(token_hd, str) or not token_hd:
        return False
    if configured == "*":
        return True
    return token_hd == configured


def _to_bool(value: Any) -> bool:
    """TS ``toBoolean`` — Google's ``email_verified`` claim is sometimes the string "true"."""
    return value is True or value == "true"


class OneTapPlugin(Plugin):
    """TS ``oneTap()`` — see module docstring for the source file."""

    id = "one-tap"

    def __init__(
        self,
        *,
        disable_signup: bool = False,
        client_id: str | list[str] | None = None,
    ) -> None:
        self.disable_signup = disable_signup
        self.client_id = client_id

    def routes(self) -> list[Route]:
        return [("POST", "/one-tap/callback", self.one_tap_callback)]

    async def one_tap_callback(self, ctx: Ctx) -> AuthResponse:
        body = ctx.body()
        id_token = body.get("idToken")
        if not isinstance(id_token, str):
            id_token = ""

        # Sent so the caller can validate the post-login redirect target against
        # trustedOrigins before navigating. This endpoint never redirects itself, but an
        # unchecked target would still be an open-redirect once the client acts on it
        # (TS relies on the global origin-check middleware for the same body field).
        callback_url = body.get("callbackURL")
        if callback_url:
            ctx.auth.ensure_trusted_url(callback_url)

        # Fail closed on a missing audience: without an expected client ID, verification
        # would check Google's signature and issuer but not that the token was minted for
        # this relying party, so a token issued to a different Google client would pass.
        google_provider = ctx.auth.social_providers.get("google")
        audience = self.client_id or (google_provider.client_id if google_provider else None)
        if not audience or (isinstance(audience, list) and len(audience) == 0):
            raise APIError(
                400,
                "BAD_REQUEST",
                "Google client ID is required for One Tap. Set it on the oneTap plugin "
                "(clientId) or on socialProviders.google.",
            )

        google = Google(client_id=audience)
        claims = await verify_id_token(
            ctx.auth.http,
            id_token,
            jwks_uri=google.jwks_url,
            audience=audience,
            issuers=google.issuers,
            max_age=_GOOGLE_ID_TOKEN_MAX_AGE,
        )
        if claims is None or not claims.get("sub"):
            raise APIError(400, "BAD_REQUEST", "invalid id token")

        # Apply the configured Google hosted domain (`hd`) so One Tap matches redirect
        # sign-in, which rejects tokens whose `hd` claim is missing or out of restriction.
        configured_hd = google_provider.authorize_params.get("hd") if google_provider else None
        if not _hd_allowed(configured_hd, claims.get("hd")):
            raise APIError(400, "BAD_REQUEST", "invalid id token")

        raw_email = claims.get("email")
        if not raw_email:
            return AuthResponse(body={"error": "Email not available in token"})
        email = raw_email.lower()

        # Resolve identity through the shared OAuth path so One Tap matches the redirect
        # and signIn.social flows: the account that owns the Google `sub` wins, never
        # whichever local user happens to share the token's email.
        info = OAuthUserInfo(
            id=claims["sub"],
            email=email,
            name=claims.get("name") or "",
            image=claims.get("picture"),
            email_verified=_to_bool(claims.get("email_verified")),
            raw=claims,
        )
        tokens = OAuthTokens(id_token=id_token, scope="openid,profile,email")
        # TS index.ts:182 `disableSignUp: options?.disableSignup || googleProvider?.disableSignUp`
        # — the registered provider's restriction must hold here too (the fresh `Google`
        # built above carries none of the registered config, so it is read explicitly).
        disable_sign_up = self.disable_signup or bool(
            google_provider and google_provider.disable_sign_up
        )
        try:
            user_id, _is_new = await handle_oauth_user_info(
                ctx, google, info, tokens, disable_sign_up=disable_sign_up
            )
        except OAuthLinkError as err:
            raise APIError(401, "OAUTH_LINK_ERROR", err.code) from None

        session, cookies = await create_session(ctx.auth, user_id, ctx.request, ctx=ctx)
        user = await ctx.adapter.find_one("user", [Where("id", user_id)])
        response = AuthResponse(
            body={
                "token": session["token"],
                "user": ctx.auth.parse_user_output(user) if user else None,
            }
        )
        for cookie in cookies:
            response.set_cookie(cookie)
        return response
