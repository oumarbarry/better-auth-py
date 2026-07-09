"""Social sign-in: OAuth2/OIDC providers and the sign-in/callback endpoints.

Follows better-auth's flow: state stored in the `verification` table (identifier = state,
value = JSON payload, 10 min expiry) plus a short-lived signed state cookie; PKCE (S256)
for providers that support it; account rows keyed by (providerId, accountId).
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from urllib.parse import urlencode

import httpx

from .adapters.base import Where
from .crypto import generate_id, generate_random_string, sign_value, unsign_value
from .session import build_cookie, clear_cookie, cookie_name, create_session, utcnow
from .types import APIError, AuthResponse, Ctx

STATE_EXPIRES_IN = 600  # seconds, like better-auth
STATE_COOKIE = "state"


@dataclass
class OAuthTokens:
    access_token: str | None = None
    refresh_token: str | None = None
    id_token: str | None = None
    scope: str | None = None
    access_token_expires_at: datetime | None = None


@dataclass
class OAuthUserInfo:
    id: str
    email: str | None
    name: str
    image: str | None = None
    email_verified: bool = False


@dataclass
class OAuthProvider:
    """Generic OAuth2 provider. Subclass (or instantiate directly) for custom providers."""

    client_id: str
    client_secret: str
    provider_id: str = ""
    authorize_url: str = ""
    token_url: str = ""
    userinfo_url: str = ""
    scopes: list[str] = field(default_factory=list)
    use_pkce: bool = False
    #: overrides {base_url}{base_path}/callback/{provider_id}
    redirect_uri: str | None = None
    #: extra query params for the authorize URL (e.g. {"access_type": "offline"})
    authorize_params: dict[str, str] = field(default_factory=dict)

    async def fetch_user(self, tokens: OAuthTokens, http: httpx.AsyncClient) -> OAuthUserInfo:
        """Default OIDC-style userinfo fetch; providers override for their own shapes."""
        response = await http.get(
            self.userinfo_url,
            headers={"authorization": f"Bearer {tokens.access_token}"},
        )
        response.raise_for_status()
        data = response.json()
        return OAuthUserInfo(
            id=str(data["sub"]),
            email=data.get("email"),
            name=data.get("name") or data.get("email") or "",
            image=data.get("picture"),
            email_verified=bool(data.get("email_verified", False)),
        )


@dataclass
class GitHub(OAuthProvider):
    provider_id: str = "github"
    authorize_url: str = "https://github.com/login/oauth/authorize"
    token_url: str = "https://github.com/login/oauth/access_token"
    userinfo_url: str = "https://api.github.com/user"
    scopes: list[str] = field(default_factory=lambda: ["read:user", "user:email"])

    async def fetch_user(self, tokens: OAuthTokens, http: httpx.AsyncClient) -> OAuthUserInfo:
        headers = {
            "authorization": f"Bearer {tokens.access_token}",
            "user-agent": "better-auth-py",
            "accept": "application/vnd.github+json",
        }
        response = await http.get(self.userinfo_url, headers=headers)
        response.raise_for_status()
        profile = response.json()
        email, verified = profile.get("email"), False
        emails_response = await http.get(f"{self.userinfo_url}/emails", headers=headers)
        if emails_response.status_code == 200:
            emails = emails_response.json()
            primary = next((e for e in emails if e.get("primary")), None) or next(
                iter(emails), None
            )
            if primary:
                email = primary.get("email") or email
                verified = bool(primary.get("verified", False))
        return OAuthUserInfo(
            id=str(profile["id"]),
            email=email,
            name=profile.get("name") or profile.get("login") or "",
            image=profile.get("avatar_url"),
            email_verified=verified,
        )


@dataclass
class Google(OAuthProvider):
    provider_id: str = "google"
    authorize_url: str = "https://accounts.google.com/o/oauth2/v2/auth"
    token_url: str = "https://oauth2.googleapis.com/token"
    userinfo_url: str = "https://openidconnect.googleapis.com/v1/userinfo"
    scopes: list[str] = field(default_factory=lambda: ["openid", "email", "profile"])
    use_pkce: bool = True


@dataclass
class Discord(OAuthProvider):
    provider_id: str = "discord"
    authorize_url: str = "https://discord.com/oauth2/authorize"
    token_url: str = "https://discord.com/api/oauth2/token"
    userinfo_url: str = "https://discord.com/api/users/@me"
    scopes: list[str] = field(default_factory=lambda: ["identify", "email"])

    async def fetch_user(self, tokens: OAuthTokens, http: httpx.AsyncClient) -> OAuthUserInfo:
        response = await http.get(
            self.userinfo_url, headers={"authorization": f"Bearer {tokens.access_token}"}
        )
        response.raise_for_status()
        profile = response.json()
        image = None
        if profile.get("avatar"):
            image = f"https://cdn.discordapp.com/avatars/{profile['id']}/{profile['avatar']}.png"
        return OAuthUserInfo(
            id=str(profile["id"]),
            email=profile.get("email"),
            name=profile.get("global_name") or profile.get("username") or "",
            image=image,
            email_verified=bool(profile.get("verified", False)),
        )


def _redirect_uri(ctx: Ctx, provider: OAuthProvider) -> str:
    return (
        provider.redirect_uri
        or f"{ctx.auth.base_url}{ctx.auth.base_path}/callback/{provider.provider_id}"
    )


def _code_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


async def sign_in_social(ctx: Ctx) -> AuthResponse:
    body = ctx.body()
    provider_id = body.get("provider")
    provider = ctx.auth.social_providers.get(provider_id or "")
    if provider is None:
        raise APIError(404, "PROVIDER_NOT_FOUND", "Provider not found")

    callback_url = body.get("callbackURL") or "/"
    ctx.auth.ensure_trusted_url(callback_url)
    error_url = body.get("errorCallbackURL")
    if error_url:
        ctx.auth.ensure_trusted_url(error_url)
    new_user_url = body.get("newUserCallbackURL")
    if new_user_url:
        ctx.auth.ensure_trusted_url(new_user_url)

    state = generate_random_string(32)
    code_verifier = generate_random_string(128)
    now = utcnow()
    payload = {
        "callbackURL": callback_url,
        "codeVerifier": code_verifier,
        "errorURL": error_url,
        "newUserURL": new_user_url,
        "expiresAt": int(now.timestamp() * 1000) + STATE_EXPIRES_IN * 1000,
    }
    await ctx.adapter.create(
        "verification",
        {
            "id": generate_id(),
            "identifier": state,
            "value": json.dumps(payload),
            "expiresAt": now + timedelta(seconds=STATE_EXPIRES_IN),
            "createdAt": now,
            "updatedAt": now,
        },
    )

    params = {
        "client_id": provider.client_id,
        "response_type": "code",
        "redirect_uri": _redirect_uri(ctx, provider),
        "state": state,
        **provider.authorize_params,
    }
    if provider.scopes:
        scopes = list(provider.scopes) + list(body.get("scopes") or [])
        params["scope"] = " ".join(dict.fromkeys(scopes))
    if provider.use_pkce:
        params["code_challenge"] = _code_challenge(code_verifier)
        params["code_challenge_method"] = "S256"

    response = AuthResponse(
        body={"url": f"{provider.authorize_url}?{urlencode(params)}", "redirect": True}
    )
    # short-lived signed state cookie, checked on callback (CSRF binding)
    response.set_cookie(
        build_cookie(ctx.auth, sign_value(ctx.auth.secret, state), 300, STATE_COOKIE)
    )
    return response


async def _exchange_code(
    ctx: Ctx, provider: OAuthProvider, code: str, code_verifier: str | None
) -> OAuthTokens:
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": _redirect_uri(ctx, provider),
        "client_id": provider.client_id,
        "client_secret": provider.client_secret,
    }
    if provider.use_pkce and code_verifier:
        data["code_verifier"] = code_verifier
    response = await ctx.auth.http.post(
        provider.token_url, data=data, headers={"accept": "application/json"}
    )
    if response.status_code != 200:
        raise _CallbackError("invalid_code")
    payload = response.json()
    if "access_token" not in payload:
        raise _CallbackError("invalid_code")
    expires_at = None
    if payload.get("expires_in"):
        expires_at = utcnow() + timedelta(seconds=int(payload["expires_in"]))
    return OAuthTokens(
        access_token=payload.get("access_token"),
        refresh_token=payload.get("refresh_token"),
        id_token=payload.get("id_token"),
        scope=payload.get("scope"),
        access_token_expires_at=expires_at,
    )


class _CallbackError(Exception):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


def _error_redirect(ctx: Ctx, error: str, error_url: str | None) -> AuthResponse:
    target = error_url or f"{ctx.auth.base_url}{ctx.auth.base_path}/error"
    separator = "&" if "?" in target else "?"
    return AuthResponse(redirect_to=f"{target}{separator}error={error}")


async def oauth_callback(ctx: Ctx) -> AuthResponse:
    provider = ctx.auth.social_providers.get(ctx.params.get("provider", ""))
    if provider is None:
        return _error_redirect(ctx, "oauth_provider_not_found", None)

    state = ctx.request.query.get("state", "")
    row = (
        await ctx.adapter.find_one("verification", [Where("identifier", state)]) if state else None
    )
    if row is None:
        return _error_redirect(ctx, "state_not_found", None)
    await ctx.adapter.delete_many("verification", [Where("identifier", state)])
    data = json.loads(row["value"])
    error_url = data.get("errorURL") or data.get("callbackURL")

    try:
        if row["expiresAt"] <= utcnow():
            raise _CallbackError("state_invalid")
        if not ctx.auth.skip_state_cookie_check:
            raw = ctx.request.cookies().get(cookie_name(ctx.auth, STATE_COOKIE))
            if raw is None or unsign_value(ctx.auth.secret, raw) != state:
                raise _CallbackError("state_mismatch")
        if ctx.request.query.get("error"):
            raise _CallbackError(ctx.request.query["error"])
        code = ctx.request.query.get("code")
        if not code:
            raise _CallbackError("no_code")

        tokens = await _exchange_code(ctx, provider, code, data.get("codeVerifier"))
        try:
            info = await provider.fetch_user(tokens, ctx.auth.http)
        except httpx.HTTPError:
            raise _CallbackError("unable_to_get_user_info") from None
        if not info.email:
            raise _CallbackError("email_not_found")

        user_id, is_new_user = await _resolve_user(ctx, provider, info, tokens)
    except _CallbackError as err:
        response = _error_redirect(ctx, err.code, error_url)
        response.set_cookie(clear_cookie(ctx.auth, STATE_COOKIE))
        return response

    _session, cookies = await create_session(ctx.auth, user_id, ctx.request)
    target = (
        (data.get("newUserURL") or data.get("callbackURL"))
        if is_new_user
        else data.get("callbackURL")
    )
    response = AuthResponse(redirect_to=_absolute_url(ctx, target or "/"))
    for cookie in [*cookies, clear_cookie(ctx.auth, STATE_COOKIE)]:
        response.set_cookie(cookie)
    return response


def _absolute_url(ctx: Ctx, url: str) -> str:
    return f"{ctx.auth.base_url}{url}" if url.startswith("/") else url


async def _resolve_user(
    ctx: Ctx, provider: OAuthProvider, info: OAuthUserInfo, tokens: OAuthTokens
) -> tuple[str, bool]:
    """Find or create the user + account rows. Returns (user_id, is_new_user)."""
    now = utcnow()
    email = (info.email or "").lower()
    token_fields = {
        "accessToken": tokens.access_token,
        "refreshToken": tokens.refresh_token,
        "idToken": tokens.id_token,
        "accessTokenExpiresAt": tokens.access_token_expires_at,
        "scope": tokens.scope,
    }

    account = await ctx.adapter.find_one(
        "account",
        [Where("providerId", provider.provider_id), Where("accountId", info.id)],
    )
    if account is not None:
        await ctx.adapter.update(
            "account", [Where("id", account["id"])], {**token_fields, "updatedAt": now}
        )
        return account["userId"], False

    user = await ctx.adapter.find_one("user", [Where("email", email)])
    if user is not None and not info.email_verified:
        # refuse to auto-link on an unverified provider email (account takeover guard)
        raise _CallbackError("account_not_linked")
    is_new_user = user is None
    if user is None:
        user = {
            "id": generate_id(),
            "name": info.name or email,
            "email": email,
            "emailVerified": info.email_verified,
            "image": info.image,
            "createdAt": now,
            "updatedAt": now,
        }
        await ctx.auth.run_hook("user_created_before", user)
        await ctx.adapter.create("user", user)
        await ctx.auth.run_hook("user_created_after", user)

    await ctx.adapter.create(
        "account",
        {
            "id": generate_id(),
            "accountId": info.id,
            "providerId": provider.provider_id,
            "userId": user["id"],
            **token_fields,
            "createdAt": now,
            "updatedAt": now,
        },
    )
    return user["id"], is_new_user
