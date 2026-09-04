"""Shared OAuth2 primitives — ports of better-auth's ``packages/core/src/oauth2``.

The authorize-URL builder, token exchange and refresh mirror ``create-authorization-url.ts``,
``validate-authorization-code.ts`` and ``refresh-access-token.ts``. Every outbound fetch goes
through :func:`oauth_fetch`, which refuses HTTP redirects (SSRF hardening, ``reject-redirects.ts``).
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import urlencode

import httpx

from ..session import utcnow
from .models import OAuthTokens


class OAuthFetchError(Exception):
    """Raised when an outbound OAuth fetch fails or would follow a redirect."""


async def oauth_fetch(
    http: httpx.AsyncClient, method: str, url: str, **kwargs: Any
) -> httpx.Response:
    """Outbound OAuth request that refuses redirects (SSRF guard, ``reject-redirects.ts``).

    A malicious/self-hosted OAuth endpoint (several providers accept a configurable
    ``authorization_endpoint``/``issuer``) could 3xx a server-side fetch to an internal
    address. We never follow the redirect and raise if one is returned.
    """
    response = await http.request(method, url, follow_redirects=False, **kwargs)
    if response.is_redirect:
        raise OAuthFetchError(
            f'The OAuth endpoint "{url}" returned an HTTP redirect. Server-side OAuth '
            "fetches refuse redirects to prevent SSRF; configure the final endpoint URL."
        )
    return response


def get_primary_client_id(client_id: str | list[str]) -> str:
    """``clientId[0]`` for the multi-audience array form, else ``clientId`` (``utils.ts``)."""
    if isinstance(client_id, list):
        return client_id[0] if client_id else ""
    return client_id


def code_challenge(verifier: str) -> str:
    """PKCE S256 challenge: base64url(SHA-256(verifier)) with no padding."""
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


def build_authorization_url(
    *,
    authorization_endpoint: str,
    client_id: str | list[str],
    state: str,
    redirect_uri: str,
    scopes: list[str] | None = None,
    response_type: str = "code",
    code_verifier: str | None = None,
    scope_joiner: str = " ",
    prompt: str | None = None,
    access_type: str | None = None,
    display: str | None = None,
    login_hint: str | None = None,
    hd: str | None = None,
    duration: str | None = None,
    response_mode: str | None = None,
    claims: list[str] | None = None,
    additional_params: dict[str, str] | None = None,
) -> str:
    """Port of ``createAuthorizationURL()`` — builds the ``/authorize`` redirect URL.

    Optional params are emitted only when truthy (omitted, never sent empty). PKCE
    (``code_challenge``/``S256``) is added only when ``code_verifier`` is passed — a
    per-provider decision, not a global flag.
    """
    params: dict[str, str] = {
        "response_type": response_type,
        "client_id": get_primary_client_id(client_id),
        "state": state,
    }
    if scopes is not None:
        params["scope"] = scope_joiner.join(scopes)
    params["redirect_uri"] = redirect_uri
    if duration:
        params["duration"] = duration
    if display:
        params["display"] = display
    if login_hint:
        params["login_hint"] = login_hint
    if prompt:
        params["prompt"] = prompt
    if hd:
        params["hd"] = hd
    if access_type:
        params["access_type"] = access_type
    if response_mode:
        params["response_mode"] = response_mode
    if code_verifier:
        params["code_challenge_method"] = "S256"
        params["code_challenge"] = code_challenge(code_verifier)
    if claims:
        claims_obj: dict[str, Any] = {"email": None, "email_verified": None}
        for claim in claims:
            claims_obj[claim] = None
        params["claims"] = json.dumps({"id_token": claims_obj}, separators=(",", ":"))
    if additional_params:
        params.update(additional_params)
    return f"{authorization_endpoint}?{urlencode(params)}"


def _client_auth(
    body: dict[str, str],
    headers: dict[str, str],
    client_id: str | list[str],
    client_secret: str,
    authentication: str,
) -> None:
    """Apply ``basic`` (RFC 7617 Authorization header) or ``post`` (body) client auth."""
    primary = get_primary_client_id(client_id)
    if authentication == "basic":
        raw = f"{primary}:{client_secret or ''}".encode()
        headers["authorization"] = "Basic " + base64.b64encode(raw).decode()
    else:
        body["client_id"] = primary
        if client_secret:
            body["client_secret"] = client_secret


def _form(body: dict[str, str], resource: str | list[str] | None) -> dict[str, Any]:
    """Form-urlencoded body as a dict (httpx encodes a list value as repeated keys — this
    is how RFC 8707 repeatable ``resource`` indicators are sent). A dict body is required:
    a *list* passed to httpx ``data=`` builds a sync stream that an AsyncClient rejects."""
    form: dict[str, Any] = dict(body)
    if resource is not None:
        form["resource"] = resource
    return form


def _expiry(seconds: int | None) -> datetime | None:
    return utcnow() + timedelta(seconds=int(seconds)) if seconds else None


async def exchange_code(
    http: httpx.AsyncClient,
    *,
    token_endpoint: str,
    code: str,
    redirect_uri: str,
    client_id: str | list[str],
    client_secret: str,
    code_verifier: str | None = None,
    authentication: str = "post",
    client_key: str | None = None,
    device_id: str | None = None,
    resource: str | list[str] | None = None,
    headers: dict[str, str] | None = None,
    additional_params: dict[str, str] | None = None,
) -> OAuthTokens:
    """Port of ``validateAuthorizationCode()`` — POST ``grant_type=authorization_code``."""
    body: dict[str, str] = {"grant_type": "authorization_code", "code": code}
    if code_verifier:
        body["code_verifier"] = code_verifier
    if client_key:
        body["client_key"] = client_key
    if device_id:
        body["device_id"] = device_id
    body["redirect_uri"] = redirect_uri
    req_headers = {
        "content-type": "application/x-www-form-urlencoded",
        "accept": "application/json",
    }
    if headers:
        req_headers.update(headers)
    _client_auth(body, req_headers, client_id, client_secret, authentication)
    for key, value in (additional_params or {}).items():
        body.setdefault(key, value)
    response = await oauth_fetch(
        http, "POST", token_endpoint, data=_form(body, resource), headers=req_headers
    )
    if response.status_code != 200:
        raise OAuthFetchError(f"token endpoint returned {response.status_code}")
    payload = response.json()
    if "access_token" not in payload:
        raise OAuthFetchError("token response missing access_token")
    return get_oauth2_tokens(payload)


async def refresh_access_token(
    http: httpx.AsyncClient,
    *,
    token_endpoint: str,
    refresh_token: str,
    client_id: str | list[str],
    client_secret: str,
    authentication: str = "post",
    resource: str | list[str] | None = None,
    extra_params: dict[str, str] | None = None,
) -> OAuthTokens:
    """Port of ``refreshAccessToken()`` — POST ``grant_type=refresh_token``."""
    body: dict[str, str] = {"grant_type": "refresh_token", "refresh_token": refresh_token}
    headers = {"content-type": "application/x-www-form-urlencoded", "accept": "application/json"}
    _client_auth(body, headers, client_id, client_secret, authentication)
    for key, value in (extra_params or {}).items():
        body[key] = value
    response = await oauth_fetch(
        http, "POST", token_endpoint, data=_form(body, resource), headers=headers
    )
    if response.status_code != 200:
        raise OAuthFetchError("refresh token endpoint failed")
    payload = response.json()
    if "access_token" not in payload:
        raise OAuthFetchError("refresh token endpoint failed")
    return get_oauth2_tokens(payload)


def get_oauth2_tokens(data: dict[str, Any]) -> OAuthTokens:
    """Port of ``getOAuth2Tokens()`` — normalize a token-endpoint JSON response.

    Preserves the raw response under ``.raw`` so providers can read provider-specific
    fields (e.g. VK/WeChat) without redefining the token shape.
    """
    scope = data.get("scope")
    return OAuthTokens(
        access_token=data.get("access_token"),
        refresh_token=data.get("refresh_token"),
        id_token=data.get("id_token"),
        token_type=data.get("token_type"),
        scope=scope,
        scopes=scope.split(" ") if scope else [],
        access_token_expires_at=_expiry(data.get("expires_in")),
        refresh_token_expires_at=_expiry(data.get("refresh_token_expires_in")),
        raw=data,
    )
