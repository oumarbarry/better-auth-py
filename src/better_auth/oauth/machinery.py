"""Shared OAuth2 primitives — ports of better-auth's ``packages/core/src/oauth2``.

The authorize-URL builder, token exchange and refresh mirror ``create-authorization-url.ts``,
``validate-authorization-code.ts`` and ``refresh-access-token.ts``. Every outbound fetch goes
through :func:`oauth_fetch`, which refuses HTTP redirects (SSRF hardening, ``reject-redirects.ts``).
"""

from __future__ import annotations

import base64
import hashlib
import inspect
import json
import re
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import quote_plus, urlencode

import httpx
import jwt

from ..session import utcnow
from .models import OAuthTokens

#: zod v4 ``z.email()`` pattern (zod/v4/core/regexes.ts ``email``)
_ZOD_EMAIL = re.compile(
    r"(?!\.)(?!.*\.\.)([A-Za-z0-9_'+\-\.]*)[A-Za-z0-9_+-]@([A-Za-z0-9][A-Za-z0-9\-]*\.)+[A-Za-z]{2,}"
)


def create_placeholder_email(*, identifier: str, namespace: str) -> str:
    """TS v1.7.6 core/utils/email.ts ``createPlaceholderEmail`` (b4ad5a110): a stable,
    non-routable ``{identifier}@{namespace}.placeholder.invalid`` (RFC 6761 section 6.4).
    Raises ``TypeError`` when the address fails zod's email check, as TS does."""
    email = f"{identifier}@{namespace}.placeholder.invalid"
    if not _ZOD_EMAIL.fullmatch(email):
        raise TypeError("Invalid placeholder email")
    return email


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


#: create-authorization-url.ts:11-20 RESERVED_AUTHORIZATION_PARAMS: framework-owned keys a
#: caller's ``additional_params`` can never override.
RESERVED_AUTHORIZATION_PARAMS = frozenset(
    {
        "state",
        "client_id",
        "redirect_uri",
        "response_type",
        "code_challenge",
        "code_challenge_method",
        "nonce",
        "scope",
    }
)


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
    nonce: str | None = None,
    hd: str | None = None,
    duration: str | None = None,
    response_mode: str | None = None,
    claims: list[str] | None = None,
    additional_params: dict[str, str] | None = None,
) -> str:
    """Port of ``createAuthorizationURL()`` — builds the ``/authorize`` redirect URL.

    Optional params are emitted only when truthy (omitted, never sent empty). PKCE
    (``code_challenge``/``S256``) is added only when ``code_verifier`` is passed — a
    per-provider decision, not a global flag. ``additional_params`` never override a
    reserved key (TS v1.7.6 create-authorization-url.ts:108-111).
    """
    params: dict[str, str] = {
        "response_type": response_type,
        "client_id": get_primary_client_id(client_id),
        "state": state,
    }
    if scopes:
        params["scope"] = scope_joiner.join(scopes)
    params["redirect_uri"] = redirect_uri
    if duration:
        params["duration"] = duration
    if display:
        params["display"] = display
    if login_hint:
        params["login_hint"] = login_hint
    if nonce:
        params["nonce"] = nonce
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
    for key, value in (additional_params or {}).items():
        if key not in RESERVED_AUTHORIZATION_PARAMS:
            params[key] = value
    # URLSearchParams serialization (``*`` literal, ``~`` escaped)
    query = urlencode(params, quote_via=lambda value, *_: _form_url_encode(str(value)))
    return f"{authorization_endpoint}?{query}"


def _form_url_encode(value: str) -> str:
    """``application/x-www-form-urlencoded`` value encoding (URLSearchParams): space is
    ``+``, ``*`` stays literal, ``~`` is escaped."""
    return quote_plus(value, safe="*").replace("~", "%7E")


def encode_basic_credentials(client_id: str, client_secret: str) -> str:
    """RFC 6749 section 2.3.1 Basic credentials: both halves form-url-encoded before base64
    (TS v1.7.6 basic-credentials.ts:38-44)."""
    payload = f"{_form_url_encode(client_id)}:{_form_url_encode(client_secret)}"
    return "Basic " + base64.b64encode(payload.encode()).decode()


#: client-assertion.ts:74 CLIENT_ASSERTION_TYPE (RFC 7523)
CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
#: client-assertion.ts:6-17 asymmetric algorithms accepted for private_key_jwt
PRIVATE_KEY_JWT_SIGNING_ALGORITHMS = (
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
    "EdDSA",
)


@dataclass
class TokenEndpointAuth:
    """Token endpoint client authentication (TS v1.7.6 token-endpoint-auth.ts).

    ``method`` is one of ``"none"``, ``"client_secret_basic"``, ``"client_secret_post"``,
    ``"private_key_jwt"`` (needs ``get_client_assertion``) or ``"custom"`` (needs
    ``customize_request``). ``get_client_assertion(context)`` receives
    ``{"clientId", "tokenEndpoint", "grantType"}`` and returns the signed JWT (may be async).
    ``customize_request(request)`` receives a mutable ``{"body", "headers", "client_id",
    "client_secret", "token_endpoint", "grant_type"}`` dict after the grant parameters are
    set (may be async).
    """

    method: str
    get_client_assertion: Callable[[dict[str, str]], Any] | None = None
    customize_request: Callable[[dict[str, Any]], Any] | None = None


async def _maybe_await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


def _resolve_private_key_jwt_algorithm(
    jwk: dict[str, Any] | None, pem: str | None, algorithm: str | None
) -> str:
    """client-assertion.ts:43-71 ``resolveValidPrivateKeyJwtOptions``."""
    if not jwk and not pem:
        raise ValueError("private_key_jwt requires either privateKeyJwk or privateKeyPem")
    jwk_alg = (jwk or {}).get("alg")
    for candidate in (algorithm, jwk_alg):
        if isinstance(candidate, str) and candidate not in PRIVATE_KEY_JWT_SIGNING_ALGORITHMS:
            raise ValueError(
                f"Unsupported private_key_jwt signing algorithm: {candidate}. Use one of "
                f"{', '.join(PRIVATE_KEY_JWT_SIGNING_ALGORITHMS)}."
            )
    if algorithm and isinstance(jwk_alg, str) and algorithm != jwk_alg:
        raise ValueError(
            f'JWK alg "{jwk_alg}" does not match configured algorithm "{algorithm}". Remove '
            "the JWK alg field, or pass an algorithm that matches the JWK."
        )
    return algorithm or (jwk_alg if isinstance(jwk_alg, str) else "RS256")


def sign_private_key_jwt_client_assertion(
    *,
    client_id: str,
    token_endpoint: str,
    private_key_jwk: dict[str, Any] | None = None,
    private_key_pem: str | None = None,
    kid: str | None = None,
    algorithm: str | None = None,
    expires_in: int = 120,
) -> str:
    """RFC 7523 client assertion: iss=sub=client_id, aud=token endpoint, 120 s lifetime
    (TS v1.7.6 client-assertion.ts:120-160)."""
    alg = _resolve_private_key_jwt_algorithm(private_key_jwk, private_key_pem, algorithm)
    resolved_kid = kid or (private_key_jwk or {}).get("kid")
    key: Any = jwt.PyJWK.from_dict(private_key_jwk, alg).key if private_key_jwk else private_key_pem
    headers: dict[str, Any] = {"alg": alg, "typ": "JWT"}
    if resolved_kid:
        headers["kid"] = resolved_kid
    now = int(time.time())
    claims = {
        "iss": client_id,
        "sub": client_id,
        "aud": token_endpoint,
        "iat": now,
        "exp": now + expires_in,
        "jti": str(uuid.uuid4()),
    }
    return jwt.encode(claims, key, algorithm=alg, headers=headers)


def create_private_key_jwt_client_assertion_getter(
    *,
    private_key_jwk: dict[str, Any] | None = None,
    private_key_pem: str | None = None,
    kid: str | None = None,
    algorithm: str | None = None,
    expires_in: int = 120,
) -> Callable[[dict[str, str]], str]:
    """client-assertion.ts:170-189: validates eagerly, signs a fresh assertion per request."""
    _resolve_private_key_jwt_algorithm(private_key_jwk, private_key_pem, algorithm)

    def getter(context: dict[str, str]) -> str:
        return sign_private_key_jwt_client_assertion(
            client_id=context["clientId"],
            token_endpoint=context["tokenEndpoint"],
            private_key_jwk=private_key_jwk,
            private_key_pem=private_key_pem,
            kid=kid,
            algorithm=algorithm,
            expires_in=expires_in,
        )

    return getter


async def apply_token_endpoint_auth(
    body: dict[str, Any],
    headers: dict[str, str],
    *,
    client_id: str | list[str] | None,
    client_secret: str | None,
    token_endpoint: str,
    grant_type: str,
    token_endpoint_auth: TokenEndpointAuth | None = None,
    authentication: str | None = None,
) -> None:
    """Port of TS v1.7.6 token-endpoint-auth.ts ``applyTokenEndpointAuth``. A misconfigured
    method raises :class:`OAuthFetchError` (TS throws inside the token request)."""

    def fail(message: str) -> OAuthFetchError:
        return OAuthFetchError(message)

    def assert_complete_assertion() -> None:
        if ("client_assertion" in body) != ("client_assertion_type" in body):
            raise fail("client_assertion and client_assertion_type must both be provided")

    def assert_no_secret(method: str) -> None:
        if client_secret or "client_secret" in body:
            raise fail(
                f"{method} token endpoint authentication cannot be combined with clientSecret"
            )

    def require_client_id(method: str) -> str:
        if not primary:
            raise fail(f"{method} token endpoint authentication requires clientId")
        return primary

    assert_complete_assertion()
    primary = get_primary_client_id(client_id) if client_id else ""
    if "client_assertion" in body:
        if token_endpoint_auth:
            raise fail("client_assertion body parameters cannot be combined with tokenEndpointAuth")
        assert_no_secret("private_key_jwt")
        if primary:
            body["client_id"] = primary
        return

    auth = token_endpoint_auth
    if auth is None:
        if authentication == "basic":
            auth = TokenEndpointAuth("client_secret_basic")
        else:
            auth = TokenEndpointAuth("client_secret_post" if client_secret else "none")
    method = auth.method

    if method == "custom":
        if auth.customize_request is None:
            raise fail("custom token endpoint authentication requires customizeRequest")
        await _maybe_await(
            auth.customize_request(
                {
                    "body": body,
                    "headers": headers,
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "token_endpoint": token_endpoint,
                    "grant_type": grant_type,
                }
            )
        )
        assert_complete_assertion()
        return
    if method == "private_key_jwt":
        assert_no_secret(method)
        cid = require_client_id(method)
        if not token_endpoint:
            raise fail("private_key_jwt token endpoint authentication requires tokenEndpoint")
        if auth.get_client_assertion is None:
            raise fail("private_key_jwt token endpoint authentication requires getClientAssertion")
        assertion = await _maybe_await(
            auth.get_client_assertion(
                {"clientId": cid, "tokenEndpoint": token_endpoint, "grantType": grant_type}
            )
        )
        body["client_id"] = cid
        body["client_assertion"] = assertion
        body["client_assertion_type"] = CLIENT_ASSERTION_TYPE
        return
    if method == "none":
        assert_no_secret(method)
        if grant_type == "client_credentials":
            raise fail(
                "none token endpoint authentication cannot be used with client_credentials grant"
            )
        body["client_id"] = require_client_id(method)
        return
    if method == "client_secret_basic":
        if "client_secret" in body:
            raise fail(
                "client_secret_basic token endpoint authentication cannot be combined with "
                "client_secret body parameters"
            )
        if not client_secret:
            raise fail("client_secret_basic token endpoint authentication requires clientSecret")
        headers["authorization"] = encode_basic_credentials(
            require_client_id(method), client_secret
        )
        return
    # client_secret_post
    if token_endpoint_auth is not None and not client_secret:
        raise fail("client_secret_post token endpoint authentication requires clientSecret")
    if client_secret:
        body["client_id"] = require_client_id("client_secret_post")
        body["client_secret"] = client_secret


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
    token_endpoint_auth: TokenEndpointAuth | None = None,
) -> OAuthTokens:
    """Port of ``validateAuthorizationCode()`` — POST ``grant_type=authorization_code``."""
    body: dict[str, Any] = {"grant_type": "authorization_code", "code": code}
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
    if resource is not None:
        # httpx encodes a list value as repeated keys (RFC 8707 repeatable ``resource``).
        body["resource"] = resource
    for key, value in (additional_params or {}).items():
        body.setdefault(key, value)
    await apply_token_endpoint_auth(
        body,
        req_headers,
        client_id=client_id,
        client_secret=client_secret,
        token_endpoint=token_endpoint,
        grant_type="authorization_code",
        token_endpoint_auth=token_endpoint_auth,
        authentication=authentication,
    )
    response = await oauth_fetch(http, "POST", token_endpoint, data=body, headers=req_headers)
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
    token_endpoint_auth: TokenEndpointAuth | None = None,
) -> OAuthTokens:
    """Port of ``refreshAccessToken()``: POST ``grant_type=refresh_token``. Extra params
    never replace ``grant_type``/``refresh_token``, and client authentication is applied
    after them (TS v1.7.6 refresh-access-token.ts:35-41, 76-83)."""
    body: dict[str, Any] = {"grant_type": "refresh_token", "refresh_token": refresh_token}
    headers = {"content-type": "application/x-www-form-urlencoded", "accept": "application/json"}
    if resource is not None:
        body["resource"] = resource
    for key, value in (extra_params or {}).items():
        if key not in _BLOCKED_REFRESH_TOKEN_PARAMS:
            body[key] = value
    await apply_token_endpoint_auth(
        body,
        headers,
        client_id=client_id,
        client_secret=client_secret,
        token_endpoint=token_endpoint,
        grant_type="refresh_token",
        token_endpoint_auth=token_endpoint_auth,
        authentication=authentication,
    )
    response = await oauth_fetch(http, "POST", token_endpoint, data=body, headers=headers)
    if response.status_code != 200:
        raise OAuthFetchError("refresh token endpoint failed")
    payload = response.json()
    if "access_token" not in payload:
        raise OAuthFetchError("refresh token endpoint failed")
    return get_oauth2_tokens(payload)


_BLOCKED_REFRESH_TOKEN_PARAMS = frozenset({"grant_type", "refresh_token"})


def parse_scope_field(scope: Any) -> list[str]:
    """TS v1.7.6 core/oauth2/utils.ts:13-23 ``parseScopeField``: a space-delimited string or
    an already-split array; empty and non-string entries are dropped."""
    if isinstance(scope, list):
        return [s.strip() for s in scope if isinstance(s, str) and s.strip()]
    if isinstance(scope, str):
        return scope.split()
    return []


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
        scope=scope if isinstance(scope, str) else None,
        scopes=parse_scope_field(scope),
        access_token_expires_at=_expiry(data.get("expires_in")),
        refresh_token_expires_at=_expiry(data.get("refresh_token_expires_in")),
        raw=data,
    )
