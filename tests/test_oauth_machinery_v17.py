"""OAuth2 primitives at better-auth v1.7.6 (packages/core/src/oauth2)."""

import base64
import json
import time
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import RSAAlgorithm

from better_auth.oauth import verify
from better_auth.oauth.machinery import (
    OAuthFetchError,
    TokenEndpointAuth,
    build_authorization_url,
    create_private_key_jwt_client_assertion_getter,
    encode_basic_credentials,
    exchange_code,
    get_oauth2_tokens,
    refresh_access_token,
)
from better_auth.oauth.verify import verify_id_token


@pytest.fixture(autouse=True)
def _reset_jwks_cache():
    verify._cache._cache.clear()
    verify._cache._last_miss.clear()
    yield


def _query(url: str) -> dict[str, list[str]]:
    return parse_qs(urlsplit(url).query)


# --- create-authorization-url.ts ------------------------------------------------------


def test_authorization_url_drops_reserved_additional_params():
    # create-authorization-url.ts:108-111 skips RESERVED_AUTHORIZATION_PARAMS
    url = build_authorization_url(
        authorization_endpoint="https://idp/authorize",
        client_id="cid",
        state="s1",
        redirect_uri="https://app/cb",
        scopes=["openid"],
        additional_params={"state": "evil", "nonce": "evil", "scope": "x", "hd": "corp"},
    )
    q = _query(url)
    assert q["state"] == ["s1"]
    assert q["scope"] == ["openid"]
    assert "nonce" not in q
    assert q["hd"] == ["corp"]


def test_authorization_url_nonce_param_and_empty_scopes_omitted():
    url = build_authorization_url(
        authorization_endpoint="https://idp/authorize",
        client_id="cid",
        state="s1",
        redirect_uri="https://app/cb",
        scopes=[],
        nonce="n-1",
    )
    q = _query(url)
    assert q["nonce"] == ["n-1"]
    assert "scope" not in q  # `if (scopes?.length)`


# --- utils.ts getOAuth2Tokens / parseScopeField ----------------------------------------


def test_scope_field_accepts_array_and_collapses_whitespace():
    assert get_oauth2_tokens({"access_token": "a", "scope": ["a", " b ", 3, ""]}).scopes == [
        "a",
        "b",
    ]
    assert get_oauth2_tokens({"access_token": "a", "scope": " a   b "}).scopes == ["a", "b"]
    assert get_oauth2_tokens({"access_token": "a"}).scopes == []


# --- basic-credentials.ts ---------------------------------------------------------------


def test_basic_credentials_are_form_url_encoded_before_base64():
    header = encode_basic_credentials("id with space", "s:e~c*r!")
    raw = base64.b64decode(header.removeprefix("Basic ")).decode()
    assert raw == "id+with+space:s%3Ae%7Ec*r%21"


# --- token-endpoint-auth.ts ------------------------------------------------------------


def _capture():
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = parse_qs(request.content.decode())
        seen["headers"] = request.headers
        return httpx.Response(200, json={"access_token": "at", "refresh_token": "rt"})

    return seen, httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_refresh_extra_params_cannot_override_protected_keys():
    # refresh-access-token.ts:35-41 BLOCKED_REFRESH_TOKEN_PARAMS; client auth set after
    seen, http = _capture()
    await refresh_access_token(
        http,
        token_endpoint="https://idp/token",
        refresh_token="rt-1",
        client_id="cid",
        client_secret="sec",
        extra_params={
            "grant_type": "password",
            "refresh_token": "x",
            "client_id": "evil",
            "scope": "org:1",
        },
    )
    body = seen["body"]
    assert body["grant_type"] == ["refresh_token"]
    assert body["refresh_token"] == ["rt-1"]
    assert body["client_id"] == ["cid"]
    assert body["scope"] == ["org:1"]


async def test_private_key_jwt_sends_client_assertion_not_secret():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(RSAAlgorithm.to_jwk(key, as_dict=False))
    jwk["kid"] = "k1"
    getter = create_private_key_jwt_client_assertion_getter(private_key_jwk=jwk)
    seen, http = _capture()
    await exchange_code(
        http,
        token_endpoint="https://idp/token",
        code="c",
        redirect_uri="https://app/cb",
        client_id="cid",
        client_secret="",
        token_endpoint_auth=TokenEndpointAuth(
            method="private_key_jwt", get_client_assertion=getter
        ),
    )
    body = seen["body"]
    assert "client_secret" not in body
    assert body["client_id"] == ["cid"]
    assert body["client_assertion_type"] == [
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    ]
    assertion = body["client_assertion"][0]
    header = jwt.get_unverified_header(assertion)
    assert header == {"alg": "RS256", "typ": "JWT", "kid": "k1"}
    claims = jwt.decode(
        assertion, key.public_key(), algorithms=["RS256"], audience="https://idp/token"
    )
    assert claims["iss"] == claims["sub"] == "cid"
    assert claims["exp"] - claims["iat"] == 120
    assert claims["jti"]


async def test_secretless_auth_combined_with_secret_is_refused():
    _seen, http = _capture()
    with pytest.raises(OAuthFetchError):
        await exchange_code(
            http,
            token_endpoint="https://idp/token",
            code="c",
            redirect_uri="https://app/cb",
            client_id="cid",
            client_secret="sec",
            token_endpoint_auth=TokenEndpointAuth(method="none"),
        )


async def test_custom_token_request_authentication_hook():
    # token-endpoint-auth.ts (3e9e19746): `custom` customizes the finished request
    seen, http = _capture()

    async def customize(request: dict[str, Any]) -> None:
        assert request["grant_type"] == "authorization_code"
        assert request["token_endpoint"] == "https://idp/token"
        request["body"]["client_key"] = "ck"
        request["headers"]["x-sig"] = "1"

    await exchange_code(
        http,
        token_endpoint="https://idp/token",
        code="c",
        redirect_uri="https://app/cb",
        client_id="cid",
        client_secret="sec",
        token_endpoint_auth=TokenEndpointAuth(method="custom", customize_request=customize),
    )
    assert seen["body"]["client_key"] == ["ck"]
    assert "client_secret" not in seen["body"]
    assert seen["headers"]["x-sig"] == "1"


async def test_basic_auth_uses_encoded_credentials():
    seen, http = _capture()
    await exchange_code(
        http,
        token_endpoint="https://idp/token",
        code="c",
        redirect_uri="https://app/cb",
        client_id="c id",
        client_secret="s",
        authentication="basic",
    )
    assert seen["headers"]["authorization"] == encode_basic_credentials("c id", "s")
    assert "client_id" not in seen["body"]


# --- verify-id-token.ts: algorithm allowlist + every key matching the kid ----------------


def _signed(key: Any, alg: str, kid: str, **claims: Any) -> str:
    now = int(time.time())
    payload = {"iss": "https://idp", "aud": "cid", "sub": "s", "iat": now, "exp": now + 600}
    payload.update(claims)
    return jwt.encode(payload, key, algorithm=alg, headers={"kid": kid})


def _jwks_http(keys: list[dict[str, Any]]) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"keys": keys}))
    )


async def test_verifier_rejects_alg_outside_allowlist():
    key = ec.generate_private_key(ec.SECP256R1())
    from jwt.algorithms import ECAlgorithm

    jwk = json.loads(ECAlgorithm.to_jwk(key.public_key(), as_dict=False))
    jwk["kid"] = "e1"
    token = _signed(key, "ES256", "e1")
    http = _jwks_http([jwk])
    common: dict[str, Any] = {
        "jwks_uri": "https://idp/jwks",
        "audience": "cid",
        "issuers": ["https://idp"],
    }
    assert await verify_id_token(http, token, **common) is not None
    assert await verify_id_token(http, token, algorithms=["RS256"], **common) is None


async def test_verifier_tries_every_key_sharing_the_kid():
    # google.ts:107-125 loops over every JWK that matches the kid
    good = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    stale = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    keys = []
    for k in (stale, good):
        jwk = json.loads(RSAAlgorithm.to_jwk(k.public_key(), as_dict=False))
        jwk["kid"] = "same"
        keys.append(jwk)
    token = _signed(good, "RS256", "same")
    claims = await verify_id_token(
        _jwks_http(keys),
        token,
        jwks_uri="https://idp/jwks",
        audience="cid",
        issuers=["https://idp"],
        algorithms=["RS256"],
    )
    assert claims is not None and claims["sub"] == "s"


async def test_verifier_nonce_exact_or_sha256():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key(), as_dict=False))
    jwk["kid"] = "k"
    import hashlib

    token = _signed(key, "RS256", "k", nonce=hashlib.sha256(b"raw").hexdigest())
    common: dict[str, Any] = {
        "jwks_uri": "https://idp/jwks",
        "audience": "cid",
        "issuers": ["https://idp"],
    }
    http = _jwks_http([jwk])
    assert await verify_id_token(http, token, nonce="raw", **common) is None
    assert (
        await verify_id_token(
            http, token, nonce="raw", nonce_comparison="exact-or-sha256", **common
        )
        is not None
    )
