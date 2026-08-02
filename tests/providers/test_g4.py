"""W2-B-G4 — the four quirkiest social providers: apple, facebook, microsoft, paypal.

Each provider is exercised directly (not through the full HTTP flow): authorize-URL
shape, id-token verification with self-built JWKS fixtures, profile mapping, and the
per-provider quirks that motivated the port.
"""

from __future__ import annotations

import json
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import jwt.algorithms
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa

from better_auth.oauth import verify
from better_auth.oauth.models import OAuthTokens
from better_auth.oauth.providers_ext.apple import Apple
from better_auth.oauth.providers_ext.facebook import Facebook
from better_auth.oauth.providers_ext.microsoft_entra_id import MicrosoftEntraId
from better_auth.oauth.providers_ext.paypal import Paypal

KID = "test-key"


@pytest.fixture(autouse=True)
def _reset_jwks_cache():
    verify._cache._cache.clear()
    verify._cache._last_miss.clear()
    yield


# --- key / token helpers ----------------------------------------------------------------


def _rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _rsa_jwk(private_key, kid=KID):
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private_key.public_key()))
    jwk.update(kid=kid, alg="RS256", use="sig")
    return jwk


def _ec_key():
    return ec.generate_private_key(ec.SECP256R1())


def _ec_jwk(private_key, kid=KID):
    jwk = json.loads(jwt.algorithms.ECAlgorithm.to_jwk(private_key.public_key()))
    jwk.update(kid=kid, alg="ES256", use="sig")
    return jwk


def _now_claims(**extra):
    now = int(time.time())
    return {"iat": now, "exp": now + 3600, **extra}


def _sign(claims, key, alg, kid=KID):
    return jwt.encode(claims, key, algorithm=alg, headers={"kid": kid})


def _mock_http(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _jwks_http(jwks_path, jwks, routes=None):
    routes = routes or {}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == jwks_path:
            return httpx.Response(200, json={"keys": jwks})
        if path in routes:
            return routes[path](request)
        return httpx.Response(404)

    return _mock_http(handler)


# ===================================================================================
# Apple
# ===================================================================================


def test_apple_authorization_url_form_post():
    provider = Apple(client_id="service.example.app", client_secret="secret")
    url = provider.authorization_url(state="st", redirect_uri="https://app/cb")
    parts = urlsplit(url)
    query = parse_qs(parts.query)
    assert parts.netloc == "appleid.apple.com"
    assert parts.path == "/auth/authorize"
    # default scopes email+name require Apple's form_post response mode.
    assert query["response_mode"] == ["form_post"]
    assert query["response_type"] == ["code id_token"]
    assert query["scope"] == ["email name"]
    assert query["client_id"] == ["service.example.app"]


def test_apple_authorization_url_requires_client_secret():
    provider = Apple(client_id="service.example.app", client_secret="")
    with pytest.raises(ValueError, match="CLIENT_ID_AND_SECRET_REQUIRED"):
        provider.authorization_url(state="st", redirect_uri="https://app/cb")


async def test_apple_verify_id_token_raw_nonce():
    key = _ec_key()
    token = _sign(
        _now_claims(
            sub="apple-user",
            email="u@example.com",
            aud="com.example.app",
            iss="https://appleid.apple.com",
            nonce="raw-nonce",
        ),
        key,
        "ES256",
    )
    provider = Apple(
        client_id="service.example.app",
        client_secret="secret",
        app_bundle_identifier="com.example.app",
        audience="com.example.app",
    )
    http = _jwks_http("/auth/keys", [_ec_jwk(key)])
    claims = await provider.verify_id_token(http, token, "raw-nonce")
    assert claims is not None
    assert claims["sub"] == "apple-user"


async def test_apple_verify_id_token_hashed_nonce_fallback():
    import hashlib

    raw = "raw-native-ios-nonce"
    hashed = hashlib.sha256(raw.encode()).hexdigest()
    key = _ec_key()
    provider = Apple(
        client_id="service.example.app",
        client_secret="secret",
        audience="com.example.app",
    )
    http = _jwks_http("/auth/keys", [_ec_jwk(key)])
    token2 = _sign(
        _now_claims(
            sub="u",
            aud="com.example.app",
            iss="https://appleid.apple.com",
            nonce=hashed,
        ),
        key,
        "ES256",
    )
    assert await provider.verify_id_token(http, token2, raw) is not None


async def test_apple_verify_id_token_mismatched_nonce():
    key = _ec_key()
    token = _sign(
        _now_claims(
            sub="u",
            aud="com.example.app",
            iss="https://appleid.apple.com",
            nonce="whatever",
        ),
        key,
        "ES256",
    )
    provider = Apple(
        client_id="service.example.app",
        client_secret="secret",
        audience="com.example.app",
    )
    http = _jwks_http("/auth/keys", [_ec_jwk(key)])
    assert await provider.verify_id_token(http, token, "different") is None


async def test_apple_verify_coerces_email_verified_to_bool():
    key = _ec_key()
    token = _sign(
        _now_claims(
            sub="u",
            aud="com.example.app",
            iss="https://appleid.apple.com",
            email_verified="true",
            is_private_email="false",
        ),
        key,
        "ES256",
    )
    provider = Apple(
        client_id="service.example.app",
        client_secret="secret",
        audience="com.example.app",
    )
    http = _jwks_http("/auth/keys", [_ec_jwk(key)])
    claims = await provider.verify_id_token(http, token)
    assert claims is not None
    # both coerced to real bools (matches TS Boolean(): any non-empty string -> True)
    assert claims["email_verified"] is True
    assert claims["is_private_email"] is True


def test_apple_user_info_mapping():
    provider = Apple(client_id="cid", client_secret="s")
    info = provider.user_info_from_id_token(
        {"sub": "abc", "email": "u@x.com", "name": "Jane", "email_verified": "true"}
    )
    assert info.id == "abc"
    assert info.email == "u@x.com"
    assert info.name == "Jane"
    assert info.email_verified is True


def test_apple_generate_client_secret_es256():
    key = _ec_key()
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    secret = Apple.generate_client_secret(
        client_id="service.example.app",
        team_id="TEAM123",
        key_id="KEY456",
        private_key=pem,
    )
    header = jwt.get_unverified_header(secret)
    assert header["alg"] == "ES256"
    assert header["kid"] == "KEY456"
    # decodable/verifiable with the matching public key + exact claims.
    claims = jwt.decode(
        secret,
        key.public_key(),
        algorithms=["ES256"],
        audience="https://appleid.apple.com",
    )
    assert claims["iss"] == "TEAM123"
    assert claims["sub"] == "service.example.app"
    assert claims["aud"] == "https://appleid.apple.com"
    assert claims["exp"] > claims["iat"]
    assert claims["exp"] - claims["iat"] == 180 * 24 * 60 * 60


# ===================================================================================
# Facebook
# ===================================================================================


def test_facebook_authorization_url():
    provider = Facebook(client_id="fbapp", client_secret="secret", config_id="cfg1")
    url = provider.authorization_url(state="st", redirect_uri="https://app/cb")
    parts = urlsplit(url)
    query = parse_qs(parts.query)
    assert parts.netloc == "www.facebook.com"
    assert parts.path == "/v24.0/dialog/oauth"
    assert query["scope"] == ["email public_profile"]
    assert query["config_id"] == ["cfg1"]


async def test_facebook_verify_limited_login_jwt():
    key = _rsa_key()
    token = _sign(
        _now_claims(
            sub="fb-user",
            aud="fbapp",
            iss="https://www.facebook.com",
            nonce="n1",
        ),
        key,
        "RS256",
    )
    provider = Facebook(client_id="fbapp", client_secret="secret")
    http = _jwks_http("/.well-known/oauth/openid/jwks/", [_rsa_jwk(key)])
    claims = await provider.verify_id_token(http, token, "n1")
    assert claims is not None
    assert claims["sub"] == "fb-user"


async def test_facebook_verify_opaque_access_token_via_debug_token():
    def debug_token(request: httpx.Request) -> httpx.Response:
        q = parse_qs(request.url.query.decode())
        assert q["input_token"] == ["opaque-abc"]
        assert q["access_token"] == ["fbapp|secret"]
        return httpx.Response(
            200,
            json={"data": {"is_valid": True, "app_id": "fbapp", "user_id": "u-42"}},
        )

    provider = Facebook(client_id="fbapp", client_secret="secret")
    http = _jwks_http("/__none__", [], routes={"/debug_token": debug_token})
    result = await provider.verify_id_token(http, "opaque-abc")
    assert result == {"user_id": "u-42"}


async def test_facebook_verify_opaque_rejects_wrong_app():
    def debug_token(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"data": {"is_valid": True, "app_id": "other-app", "user_id": "u-1"}},
        )

    provider = Facebook(client_id="fbapp", client_secret="secret")
    http = _jwks_http("/__none__", [], routes={"/debug_token": debug_token})
    assert await provider.verify_id_token(http, "opaque-abc") is None


async def test_facebook_fetch_user_limited_login():
    profile = {"sub": "fb-1", "name": "Zed", "email": "z@x.com", "picture": "http://p"}
    token = _sign(profile, _rsa_key(), "RS256")  # decoded unverified in fetch_user
    provider = Facebook(client_id="fbapp", client_secret="secret")
    http = _mock_http(lambda r: httpx.Response(404))
    info = await provider.fetch_user(OAuthTokens(id_token=token), http)
    assert info.id == "fb-1"
    assert info.email == "z@x.com"
    assert info.email_verified is False


async def test_facebook_fetch_user_graph_path():
    def debug_token(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"data": {"is_valid": True, "app_id": "fbapp", "user_id": "g-9"}},
        )

    def me(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "id": "g-9",
                "name": "Graph User",
                "email": "g@x.com",
                "email_verified": True,
                "picture": {"data": {"url": "http://avatar"}},
            },
        )

    provider = Facebook(client_id="fbapp", client_secret="secret")
    http = _jwks_http("/__none__", [], routes={"/debug_token": debug_token, "/me": me})
    info = await provider.fetch_user(OAuthTokens(access_token="opaque"), http)
    assert info.id == "g-9"
    assert info.image == "http://avatar"
    assert info.email_verified is True


# ===================================================================================
# Microsoft Entra ID
# ===================================================================================


def test_microsoft_authorization_url_tenant_in_endpoint():
    provider = MicrosoftEntraId(client_id="msapp", client_secret="", tenant_id="my-tenant")
    url = provider.authorization_url(
        state="st", redirect_uri="https://app/cb", code_verifier="verifier123"
    )
    parts = urlsplit(url)
    query = parse_qs(parts.query)
    assert parts.netloc == "login.microsoftonline.com"
    assert parts.path == "/my-tenant/oauth2/v2.0/authorize"
    assert "openid" in query["scope"][0]
    assert "User.Read" in query["scope"][0]
    # PKCE forwarded.
    assert query["code_challenge_method"] == ["S256"]


def test_microsoft_authority_trailing_slash_trimmed():
    provider = MicrosoftEntraId(
        client_id="msapp", authority="https://login.microsoftonline.com/", tenant_id="t1"
    )
    assert provider.authorization_endpoint == (
        "https://login.microsoftonline.com/t1/oauth2/v2.0/authorize"
    )
    assert provider.jwks_url == ("https://login.microsoftonline.com/t1/discovery/v2.0/keys")


async def test_microsoft_verify_specific_tenant():
    key = _rsa_key()
    tid = "my-tenant"
    iss = f"https://login.microsoftonline.com/{tid}/v2.0"
    token = _sign(
        _now_claims(sub="ms-user", aud="msapp", tid=tid, iss=iss, name="M"),
        key,
        "RS256",
    )
    provider = MicrosoftEntraId(client_id="msapp", tenant_id=tid)
    http = _jwks_http(f"/{tid}/discovery/v2.0/keys", [_rsa_jwk(key)])
    claims = await provider.verify_id_token(http, token)
    assert claims is not None
    assert claims["tid"] == tid


async def test_microsoft_verify_common_tenant_tid_crosscheck():
    key = _rsa_key()
    tid = "abcd-tenant-guid"
    iss = f"https://login.microsoftonline.com/{tid}/v2.0"
    token = _sign(_now_claims(sub="u", aud="msapp", tid=tid, iss=iss), key, "RS256")
    provider = MicrosoftEntraId(client_id="msapp")  # tenant defaults to "common"
    http = _jwks_http("/common/discovery/v2.0/keys", [_rsa_jwk(key)])
    assert await provider.verify_id_token(http, token) is not None


async def test_microsoft_organizations_rejects_consumer_tenant():
    key = _rsa_key()
    consumer = "9188040d-6c67-4c5b-b112-36a304b66dad"
    iss = f"https://login.microsoftonline.com/{consumer}/v2.0"
    token = _sign(_now_claims(sub="u", aud="msapp", tid=consumer, iss=iss), key, "RS256")
    provider = MicrosoftEntraId(client_id="msapp", tenant_id="organizations")
    http = _jwks_http("/organizations/discovery/v2.0/keys", [_rsa_jwk(key)])
    assert await provider.verify_id_token(http, token) is None


async def test_microsoft_consumers_requires_consumer_tenant():
    key = _rsa_key()
    tid = "some-work-tenant"
    iss = f"https://login.microsoftonline.com/{tid}/v2.0"
    token = _sign(_now_claims(sub="u", aud="msapp", tid=tid, iss=iss), key, "RS256")
    provider = MicrosoftEntraId(client_id="msapp", tenant_id="consumers")
    http = _jwks_http("/consumers/discovery/v2.0/keys", [_rsa_jwk(key)])
    assert await provider.verify_id_token(http, token) is None


async def test_microsoft_fetch_user_email_verified_fallback():
    claims = {
        "sub": "ms-1",
        "name": "Verified User",
        "email": "v@x.com",
        "verified_primary_email": ["v@x.com"],
    }
    token = _sign(claims, _rsa_key(), "RS256")
    provider = MicrosoftEntraId(client_id="msapp", disable_profile_photo=True)
    http = _mock_http(lambda r: httpx.Response(404))
    info = await provider.fetch_user(OAuthTokens(id_token=token), http)
    assert info.id == "ms-1"
    # no email_verified claim, but email is in verified_primary_email -> True
    assert info.email_verified is True


# ===================================================================================
# PayPal
# ===================================================================================


def test_paypal_authorization_url_sandbox_empty_scope():
    provider = Paypal(client_id="ppclient", client_secret="secret")  # sandbox default
    url = provider.authorization_url(
        state="st", redirect_uri="https://app/cb", code_verifier="verifier123"
    )
    parts = urlsplit(url)
    query = parse_qs(parts.query, keep_blank_values=True)
    assert parts.netloc == "www.sandbox.paypal.com"
    assert parts.path == "/signin/authorize"
    # empty scope param (permissions live in the PayPal dashboard)
    assert query["scope"] == [""]
    assert query["code_challenge_method"] == ["S256"]


def test_paypal_live_endpoints():
    provider = Paypal(client_id="c", client_secret="s", environment="live")
    assert provider.authorization_endpoint == "https://www.paypal.com/signin/authorize"
    assert provider.token_endpoint == "https://api-m.paypal.com/v1/oauth2/token"
    assert provider.jwks_url == "https://api.paypal.com/v1/oauth2/certs"
    assert provider._issuer == "https://www.paypal.com"


async def test_paypal_verify_rs256_via_jwks():
    key = _rsa_key()
    token = _sign(
        _now_claims(
            sub="pp-user",
            aud="ppclient",
            iss="https://www.sandbox.paypal.com",
        ),
        key,
        "RS256",
    )
    provider = Paypal(client_id="ppclient", client_secret="secret")
    http = _jwks_http("/v1/oauth2/certs", [_rsa_jwk(key)])
    claims = await provider.verify_id_token(http, token)
    assert claims is not None
    assert claims["sub"] == "pp-user"


async def test_paypal_verify_hs256_via_client_secret():
    secret = "shared-hmac-secret-at-least-32-bytes-long"
    token = _sign(
        _now_claims(sub="pp-hs", aud="ppclient", iss="https://www.sandbox.paypal.com"),
        secret,
        "HS256",
    )
    provider = Paypal(client_id="ppclient", client_secret=secret)
    http = _mock_http(lambda r: httpx.Response(404))  # no JWKS fetch for HS256
    claims = await provider.verify_id_token(http, token)
    assert claims is not None
    assert claims["sub"] == "pp-hs"


async def test_paypal_verify_rejects_unlisted_algorithm():
    key = _ec_key()
    token = _sign(
        _now_claims(sub="u", aud="ppclient", iss="https://www.sandbox.paypal.com"),
        key,
        "ES256",
    )
    provider = Paypal(client_id="ppclient", client_secret="secret")
    http = _jwks_http("/v1/oauth2/certs", [_ec_jwk(key)])
    assert await provider.verify_id_token(http, token) is None


async def test_paypal_exchange_basic_auth_no_code_verifier():
    captured = {}

    def token_endpoint(request: httpx.Request) -> httpx.Response:
        captured["auth"] = request.headers.get("authorization")
        captured["body"] = request.content.decode()
        return httpx.Response(
            200,
            json={
                "access_token": "pp-access",
                "refresh_token": "pp-refresh",
                "expires_in": 3600,
                "id_token": "pp-id",
            },
        )

    provider = Paypal(client_id="ppclient", client_secret="secret")
    http = _jwks_http("/__none__", [], routes={"/v1/oauth2/token": token_endpoint})
    tokens = await provider.exchange(
        http, code="the-code", redirect_uri="https://app/cb", code_verifier="v123"
    )
    assert tokens.access_token == "pp-access"
    assert tokens.id_token == "pp-id"
    assert captured["auth"].startswith("Basic ")
    # PayPal's exchange body deliberately omits code_verifier.
    assert "code_verifier" not in captured["body"]
    assert "grant_type=authorization_code" in captured["body"]


async def test_paypal_fetch_user_sub_binding():
    id_token = _sign({"sub": "pp-sub"}, _rsa_key(), "RS256")

    def userinfo(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "user_id": "pp-sub",
                "sub": "pp-sub",
                "name": "Pay Pal",
                "email": "p@x.com",
                "email_verified": True,
                "picture": "http://pp",
            },
        )

    provider = Paypal(client_id="ppclient", client_secret="secret")
    http = _jwks_http("/__none__", [], routes={"/v1/identity/oauth2/userinfo": userinfo})
    info = await provider.fetch_user(OAuthTokens(access_token="a", id_token=id_token), http)
    assert info.id == "pp-sub"
    assert info.email == "p@x.com"
    assert info.email_verified is True


async def test_paypal_fetch_user_rejects_subject_mismatch():
    id_token = _sign({"sub": "real-sub"}, _rsa_key(), "RS256")

    def userinfo(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"user_id": "other-sub", "email": "p@x.com"})

    provider = Paypal(client_id="ppclient", client_secret="secret")
    http = _jwks_http("/__none__", [], routes={"/v1/identity/oauth2/userinfo": userinfo})
    from better_auth.oauth.machinery import OAuthFetchError

    with pytest.raises(OAuthFetchError):
        await provider.fetch_user(OAuthTokens(access_token="a", id_token=id_token), http)
