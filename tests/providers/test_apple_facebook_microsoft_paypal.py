"""The four quirkiest social providers: apple, facebook, microsoft, paypal.

Each provider is exercised directly (not through the full HTTP flow): authorize-URL
shape, id-token verification with self-built JWKS fixtures, profile mapping, and the
per-provider quirks that motivated the port.
"""

from __future__ import annotations

import base64
import hashlib
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


def test_apple_authorization_url_sends_pkce_challenge():
    """TS 0ffd1fb28 — apple.ts forwards ``codeVerifier`` to ``createAuthorizationURL``."""
    provider = Apple(client_id="service.example.app", client_secret="secret")
    url = provider.authorization_url(
        state="st", redirect_uri="https://app/cb", code_verifier="apple-code-verifier"
    )
    query = parse_qs(urlsplit(url).query)
    expected = (
        base64.urlsafe_b64encode(hashlib.sha256(b"apple-code-verifier").digest())
        .decode()
        .rstrip("=")
    )
    assert query["code_challenge_method"] == ["S256"]
    assert query["code_challenge"] == [expected]
    assert "code_verifier" not in query


def test_apple_authorization_url_omits_pkce_without_verifier():
    provider = Apple(client_id="service.example.app", client_secret="secret")
    url = provider.authorization_url(state="st", redirect_uri="https://app/cb", code_verifier="")
    query = parse_qs(urlsplit(url).query)
    assert "code_challenge_method" not in query
    assert "code_challenge" not in query


async def test_apple_token_exchange_sends_code_verifier():
    """The challenge is only usable if the callback exchange carries the verifier
    (TS ``apple.validateAuthorizationCode`` forwards ``codeVerifier``)."""
    seen: dict[str, list[str]] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(parse_qs(request.content.decode()))
        return httpx.Response(200, json={"access_token": "at"})

    provider = Apple(client_id="service.example.app", client_secret="secret")
    await provider.exchange(
        _mock_http(handler),
        code="the-code",
        redirect_uri="https://app/cb",
        code_verifier="apple-code-verifier",
    )
    assert seen["code_verifier"] == ["apple-code-verifier"]


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


async def test_apple_verify_keeps_string_email_verified():
    """TS v1.7.6 apple.ts:125-136 declares an ``idToken`` config: the shared verifier no
    longer rewrites claims, so a string ``"false"`` stays unverified (apple.ts:168-171)."""
    key = _ec_key()
    token = _sign(
        _now_claims(
            sub="u",
            aud="com.example.app",
            iss="https://appleid.apple.com",
            email="u@x.com",
            email_verified="false",
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
    assert claims["email_verified"] == "false"
    assert provider.user_info_from_id_token(claims).email_verified is False


def test_apple_authorization_url_forwards_additional_params():
    # TS v1.7.6 apple.ts:112 forwards the per-request additionalParams (e7eb45b06).
    provider = Apple(client_id="svc", client_secret="s", authorize_params={"a": "config"})
    url = provider.authorization_url(
        state="st", redirect_uri="https://app/cb", additional_params={"a": "req", "b": "2"}
    )
    query = parse_qs(urlsplit(url).query)
    assert query["a"] == ["req"]
    assert query["b"] == ["2"]


@pytest.mark.parametrize(
    "provider",
    [
        Apple(client_id="c", client_secret="s", disable_id_token_sign_in=True),
        Facebook(client_id="c", client_secret="s", disable_id_token_sign_in=True),
        MicrosoftEntraId(client_id="c", disable_id_token_sign_in=True),
    ],
)
def test_disable_id_token_sign_in_reports_unsupported(provider):
    # TS v1.7.6 oauth2/verify-id-token.ts:41-47 supportsIdTokenSignIn: the route answers
    # ID_TOKEN_NOT_SUPPORTED instead of INVALID_TOKEN.
    assert provider.supports_id_token is False


def test_apple_user_info_mapping():
    provider = Apple(client_id="cid", client_secret="s")
    info = provider.user_info_from_id_token(
        {"sub": "abc", "email": "u@x.com", "name": "Jane", "email_verified": "true"}
    )
    assert info.id == "abc"
    assert info.email == "u@x.com"
    assert info.name == "Jane"
    assert info.email_verified is True


def _apple_id_token(**claims):
    return jwt.encode(
        {"sub": "apple-user", "email": "user@example.com", "email_verified": "true", **claims},
        "unused-signing-key-at-least-32-bytes-long",
        algorithm="HS256",
    )


async def test_apple_fetch_user_uses_form_post_user_name():
    """TS apple.ts:198-206 -- ``token.user?.name`` (the base callback's form_post payload,
    threaded onto ``tokens.user`` in oauth/flow.py) overrides the id-token-derived name."""
    provider = Apple(client_id="cid", client_secret="s")
    tokens = OAuthTokens(
        id_token=_apple_id_token(), user={"name": {"firstName": "Jane", "lastName": "Doe"}}
    )
    info = await provider.fetch_user(tokens, httpx.AsyncClient())
    assert info.name == "Jane Doe"


async def test_apple_fetch_user_falls_back_to_id_token_name_without_user():
    """No ``tokens.user`` (e.g. a returning user's second+ consent) -> the id-token ``name``
    claim, matching apple.ts:204-205's else branch."""
    provider = Apple(client_id="cid", client_secret="s")
    tokens = OAuthTokens(id_token=_apple_id_token(name="Existing Name"))
    info = await provider.fetch_user(tokens, httpx.AsyncClient())
    assert info.name == "Existing Name"


async def test_apple_fetch_user_only_first_name():
    """TS apple.ts:200-202 -- a missing ``lastName`` folds to ``""`` and the join trims the
    trailing space, so a lone ``firstName`` survives on its own."""
    provider = Apple(client_id="cid", client_secret="s")
    tokens = OAuthTokens(id_token=_apple_id_token(), user={"name": {"firstName": "Jane"}})
    info = await provider.fetch_user(tokens, httpx.AsyncClient())
    assert info.name == "Jane"


async def test_apple_fetch_user_only_last_name():
    """Mirror of the above for a missing ``firstName``."""
    provider = Apple(client_id="cid", client_secret="s")
    tokens = OAuthTokens(id_token=_apple_id_token(), user={"name": {"lastName": "Doe"}})
    info = await provider.fetch_user(tokens, httpx.AsyncClient())
    assert info.name == "Doe"


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


def _graph_routes(user_id="g-9", app_id="fbapp"):
    def debug_token(request: httpx.Request) -> httpx.Response:
        q = parse_qs(request.url.query.decode())
        assert q["input_token"] == ["real-access"]
        return httpx.Response(
            200, json={"data": {"is_valid": True, "app_id": app_id, "user_id": user_id}}
        )

    def me(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer real-access"
        return httpx.Response(
            200,
            json={
                "id": user_id,
                "name": "Graph User",
                "email": "g@x.com",
                "picture": {"data": {"url": "http://avatar"}},
            },
        )

    return {"/debug_token": debug_token, "/me": me}


async def _facebook_id_token_sign_in(id_token, app_id="fbapp"):
    from conftest import make_auth, make_client

    auth = make_auth(
        social_providers={"facebook": Facebook(client_id="fbapp", client_secret="secret")},
        http_client=_jwks_http("/__none__", [], routes=_graph_routes(app_id=app_id)),
    )
    async with make_client(auth) as client:
        r = await client.post(
            "/api/auth/sign-in/social", json={"provider": "facebook", "idToken": id_token}
        )
    return auth, r


async def test_facebook_opaque_token_resolves_identity_from_access_token():
    """TS v1.7.6 facebook.ts:151-162 ``allowOpaqueToken``: an opaque idToken passes the
    verifier and identity comes from ``idToken.accessToken`` through debug_token + Graph
    ``/me`` (sign-in.ts:296-302, facebook.ts:208-250)."""
    auth, r = await _facebook_id_token_sign_in(
        {"token": "opaque-abc", "accessToken": "real-access"}
    )
    assert r.status_code == 200, r.text
    assert r.json()["user"]["email"] == "g@x.com"
    assert r.json()["user"]["image"] == "http://avatar"
    [account] = await auth.adapter.find_many("account")
    assert account["accountId"] == "g-9"  # accountSubject: `"sub" in profile ? sub : id`


@pytest.mark.parametrize(
    ("id_token", "app_id"),
    [
        ({"token": "opaque-abc"}, "fbapp"),
        ({"token": "opaque-abc", "accessToken": "real-access"}, "other-app"),
    ],
)
async def test_facebook_opaque_token_without_valid_access_token_fails(id_token, app_id):
    # TS v1.7.6 sign-in.ts:302-310: getUserInfo returns null -> FAILED_TO_GET_USER_INFO.
    _, r = await _facebook_id_token_sign_in(id_token, app_id=app_id)
    assert r.status_code == 401
    assert r.json()["code"] == "FAILED_TO_GET_USER_INFO"


async def test_facebook_limited_login_pins_rs256():
    # TS v1.7.6 facebook.ts:158 `algorithms: ["RS256"]`: an HS256 token signed with a
    # symmetric JWK is refused even though the key matches.
    secret = "k" * 32
    oct_jwk = {
        "kty": "oct",
        "kid": KID,
        "k": base64.urlsafe_b64encode(secret.encode()).decode().rstrip("="),
    }
    token = _sign(
        _now_claims(sub="x", aud="fbapp", iss="https://www.facebook.com"), secret, "HS256"
    )
    provider = Facebook(client_id="fbapp", client_secret="secret")
    http = _jwks_http("/.well-known/oauth/openid/jwks/", [oct_jwk])
    assert await provider.verify_id_token(http, token) is None


def test_facebook_additional_params_override_config_id():
    # TS v1.7.6 facebook.ts:137-140 `{config_id, ...additionalParams}`.
    provider = Facebook(client_id="c", client_secret="s", config_id="cfg")
    url = provider.authorization_url(
        state="st", redirect_uri="https://app/cb", additional_params={"config_id": "req"}
    )
    assert parse_qs(urlsplit(url).query)["config_id"] == ["req"]


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
        "oid": "oid-1",
        "name": "Verified User",
        "email": "v@x.com",
        "verified_primary_email": ["v@x.com"],
    }
    token = _sign(claims, _rsa_key(), "RS256")
    provider = MicrosoftEntraId(client_id="msapp", disable_profile_photo=True)
    http = _mock_http(lambda r: httpx.Response(404))
    info = await provider.fetch_user(OAuthTokens(id_token=token), http)
    assert info.id == "oid-1"
    # no email_verified claim, but email is in verified_primary_email -> True
    assert info.email_verified is True


async def test_microsoft_account_id_is_oid():
    """TS v1.7.6 social-providers/microsoft-entra-id.ts:190 (0683a5f36): the account id
    is the tenant-stable ``oid``, not the per-app pairwise ``sub``."""
    provider = MicrosoftEntraId(client_id="msapp", disable_profile_photo=True)
    claims = {"sub": "pairwise-sub", "oid": "object-id", "email": "u@x.com"}
    assert provider.user_info_from_id_token(claims).id == "object-id"
    token = _sign(claims, _rsa_key(), "RS256")
    http = _mock_http(lambda r: httpx.Response(404))
    assert (await provider.fetch_user(OAuthTokens(id_token=token), http)).id == "object-id"


async def test_microsoft_missing_oid_yields_no_account_id(caplog):
    """TS v1.7.6 microsoft-entra-id.ts:281-286: a token without a usable ``oid`` gives
    no account identity (the flow then refuses it)."""
    provider = MicrosoftEntraId(client_id="msapp", disable_profile_photo=True)
    assert provider.user_info_from_id_token({"sub": "s", "oid": "  "}).id == ""
    assert "did not include a valid oid claim" in caplog.text


def test_microsoft_account_id_claim_option_keeps_sub():
    """Port option, not in TS: ``account_id_claim="sub"`` keeps pre-1.1 account ids so
    existing rows match until they are migrated to ``oid``."""
    provider = MicrosoftEntraId(client_id="msapp", account_id_claim="sub")
    assert provider.user_info_from_id_token({"sub": "s", "oid": "o"}).id == "s"


# ===================================================================================
# PayPal
# ===================================================================================


async def test_microsoft_verify_tries_every_key_sharing_the_kid():
    # Shared verifier (TS v1.7.6 microsoft-entra-id.ts:229-272 `idToken`): a rotated key
    # sharing the kid must not shadow the one that signed the token.
    key, stale = _rsa_key(), _rsa_key()
    tid = "my-tenant"
    iss = f"https://login.microsoftonline.com/{tid}/v2.0"
    token = _sign(_now_claims(sub="u", oid="o", aud="msapp", tid=tid, iss=iss), key, "RS256")
    provider = MicrosoftEntraId(client_id="msapp", tenant_id=tid)
    http = _jwks_http(f"/{tid}/discovery/v2.0/keys", [_rsa_jwk(stale), _rsa_jwk(key)])
    assert await provider.verify_id_token(http, token) is not None


def test_microsoft_client_assertion_cannot_combine_with_secret():
    # TS v1.7.6 microsoft-entra-id.ts:175-179
    with pytest.raises(ValueError, match="cannot be combined with clientSecret"):
        MicrosoftEntraId(client_id="msapp", client_secret="s", client_assertion=lambda c: "x")


async def test_microsoft_client_assertion_sent_as_private_key_jwt():
    # TS v1.7.6 microsoft-entra-id.ts:180-186, :226 and :358 (7fe0e2b16).
    seen: list[dict[str, list[str]]] = []
    contexts: list[dict[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(parse_qs(request.content.decode()))
        return httpx.Response(200, json={"access_token": "at"})

    def assertion(context: dict[str, str]) -> str:
        contexts.append(context)
        return "signed-jwt"

    provider = MicrosoftEntraId(client_id="msapp", tenant_id="t1", client_assertion=assertion)
    http = _mock_http(handler)
    await provider.exchange(http, code="c", redirect_uri="https://app/cb", code_verifier="v")
    await provider.refresh(http, "rt")
    for body in seen:
        assert body["client_assertion"] == ["signed-jwt"]
        assert body["client_assertion_type"] == [
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        ]
        assert body["client_id"] == ["msapp"]
        assert "client_secret" not in body
    assert [c["grantType"] for c in contexts] == ["authorization_code", "refresh_token"]
    assert contexts[0]["tokenEndpoint"] == "https://login.microsoftonline.com/t1/oauth2/v2.0/token"


async def test_microsoft_refresh_sends_scope():
    # TS v1.7.6 microsoft-entra-id.ts:343-357: the default scopes ride on every refresh.
    seen: dict[str, list[str]] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(parse_qs(request.content.decode()))
        return httpx.Response(200, json={"access_token": "at"})

    await MicrosoftEntraId(client_id="msapp", client_secret="s").refresh(_mock_http(handler), "rt")
    assert seen["scope"] == ["openid profile email User.Read offline_access"]
    assert seen["client_secret"] == ["s"]


def test_paypal_authorization_url_sandbox_empty_scope():
    provider = Paypal(client_id="ppclient", client_secret="secret")  # sandbox default
    url = provider.authorization_url(
        state="st", redirect_uri="https://app/cb", code_verifier="verifier123"
    )
    parts = urlsplit(url)
    query = parse_qs(parts.query, keep_blank_values=True)
    assert parts.netloc == "www.sandbox.paypal.com"
    assert parts.path == "/signin/authorize"
    # no scope param: permissions live in the PayPal dashboard and v1.7.6
    # create-authorization-url.ts only sets `scope` when `scopes?.length`
    assert "scope" not in query
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
    provider = Paypal(client_id="ppclient", client_secret="secret", legacy_id_token_sign_in=True)
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
    provider = Paypal(client_id="ppclient", client_secret=secret, legacy_id_token_sign_in=True)
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
    provider = Paypal(client_id="ppclient", client_secret="secret", legacy_id_token_sign_in=True)
    http = _jwks_http("/v1/oauth2/certs", [_ec_jwk(key)])
    assert await provider.verify_id_token(http, token) is None


async def test_paypal_exchange_uses_shared_token_flow():
    """TS v1.7.6 paypal.ts:132-145 (9e36635eb): validateAuthorizationCode with
    ``client_secret_basic``; the verifier is sent and credentials are form-encoded."""
    captured = {}

    def token_endpoint(request: httpx.Request) -> httpx.Response:
        captured["headers"] = request.headers
        captured["body"] = parse_qs(request.content.decode())
        return httpx.Response(
            200,
            json={
                "access_token": "pp-access",
                "refresh_token": "pp-refresh",
                "expires_in": 3600,
                "id_token": "pp-id",
            },
        )

    provider = Paypal(client_id="pp client", client_secret="se:cret")
    http = _jwks_http("/__none__", [], routes={"/v1/oauth2/token": token_endpoint})
    tokens = await provider.exchange(
        http, code="the-code", redirect_uri="https://app/cb", code_verifier="v123"
    )
    assert tokens.access_token == "pp-access"
    assert tokens.id_token == "pp-id"
    creds = base64.b64encode(b"pp+client:se%3Acret").decode()
    assert captured["headers"]["authorization"] == f"Basic {creds}"
    assert "accept-language" not in captured["headers"]
    assert captured["body"] == {
        "grant_type": ["authorization_code"],
        "code": ["the-code"],
        "code_verifier": ["v123"],
        "redirect_uri": ["https://app/cb"],
    }


async def test_paypal_refresh_uses_client_secret_basic():
    # TS v1.7.6 paypal.ts:148-162
    captured = {}

    def token_endpoint(request: httpx.Request) -> httpx.Response:
        captured["auth"] = request.headers.get("authorization")
        captured["body"] = parse_qs(request.content.decode())
        return httpx.Response(200, json={"access_token": "new"})

    provider = Paypal(client_id="ppclient", client_secret="secret", environment="live")
    http = _jwks_http("/__none__", [], routes={"/v1/oauth2/token": token_endpoint})
    assert (await provider.refresh(http, "rt")).access_token == "new"
    assert captured["auth"] == "Basic " + base64.b64encode(b"ppclient:secret").decode()
    assert captured["body"] == {"grant_type": ["refresh_token"], "refresh_token": ["rt"]}


def test_paypal_id_token_sign_in_unsupported_by_default():
    # TS v1.7.6 paypal.ts declares no `idToken` config (removed by 4f53b61f4), so
    # supportsIdTokenSignIn is false. The port keeps the old verifier behind an option.
    assert Paypal(client_id="c", client_secret="s").supports_id_token is False
    assert Paypal(client_id="c", client_secret="s", legacy_id_token_sign_in=True).supports_id_token
    assert not Paypal(
        client_id="c",
        client_secret="s",
        legacy_id_token_sign_in=True,
        disable_id_token_sign_in=True,
    ).supports_id_token


def test_paypal_authorization_url_forwards_additional_params():
    # TS v1.7.6 paypal.ts:127
    url = Paypal(client_id="c", client_secret="s").authorization_url(
        state="st", redirect_uri="https://app/cb", additional_params={"flowEntry": "static"}
    )
    assert parse_qs(urlsplit(url).query)["flowEntry"] == ["static"]


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
