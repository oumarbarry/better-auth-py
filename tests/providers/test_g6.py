"""W2-B-G6: atlassian, cognito, kakao, line, naver, vk — authorize-URL shape,
config-driven endpoints, profile mapping (mock transport), and per-provider quirks vs TS.
"""

import json
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from better_auth.oauth.machinery import OAuthFetchError
from better_auth.oauth.models import OAuthTokens
from better_auth.oauth.providers_ext.atlassian import Atlassian
from better_auth.oauth.providers_ext.cognito import Cognito
from better_auth.oauth.providers_ext.kakao import Kakao
from better_auth.oauth.providers_ext.line import Line
from better_auth.oauth.providers_ext.naver import Naver
from better_auth.oauth.providers_ext.vk import VK


def mock_http(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def authz_query(provider, **kw):
    kw.setdefault("state", "st")
    kw.setdefault("redirect_uri", "http://app/callback/x")
    kw.setdefault("code_verifier", "v" * 43)
    return parse_qs(urlsplit(provider.authorization_url(**kw)).query)


# --- provider_id byte-exactness -----------------------------------------------------------


def test_provider_ids():
    assert Atlassian(client_id="c").provider_id == "atlassian"
    assert Kakao(client_id="c").provider_id == "kakao"
    assert Line(client_id="c").provider_id == "line"
    assert Naver(client_id="c").provider_id == "naver"
    assert VK(client_id="c").provider_id == "vk"
    assert (
        Cognito(
            client_id="c",
            domain="d.auth.us-east-1.amazoncognito.com",
            region="us-east-1",
            user_pool_id="us-east-1_x",
        ).provider_id
        == "cognito"
    )


# --- atlassian ----------------------------------------------------------------------------


def test_atlassian_authorization_url():
    p = Atlassian(client_id="cid", client_secret="sec")
    u = p.authorization_url(state="st", redirect_uri="http://app/cb", code_verifier="v" * 43)
    assert u.startswith("https://auth.atlassian.com/authorize?")
    q = parse_qs(urlsplit(u).query)
    assert q["audience"] == ["api.atlassian.com"]
    assert q["scope"] == ["read:jira-user offline_access"]
    assert q["code_challenge_method"] == ["S256"]  # PKCE
    assert p.token_endpoint == "https://auth.atlassian.com/oauth/token"


def test_atlassian_disable_default_scope():
    q = authz_query(Atlassian(client_id="c", disable_default_scope=True), extra_scopes=["x"])
    assert q["scope"] == ["x"]


async def test_atlassian_profile_mapping():
    def handler(request):
        assert request.url.path == "/me"
        return httpx.Response(
            200,
            json={
                "account_id": "abc-123",
                "name": "Jane",
                "email": "jane@x.io",
                "picture": "http://img/j.png",
            },
        )

    p = Atlassian(client_id="c")
    info = await p.fetch_user(OAuthTokens(access_token="tok"), mock_http(handler))
    assert info.id == "abc-123"
    assert info.email == "jane@x.io"
    assert info.name == "Jane"
    assert info.image == "http://img/j.png"
    assert info.email_verified is False  # atlassian never reports verification


# --- kakao --------------------------------------------------------------------------------


def test_kakao_authorization_url():
    p = Kakao(client_id="c")
    q = authz_query(p)
    assert q["scope"] == ["account_email profile_image profile_nickname"]
    assert "code_challenge" not in q  # no PKCE
    assert p.authorization_endpoint == "https://kauth.kakao.com/oauth/authorize"
    assert p.token_endpoint == "https://kauth.kakao.com/oauth/token"


async def test_kakao_profile_mapping_nested_envelope():
    profile = {
        "id": 424242,
        "kakao_account": {
            "email": "k@x.io",
            "is_email_valid": True,
            "is_email_verified": True,
            "profile": {"nickname": "Nick", "profile_image_url": "http://img/p.png"},
        },
    }

    def handler(request):
        assert request.url.host == "kapi.kakao.com"
        return httpx.Response(200, json=profile)

    info = await Kakao(client_id="c").fetch_user(OAuthTokens(access_token="t"), mock_http(handler))
    assert info.id == "424242"  # stringified numeric id
    assert info.name == "Nick"
    assert info.email == "k@x.io"
    assert info.image == "http://img/p.png"
    assert info.email_verified is True  # is_email_valid AND is_email_verified


async def test_kakao_email_verified_requires_both_flags():
    profile = {"id": 1, "kakao_account": {"is_email_valid": True, "is_email_verified": False}}
    info = await Kakao(client_id="c").fetch_user(
        OAuthTokens(access_token="t"), mock_http(lambda r: httpx.Response(200, json=profile))
    )
    assert info.email_verified is False


# --- naver --------------------------------------------------------------------------------


def test_naver_authorization_url():
    p = Naver(client_id="c")
    q = authz_query(p)
    assert q["scope"] == ["profile email"]
    assert "code_challenge" not in q  # no PKCE
    assert p.authorization_endpoint == "https://nid.naver.com/oauth2.0/authorize"


async def test_naver_profile_mapping_response_envelope():
    profile = {
        "resultcode": "00",
        "message": "success",
        "response": {
            "id": "n-1",
            "name": "Real Name",
            "nickname": "nick",
            "email": "n@x.io",
            "profile_image": "http://img/n.png",
        },
    }

    def handler(request):
        assert request.url.host == "openapi.naver.com"
        return httpx.Response(200, json=profile)

    info = await Naver(client_id="c").fetch_user(OAuthTokens(access_token="t"), mock_http(handler))
    assert info.id == "n-1"
    assert info.name == "Real Name"  # name preferred over nickname
    assert info.email == "n@x.io"
    assert info.image == "http://img/n.png"


async def test_naver_bad_resultcode_rejected():
    # TS returns null when resultcode != "00"; port surfaces it as a fetch failure
    profile = {"resultcode": "024", "message": "auth failed", "response": {}}
    with pytest.raises(OAuthFetchError):
        await Naver(client_id="c").fetch_user(
            OAuthTokens(access_token="t"), mock_http(lambda r: httpx.Response(200, json=profile))
        )


# --- vk -----------------------------------------------------------------------------------


def test_vk_authorization_url():
    p = VK(client_id="vc")
    q = authz_query(p)
    assert q["scope"] == ["email phone"]
    assert q["code_challenge_method"] == ["S256"]  # PKCE
    assert p.authorization_endpoint == "https://id.vk.com/authorize"
    assert p.token_endpoint == "https://id.vk.com/oauth2/auth"


async def test_vk_userinfo_posts_form_body():
    captured = {}

    def handler(request):
        captured["method"] = request.method
        captured["url"] = str(request.url)
        captured["body"] = request.content.decode()
        return httpx.Response(
            200,
            json={
                "user": {
                    "user_id": "77",
                    "first_name": "Ivan",
                    "last_name": "Petrov",
                    "email": "ivan@x.ru",
                    "avatar": "http://img/v.png",
                    "birthday": "1.1.2000",
                }
            },
        )

    info = await VK(client_id="vc").fetch_user(OAuthTokens(access_token="atok"), mock_http(handler))
    assert captured["method"] == "POST"  # not a bearer GET
    assert captured["url"] == "https://id.vk.com/oauth2/user_info"
    assert "access_token=atok" in captured["body"]
    assert "client_id=vc" in captured["body"]  # client_id in the form body
    assert info.id == "77"
    assert info.name == "Ivan Petrov"  # first + last
    assert info.email == "ivan@x.ru"
    assert info.image == "http://img/v.png"


async def test_vk_no_email_leaves_email_none():
    # VK hard-fails sign-in without an email; the port maps email=None so the callback rejects it
    profile = {"user": {"user_id": "9", "first_name": "A", "last_name": "B"}}
    info = await VK(client_id="vc").fetch_user(
        OAuthTokens(access_token="t"), mock_http(lambda r: httpx.Response(200, json=profile))
    )
    assert info.email is None


# --- line ---------------------------------------------------------------------------------


def test_line_authorization_url():
    p = Line(client_id="lc")
    q = authz_query(p, login_hint="user@x.io")
    assert q["scope"] == ["openid profile email"]
    assert q["code_challenge_method"] == ["S256"]  # PKCE
    assert q["login_hint"] == ["user@x.io"]
    assert p.authorization_endpoint == "https://access.line.me/oauth2/v2.1/authorize"
    assert p.token_endpoint == "https://api.line.me/oauth2/v2.1/token"


async def test_line_prefers_id_token_decode_no_network():
    # id_token present → decode it, never hit the userinfo endpoint
    token = jwt.encode(
        {"sub": "line-1", "name": "Taro", "picture": "http://img/l.png", "email": "t@x.jp"},
        "x" * 32,
        algorithm="HS256",
    )

    def handler(request):
        raise AssertionError("userinfo must not be called when an id_token is present")

    info = await Line(client_id="lc").fetch_user(
        OAuthTokens(access_token="a", id_token=token), mock_http(handler)
    )
    assert info.id == "line-1"
    assert info.name == "Taro"
    assert info.email == "t@x.jp"
    assert info.email_verified is False  # LINE never exposes verification


async def test_line_falls_back_to_userinfo():
    def handler(request):
        assert request.url.path == "/oauth2/v2.1/userinfo"
        return httpx.Response(200, json={"sub": "line-2", "name": "Hana", "picture": "http://i"})

    info = await Line(client_id="lc").fetch_user(OAuthTokens(access_token="a"), mock_http(handler))
    assert info.id == "line-2"
    assert info.name == "Hana"


async def test_line_verify_id_token_uses_verify_endpoint():
    # LINE verifies via its own POST /verify endpoint (not JWKS), checking aud + nonce
    captured = {}

    def handler(request):
        captured["url"] = str(request.url)
        captured["body"] = request.content.decode()
        return httpx.Response(200, json={"sub": "s", "aud": "lc", "nonce": "n0nce", "iss": "line"})

    claims = await Line(client_id="lc").verify_id_token(mock_http(handler), "the-token", "n0nce")
    assert captured["url"] == "https://api.line.me/oauth2/v2.1/verify"
    assert "id_token=the-token" in captured["body"]
    assert "client_id=lc" in captured["body"]
    assert claims is not None and claims["aud"] == "lc"


async def test_line_verify_rejects_wrong_aud():
    def handler(r):
        return httpx.Response(200, json={"aud": "someone-else", "sub": "s"})

    assert await Line(client_id="lc").verify_id_token(mock_http(handler), "t", None) is None


async def test_line_verify_rejects_wrong_nonce():
    def handler(r):
        return httpx.Response(200, json={"aud": "lc", "nonce": "real", "sub": "s"})

    assert await Line(client_id="lc").verify_id_token(mock_http(handler), "t", "wrong") is None


def test_line_id_token_sign_in_gated_by_opt_out():
    assert Line(client_id="lc").supports_id_token is True
    assert Line(client_id="lc", disable_id_token_sign_in=True).supports_id_token is False


# --- cognito ------------------------------------------------------------------------------


def cognito(
    client_id="cog-id",
    domain="myapp.auth.us-east-1.amazoncognito.com",
    region="us-east-1",
    user_pool_id="us-east-1_ABC123",
    disable_id_token_sign_in=False,
):
    return Cognito(
        client_id=client_id,
        domain=domain,
        region=region,
        user_pool_id=user_pool_id,
        disable_id_token_sign_in=disable_id_token_sign_in,
    )


def test_cognito_requires_pool_config():
    with pytest.raises(ValueError):
        Cognito(client_id="c", domain="", region="us-east-1", user_pool_id="p")
    with pytest.raises(ValueError):
        Cognito(client_id="c", domain="d", region="", user_pool_id="p")
    with pytest.raises(ValueError):
        Cognito(client_id="c", domain="d", region="us-east-1", user_pool_id="")


def test_cognito_endpoints_from_domain_and_region():
    p = cognito()
    assert (
        p.authorization_endpoint
        == "https://myapp.auth.us-east-1.amazoncognito.com/oauth2/authorize"
    )
    assert p.token_endpoint == "https://myapp.auth.us-east-1.amazoncognito.com/oauth2/token"
    assert p.userinfo_endpoint == "https://myapp.auth.us-east-1.amazoncognito.com/oauth2/userinfo"
    assert p.jwks_url == (
        "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_ABC123/.well-known/jwks.json"
    )
    assert p.issuers == ["https://cognito-idp.us-east-1.amazonaws.com/us-east-1_ABC123"]


def test_cognito_strips_scheme_from_domain():
    p = cognito(domain="https://myapp.auth.us-east-1.amazoncognito.com")
    assert p.authorization_endpoint.startswith("https://myapp.auth.us-east-1.amazoncognito.com/")
    assert "https://https://" not in p.authorization_endpoint


def test_cognito_scope_percent20_encoded():
    # AWS Cognito needs %20-joined scopes, not '+'; the scope param must not contain '+'
    u = cognito().authorization_url(
        state="st", redirect_uri="http://app/cb", code_verifier="v" * 43
    )
    scope_part = urlsplit(u).query.split("scope=")[1].split("&")[0]
    assert scope_part == "openid%20profile%20email"
    assert "+" not in scope_part
    assert parse_qs(urlsplit(u).query)["scope"] == ["openid profile email"]  # decodes back


def test_cognito_client_id_array_supported():
    p = cognito(client_id=["ios-aud", "web-aud"])
    q = parse_qs(
        urlsplit(
            p.authorization_url(state="s", redirect_uri="http://c", code_verifier="v" * 43)
        ).query
    )
    assert q["client_id"] == ["ios-aud"]  # primary is index 0


async def test_cognito_getuserinfo_decodes_id_token():
    id_token = jwt.encode(
        {
            "sub": "cog-1",
            "given_name": "Given",
            "username": "usr",
            "email": "c@x.io",
            "email_verified": True,
            "picture": "http://img/c.png",
        },
        "x" * 32,
        algorithm="HS256",
    )

    def handler(request):
        raise AssertionError("userinfo must not be called when an id_token is present")

    info = await cognito().fetch_user(
        OAuthTokens(access_token="a", id_token=id_token), mock_http(handler)
    )
    assert info.id == "cog-1"
    assert info.name == "Given"  # name || given_name || username
    assert info.email == "c@x.io"
    assert info.email_verified is True


async def test_cognito_getuserinfo_falls_back_to_userinfo_endpoint():
    def handler(request):
        assert request.url.path == "/oauth2/userinfo"
        return httpx.Response(
            200, json={"sub": "cog-2", "username": "onlyuser", "email": "c2@x.io"}
        )

    info = await cognito().fetch_user(OAuthTokens(access_token="a"), mock_http(handler))
    assert info.id == "cog-2"
    assert info.name == "onlyuser"  # falls through to username


def _rsa_jwks_and_signer():
    import uuid

    kid = uuid.uuid4().hex
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    jwk["kid"], jwk["alg"] = kid, "RS256"

    def sign(payload):
        return jwt.encode(payload, key, algorithm="RS256", headers={"kid": kid})

    return {"keys": [jwk]}, sign


@pytest.fixture(autouse=True)
def _reset_jwks_cache():
    from better_auth.oauth import verify

    verify._cache._cache.clear()
    verify._cache._last_miss.clear()
    yield


async def test_cognito_verify_id_token_via_jwks():
    jwks, sign = _rsa_jwks_and_signer()
    p = cognito()
    now = int(time.time())
    token = sign(
        {
            "iss": p.issuers[0],
            "aud": "cog-id",
            "sub": "cog-9",
            "email": "c@x.io",
            "nonce": "nn",
            "iat": now,
            "exp": now + 600,
        }
    )

    def handler(request):
        assert request.url.path.endswith("/.well-known/jwks.json")
        return httpx.Response(200, json=jwks)

    claims = await p.verify_id_token(mock_http(handler), token, "nn")
    assert claims is not None and claims["sub"] == "cog-9"


async def test_cognito_verify_id_token_max_age_1h():
    # TS enforces maxTokenAge "1h"; a token issued > 1h ago must be rejected
    jwks, sign = _rsa_jwks_and_signer()
    p = cognito()
    now = int(time.time())
    token = sign(
        {
            "iss": p.issuers[0],
            "aud": "cog-id",
            "sub": "cog-old",
            "email": "c@x.io",
            "iat": now - 7200,
            "exp": now + 600,
        }
    )

    def handler(r):
        return httpx.Response(200, json=jwks)

    assert await p.verify_id_token(mock_http(handler), token, None) is None


def test_cognito_disable_id_token_sign_in():
    assert cognito().supports_id_token is True
    assert cognito(disable_id_token_sign_in=True).supports_id_token is False
