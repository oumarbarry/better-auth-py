"""W2-B-G3: twitch, zoom, vercel, railway, polar, paybin — authorize-URL shape +
profile-to-user mapping fidelity vs. TS ``social-providers/*.ts``."""

from __future__ import annotations

import base64
import json
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest

from better_auth.oauth.providers_ext.paybin import Paybin
from better_auth.oauth.providers_ext.polar import Polar
from better_auth.oauth.providers_ext.railway import Railway
from better_auth.oauth.providers_ext.twitch import Twitch
from better_auth.oauth.providers_ext.vercel import Vercel
from better_auth.oauth.providers_ext.zoom import Zoom


def http_with(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def unsigned_jwt(claims: dict) -> str:
    return jwt.encode(claims, "unused-signing-key-not-verified-by-decoder", algorithm="HS256")


# --- Twitch ---------------------------------------------------------------------------


def test_twitch_authorization_url_no_pkce_default_claims():
    p = Twitch(client_id="cid", client_secret="csecret")
    url = p.authorization_url(
        state="st", redirect_uri="http://cb", code_verifier="verifier-should-be-ignored"
    )
    parts = urlsplit(url)
    query = parse_qs(parts.query)
    assert parts.netloc == "id.twitch.tv"
    assert parts.path == "/oauth2/authorize"
    assert query["client_id"] == ["cid"]
    assert set(query["scope"][0].split(" ")) == {"user:read:email", "openid"}
    # no PKCE, ever
    assert "code_challenge" not in query
    assert "code_challenge_method" not in query
    claims = json.loads(query["claims"][0])
    assert claims == {
        "id_token": {
            "email": None,
            "email_verified": None,
            "preferred_username": None,
            "picture": None,
        }
    }


def test_twitch_authorization_url_custom_claims():
    p = Twitch(client_id="cid", client_secret="csecret", claims=["email"])
    url = p.authorization_url(state="st", redirect_uri="http://cb")
    query = parse_qs(urlsplit(url).query)
    claims = json.loads(query["claims"][0])
    assert claims == {"id_token": {"email": None, "email_verified": None}}


async def test_twitch_fetch_user_decodes_id_token():
    p = Twitch(client_id="cid", client_secret="csecret")
    from better_auth.oauth.models import OAuthTokens

    id_token = unsigned_jwt(
        {
            "sub": "u1",
            "preferred_username": "octo",
            "email": "octo@twitch.tv",
            "email_verified": True,
            "picture": "http://img/x.png",
        }
    )
    tokens = OAuthTokens(access_token="at", id_token=id_token)
    info = await p.fetch_user(tokens, http_with(lambda r: httpx.Response(404)))
    assert info.id == "u1"
    assert info.name == "octo"
    assert info.email == "octo@twitch.tv"
    assert info.email_verified is True
    assert info.image == "http://img/x.png"


async def test_twitch_fetch_user_requires_id_token():
    from better_auth.oauth.machinery import OAuthFetchError
    from better_auth.oauth.models import OAuthTokens

    p = Twitch(client_id="cid", client_secret="csecret")
    with pytest.raises(OAuthFetchError):
        await p.fetch_user(OAuthTokens(access_token="at"), http_with(lambda r: httpx.Response(404)))


# --- Zoom -------------------------------------------------------------------------------


def test_zoom_authorization_url_no_scope_ever():
    p = Zoom(client_id="cid", client_secret="csecret")
    url = p.authorization_url(
        state="st", redirect_uri="http://cb", code_verifier="verifier", extra_scopes=["ignored"]
    )
    parts = urlsplit(url)
    query = parse_qs(parts.query)
    assert parts.netloc == "zoom.us"
    assert parts.path == "/oauth/authorize"
    assert "scope" not in query
    assert query["response_type"] == ["code"]
    assert query["client_id"] == ["cid"]
    # pkce defaults True
    assert query["code_challenge_method"] == ["S256"]
    assert "code_challenge" in query


def test_zoom_pkce_can_be_disabled():
    p = Zoom(client_id="cid", client_secret="csecret", use_pkce=False)
    url = p.authorization_url(state="st", redirect_uri="http://cb", code_verifier="verifier")
    query = parse_qs(urlsplit(url).query)
    assert "code_challenge" not in query


async def test_zoom_exchange_forwards_code_verifier_even_when_pkce_disabled():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["body"] = request.content.decode()
        return httpx.Response(200, json={"access_token": "zoom_at"})

    p = Zoom(client_id="cid", client_secret="csecret", use_pkce=False)
    await p.exchange(
        http_with(handler), code="abc", redirect_uri="http://cb", code_verifier="verifier"
    )
    assert "code_verifier=verifier" in seen["body"]


async def test_zoom_fetch_user_maps_verified_int_to_bool():
    profile = {
        "id": "z1",
        "display_name": "Jill Chill",
        "email": "jchill@example.com",
        "pic_url": "http://img/jill.png",
        "verified": 1,
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["authorization"] == "Bearer zoom_at"
        return httpx.Response(200, json=profile)

    from better_auth.oauth.models import OAuthTokens

    p = Zoom(client_id="cid", client_secret="csecret")
    info = await p.fetch_user(OAuthTokens(access_token="zoom_at"), http_with(handler))
    assert info.id == "z1"
    assert info.name == "Jill Chill"
    assert info.email == "jchill@example.com"
    assert info.image == "http://img/jill.png"
    assert info.email_verified is True


# --- Vercel -------------------------------------------------------------------------------


def test_vercel_requires_code_verifier():
    p = Vercel(client_id="cid", client_secret="csecret")
    with pytest.raises(ValueError, match="codeVerifier"):
        p.authorization_url(state="st", redirect_uri="http://cb")


def test_vercel_no_default_scope():
    p = Vercel(client_id="cid", client_secret="csecret")
    url = p.authorization_url(state="st", redirect_uri="http://cb", code_verifier="v")
    query = parse_qs(urlsplit(url).query)
    assert "scope" not in query
    assert query["code_challenge_method"] == ["S256"]


def test_vercel_scope_sent_when_extra_scopes_given():
    p = Vercel(client_id="cid", client_secret="csecret")
    url = p.authorization_url(
        state="st", redirect_uri="http://cb", code_verifier="v", extra_scopes=["read"]
    )
    query = parse_qs(urlsplit(url).query)
    assert query["scope"] == ["read"]


async def test_vercel_fetch_user_name_fallback():
    from better_auth.oauth.models import OAuthTokens

    p = Vercel(client_id="cid", client_secret="csecret")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "sub": "v1",
                "preferred_username": "vercel-user",
                "email": "u@vercel.com",
                "email_verified": True,
                "picture": "http://img/v.png",
            },
        )

    info = await p.fetch_user(OAuthTokens(access_token="at"), http_with(handler))
    assert info.id == "v1"
    assert info.name == "vercel-user"  # falls back since `name` is absent
    assert info.email_verified is True


# --- Railway ------------------------------------------------------------------------------


def test_railway_authorization_url_default_scopes_and_pkce():
    p = Railway(client_id="cid", client_secret="csecret")
    url = p.authorization_url(state="st", redirect_uri="http://cb", code_verifier="v")
    parts = urlsplit(url)
    query = parse_qs(parts.query)
    assert parts.netloc == "backboard.railway.com"
    assert parts.path == "/oauth/auth"
    assert set(query["scope"][0].split(" ")) == {"openid", "email", "profile"}
    assert "code_challenge" in query


async def test_railway_exchange_uses_basic_auth():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("authorization")
        seen["body"] = request.content.decode()
        return httpx.Response(200, json={"access_token": "rw_at"})

    p = Railway(client_id="cid", client_secret="csecret")
    await p.exchange(http_with(handler), code="abc", redirect_uri="http://cb", code_verifier="v")
    expected = "Basic " + base64.b64encode(b"cid:csecret").decode()
    assert seen["auth"] == expected
    assert "client_secret" not in seen["body"]  # basic auth: no secret in the body


async def test_railway_email_verified_always_false():
    from better_auth.oauth.models import OAuthTokens

    p = Railway(client_id="cid", client_secret="csecret")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "sub": "r1",
                "email": "u@railway.app",
                "name": "Railway User",
                "picture": "http://img/r.png",
            },
        )

    info = await p.fetch_user(OAuthTokens(access_token="at"), http_with(handler))
    assert info.id == "r1"
    assert info.email_verified is False


# --- Polar --------------------------------------------------------------------------------


def test_polar_authorization_url_default_scopes_and_prompt_passthrough():
    p = Polar(client_id="cid", client_secret="csecret", authorize_params={"prompt": "consent"})
    url = p.authorization_url(state="st", redirect_uri="http://cb", code_verifier="v")
    parts = urlsplit(url)
    query = parse_qs(parts.query)
    assert parts.netloc == "polar.sh"
    assert set(query["scope"][0].split(" ")) == {"openid", "profile", "email"}
    assert query["prompt"] == ["consent"]
    assert "code_challenge" in query


async def test_polar_fetch_user_name_fallback_and_email_verified_default_false():
    from better_auth.oauth.models import OAuthTokens

    p = Polar(client_id="cid", client_secret="csecret")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "id": "p1",
                "email": "u@polar.sh",
                "username": "polaruser",
                "avatar_url": "http://img/p.png",
            },
        )

    info = await p.fetch_user(OAuthTokens(access_token="at"), http_with(handler))
    assert info.name == "polaruser"  # public_name absent, falls back to username
    assert info.email_verified is False  # absent claim defaults False


async def test_polar_fetch_user_email_verified_true_when_present():
    from better_auth.oauth.models import OAuthTokens

    p = Polar(client_id="cid", client_secret="csecret")

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "id": "p1",
                "email": "u@polar.sh",
                "public_name": "Polar User",
                "username": "polaruser",
                "avatar_url": "http://img/p.png",
                "email_verified": True,
            },
        )

    info = await p.fetch_user(OAuthTokens(access_token="at"), http_with(handler))
    assert info.name == "Polar User"
    assert info.email_verified is True


# --- Paybin -------------------------------------------------------------------------------


def test_paybin_default_issuer_endpoints():
    p = Paybin(client_id="cid", client_secret="csecret")
    assert p.authorization_endpoint == "https://idp.paybin.io/oauth2/authorize"
    assert p.token_endpoint == "https://idp.paybin.io/oauth2/token"


def test_paybin_custom_issuer_endpoints():
    p = Paybin(client_id="cid", client_secret="csecret", issuer="https://idp.example.com")
    assert p.authorization_endpoint == "https://idp.example.com/oauth2/authorize"
    assert p.token_endpoint == "https://idp.example.com/oauth2/token"


def test_paybin_requires_client_secret():
    p = Paybin(client_id="cid", client_secret="")
    with pytest.raises(ValueError, match="CLIENT_ID_AND_SECRET_REQUIRED"):
        p.authorization_url(state="st", redirect_uri="http://cb", code_verifier="v")


def test_paybin_requires_code_verifier():
    p = Paybin(client_id="cid", client_secret="csecret")
    with pytest.raises(ValueError, match="codeVerifier"):
        p.authorization_url(state="st", redirect_uri="http://cb")


def test_paybin_authorization_url_shape():
    p = Paybin(client_id="cid", client_secret="csecret")
    url = p.authorization_url(state="st", redirect_uri="http://cb", code_verifier="v")
    parts = urlsplit(url)
    query = parse_qs(parts.query)
    assert parts.netloc == "idp.paybin.io"
    assert set(query["scope"][0].split(" ")) == {"openid", "email", "profile"}
    assert query["code_challenge_method"] == ["S256"]


async def test_paybin_fetch_user_decodes_id_token():
    from better_auth.oauth.models import OAuthTokens

    p = Paybin(client_id="cid", client_secret="csecret")
    id_token = unsigned_jwt(
        {
            "sub": "pb1",
            "email": "u@paybin.io",
            "email_verified": True,
            "given_name": "Pay",
            "preferred_username": "paybin-user",
            "picture": "http://img/pb.png",
        }
    )
    info = await p.fetch_user(
        OAuthTokens(access_token="at", id_token=id_token), http_with(lambda r: httpx.Response(404))
    )
    assert info.id == "pb1"
    assert info.name == "paybin-user"  # no `name` claim, falls back to preferred_username
    assert info.email_verified is True


async def test_paybin_fetch_user_requires_id_token():
    from better_auth.oauth.machinery import OAuthFetchError
    from better_auth.oauth.models import OAuthTokens

    p = Paybin(client_id="cid", client_secret="csecret")
    with pytest.raises(OAuthFetchError):
        await p.fetch_user(OAuthTokens(access_token="at"), http_with(lambda r: httpx.Response(404)))
