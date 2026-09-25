"""Provider parity: Cloudflare (TS v1.7.6 ``social-providers/cloudflare.ts``, 76d311f4b)."""

from __future__ import annotations

import base64
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from better_auth.oauth import PROVIDER_REGISTRY
from better_auth.oauth.machinery import OAuthFetchError
from better_auth.oauth.models import OAuthTokens
from better_auth.oauth.providers_ext import Cloudflare


def capturing(payload: dict, status: int = 200):
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(status, json=payload)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler)), seen


def test_registered_under_ts_id():
    assert PROVIDER_REGISTRY["cloudflare"] is Cloudflare


def test_authorization_url_shape():
    # cloudflare.ts:141-160: default scope, PKCE, no login hint, no per-request extras
    p = Cloudflare(client_id="cf", client_secret="sec")
    url = p.authorization_url(
        state="st",
        redirect_uri="http://cb",
        code_verifier="v" * 43,
        extra_scopes=["account.read", "user-details.read"],
        login_hint="a@b.c",
        additional_params={"foo": "bar"},
    )
    parts = urlsplit(url)
    query = parse_qs(parts.query)
    assert (
        f"{parts.scheme}://{parts.netloc}{parts.path}" == "https://dash.cloudflare.com/oauth2/auth"
    )
    assert list(query) == [
        "response_type",
        "client_id",
        "state",
        "scope",
        "redirect_uri",
        "code_challenge_method",
        "code_challenge",
    ]
    assert query["scope"] == ["user-details.read account.read"]


def test_authorization_url_without_scopes_omits_scope():
    p = Cloudflare(client_id="cf", disable_default_scope=True)
    url = p.authorization_url(state="st", redirect_uri="http://cb", code_verifier="v" * 43)
    assert "scope" not in parse_qs(urlsplit(url).query)


async def test_exchange_defaults_to_client_secret_basic():
    # cloudflare.ts:127-134 getTokenEndpointAuth
    http, seen = capturing({"access_token": "at"})
    p = Cloudflare(client_id="cf", client_secret="sec")
    await p.exchange(http, code="c", redirect_uri="http://cb", code_verifier="ver")
    request = seen[0]
    assert str(request.url) == "https://dash.cloudflare.com/oauth2/token"
    assert request.headers["authorization"] == "Basic " + base64.b64encode(b"cf:sec").decode()
    body = parse_qs(request.content.decode())
    assert body["code_verifier"] == ["ver"]
    assert "client_secret" not in body


async def test_exchange_client_secret_post():
    http, seen = capturing({"access_token": "at"})
    p = Cloudflare(
        client_id="cf", client_secret="sec", token_endpoint_auth_method="client_secret_post"
    )
    await p.exchange(http, code="c", redirect_uri="http://cb", code_verifier="ver")
    body = parse_qs(seen[0].content.decode())
    assert body["client_id"] == ["cf"]
    assert body["client_secret"] == ["sec"]
    assert "authorization" not in seen[0].headers


async def test_public_client_refresh_sends_client_id_only():
    http, seen = capturing({"access_token": "at2"})
    p = Cloudflare(client_id="cf")
    await p.refresh(http, "rt")
    body = parse_qs(seen[0].content.decode())
    assert body == {"grant_type": ["refresh_token"], "refresh_token": ["rt"], "client_id": ["cf"]}
    assert "authorization" not in seen[0].headers


async def test_fetch_user_maps_profile():
    # cloudflare.ts:180-212
    http, seen = capturing(
        {
            "success": True,
            "errors": [],
            "result": {
                "id": "cloudflare-user-1",
                "email": "user@example.com",
                "first_name": "Cloudflare",
                "last_name": "User",
            },
        }
    )
    info = await Cloudflare(client_id="cf", client_secret="s").fetch_user(
        OAuthTokens(access_token="at"), http
    )
    assert str(seen[0].url) == "https://api.cloudflare.com/client/v4/user"
    assert seen[0].headers["authorization"] == "Bearer at"
    assert info.id == "cloudflare-user-1"
    assert info.name == "Cloudflare User"
    assert info.email == "user@example.com"
    assert info.email_verified is False


async def test_fetch_user_name_falls_back_to_email():
    http, _ = capturing(
        {"success": True, "errors": [], "result": {"id": "u2", "email": "nameless@example.com"}}
    )
    info = await Cloudflare(client_id="cf").fetch_user(OAuthTokens(access_token="at"), http)
    assert info.name == "nameless@example.com"


@pytest.mark.parametrize(
    ("payload", "status"),
    [
        ({}, 500),
        ({"success": False, "errors": [{"code": 1000, "message": "no"}], "result": None}, 200),
        ({"success": True, "errors": [], "result": None}, 200),
    ],
)
async def test_fetch_user_failures(payload, status):
    http, _ = capturing(payload, status)
    with pytest.raises(OAuthFetchError):
        await Cloudflare(client_id="cf").fetch_user(OAuthTokens(access_token="at"), http)
