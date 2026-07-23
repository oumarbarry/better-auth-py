"""W2-B-G1: dropbox, figma, gitlab, huggingface, kick, linear provider parity.

Unit-level: exercises `authorization_url()` (endpoint/scopes/PKCE shape) and
`fetch_user()` (profile -> OAuthUserInfo mapping, provider-specific quirks) directly
against each ProviderConfig subclass, with a mocked httpx transport standing in for the
provider's HTTP API. No app/BetterAuth wiring needed for these.
"""

from __future__ import annotations

import json
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from better_auth.oauth.machinery import OAuthFetchError
from better_auth.oauth.models import OAuthTokens
from better_auth.oauth.providers_ext.dropbox import Dropbox
from better_auth.oauth.providers_ext.figma import Figma
from better_auth.oauth.providers_ext.gitlab import Gitlab
from better_auth.oauth.providers_ext.huggingface import Huggingface
from better_auth.oauth.providers_ext.kick import Kick
from better_auth.oauth.providers_ext.linear import Linear

TOKENS = OAuthTokens(access_token="tok")


def qs(url: str) -> dict[str, str]:
    return {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}


def mock_http(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


# --- Dropbox --------------------------------------------------------------------------


def test_dropbox_authorization_url_shape():
    p = Dropbox(client_id="cid", client_secret="csecret", access_type="offline")
    url = p.authorization_url(state="st", redirect_uri="https://app/cb", code_verifier="verifier")
    assert url.startswith("https://www.dropbox.com/oauth2/authorize?")
    params = qs(url)
    assert params["client_id"] == "cid"
    assert params["scope"] == "account_info.read"
    assert params["code_challenge_method"] == "S256"
    assert "code_challenge" in params
    assert params["token_access_type"] == "offline"


DROPBOX_PROFILE = {
    "account_id": "dbid:AAH4f99T0taONIb",
    "name": {
        "given_name": "John",
        "surname": "Doe",
        "familiar_name": "John",
        "display_name": "John Doe",
        "abbreviated_name": "JD",
    },
    "email": "john@example.com",
    "email_verified": True,
    "profile_photo_url": "https://dl.dropboxusercontent.com/photo.jpg",
}


async def test_dropbox_fetch_user_posts_and_maps_profile():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["method"] = request.method
        seen["url"] = str(request.url)
        return httpx.Response(200, json=DROPBOX_PROFILE)

    p = Dropbox(client_id="cid", client_secret="csecret")
    info = await p.fetch_user(TOKENS, mock_http(handler))
    assert seen["method"] == "POST"
    assert seen["url"] == "https://api.dropboxapi.com/2/users/get_current_account"
    assert info.id == "dbid:AAH4f99T0taONIb"
    assert info.name == "John Doe"
    assert info.email == "john@example.com"
    assert info.email_verified is True
    assert info.image == "https://dl.dropboxusercontent.com/photo.jpg"
    assert info.raw == DROPBOX_PROFILE


# --- Figma ------------------------------------------------------------------------------


def test_figma_authorization_url_shape():
    p = Figma(client_id="cid", client_secret="csecret")
    url = p.authorization_url(state="st", redirect_uri="https://app/cb", code_verifier="verifier")
    assert url.startswith("https://www.figma.com/oauth?")
    params = qs(url)
    assert params["scope"] == "current_user:read"
    assert params["code_challenge_method"] == "S256"


async def test_figma_exchange_uses_basic_auth():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("authorization")
        return httpx.Response(200, json={"access_token": "at"})

    p = Figma(client_id="cid", client_secret="csecret")
    await p.exchange(mock_http(handler), code="c", redirect_uri="https://app/cb", code_verifier="v")
    assert seen["auth"].startswith("Basic ")


FIGMA_PROFILE = {
    "id": "1234",
    "email": "designer@example.com",
    "handle": "johnny",
    "img_url": "https://figma/avatar.png",
}


async def test_figma_fetch_user_maps_profile_email_unverified():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=FIGMA_PROFILE)

    p = Figma(client_id="cid", client_secret="csecret")
    info = await p.fetch_user(TOKENS, mock_http(handler))
    assert info.id == "1234"
    assert info.name == "johnny"
    assert info.email == "designer@example.com"
    assert info.email_verified is False  # figma.ts hardcodes emailVerified: false


# --- Gitlab -------------------------------------------------------------------------


def test_gitlab_authorization_url_default_host():
    p = Gitlab(client_id="cid", client_secret="csecret")
    url = p.authorization_url(state="st", redirect_uri="https://app/cb", code_verifier="v")
    assert url.startswith("https://gitlab.com/oauth/authorize?")
    assert qs(url)["scope"] == "read_user"
    assert qs(url)["code_challenge_method"] == "S256"


def test_gitlab_self_hosted_issuer_cleans_double_slashes():
    p = Gitlab(client_id="cid", client_secret="csecret", issuer="https://git.example.com//")
    assert p.authorization_endpoint == "https://git.example.com/oauth/authorize"
    assert p.token_endpoint == "https://git.example.com/oauth/token"
    assert p.userinfo_endpoint == "https://git.example.com/api/v4/user"


GITLAB_PROFILE = {
    "id": 42,
    "username": "octocat",
    "name": "Octo Cat",
    "email": "octo@example.com",
    "state": "active",
    "locked": False,
    "avatar_url": "https://gitlab/avatar.png",
}


async def test_gitlab_fetch_user_maps_profile_id_coerced_to_str():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=GITLAB_PROFILE)

    p = Gitlab(client_id="cid", client_secret="csecret")
    info = await p.fetch_user(TOKENS, mock_http(handler))
    assert info.id == "42"
    assert isinstance(info.id, str)
    assert info.name == "Octo Cat"
    assert info.email_verified is False  # no email_verified claim in this payload


@pytest.mark.parametrize(
    "overrides",
    [{"state": "blocked"}, {"locked": True}],
)
async def test_gitlab_fetch_user_rejects_inactive_or_locked_account(overrides):
    profile = {**GITLAB_PROFILE, **overrides}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=profile)

    p = Gitlab(client_id="cid", client_secret="csecret")
    with pytest.raises(OAuthFetchError):
        await p.fetch_user(TOKENS, mock_http(handler))


# --- Huggingface ----------------------------------------------------------------------


def test_huggingface_authorization_url_shape():
    p = Huggingface(client_id="cid", client_secret="csecret")
    url = p.authorization_url(state="st", redirect_uri="https://app/cb", code_verifier="v")
    assert url.startswith("https://huggingface.co/oauth/authorize?")
    params = qs(url)
    assert params["scope"] == "openid profile email"
    assert params["code_challenge_method"] == "S256"


HF_PROFILE = {
    "sub": "hf-user-1",
    "name": "Jane Dev",
    "preferred_username": "janedev",
    "picture": "https://hf/avatar.png",
    "email": "jane@example.com",
    "email_verified": True,
    "isPro": False,
}


async def test_huggingface_fetch_user_maps_profile():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"
        return httpx.Response(200, json=HF_PROFILE)

    p = Huggingface(client_id="cid", client_secret="csecret")
    info = await p.fetch_user(TOKENS, mock_http(handler))
    assert info.id == "hf-user-1"
    assert info.name == "Jane Dev"
    assert info.email_verified is True


async def test_huggingface_fetch_user_falls_back_to_preferred_username():
    profile = {**HF_PROFILE, "name": ""}

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=profile)

    p = Huggingface(client_id="cid", client_secret="csecret")
    info = await p.fetch_user(TOKENS, mock_http(handler))
    assert info.name == "janedev"


# --- Kick -------------------------------------------------------------------------------


def test_kick_authorization_url_shape():
    p = Kick(client_id="cid", client_secret="csecret")
    url = p.authorization_url(state="st", redirect_uri="https://app/cb", code_verifier="v")
    assert url.startswith("https://id.kick.com/oauth/authorize?")
    params = qs(url)
    assert params["scope"] == "user:read"
    assert params["code_challenge_method"] == "S256"


KICK_PROFILE = {
    "user_id": 99,
    "name": "Kicker",
    "email": "kicker@example.com",
    "profile_picture": "https://kick/avatar.png",
}


async def test_kick_fetch_user_unwraps_data_array_and_id_coerced():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": [KICK_PROFILE]})

    p = Kick(client_id="cid", client_secret="csecret")
    info = await p.fetch_user(TOKENS, mock_http(handler))
    assert info.id == "99"
    assert isinstance(info.id, str)
    assert info.name == "Kicker"
    assert info.email_verified is False  # kick.ts hardcodes emailVerified: false


async def test_kick_fetch_user_rejects_empty_data_array():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": []})

    p = Kick(client_id="cid", client_secret="csecret")
    with pytest.raises(OAuthFetchError):
        await p.fetch_user(TOKENS, mock_http(handler))


# --- Linear -------------------------------------------------------------------------------


def test_linear_authorization_url_has_no_pkce():
    p = Linear(client_id="cid", client_secret="csecret")
    url = p.authorization_url(state="st", redirect_uri="https://app/cb", code_verifier="verifier")
    assert url.startswith("https://linear.app/oauth/authorize?")
    params = qs(url)
    assert params["scope"] == "read"
    # linear.ts never forwards codeVerifier -> no PKCE params on the authorize URL
    assert "code_challenge" not in params
    assert "code_challenge_method" not in params


LINEAR_VIEWER = {
    "id": "abc-123",
    "name": "Ada Lovelace",
    "email": "ada@example.com",
    "avatarUrl": "https://linear/avatar.png",
    "active": True,
    "createdAt": "2024-01-01T00:00:00.000Z",
    "updatedAt": "2024-01-01T00:00:00.000Z",
}


async def test_linear_fetch_user_posts_graphql_and_maps_viewer():
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["method"] = request.method
        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content.decode())
        return httpx.Response(200, json={"data": {"viewer": LINEAR_VIEWER}})

    p = Linear(client_id="cid", client_secret="csecret")
    info = await p.fetch_user(TOKENS, mock_http(handler))
    assert seen["method"] == "POST"
    assert seen["url"] == "https://api.linear.app/graphql"
    assert "viewer" in seen["body"]["query"]
    assert info.id == "abc-123"
    assert info.name == "Ada Lovelace"
    assert info.image == "https://linear/avatar.png"
    assert info.email_verified is False  # linear.ts hardcodes emailVerified: false
    assert info.raw == LINEAR_VIEWER


async def test_linear_fetch_user_rejects_missing_viewer():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": {}})

    p = Linear(client_id="cid", client_secret="csecret")
    with pytest.raises(OAuthFetchError):
        await p.fetch_user(TOKENS, mock_http(handler))
