"""Provider parity: linkedin, notion, reddit, roblox, slack, spotify.

Per provider: authorize-URL shape (endpoints/scopes/PKCE) built directly off the
``ProviderConfig`` subclass, and profile -> ``OAuthUserInfo`` mapping against TS-shaped
fixtures fed through a mock ``httpx`` transport (``fetch_user``/``exchange``). Unit-level
against the provider classes themselves -- no FastAPI app/DB needed for these checks.
"""

from __future__ import annotations

import base64
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from better_auth.oauth.machinery import OAuthFetchError
from better_auth.oauth.models import OAuthTokens
from better_auth.oauth.providers_ext.linkedin import LinkedIn
from better_auth.oauth.providers_ext.notion import Notion
from better_auth.oauth.providers_ext.reddit import Reddit, create_placeholder_email
from better_auth.oauth.providers_ext.roblox import Roblox
from better_auth.oauth.providers_ext.slack import Slack
from better_auth.oauth.providers_ext.spotify import Spotify


def tokens(access_token: str = "tok") -> OAuthTokens:
    return OAuthTokens(access_token=access_token)


def mock_http(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def endpoint(url: str) -> str:
    parts = urlsplit(url)
    return f"{parts.scheme}://{parts.netloc}{parts.path}"


# --- LinkedIn --------------------------------------------------------------------------


def test_linkedin_authorization_url():
    p = LinkedIn(client_id="cid", client_secret="secret")
    url = p.authorization_url(state="st", redirect_uri="https://app.example/cb")
    q = parse_qs(urlsplit(url).query)
    assert endpoint(url) == "https://www.linkedin.com/oauth/v2/authorization"
    assert q["client_id"] == ["cid"]
    assert q["state"] == ["st"]
    assert q["redirect_uri"] == ["https://app.example/cb"]
    assert q["response_type"] == ["code"]
    assert set(q["scope"][0].split(" ")) == {"profile", "email", "openid"}
    assert "code_challenge" not in q  # linkedin: no PKCE


async def test_linkedin_profile_mapping():
    p = LinkedIn(client_id="cid", client_secret="secret")
    profile = {
        "sub": "li-123",
        "name": "Ada Lovelace",
        "email": "ada@example.com",
        "email_verified": True,
        "picture": "https://img/ada.png",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v2/userinfo"
        assert request.headers["authorization"] == "Bearer tok"
        return httpx.Response(200, json=profile)

    async with mock_http(handler) as http:
        info = await p.fetch_user(tokens(), http)
    assert info.id == "li-123"
    assert info.email == "ada@example.com"
    assert info.name == "Ada Lovelace"
    assert info.image == "https://img/ada.png"
    assert info.email_verified is True
    assert info.raw == profile


async def test_linkedin_missing_email_verified_defaults_false():
    p = LinkedIn(client_id="cid", client_secret="secret")
    profile = {"sub": 99, "name": "No Verify Claim", "picture": "https://img/x.png"}

    async with mock_http(lambda r: httpx.Response(200, json=profile)) as http:
        info = await p.fetch_user(tokens(), http)
    assert info.id == "99"  # str-coerced
    assert info.email is None
    assert info.email_verified is False


# --- Notion ------------------------------------------------------------------------------


def test_notion_authorization_url_owner_param_no_default_scope():
    p = Notion(client_id="cid", client_secret="secret")
    url = p.authorization_url(state="st", redirect_uri="https://app.example/cb")
    q = parse_qs(urlsplit(url).query)
    assert endpoint(url) == "https://api.notion.com/v1/oauth/authorize"
    assert q["owner"] == ["user"]
    assert "scope" not in q  # notion has no default scopes
    assert "code_challenge" not in q  # no PKCE


async def test_notion_profile_mapping_nested_bot_owner_user():
    p = Notion(client_id="cid", client_secret="secret")
    profile = {
        "object": "user",
        "id": "notion-1",
        "type": "person",
        "name": "Ada",
        "avatar_url": "https://img/ada.png",
        "person": {"email": "ada@example.com"},
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/users/me"
        assert request.headers["notion-version"] == "2022-06-28"
        assert request.headers["authorization"] == "Bearer tok"
        return httpx.Response(200, json={"bot": {"owner": {"user": profile}}})

    async with mock_http(handler) as http:
        info = await p.fetch_user(tokens(), http)
    assert info.id == "notion-1"
    assert info.email == "ada@example.com"
    assert info.name == "Ada"
    assert info.image == "https://img/ada.png"
    assert info.email_verified is False  # notion never reports verification
    assert info.raw == profile


async def test_notion_missing_email_maps_to_none():
    p = Notion(client_id="cid", client_secret="secret")
    profile = {"object": "user", "id": "bot-1", "type": "bot"}
    payload = {"bot": {"owner": {"user": profile}}}

    async with mock_http(lambda r: httpx.Response(200, json=payload)) as http:
        info = await p.fetch_user(tokens(), http)
    assert info.email is None


async def test_notion_missing_owner_user_raises():
    p = Notion(client_id="cid", client_secret="secret")

    async with mock_http(lambda r: httpx.Response(200, json={"bot": {}})) as http:
        with pytest.raises(OAuthFetchError):
            await p.fetch_user(tokens(), http)


async def test_notion_token_exchange_uses_basic_auth():
    p = Notion(client_id="cid", client_secret="csecret")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/oauth/token"
        assert request.headers["authorization"].startswith("Basic ")
        body = request.content.decode()
        assert "client_secret" not in body  # basic auth: creds in header, not body
        return httpx.Response(200, json={"access_token": "at"})

    async with mock_http(handler) as http:
        result = await p.exchange(http, code="abc", redirect_uri="https://app.example/cb")
    assert result.access_token == "at"


# --- Reddit --------------------------------------------------------------------------------


def test_reddit_authorization_url_defaults():
    p = Reddit(client_id="cid", client_secret="secret")
    url = p.authorization_url(state="st", redirect_uri="https://app.example/cb")
    q = parse_qs(urlsplit(url).query)
    assert endpoint(url) == "https://www.reddit.com/api/v1/authorize"
    assert q["scope"] == ["identity"]
    assert "code_challenge" not in q  # reddit: no PKCE
    assert "duration" not in q  # not configured by default


def test_reddit_authorization_url_duration_via_authorize_params():
    p = Reddit(client_id="cid", client_secret="secret", authorize_params={"duration": "permanent"})
    url = p.authorization_url(state="st", redirect_uri="https://app.example/cb")
    q = parse_qs(urlsplit(url).query)
    assert q["duration"] == ["permanent"]


async def test_reddit_token_exchange_basic_auth_and_headers():
    p = Reddit(client_id="cid", client_secret="csecret")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/access_token"
        assert request.headers["accept"] == "text/plain"
        assert request.headers["user-agent"] == "better-auth"  # TS v1.7.6 reddit.ts:64-67
        assert request.headers["authorization"].startswith("Basic ")
        body = request.content.decode()
        assert "grant_type=authorization_code" in body
        assert "client_id" not in body  # basic auth: no client_id/secret in body
        return httpx.Response(200, json={"access_token": "r_tok"})

    async with mock_http(handler) as http:
        result = await p.exchange(http, code="abc", redirect_uri="https://app.example/cb")
    assert result.access_token == "r_tok"


async def test_reddit_profile_mapping_synthesizes_placeholder_email():
    p = Reddit(client_id="cid", client_secret="secret")
    profile = {
        "id": "8xwlg",
        "name": "spez",
        "icon_img": "https://img/reddit.png?width=256&crop=1",
        "has_verified_email": True,
        "oauth_client_id": "cid",
        "verified": True,
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/v1/me"
        assert request.headers["user-agent"] == "better-auth"  # TS v1.7.6 reddit.ts:89-92
        assert request.headers["authorization"] == "Bearer tok"
        return httpx.Response(200, json=profile)

    async with mock_http(handler) as http:
        info = await p.fetch_user(tokens(), http)
    assert info.id == "8xwlg"
    # TS v1.7.6 reddit.ts:105-110 + utils/email.ts:6,30 (b4ad5a110)
    assert info.email == "8xwlg@reddit.placeholder.invalid"
    assert info.email_verified is False
    assert info.image == "https://img/reddit.png"  # query string stripped


# --- Roblox ----------------------------------------------------------------------------


def test_roblox_authorization_url_scopes_and_default_prompt():
    p = Roblox(client_id="cid", client_secret="secret")
    url = p.authorization_url(state="st", redirect_uri="https://app.example/cb")
    q = parse_qs(urlsplit(url).query)
    assert endpoint(url) == "https://apis.roblox.com/oauth/v1/authorize"
    assert set(q["scope"][0].split(" ")) == {"openid", "profile"}
    assert q["prompt"] == ["select_account consent"]
    assert "code_challenge" not in q  # roblox: no PKCE


def test_roblox_authorization_url_custom_prompt_override():
    p = Roblox(client_id="cid", client_secret="secret", authorize_params={"prompt": "login"})
    url = p.authorization_url(state="st", redirect_uri="https://app.example/cb")
    q = parse_qs(urlsplit(url).query)
    assert q["prompt"] == ["login"]


async def test_roblox_profile_mapping_no_real_email():
    p = Roblox(client_id="cid", client_secret="secret")
    profile = {
        "sub": 123456,
        "preferred_username": "builder123",
        "nickname": "Builder",
        "name": "Builder",
        "created_at": 1700000000,
        "profile": "https://roblox.com/users/123456/profile",
        "picture": "https://img/roblox.png",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/oauth/v1/userinfo"
        return httpx.Response(200, json=profile)

    async with mock_http(handler) as http:
        info = await p.fetch_user(tokens(), http)
    assert info.id == "123456"  # str-coerced
    assert info.name == "Builder"
    # TS v1.7.6 roblox.ts:105-108 (b4ad5a110): placeholder keyed to sub, not the username
    assert info.email == "123456@roblox.placeholder.invalid"
    assert info.email_verified is False


async def test_roblox_name_falls_back_to_preferred_username():
    p = Roblox(client_id="cid", client_secret="secret")
    profile = {"sub": "1", "preferred_username": "onlyusername", "picture": "https://img/x.png"}

    async with mock_http(lambda r: httpx.Response(200, json=profile)) as http:
        info = await p.fetch_user(tokens(), http)
    assert info.name == "onlyusername"


# --- Slack -------------------------------------------------------------------------------


def test_slack_authorization_url():
    p = Slack(client_id="cid", client_secret="secret")
    url = p.authorization_url(state="st", redirect_uri="https://app.example/cb")
    q = parse_qs(urlsplit(url).query)
    assert endpoint(url) == "https://slack.com/openid/connect/authorize"
    assert set(q["scope"][0].split(" ")) == {"openid", "profile", "email"}
    assert q["response_type"] == ["code"]
    assert "code_challenge" not in q  # slack: no PKCE


async def test_slack_profile_mapping_namespaced_claims():
    p = Slack(client_id="cid", client_secret="secret")
    profile = {
        "ok": True,
        "sub": "U0123",
        "https://slack.com/user_id": "U0123",
        "https://slack.com/team_id": "T0123",
        "email": "ada@example.com",
        "email_verified": True,
        "name": "Ada Lovelace",
        "picture": "https://img/pic.png",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/openid.connect.userInfo"
        assert request.headers["authorization"] == "Bearer tok"
        return httpx.Response(200, json=profile)

    async with mock_http(handler) as http:
        info = await p.fetch_user(tokens(), http)
    assert info.id == "U0123"
    assert info.email == "ada@example.com"
    assert info.image == "https://img/pic.png"
    assert info.email_verified is True


async def test_slack_image_falls_back_to_team_scoped_avatar():
    p = Slack(client_id="cid", client_secret="secret")
    profile = {
        "sub": "U9",
        "https://slack.com/user_id": "U9",
        "email": "x@example.com",
        "email_verified": False,
        "name": "X",
        "https://slack.com/user_image_512": "https://img/512.png",
    }

    async with mock_http(lambda r: httpx.Response(200, json=profile)) as http:
        info = await p.fetch_user(tokens(), http)
    assert info.image == "https://img/512.png"


# --- Spotify -----------------------------------------------------------------------------


def test_spotify_authorization_url_uses_pkce():
    p = Spotify(client_id="cid", client_secret="secret")
    url = p.authorization_url(
        state="st", redirect_uri="https://app.example/cb", code_verifier="verifier123"
    )
    q = parse_qs(urlsplit(url).query)
    assert endpoint(url) == "https://accounts.spotify.com/authorize"
    assert q["scope"] == ["user-read-email"]
    assert q["code_challenge_method"] == ["S256"]
    assert "code_challenge" in q


async def test_spotify_profile_mapping_takes_first_image():
    p = Spotify(client_id="cid", client_secret="secret")
    profile = {
        "id": 555,
        "display_name": "Ada Lovelace",
        "email": "ada@example.com",
        "images": [{"url": "https://img/large.png"}, {"url": "https://img/small.png"}],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/me"
        assert request.headers["authorization"] == "Bearer tok"
        return httpx.Response(200, json=profile)

    async with mock_http(handler) as http:
        info = await p.fetch_user(tokens(), http)
    assert info.id == "555"  # str-coerced
    assert info.name == "Ada Lovelace"
    assert info.image == "https://img/large.png"
    assert info.email_verified is False  # spotify never reports verification


async def test_spotify_profile_mapping_no_images():
    p = Spotify(client_id="cid", client_secret="secret")
    profile = {"id": "1", "display_name": "No Pic", "email": "x@example.com", "images": []}

    async with mock_http(lambda r: httpx.Response(200, json=profile)) as http:
        info = await p.fetch_user(tokens(), http)
    assert info.image is None


async def test_spotify_token_exchange_sends_code_verifier():
    p = Spotify(client_id="cid", client_secret="secret")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/token"
        body = request.content.decode()
        assert "code_verifier=verifier123" in body
        return httpx.Response(200, json={"access_token": "sp_tok"})

    async with mock_http(handler) as http:
        result = await p.exchange(
            http, code="abc", redirect_uri="https://app.example/cb", code_verifier="verifier123"
        )
    assert result.access_token == "sp_tok"


# --- v1.7.6: per-request additionalParams (e7eb45b06) ------------------------------------


@pytest.mark.parametrize("cls", [LinkedIn, Notion, Reddit, Roblox, Slack, Spotify])
def test_authorization_url_forwards_request_additional_params(cls):
    # TS v1.7.6 linkedin.ts:41, notion.ts:37, reddit.ts:42, roblox.ts:46, slack.ts:50,
    # spotify.ts:33: caller extras are forwarded, reserved keys are never overridden.
    p = cls(client_id="cid", client_secret="secret")
    url = p.authorization_url(
        state="st",
        redirect_uri="https://app.example/cb",
        additional_params={"audience": "x", "state": "evil"},
    )
    q = parse_qs(urlsplit(url).query)
    assert q["audience"] == ["x"]
    assert q["state"] == ["st"]


def test_notion_owner_param_wins_over_request_params():
    # TS v1.7.6 notion.ts:50-53: `{...additionalParams, owner: "user"}`
    p = Notion(client_id="cid", client_secret="secret")
    url = p.authorization_url(
        state="st", redirect_uri="https://app.example/cb", additional_params={"owner": "workspace"}
    )
    assert parse_qs(urlsplit(url).query)["owner"] == ["user"]


def test_request_params_win_over_reddit_duration_and_roblox_prompt():
    # create-authorization-url.ts:108-112 sets additionalParams after duration/prompt
    reddit = Reddit(client_id="cid", client_secret="s", authorize_params={"duration": "permanent"})
    url = reddit.authorization_url(
        state="st",
        redirect_uri="https://app.example/cb",
        additional_params={"duration": "temporary"},
    )
    assert parse_qs(urlsplit(url).query)["duration"] == ["temporary"]
    roblox = Roblox(client_id="cid", client_secret="s")
    url = roblox.authorization_url(
        state="st", redirect_uri="https://app.example/cb", additional_params={"prompt": "login"}
    )
    assert parse_qs(urlsplit(url).query)["prompt"] == ["login"]


# --- v1.7.6: Reddit shared token flow (a2bae0cad) ----------------------------------------


async def test_reddit_token_requests_use_form_encoded_basic_credentials():
    # TS v1.7.6 reddit.ts:34-36 client_secret_basic for both exchange and refresh; the
    # credentials are form-url-encoded before base64 (basic-credentials.ts:38-44).
    p = Reddit(client_id="c:id", client_secret="s cret")
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"access_token": "r_tok"})

    async with mock_http(handler) as http:
        await p.exchange(http, code="abc", redirect_uri="https://app.example/cb")
        await p.refresh(http, "rt")
    expected = "Basic " + base64.b64encode(b"c%3Aid:s+cret").decode()
    assert [r.headers["authorization"] for r in seen] == [expected, expected]
    refresh = seen[1]
    assert refresh.url == "https://www.reddit.com/api/v1/access_token"
    assert parse_qs(refresh.content.decode()) == {
        "grant_type": ["refresh_token"],
        "refresh_token": ["rt"],
    }
    # refresh sends no Reddit-specific headers (reddit.ts:74-79)
    assert refresh.headers["accept"] == "application/json"


async def test_reddit_token_request_without_secret_fails():
    # token-endpoint-auth.ts: client_secret_basic requires clientSecret
    p = Reddit(client_id="cid")
    async with mock_http(lambda r: httpx.Response(200, json={"access_token": "x"})) as http:
        with pytest.raises(OAuthFetchError):
            await p.exchange(http, code="abc", redirect_uri="https://app.example/cb")


def test_placeholder_email_rejects_invalid_identifier():
    # TS v1.7.6 utils/email.ts:28-33 throws TypeError when the address fails z.email()
    with pytest.raises(TypeError, match="Invalid placeholder email"):
        create_placeholder_email(identifier="a b", namespace="reddit")
    assert create_placeholder_email(identifier="42", namespace="roblox") == (
        "42@roblox.placeholder.invalid"
    )
