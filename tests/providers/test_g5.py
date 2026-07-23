"""W2-B-G5 — twitter, tiktok, wechat, salesforce provider ports.

Asserts each provider's non-standard authorize-URL shape, token-exchange request
form (via a capturing MockTransport), and profile mapping — byte-exact to the TS
source in ``packages/core/src/social-providers/{twitter,tiktok,wechat,salesforce}.ts``.
"""

from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from better_auth.oauth.machinery import OAuthFetchError
from better_auth.oauth.models import OAuthTokens
from better_auth.oauth.providers_ext.salesforce import Salesforce
from better_auth.oauth.providers_ext.tiktok import TikTok
from better_auth.oauth.providers_ext.twitter import Twitter
from better_auth.oauth.providers_ext.wechat import WeChat


def capturing(routes):
    """MockTransport where ``routes`` maps url.path -> (json[, status]). Records every
    request into ``.requests`` for outgoing-form assertions."""
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        entry = routes.get(request.url.path)
        if entry is None:
            return httpx.Response(404)
        body, status = (entry, 200) if isinstance(entry, dict) else entry
        return httpx.Response(status, json=body)

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    client.requests = seen  # ty: ignore[unresolved-attribute]  # noqa: shim for assertions
    return client


# --------------------------------------------------------------------------- twitter


def test_twitter_authorization_url():
    p = Twitter(client_id="tw_id", client_secret="tw_secret")
    url = p.authorization_url(
        state="st", redirect_uri="http://app/cb/twitter", code_verifier="v" * 43
    )
    split = urlsplit(url)
    assert split.scheme + "://" + split.netloc + split.path == "https://x.com/i/oauth2/authorize"
    q = parse_qs(split.query)
    assert q["scope"][0] == "users.read tweet.read offline.access users.email"
    assert q["response_type"] == ["code"]
    assert q["client_id"] == ["tw_id"]
    # PKCE is required for twitter.
    assert q["code_challenge_method"] == ["S256"]
    assert "code_challenge" in q


async def test_twitter_exchange_uses_basic_auth():
    http = capturing({"/2/oauth2/token": {"access_token": "at", "token_type": "bearer"}})
    p = Twitter(client_id="tw_id", client_secret="tw_secret")
    await p.exchange(http, code="c", redirect_uri="http://app/cb/twitter", code_verifier="v" * 43)
    req = http.requests[0]
    # basic auth -> Authorization header, NOT client_id in the body.
    assert req.headers["authorization"].startswith("Basic ")
    body = req.content.decode()
    assert "client_id" not in body
    assert "code_verifier=" in body


async def test_twitter_fetch_user_two_calls_and_email():
    # Two calls hit /2/users/me; the confirmed_email query returns the email.
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/2/users/me":
            if "confirmed_email" in request.url.query.decode():
                return httpx.Response(200, json={"data": {"confirmed_email": "elon@x.com"}})
            return httpx.Response(
                200,
                json={
                    "data": {
                        "id": "42",
                        "name": "Elon",
                        "username": "elon",
                        "profile_image_url": "http://img/x.png",
                    }
                },
            )
        return httpx.Response(404)

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    p = Twitter(client_id="tw_id", client_secret="tw_secret")
    info = await p.fetch_user(OAuthTokens(access_token="at"), http)
    assert info.id == "42"
    assert info.name == "Elon"
    assert info.email == "elon@x.com"
    assert info.email_verified is True
    assert info.image == "http://img/x.png"


async def test_twitter_falls_back_to_username_when_no_email():
    def handler(request: httpx.Request) -> httpx.Response:
        if "confirmed_email" in request.url.query.decode():
            return httpx.Response(200, json={"data": {}})
        return httpx.Response(200, json={"data": {"id": "1", "name": "N", "username": "handle"}})

    http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    p = Twitter(client_id="i", client_secret="s")
    info = await p.fetch_user(OAuthTokens(access_token="at"), http)
    assert info.email == "handle"
    assert info.email_verified is False


# ---------------------------------------------------------------------------- tiktok


def test_tiktok_authorization_url_hand_built():
    p = TikTok(client_secret="ts", client_key="ck123")
    url = p.authorization_url(state="STATE", redirect_uri="http://app/cb/tiktok")
    # Exact, ordered, non-standard shape: scope, response_type, client_key, redirect_uri, state.
    assert url == (
        "https://www.tiktok.com/v2/auth/authorize?scope=user.info.profile"
        "&response_type=code&client_key=ck123"
        "&redirect_uri=http%3A%2F%2Fapp%2Fcb%2Ftiktok&state=STATE"
    )


def test_tiktok_scopes_comma_joined():
    p = TikTok(client_secret="ts", client_key="ck")
    url = p.authorization_url(state="s", redirect_uri="http://app/cb", extra_scopes=["video.list"])
    assert "scope=user.info.profile,video.list" in url


async def test_tiktok_exchange_sends_client_key_not_client_id():
    http = capturing({"/v2/oauth/token/": {"access_token": "at"}})
    p = TikTok(client_secret="ts", client_key="ck123")
    await p.exchange(http, code="c", redirect_uri="http://app/cb/tiktok")
    body = http.requests[0].content.decode()
    assert "client_key=ck123" in body
    assert "client_secret=ts" in body
    assert "grant_type=authorization_code" in body
    # No PKCE for tiktok.
    assert "code_verifier" not in body


async def test_tiktok_fetch_user_profile_mapping():
    http = capturing(
        {
            "/v2/user/info/": {
                "data": {
                    "user": {
                        "open_id": "oid_1",
                        "display_name": "Dancer",
                        "username": "dancer99",
                        "avatar_large_url": "http://tt/av.png",
                    }
                }
            }
        }
    )
    p = TikTok(client_secret="ts", client_key="ck")
    info = await p.fetch_user(OAuthTokens(access_token="at"), http)
    assert info.id == "oid_1"
    assert info.name == "Dancer"
    # TikTok has no email; falls back to username.
    assert info.email == "dancer99"
    assert info.image == "http://tt/av.png"
    assert info.email_verified is False
    # fields query is exact.
    assert (
        http.requests[0].url.query.decode()
        == "fields=open_id,avatar_large_url,display_name,username"
    )


# ---------------------------------------------------------------------------- wechat


def test_wechat_authorization_url_appid_and_fragment():
    p = WeChat(client_id="wxappid", client_secret="wxsecret")
    url = p.authorization_url(state="STATE", redirect_uri="http://app/cb/wechat")
    assert url.startswith("https://open.weixin.qq.com/connect/qrconnect?")
    assert url.endswith("#wechat_redirect")
    q = parse_qs(urlsplit(url).query)
    assert q["appid"] == ["wxappid"]
    assert "client_id" not in q
    assert q["scope"] == ["snsapi_login"]
    assert q["response_type"] == ["code"]
    assert q["lang"] == ["cn"]
    assert q["redirect_uri"] == ["http://app/cb/wechat"]


async def test_wechat_exchange_is_get_with_appid_secret():
    http = capturing(
        {
            "/sns/oauth2/access_token": {
                "access_token": "wx_at",
                "expires_in": 7200,
                "refresh_token": "wx_rt",
                "openid": "OPENID_1",
                "scope": "snsapi_login",
                "unionid": "UNION_1",
            }
        }
    )
    p = WeChat(client_id="wxappid", client_secret="wxsecret")
    tokens = await p.exchange(http, code="thecode", redirect_uri="ignored")
    req = http.requests[0]
    assert req.method == "GET"
    q = parse_qs(req.url.query.decode())
    assert q["appid"] == ["wxappid"]
    assert q["secret"] == ["wxsecret"]
    assert q["code"] == ["thecode"]
    assert q["grant_type"] == ["authorization_code"]
    # openid is stashed on raw for the userinfo call.
    assert tokens.raw["openid"] == "OPENID_1"
    assert tokens.access_token == "wx_at"
    assert tokens.scopes == ["snsapi_login"]


async def test_wechat_exchange_raises_on_errcode():
    http = capturing({"/sns/oauth2/access_token": {"errcode": 40029, "errmsg": "invalid code"}})
    p = WeChat(client_id="a", client_secret="b")
    with pytest.raises(OAuthFetchError, match="invalid code"):
        await p.exchange(http, code="bad", redirect_uri="x")


async def test_wechat_fetch_user_needs_openid_and_synthesizes_email():
    http = capturing(
        {
            "/sns/userinfo": {
                "openid": "OPENID_1",
                "nickname": "小明",
                "headimgurl": "http://wx/av.png",
                "unionid": "UNION_1",
            }
        }
    )
    p = WeChat(client_id="a", client_secret="b")
    tokens = OAuthTokens(access_token="wx_at", raw={"openid": "OPENID_1"})
    info = await p.fetch_user(tokens, http)
    # id prefers unionid; email is the .invalid placeholder keyed to the id.
    assert info.id == "UNION_1"
    assert info.email == "UNION_1@wechat.invalid"
    assert info.name == "小明"
    assert info.image == "http://wx/av.png"
    assert info.email_verified is False
    # userinfo call carries access_token + openid + lang=zh_CN.
    q = parse_qs(http.requests[0].url.query.decode())
    assert q["access_token"] == ["wx_at"]
    assert q["openid"] == ["OPENID_1"]
    assert q["lang"] == ["zh_CN"]


async def test_wechat_fetch_user_missing_openid_raises():
    http = capturing({})
    p = WeChat(client_id="a", client_secret="b")
    with pytest.raises(OAuthFetchError):
        await p.fetch_user(OAuthTokens(access_token="at", raw={}), http)


# ------------------------------------------------------------------------- salesforce


def test_salesforce_production_endpoints():
    p = Salesforce(client_id="sf", client_secret="sec")
    assert p.authorization_endpoint == "https://login.salesforce.com/services/oauth2/authorize"
    assert p.token_endpoint == "https://login.salesforce.com/services/oauth2/token"
    assert p.userinfo_endpoint == "https://login.salesforce.com/services/oauth2/userinfo"


def test_salesforce_sandbox_endpoints():
    p = Salesforce(client_id="sf", client_secret="sec", environment="sandbox")
    assert p.authorization_endpoint == "https://test.salesforce.com/services/oauth2/authorize"
    assert p.token_endpoint == "https://test.salesforce.com/services/oauth2/token"


def test_salesforce_login_url_overrides_environment():
    p = Salesforce(
        client_id="sf",
        client_secret="sec",
        environment="sandbox",
        login_url="acme.my.salesforce.com",
    )
    assert p.authorization_endpoint == "https://acme.my.salesforce.com/services/oauth2/authorize"
    assert p.userinfo_endpoint == "https://acme.my.salesforce.com/services/oauth2/userinfo"


def test_salesforce_authorization_url_uses_pkce():
    p = Salesforce(client_id="sf", client_secret="sec")
    url = p.authorization_url(
        state="st", redirect_uri="http://app/cb/salesforce", code_verifier="v" * 43
    )
    q = parse_qs(urlsplit(url).query)
    assert q["scope"][0] == "openid email profile"
    assert q["code_challenge_method"] == ["S256"]


async def test_salesforce_fetch_user_maps_user_id_and_photos():
    http = capturing(
        {
            "/services/oauth2/userinfo": {
                "sub": "https://login.salesforce.com/id/00D/005",
                "user_id": "005xxx",
                "name": "Sales Rep",
                "email": "rep@acme.com",
                "email_verified": True,
                "photos": {"picture": "http://sf/pic.png", "thumbnail": "http://sf/thumb.png"},
            }
        }
    )
    p = Salesforce(client_id="sf", client_secret="sec")
    info = await p.fetch_user(OAuthTokens(access_token="at"), http)
    assert info.id == "005xxx"
    assert info.name == "Sales Rep"
    assert info.email == "rep@acme.com"
    assert info.email_verified is True
    assert info.image == "http://sf/pic.png"
    # standard bearer auth on the userinfo call.
    assert http.requests[0].headers["authorization"] == "Bearer at"
