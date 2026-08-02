from urllib.parse import parse_qs, urlsplit

import httpx

from better_auth import GitHub
from better_auth.adapters.base import Where
from conftest import SIGNUP, make_auth, make_client, sign_up

PROFILE = {"id": 4242, "login": "octocat", "name": "Octo Cat", "avatar_url": "http://img/x.png"}
EMAILS = [{"email": "octo@example.com", "primary": True, "verified": True}]


def github_http(profile=PROFILE, emails=EMAILS, token_response=None):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login/oauth/access_token":
            return httpx.Response(200, json=token_response or {"access_token": "gh_token"})
        if request.url.path == "/user":
            return httpx.Response(200, json=profile)
        if request.url.path == "/user/emails":
            return httpx.Response(200, json=emails)
        return httpx.Response(404)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def oauth_auth(**kwargs):
    return make_auth(
        social_providers={"github": GitHub(client_id="cid", client_secret="csecret")},
        http_client=kwargs.pop("http_client", github_http()),
        **kwargs,
    )


async def start_flow(client, callback_url="/dashboard"):
    response = await client.post(
        "/api/auth/sign-in/social", json={"provider": "github", "callbackURL": callback_url}
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["redirect"] is True
    query = parse_qs(urlsplit(body["url"]).query)
    return body["url"], query["state"][0]


async def test_sign_in_social_builds_authorize_url():
    auth = oauth_auth()
    async with make_client(auth) as client:
        url, state = await start_flow(client)
        parts = urlsplit(url)
        query = parse_qs(parts.query)
        assert parts.netloc == "github.com"
        assert query["client_id"] == ["cid"]
        assert query["redirect_uri"] == ["http://testserver/api/auth/callback/github"]
        assert query["response_type"] == ["code"]
        assert "read:user" in query["scope"][0]
        assert len(state) == 32


async def test_unknown_provider():
    auth = oauth_auth()
    async with make_client(auth) as client:
        response = await client.post("/api/auth/sign-in/social", json={"provider": "gitlab"})
        assert response.status_code == 404
        assert response.json()["code"] == "PROVIDER_NOT_FOUND"


async def test_callback_creates_user_account_and_session():
    auth = oauth_auth()
    async with make_client(auth) as client:
        _url, state = await start_flow(client)
        response = await client.get(f"/api/auth/callback/github?code=abc&state={state}")
        assert response.status_code == 302
        assert response.headers["location"] == "http://testserver/dashboard"

        session = (await client.get("/api/auth/get-session")).json()
        assert session["user"]["email"] == "octo@example.com"
        assert session["user"]["emailVerified"] is True
        assert session["user"]["image"] == "http://img/x.png"

        account = await auth.adapter.find_one("account", [Where("providerId", "github")])
        assert account["accountId"] == "4242"
        assert account["accessToken"] == "gh_token"


async def test_second_login_reuses_user():
    auth = oauth_auth()
    async with make_client(auth) as client:
        _url, state = await start_flow(client)
        await client.get(f"/api/auth/callback/github?code=abc&state={state}")
        client.cookies.clear()

        _url, state = await start_flow(client)
        await client.get(f"/api/auth/callback/github?code=abc&state={state}")

        assert len(await auth.adapter.find_many("user")) == 1
        assert len(await auth.adapter.find_many("account")) == 1


async def test_state_is_single_use():
    auth = oauth_auth()
    async with make_client(auth) as client:
        _url, state = await start_flow(client)
        await client.get(f"/api/auth/callback/github?code=abc&state={state}")
        replay = await client.get(f"/api/auth/callback/github?code=abc&state={state}")
        assert replay.status_code == 302
        assert "error=state_not_found" in replay.headers["location"]


async def test_missing_state_cookie_is_rejected():
    auth = oauth_auth()
    async with make_client(auth) as client:
        _url, state = await start_flow(client)
        client.cookies.clear()
        response = await client.get(f"/api/auth/callback/github?code=abc&state={state}")
        assert "error=state_mismatch" in response.headers["location"]


async def test_provider_error_redirects():
    auth = oauth_auth()
    async with make_client(auth) as client:
        _url, state = await start_flow(client)
        response = await client.get(f"/api/auth/callback/github?error=access_denied&state={state}")
        assert response.status_code == 302
        assert "error=access_denied" in response.headers["location"]


async def test_unverified_email_does_not_link_existing_account():
    unverified = [{"email": SIGNUP["email"], "primary": True, "verified": False}]
    auth = oauth_auth(http_client=github_http(emails=unverified))
    async with make_client(auth) as client:
        await sign_up(client)  # existing credential user with that email
        client.cookies.clear()

        _url, state = await start_flow(client)
        response = await client.get(f"/api/auth/callback/github?code=abc&state={state}")
        assert "error=account_not_linked" in response.headers["location"]
        assert len(await auth.adapter.find_many("user")) == 1


async def test_verified_email_links_to_existing_user():
    # Spec-driven change (link-account.ts): `requireLocalEmailVerified` defaults True, so a
    # verified IdP email won't auto-link into a local row whose own email was never verified
    # (account-preemption guard). The credential user here is unverified, so linking is only
    # allowed with the option off — see test_require_local_email_verified_blocks_link for the
    # default-on gate.
    from better_auth import AccountLinking, AccountOptions

    linked = [{"email": SIGNUP["email"], "primary": True, "verified": True}]
    auth = oauth_auth(
        http_client=github_http(emails=linked),
        account=AccountOptions(
            account_linking=AccountLinking(require_local_email_verified=False)
        ),
    )
    async with make_client(auth) as client:
        await sign_up(client)
        client.cookies.clear()

        _url, state = await start_flow(client)
        response = await client.get(f"/api/auth/callback/github?code=abc&state={state}")
        assert response.status_code == 302
        assert "error" not in response.headers["location"]
        assert len(await auth.adapter.find_many("user")) == 1
        assert len(await auth.adapter.find_many("account")) == 2  # credential + github

        accounts = (await client.get("/api/auth/list-accounts")).json()
        provider_ids = {account["providerId"] for account in accounts}
        assert provider_ids == {"credential", "github"}
        assert all("password" not in account for account in accounts)
        assert all("accessToken" not in account for account in accounts)


async def test_failed_code_exchange_redirects():
    auth = oauth_auth(http_client=github_http(token_response={"error": "bad_code"}))
    async with make_client(auth) as client:
        _url, state = await start_flow(client)
        response = await client.get(f"/api/auth/callback/github?code=abc&state={state}")
        assert "error=invalid_code" in response.headers["location"]
