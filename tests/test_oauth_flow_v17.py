"""Social sign-in core at better-auth v1.7.6: callback.ts, sign-in.ts (social), state.ts,
link-account.ts (validateUserInfo, requireEmailVerification), account.ts refresh."""

from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx

from better_auth import AccountLinking, AccountOptions, EmailVerification
from better_auth.adapters.base import Where
from better_auth.config import UserOptions
from better_auth.oauth.flow import add_oauth_server_context, get_oauth_state
from better_auth.oauth.models import OAuthTokens, OAuthUserInfo
from better_auth.oauth.providers import ProviderConfig
from better_auth.plugins import HookSet, Plugin, PluginHook
from better_auth.types import APIError
from conftest import SIGNUP, make_auth, make_client, sign_up

PROFILE: dict[str, Any] = {
    "sub": "acme-1",
    "email": "octo@example.com",
    "email_verified": True,
    "name": "Octo",
}


def acme_http(profile: dict[str, Any] | None = None, seen: dict | None = None):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/token":
            if seen is not None:
                seen["token_body"] = parse_qs(request.content.decode())
            return httpx.Response(200, json={"access_token": "at", "refresh_token": "rt"})
        if request.url.path == "/userinfo":
            return httpx.Response(200, json=PROFILE if profile is None else profile)
        return httpx.Response(404)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def acme(**over: Any) -> ProviderConfig:
    return ProviderConfig(
        client_id="cid",
        client_secret="sec",
        provider_id="acme",
        authorization_endpoint="https://idp.test/authorize",
        token_endpoint="https://idp.test/token",
        userinfo_endpoint="https://idp.test/userinfo",
        scopes=["openid", "email"],
        **over,
    )


def acme_auth(provider: ProviderConfig | None = None, **kwargs: Any):
    return make_auth(
        social_providers={"acme": provider or acme()},
        http_client=kwargs.pop("http_client", None) or acme_http(kwargs.pop("profile", None)),
        **kwargs,
    )


async def start(client, **body: Any) -> str:
    r = await client.post("/api/auth/sign-in/social", json={"provider": "acme", **body})
    assert r.status_code == 200, r.text
    return r.json()["url"]


def state_of(url: str) -> str:
    return parse_qs(urlsplit(url).query)["state"][0]


def location(r: httpx.Response) -> str:
    assert r.status_code == 302, r.text
    return r.headers["location"]


# --- state (state.ts parseGenericState + callback.ts:106-131) --------------------------


async def test_callback_without_state_redirects_state_not_found():
    async with make_client(acme_auth()) as client:
        r = await client.get("/api/auth/callback/acme?code=abc")
        assert location(r) == "http://testserver/api/auth/error?error=state_not_found"


async def test_callback_with_unknown_state_is_state_mismatch():
    # state.ts:223-229: a missing verification row is `state_mismatch`
    async with make_client(acme_auth()) as client:
        r = await client.get("/api/auth/callback/acme?code=abc&state=nope")
        assert location(r) == "http://testserver/api/auth/error?error=state_mismatch"


async def test_state_error_url_defaults_to_error_page_not_callback_url():
    # oauth2/state.ts:108-110: errorURL falls back to the default error page
    async with make_client(acme_auth()) as client:
        url = await start(client, callbackURL="/dash")
        client.cookies.clear()
        r = await client.get(f"/api/auth/callback/acme?code=abc&state={state_of(url)}")
        assert location(r) == "http://testserver/api/auth/error?error=state_mismatch"


async def test_error_redirect_keeps_fragment_last():
    # 79904f0be appendQueryParams: the query goes before the fragment
    async with make_client(acme_auth()) as client:
        url = await start(client, errorCallbackURL="http://testserver/err#top")
        r = await client.get(f"/api/auth/callback/acme?error=access_denied&state={state_of(url)}")
        assert location(r) == "http://testserver/err?error=access_denied#top"


async def test_provider_error_carries_description():
    async with make_client(acme_auth()) as client:
        url = await start(client, errorCallbackURL="/err")
        r = await client.get(
            "/api/auth/callback/acme?error=access_denied&error_description=user%20said%20no"
            f"&state={state_of(url)}"
        )
        assert location(r) == "/err?error=access_denied&error_description=user+said+no"


# --- IdP-initiated bounce (03e6c94e9, callback.ts:106-123) -----------------------------


async def test_idp_initiated_callback_bounces_to_authorize():
    async with make_client(acme_auth(acme(allow_idp_initiated=True))) as client:
        r = await client.get("/api/auth/callback/acme?code=abc")
        target = location(r)
        assert target.startswith("https://idp.test/authorize?")
        q = parse_qs(urlsplit(target).query)
        assert q["redirect_uri"] == ["http://testserver/api/auth/callback/acme"]
        assert "better-auth.state" in r.headers.get("set-cookie", "")
        # the bounced state completes a normal sign-in
        r2 = await client.get(f"/api/auth/callback/acme?code=abc&state={q['state'][0]}")
        assert location(r2) == "http://testserver"


async def test_empty_state_param_does_not_bounce():
    async with make_client(acme_auth(acme(allow_idp_initiated=True))) as client:
        r = await client.get("/api/auth/callback/acme?code=abc&state=")
        assert location(r).endswith("error=state_not_found")


# --- RFC 9207 iss + nonce binding (27b5d8022, callback.ts:174-196) ---------------------


async def test_issuer_mismatch_is_refused():
    async with make_client(acme_auth(acme(issuer="https://idp.test"))) as client:
        url = await start(client)
        r = await client.get(
            f"/api/auth/callback/acme?code=abc&iss=https://evil.test&state={state_of(url)}"
        )
        assert location(r).endswith("error=issuer_mismatch")


class NonceProvider(ProviderConfig):
    seen_nonce: str | None = None

    async def fetch_user(self, tokens: OAuthTokens, http: httpx.AsyncClient) -> OAuthUserInfo:
        NonceProvider.seen_nonce = tokens.expected_id_token_nonce
        return await super().fetch_user(tokens, http)


async def test_nonce_bound_provider_round_trips_expected_nonce():
    provider = NonceProvider(
        client_id="cid",
        provider_id="acme",
        authorization_endpoint="https://idp.test/authorize",
        token_endpoint="https://idp.test/token",
        userinfo_endpoint="https://idp.test/userinfo",
        requires_id_token_nonce=True,
    )
    async with make_client(acme_auth(provider)) as client:
        url = await start(client)
        nonce = parse_qs(urlsplit(url).query)["nonce"][0]
        r = await client.get(f"/api/auth/callback/acme?code=abc&state={state_of(url)}")
        assert location(r) == "http://testserver/"
        assert NonceProvider.seen_nonce == nonce


async def test_state_without_nonce_for_binding_provider_is_refused():
    provider = acme()
    async with make_client(acme_auth(provider)) as client:
        url = await start(client)
        provider.requires_id_token_nonce = True
        r = await client.get(f"/api/auth/callback/acme?code=abc&state={state_of(url)}")
        assert location(r).endswith("error=nonce_binding_missing")


# --- per-request additionalParams / loginHint (e7eb45b06) ------------------------------


async def test_sign_in_forwards_additional_params_and_login_hint():
    async with make_client(acme_auth()) as client:
        url = await start(client, additionalParams={"hd": "corp"}, loginHint="a@b.c")
        q = parse_qs(urlsplit(url).query)
        assert q["hd"] == ["corp"]
        assert q["login_hint"] == ["a@b.c"]


async def test_sign_in_rejects_reserved_additional_params():
    async with make_client(acme_auth()) as client:
        r = await client.post(
            "/api/auth/sign-in/social",
            json={"provider": "acme", "additionalParams": {"redirect_uri": "https://evil"}},
        )
        assert r.status_code == 400


async def test_link_social_forwards_additional_params_and_login_hint():
    async with make_client(acme_auth()) as client:
        await sign_up(client)
        r = await client.post(
            "/api/auth/link-social",
            json={"provider": "acme", "additionalParams": {"hd": "x"}, "loginHint": "h@x"},
        )
        q = parse_qs(urlsplit(r.json()["url"]).query)
        assert q["hd"] == ["x"] and q["login_hint"] == ["h@x"]


# --- callback ordering: link runs before the email check (callback.ts:268-285) ----------


async def test_link_callback_without_provider_email_is_email_does_not_match():
    profile = {"sub": "acme-9", "email_verified": True, "name": "No Mail"}
    async with make_client(acme_auth(profile=profile)) as client:
        await sign_up(client)
        r = await client.post("/api/auth/link-social", json={"provider": "acme"})
        state = state_of(r.json()["url"])
        cb = await client.get(f"/api/auth/callback/acme?code=abc&state={state}")
        assert location(cb).endswith("error=email_does_not_match")


# --- provider sign-up policy on the redirect callback -----------------------------------


async def test_callback_honors_provider_disable_sign_up():
    async with make_client(acme_auth(acme(disable_sign_up=True))) as client:
        url = await start(client)
        r = await client.get(f"/api/auth/callback/acme?code=abc&state={state_of(url)}")
        assert location(r).endswith("error=signup_disabled")


async def test_callback_disable_implicit_sign_up_needs_request_sign_up():
    async with make_client(acme_auth(acme(disable_implicit_sign_up=True))) as client:
        url = await start(client)
        r = await client.get(f"/api/auth/callback/acme?code=abc&state={state_of(url)}")
        assert location(r).endswith("error=signup_disabled")
        url = await start(client, requestSignUp=True)
        r = await client.get(f"/api/auth/callback/acme?code=abc&state={state_of(url)}")
        assert location(r) == "http://testserver/"


# --- user.validateUserInfo (41cca606d, af572166a) ---------------------------------------


def gate(calls: list, reject: dict | None = None, raises: bool = False):
    async def validate(data: dict[str, Any], ctx: Any):
        calls.append(data)
        if raises:
            raise RuntimeError("boom")
        return reject

    return UserOptions(validate_user_info=validate)


async def test_validate_user_info_rejects_oauth_sign_up_with_source():
    calls: list = []
    auth = acme_auth(user=gate(calls, {"error": "blocked_domain", "errorDescription": "nope"}))
    async with make_client(auth) as client:
        url = await start(client, errorCallbackURL="/err")
        r = await client.get(f"/api/auth/callback/acme?code=abc&state={state_of(url)}")
        assert location(r) == "/err?error=blocked_domain&error_description=nope"
    assert await auth.adapter.find_one("user", [Where("email", "octo@example.com")]) is None
    (call,) = calls
    assert call["source"]["action"] == "create-user"
    assert call["source"]["method"] == "oauth"
    assert call["source"]["oauth"]["providerId"] == "acme"
    assert call["source"]["oauth"]["profile"]["sub"] == "acme-1"
    assert call["user"]["email"] == "octo@example.com"


async def test_validate_user_info_throwing_fails_closed():
    auth = acme_auth(user=gate([], raises=True))
    async with make_client(auth) as client:
        url = await start(client)
        r = await client.get(f"/api/auth/callback/acme?code=abc&state={state_of(url)}")
        assert location(r).endswith(
            "error=validation_failed&error_description=User+validation+failed"
        )


async def test_validate_user_info_runs_on_returning_sign_in_and_implicit_link():
    calls: list = []
    auth = acme_auth(user=gate(calls))
    async with make_client(auth) as client:
        for _ in range(2):
            url = await start(client)
            await client.get(f"/api/auth/callback/acme?code=abc&state={state_of(url)}")
    assert [c["source"]["action"] for c in calls] == ["create-user", "sign-in"]
    # the sign-in call sees the local user id, not the provider subject
    user = await auth.adapter.find_one("user", [Where("email", "octo@example.com")])
    assert calls[1]["user"]["id"] == user["id"]

    calls.clear()
    auth = acme_auth(user=gate(calls), profile={**PROFILE, "email": SIGNUP["email"]})
    async with make_client(auth) as client:
        await sign_up(client)
        client.cookies.clear()
        await auth.adapter.update(
            "user", [Where("email", SIGNUP["email"])], {"emailVerified": True}
        )
        url = await start(client)
        await client.get(f"/api/auth/callback/acme?code=abc&state={state_of(url)}")
    assert calls[-1]["source"]["action"] == "link-account"


async def test_validate_user_info_rejects_explicit_link():
    calls: list = []
    auth = acme_auth(
        user=gate(calls, {"error": "no_link"}),
        profile={**PROFILE, "email": SIGNUP["email"]},
    )
    async with make_client(auth) as client:
        await sign_up(client)
        r = await client.post("/api/auth/link-social", json={"provider": "acme"})
        cb = await client.get(f"/api/auth/callback/acme?code=abc&state={state_of(r.json()['url'])}")
        assert location(cb).endswith("error=no_link&error_description=no_link")
    assert calls[-1]["source"]["action"] == "link-account"


# --- requireEmailVerification per provider (91f235f86) ---------------------------------


async def test_require_email_verification_blocks_session_and_sends_email():
    sent: list = []

    async def send(user, url, token):
        sent.append(url)

    auth = acme_auth(
        acme(require_email_verification=True),
        profile={**PROFILE, "email_verified": False},
        email_verification=EmailVerification(send_verification_email=send),
    )
    async with make_client(auth) as client:
        url = await start(client, callbackURL="/welcome")
        r = await client.get(f"/api/auth/callback/acme?code=abc&state={state_of(url)}")
        assert location(r).endswith("error=email_not_verified")
        assert (await client.get("/api/auth/get-session")).json() is None
    assert await auth.adapter.find_one("user", [Where("email", "octo@example.com")])
    (link,) = sent
    assert "callbackURL=%2Fwelcome" in link


# --- hook error forwarding (d309e5d2b) -------------------------------------------------


async def test_callback_forwards_api_error_from_database_hook():
    async def before(user, ctx):
        raise APIError(403, "DOMAIN_BLOCKED", "Domain blocked")

    auth = acme_auth(
        database_hooks={"user": {"create": {"before": before}}},
        trusted_origins=["https://app.test"],
    )
    async with make_client(auth) as client:
        url = await start(client, errorCallbackURL="https://app.test/err")
        r = await client.get(f"/api/auth/callback/acme?code=abc&state={state_of(url)}")
        assert (
            location(r)
            == "https://app.test/err?error=DOMAIN_BLOCKED&error_description=Domain+blocked"
        )


# --- server-trusted state channel (0cbaf81be) ------------------------------------------


class ContextPlugin(Plugin):
    id = "ctx-test"
    seen: dict[str, Any] = {}

    def hooks(self) -> HookSet:
        async def before(ctx):
            if ctx.request.path.endswith("/sign-in/social"):
                await add_oauth_server_context(ctx, {"anonymousUserId": "u1"})
            return None

        async def after(ctx):
            if "/callback/" in ctx.request.path:
                ContextPlugin.seen = dict(get_oauth_state(ctx) or {})
            return None

        return HookSet(
            before=[PluginHook(matcher=lambda ctx: True, handler=before)],
            after=[PluginHook(matcher=lambda ctx: True, handler=after)],
        )


async def test_server_context_rides_the_state_and_client_cannot_spoof_it():
    auth = acme_auth(plugins=[ContextPlugin()])
    async with make_client(auth) as client:
        url = await start(client, additionalData={"serverContext": {"anonymousUserId": "evil"}})
        await client.get(f"/api/auth/callback/acme?code=abc&state={state_of(url)}")
    assert ContextPlugin.seen["serverContext"] == {"anonymousUserId": "u1"}


# --- /refresh-token response (account.ts:942-943) --------------------------------------


async def test_refresh_token_response_account_id_is_the_row_id():
    auth = acme_auth(account=AccountOptions(account_linking=AccountLinking()))
    async with make_client(auth) as client:
        url = await start(client)
        await client.get(f"/api/auth/callback/acme?code=abc&state={state_of(url)}")
        account = await auth.adapter.find_one("account", [Where("providerId", "acme")])
        assert account is not None
        r = await client.post("/api/auth/refresh-token", json={"accountId": account["id"]})
        assert r.status_code == 200, r.text
    assert r.json()["accountId"] == account["id"]
