"""Tests for the oauth-proxy plugin (proxy OAuth callbacks through production).

Ports better-auth's plugins/oauth-proxy. TS source verified against:
  packages/better-auth/src/plugins/oauth-proxy/index.ts
  packages/better-auth/src/plugins/oauth-proxy/utils.ts
  packages/better-auth/src/plugins/oauth-proxy/oauth-proxy.test.ts

The whole flow is driven through real HTTP round trips (FastAPI ASGI + httpx),
with the provider token/userinfo endpoints stubbed via ``httpx.MockTransport``
(the same idiom as tests/test_oauth.py). The Python OAuth layer is DB-state only,
so only the database state strategy is exercised (TS's cookie strategy is not
ported).

Two-server flow (the real deployment shape): a *preview* instance starts the
sign-in, a *production* instance completes the provider code exchange and replays
an encrypted profile to the preview's ``/oauth-proxy-callback``.
"""

from __future__ import annotations

import json
import time
from typing import Any
from urllib.parse import parse_qs, quote, urlsplit

import httpx
import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from nacl.exceptions import CryptoError

from better_auth import BetterAuth, GitHub, MemoryAdapter, Where
from better_auth.crypto import symmetric_decrypt, symmetric_encrypt
from better_auth.integrations.fastapi import BetterAuthFastAPI
from better_auth.plugins_ext.oauth_proxy import OAuthProxyPlugin

SECRET = "test-secret-0123456789-abcdefghijklmnop"

PROFILE = {"id": 4242, "login": "octocat", "name": "Octo Cat", "avatar_url": "http://img/x.png"}
EMAILS = [{"email": "octo@example.com", "primary": True, "verified": True}]


def github_http() -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login/oauth/access_token":
            return httpx.Response(200, json={"access_token": "gh_token"})
        if request.url.path == "/user":
            return httpx.Response(200, json=PROFILE)
        if request.url.path == "/user/emails":
            return httpx.Response(200, json=EMAILS)
        return httpx.Response(404)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def make_instance(base_url: str, plugin: OAuthProxyPlugin, **overrides: Any) -> BetterAuth:
    return BetterAuth(
        secret=overrides.pop("secret", SECRET),
        base_url=base_url,
        adapter=MemoryAdapter(),
        social_providers={"github": GitHub(client_id="cid", client_secret="csecret")},
        http_client=github_http(),
        plugins=[plugin],
        **overrides,
    )


def make_client(auth: BetterAuth) -> AsyncClient:
    app = FastAPI()
    app.include_router(BetterAuthFastAPI(auth).router)
    return AsyncClient(
        transport=ASGITransport(app=app),
        base_url=auth.base_url,
        headers={"origin": auth.base_url},
    )


async def start_sign_in(client: AsyncClient, callback_url: str = "/dashboard") -> str:
    """POST /sign-in/social and return the raw provider authorization URL."""
    response = await client.post(
        "/api/auth/sign-in/social", json={"provider": "github", "callbackURL": callback_url}
    )
    assert response.status_code == 200, response.text
    return response.json()["url"]


def state_of(url: str) -> str:
    return parse_qs(urlsplit(url).query)["state"][0]


# --- no-op / skip -------------------------------------------------------------------------


async def test_no_op_when_current_equals_production():
    """Same-origin (production == current) → plugin is a no-op: no state package, the
    provider URL keeps the plain random state and the callback lands on /dashboard."""
    auth = make_instance(
        "http://localhost:3000",
        OAuthProxyPlugin(production_url="http://localhost:3000"),
    )
    async with make_client(auth) as client:
        url = await start_sign_in(client)
        state = state_of(url)
        # Plain (non-encrypted) state — short random token, not an encrypted package.
        assert len(state) < 50
        response = await client.get(f"/api/auth/callback/github?code=abc&state={state}")
        location = response.headers["location"]
        assert "/oauth-proxy-callback" not in location
        assert "/dashboard" in location


async def test_skip_proxy_header_disables_proxy():
    """The ``x-skip-oauth-proxy`` header forces a no-op even across origins."""
    auth = make_instance(
        "http://localhost:3000",
        OAuthProxyPlugin(production_url="http://production.example.com"),
    )
    async with make_client(auth) as client:
        response = await client.post(
            "/api/auth/sign-in/social",
            json={"provider": "github", "callbackURL": "/dashboard"},
            headers={"x-skip-oauth-proxy": "1"},
        )
        assert response.status_code == 200, response.text
        state = state_of(response.json()["url"])
        assert len(state) < 50  # not an encrypted package


# --- before sign-in: callbackURL rewrite --------------------------------------------------


async def test_before_hook_rewrites_callback_url_with_embedded_return():
    """The before hook rewrites callbackURL to the current-origin proxy callback with the
    original destination embedded, and the after hook encrypts the state into a package."""
    auth = make_instance(
        "http://preview.example.com",
        OAuthProxyPlugin(production_url="http://production.example.com"),
    )
    async with make_client(auth) as client:
        url = await start_sign_in(client, "/dashboard")
        state = state_of(url)
        # after-hook replaced the plain state with a long encrypted package
        assert len(state) > 50
        package = json.loads(symmetric_decrypt(SECRET, state))
        assert package["isOAuthProxy"] is True
        assert package["state"]  # the original random state id
        assert package["stateCookie"]  # re-encrypted state payload
        # the stored state carries the rewritten proxy callbackURL
        inner = json.loads(symmetric_decrypt(SECRET, package["stateCookie"]))
        assert inner["callbackURL"] == (
            "http://preview.example.com/api/auth/oauth-proxy-callback?callbackURL=%2Fdashboard"
        )


# --- production before /callback: passthrough ---------------------------------------------


async def test_production_callback_redirects_to_proxy_with_profile():
    """On production, the /callback before hook does the exchange itself and 302s to the
    preview's oauth-proxy-callback with an encrypted profile param (passthrough)."""
    preview = make_instance(
        "http://preview.example.com",
        OAuthProxyPlugin(production_url="http://production.example.com"),
    )
    production = make_instance("http://production.example.com", OAuthProxyPlugin())

    async with make_client(preview) as pv, make_client(production) as prod:
        state = state_of(await start_sign_in(pv, "/dashboard"))
        response = await prod.get(f"/api/auth/callback/github?code=abc&state={state}")
        assert response.status_code == 302
        location = response.headers["location"]
        assert location.startswith("http://preview.example.com/api/auth/oauth-proxy-callback")
        q = parse_qs(urlsplit(location).query)
        assert q["callbackURL"] == ["/dashboard"]
        assert q["profile"][0]
        # passthrough does NOT create a user on production
        assert len(await production.adapter.find_many("user")) == 0
        # profile is encrypted with the shared secret and carries the provider data
        payload = json.loads(symmetric_decrypt(SECRET, q["profile"][0]))
        assert payload["userInfo"]["email"] == "octo@example.com"
        assert payload["account"]["providerId"] == "github"
        assert isinstance(payload["timestamp"], int)


# --- full round trip ----------------------------------------------------------------------


async def _full_round_trip(preview: BetterAuth, production: BetterAuth) -> str:
    """Drive preview sign-in -> production callback -> preview proxy callback.
    Returns the final Location from the proxy callback."""
    async with make_client(preview) as pv, make_client(production) as prod:
        state = state_of(await start_sign_in(pv, "/dashboard"))
        prod_response = await prod.get(f"/api/auth/callback/github?code=abc&state={state}")
        location = prod_response.headers["location"]
        q = parse_qs(urlsplit(location).query)
        callback_url, profile = q["callbackURL"][0], q["profile"][0]
        proxy_response = await pv.get(
            f"/api/auth/oauth-proxy-callback"
            f"?callbackURL={quote(callback_url, safe='')}&profile={quote(profile, safe='')}"
        )
        return proxy_response.headers["location"]


async def test_full_round_trip_creates_user_and_session_on_preview():
    preview = make_instance(
        "http://preview.example.com",
        OAuthProxyPlugin(production_url="http://production.example.com"),
    )
    production = make_instance("http://production.example.com", OAuthProxyPlugin())

    location = await _full_round_trip(preview, production)
    assert "error=" not in location
    assert "/dashboard" in location

    # user + account + session created ONLY on preview
    users = await preview.adapter.find_many("user")
    assert len(users) == 1
    assert users[0]["email"] == "octo@example.com"
    accounts = await preview.adapter.find_many("account", [Where("providerId", "github")])
    assert len(accounts) == 1
    sessions = await preview.adapter.find_many("session", [Where("userId", users[0]["id"])])
    assert len(sessions) == 1
    # nothing created on production
    assert len(await production.adapter.find_many("user")) == 0


async def test_dedicated_shared_secret_used_instead_of_global_secret():
    """A dedicated proxy ``secret`` (shared across envs, different global secrets) encrypts
    the profile — the global secret cannot decrypt it."""
    proxy_secret = "shared-oauth-proxy-secret-across-envs-xx"
    preview = make_instance(
        "http://preview.example.com",
        OAuthProxyPlugin(production_url="http://production.example.com", secret=proxy_secret),
        secret="preview-main-secret-0123456789-abcdef",
    )
    production = make_instance(
        "http://production.example.com",
        OAuthProxyPlugin(secret=proxy_secret),
        secret="production-main-secret-0123456789-abcd",
    )

    async with make_client(preview) as pv, make_client(production) as prod:
        state = state_of(await start_sign_in(pv, "/dashboard"))
        location = (await prod.get(f"/api/auth/callback/github?code=abc&state={state}")).headers[
            "location"
        ]
        profile = parse_qs(urlsplit(location).query)["profile"][0]
        # decryptable with the dedicated secret, NOT with the global secret
        assert "octo@example.com" in symmetric_decrypt(proxy_secret, profile)
        with pytest.raises(CryptoError):
            symmetric_decrypt("production-main-secret-0123456789-abcd", profile)

    location = await _full_round_trip(preview, production)
    assert "/dashboard" in location
    assert len(await preview.adapter.find_many("user")) == 1


async def test_different_secrets_without_shared_secret_fail_closed():
    """Preview and production with different global secrets and NO shared proxy secret:
    production can't decrypt the state package, falls through to the regular callback, which
    fails (no state row / cookie on production) rather than proxying."""
    preview = make_instance(
        "http://preview.example.com",
        OAuthProxyPlugin(production_url="http://production.example.com"),
        secret="preview-secret-key-that-is-different-00",
    )
    production = make_instance(
        "http://production.example.com",
        OAuthProxyPlugin(),
        secret="production-secret-key-that-is-different",
    )
    async with make_client(preview) as pv, make_client(production) as prod:
        state = state_of(await start_sign_in(pv, "/dashboard"))
        response = await prod.get(f"/api/auth/callback/github?code=abc&state={state}")
        location = response.headers["location"]
        # no passthrough; regular callback ran and failed on state
        assert "/oauth-proxy-callback" not in location
        assert "error=" in location


# --- oauth-proxy-callback: validation + replay protection ---------------------------------


def _encrypt_payload(secret: str, **overrides: Any) -> str:
    payload: dict[str, Any] = {
        "userInfo": {
            "id": "123",
            "email": "user@email.com",
            "name": "Test User",
            "emailVerified": True,
        },
        "account": {"providerId": "github", "accountId": "123", "accessToken": "test"},
        "state": "test-state",
        "callbackURL": "/dashboard",
        "timestamp": int(time.time() * 1000),
    }
    payload.update(overrides)
    return symmetric_encrypt(secret, json.dumps(payload))


async def test_missing_profile_rejected():
    auth = make_instance("http://preview.example.com", OAuthProxyPlugin())
    async with make_client(auth) as client:
        response = await client.get("/api/auth/oauth-proxy-callback?callbackURL=%2Fdashboard")
        assert "error=missing_profile" in response.headers["location"]


async def test_tampered_profile_rejected():
    auth = make_instance("http://preview.example.com", OAuthProxyPlugin())
    async with make_client(auth) as client:
        # a bare-hex blob that is not a valid ciphertext under the secret
        garbage = "ab" * 60
        response = await client.get(
            f"/api/auth/oauth-proxy-callback?callbackURL=%2Fdashboard&profile={garbage}"
        )
        assert "error=invalid_profile" in response.headers["location"]


async def test_expired_payload_rejected():
    auth = make_instance("http://preview.example.com", OAuthProxyPlugin(max_age=60))
    async with make_client(auth) as client:
        profile = _encrypt_payload(SECRET, timestamp=int(time.time() * 1000) - 120_000)
        response = await client.get(
            f"/api/auth/oauth-proxy-callback?callbackURL=%2Fdashboard&profile={profile}"
        )
        assert "error=payload_expired" in response.headers["location"]


async def test_custom_max_age_enforced():
    auth = make_instance("http://preview.example.com", OAuthProxyPlugin(max_age=5))
    async with make_client(auth) as client:
        profile = _encrypt_payload(SECRET, timestamp=int(time.time() * 1000) - 10_000)
        response = await client.get(
            f"/api/auth/oauth-proxy-callback?callbackURL=%2Fdashboard&profile={profile}"
        )
        assert "error=payload_expired" in response.headers["location"]


@pytest.mark.parametrize(
    "bad",
    [
        {"timestamp": "not-a-number"},  # non-numeric timestamp must not bypass validation
        {"timestamp": None},  # missing timestamp
        {"userInfo": None},  # missing userInfo
    ],
)
async def test_invalid_payload_missing_required_fields(bad: dict[str, Any]):
    auth = make_instance("http://preview.example.com", OAuthProxyPlugin())
    async with make_client(auth) as client:
        payload = {
            "userInfo": {"id": "1", "email": "u@e.com", "name": "U", "emailVerified": True},
            "account": {"providerId": "github", "accountId": "1", "accessToken": "t"},
            "state": "s",
            "callbackURL": "/dashboard",
            "timestamp": int(time.time() * 1000),
        }
        payload.update(bad)
        profile = symmetric_encrypt(SECRET, json.dumps(payload))
        response = await client.get(
            f"/api/auth/oauth-proxy-callback?callbackURL=%2Fdashboard&profile={profile}"
        )
        assert "error=invalid_payload" in response.headers["location"]


async def test_state_never_issued_rejected():
    """A well-formed, fresh, correctly-encrypted payload whose OAuth state was never issued
    (no verification row) is rejected with state_mismatch — no user/account created."""
    auth = make_instance("http://preview.example.com", OAuthProxyPlugin())
    # pre-existing user with the same email; must not gain a linked account
    await auth.adapter.create(
        "user",
        {"id": "existing", "email": "user@email.com", "name": "X", "emailVerified": True},
    )
    async with make_client(auth) as client:
        profile = _encrypt_payload(SECRET, state="never-issued-state")
        response = await client.get(
            f"/api/auth/oauth-proxy-callback?callbackURL=%2Fdashboard"
            f"&profile={quote(profile, safe='')}"
        )
        assert response.status_code == 302
        assert "error=state_mismatch" in response.headers["location"]
        assert len(await auth.adapter.find_many("account")) == 0


# --- open-redirect guard (security-critical) ----------------------------------------------


@pytest.mark.parametrize(
    "evil",
    [
        "https://evil.com",  # absolute foreign origin
        "//evil.com",  # protocol-relative
        "https://evil.com/path",  # absolute with path
        "javascript:alert(1)",  # non-http scheme
    ],
)
async def test_open_redirect_untrusted_callback_url_rejected(evil: str):
    """The proxy callback origin-checks its ``callbackURL`` query param (allowing relative
    paths only); untrusted absolute/protocol-relative/js URLs are rejected with 403."""
    auth = make_instance("http://preview.example.com", OAuthProxyPlugin())
    async with make_client(auth) as client:
        response = await client.get(
            f"/api/auth/oauth-proxy-callback?callbackURL={quote(evil, safe='')}&profile=deadbeef"
        )
        assert response.status_code == 403
        assert response.json()["code"] == "INVALID_CALLBACK_URL"


async def test_relative_callback_url_allowed_past_origin_guard():
    """A relative callbackURL passes the origin guard (and then fails later on the bad
    profile, proving the guard itself let it through)."""
    auth = make_instance("http://preview.example.com", OAuthProxyPlugin())
    async with make_client(auth) as client:
        response = await client.get(
            "/api/auth/oauth-proxy-callback?callbackURL=%2Fdashboard&profile=deadbeef"
        )
        assert response.status_code == 302  # not a 403 origin rejection
        assert "error=invalid_profile" in response.headers["location"]


# --- current-URL trust (security-critical) ------------------------------------------------


async def test_untrusted_request_origin_not_used_as_proxy_receiver():
    """resolveCurrentURL never honours an untrusted request origin as the replay receiver —
    it falls back to the configured base URL, not the raw (untrusted) request host."""
    auth = make_instance(
        "http://myapp.com",
        OAuthProxyPlugin(production_url="http://login.myapp.com"),
    )
    from better_auth.types import AuthRequest

    # sign-in initiated from an untrusted host
    sign_in = await auth.handle(
        AuthRequest(
            method="POST",
            path="/sign-in/social",
            headers={"host": "untrusted.example", "content-type": "application/json"},
            body=json.dumps({"provider": "github", "callbackURL": "/dashboard"}).encode(),
        )
    )
    state = state_of(sign_in.body["url"])
    callback = await auth.handle(
        AuthRequest(
            method="GET",
            path="/callback/github",
            headers={"host": "login.myapp.com"},
            query={"code": "abc", "state": state},
        )
    )
    location = callback.redirect_to
    assert location is not None
    assert "untrusted.example" not in location
    assert location.startswith("http://myapp.com/api/auth/oauth-proxy-callback")


async def test_trusted_request_origin_used_as_proxy_receiver():
    """An explicitly trusted request origin IS honoured as the replay receiver."""
    auth = make_instance(
        "http://myapp.com",
        OAuthProxyPlugin(production_url="http://login.myapp.com"),
        trusted_origins=["http://preview.myapp.com"],
    )
    from better_auth.types import AuthRequest

    sign_in = await auth.handle(
        AuthRequest(
            method="POST",
            path="/sign-in/social",
            headers={"host": "preview.myapp.com", "content-type": "application/json"},
            body=json.dumps({"provider": "github", "callbackURL": "/dashboard"}).encode(),
        )
    )
    state = state_of(sign_in.body["url"])
    callback = await auth.handle(
        AuthRequest(
            method="GET",
            path="/callback/github",
            headers={"host": "login.myapp.com"},
            query={"code": "abc", "state": state},
        )
    )
    assert (callback.redirect_to or "").startswith(
        "http://preview.myapp.com/api/auth/oauth-proxy-callback"
    )


async def test_explicit_current_url_overrides_request_origin():
    """An explicit ``current_url`` option is trusted as-is (used verbatim as the receiver
    origin)."""
    auth = make_instance(
        "http://localhost:3000",
        OAuthProxyPlugin(
            production_url="http://production.example.com",
            current_url="http://preview.example.com",
        ),
        trusted_origins=["http://preview.example.com"],
    )
    async with make_client(auth) as client:
        # host is localhost (base); current_url must still win as the receiver origin
        url = await start_sign_in(client, "/dashboard")
        package = json.loads(symmetric_decrypt(SECRET, state_of(url)))
        inner = json.loads(symmetric_decrypt(SECRET, package["stateCookie"]))
        assert inner["callbackURL"].startswith(
            "http://preview.example.com/api/auth/oauth-proxy-callback"
        )


async def test_vendor_env_fallback_when_request_origin_untrusted(monkeypatch: Any):
    """When the request origin is untrusted and a vendor env URL is present, resolveCurrentURL
    uses the vendor URL (VERCEL_URL) as the receiver origin."""
    monkeypatch.setenv("VERCEL_URL", "vercel-preview.example.com")
    auth = make_instance(
        "http://myapp.com",
        OAuthProxyPlugin(production_url="http://login.myapp.com"),
        trusted_origins=["https://vercel-preview.example.com"],
    )
    from better_auth.types import AuthRequest

    sign_in = await auth.handle(
        AuthRequest(
            method="POST",
            path="/sign-in/social",
            headers={"host": "untrusted.example", "content-type": "application/json"},
            body=json.dumps({"provider": "github", "callbackURL": "/dashboard"}).encode(),
        )
    )
    state = state_of(sign_in.body["url"])
    callback = await auth.handle(
        AuthRequest(
            method="GET",
            path="/callback/github",
            headers={"host": "login.myapp.com"},
            query={"code": "abc", "state": state},
        )
    )
    assert (callback.redirect_to or "").startswith(
        "https://vercel-preview.example.com/api/auth/oauth-proxy-callback"
    )


async def test_bare_vendor_name_falls_back_to_base_url(monkeypatch: Any):
    """AWS/GCP/Azure expose a bare function name (not a URL); resolveCurrentURL ignores it
    and falls back to the base URL."""
    monkeypatch.setenv("AWS_LAMBDA_FUNCTION_NAME", "my-lambda-function")
    auth = make_instance(
        "http://myapp.com",
        OAuthProxyPlugin(production_url="http://login.myapp.com"),
    )
    from better_auth.types import AuthRequest

    sign_in = await auth.handle(
        AuthRequest(
            method="POST",
            path="/sign-in/social",
            headers={"host": "untrusted.example", "content-type": "application/json"},
            body=json.dumps({"provider": "github", "callbackURL": "/dashboard"}).encode(),
        )
    )
    state = state_of(sign_in.body["url"])
    callback = await auth.handle(
        AuthRequest(
            method="GET",
            path="/callback/github",
            headers={"host": "login.myapp.com"},
            query={"code": "abc", "state": state},
        )
    )
    assert (callback.redirect_to or "").startswith("http://myapp.com/api/auth/oauth-proxy-callback")


# --- after /callback: unwrap same-origin proxy redirect (defensive branch) ----------------


async def test_after_callback_unwraps_same_origin_proxy_redirect():
    """When the regular callback (before hook fell through) redirects to a same-origin proxy
    URL, the after hook unwraps it back to the embedded original destination."""
    from better_auth.types import AuthRequest, AuthResponse, Ctx

    plugin = OAuthProxyPlugin(production_url="http://myapp.com")
    auth = make_instance("http://myapp.com", plugin)
    ctx = Ctx(auth=auth, request=AuthRequest(method="GET", path="/callback/github"))
    ctx.response = AuthResponse(
        redirect_to="http://myapp.com/api/auth/oauth-proxy-callback?callbackURL=%2Fdashboard"
    )
    assert await plugin._after_callback(ctx) is None
    assert ctx.response.redirect_to == "/dashboard"


async def test_after_callback_leaves_cross_origin_redirect_untouched():
    from better_auth.types import AuthRequest, AuthResponse, Ctx

    plugin = OAuthProxyPlugin(production_url="http://myapp.com")
    auth = make_instance("http://myapp.com", plugin)
    original = "http://preview.example.com/api/auth/oauth-proxy-callback?callbackURL=%2Fx"
    ctx = Ctx(auth=auth, request=AuthRequest(method="GET", path="/callback/github"))
    ctx.response = AuthResponse(redirect_to=original)
    await plugin._after_callback(ctx)
    assert ctx.response.redirect_to == original  # cross-origin: the before hook's job


# --- forward provider link errors verbatim ------------------------------------------------


async def test_signup_disabled_error_forwarded_verbatim():
    """When production's provider disables sign-up, the passthrough carries disableSignUp and
    the preview callback surfaces error=signup_disabled (not a collapsed generic error)."""
    preview = make_instance(
        "http://preview.example.com",
        OAuthProxyPlugin(production_url="http://production.example.com"),
    )
    production = BetterAuth(
        secret=SECRET,
        base_url="http://production.example.com",
        adapter=MemoryAdapter(),
        social_providers={
            "github": GitHub(client_id="cid", client_secret="csecret", disable_sign_up=True)
        },
        http_client=github_http(),
        plugins=[OAuthProxyPlugin()],
    )
    location = await _full_round_trip(preview, production)
    assert "error=signup_disabled" in location
    assert len(await preview.adapter.find_many("user")) == 0
