"""W2-A machinery: linking decision tree, token refresh, id-token verify, SSRF, PKCE, link."""

import json
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from better_auth import AccountLinking, AccountOptions, GitHub, Google
from better_auth.adapters.base import Where
from better_auth.oauth.machinery import OAuthFetchError, oauth_fetch
from better_auth.oauth.providers import ProviderConfig
from better_auth.types import Ctx
from conftest import SIGNUP, make_auth, make_client, sign_up

PROFILE = {"id": 4242, "login": "octocat", "name": "Octo Cat", "avatar_url": "http://img/x.png"}


def github_http(emails, *, token_response=None, refresh_response=None):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login/oauth/access_token":
            body = request.content.decode()
            if "grant_type=refresh_token" in body:
                return httpx.Response(
                    200, json=refresh_response or {"access_token": "gh_refreshed"}
                )
            return httpx.Response(200, json=token_response or {"access_token": "gh_token"})
        if request.url.path == "/user":
            return httpx.Response(200, json=PROFILE)
        if request.url.path == "/user/emails":
            return httpx.Response(200, json=emails)
        return httpx.Response(404)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def gh_auth(emails, **kwargs):
    token_response = kwargs.pop("token_response", None)
    refresh_response = kwargs.pop("refresh_response", None)
    http_client = kwargs.pop(
        "http_client",
        github_http(emails, token_response=token_response, refresh_response=refresh_response),
    )
    return make_auth(
        social_providers={"github": GitHub(client_id="cid", client_secret="csecret")},
        http_client=http_client,
        **kwargs,
    )


async def start_and_callback(client, state_query="code=abc"):
    r = await client.post("/api/auth/sign-in/social", json={"provider": "github"})
    state = parse_qs(urlsplit(r.json()["url"]).query)["state"][0]
    return await client.get(f"/api/auth/callback/github?{state_query}&state={state}")


VERIFIED = [{"email": SIGNUP["email"], "primary": True, "verified": True}]
UNVERIFIED = [{"email": SIGNUP["email"], "primary": True, "verified": False}]


@pytest.fixture(autouse=True)
def _reset_jwks_cache():
    # the JWKS cache is a module-level singleton with a TTL + no-kid cooldown; reset it so
    # tests reusing the same jwks_url don't see another test's stale keys or cooldown.
    from better_auth.oauth import verify

    verify._cache._cache.clear()
    verify._cache._last_miss.clear()
    yield


# --- linking decision-tree matrix ---------------------------------------------------------


async def test_require_local_email_verified_blocks_link():
    # default requireLocalEmailVerified=True: verified IdP email, unverified local row → refuse
    auth = gh_auth(VERIFIED)
    async with make_client(auth) as client:
        await sign_up(client)  # credential user, emailVerified False
        client.cookies.clear()
        r = await start_and_callback(client)
        assert "error=account_not_linked" in r.headers["location"]
        assert len(await auth.adapter.find_many("account")) == 1  # credential only


async def test_trusted_provider_bypasses_unverified_incoming_email():
    # untrusted + unverified incoming email → blocked; trusted → the incoming-email gate is
    # bypassed (local row is verified here so requireLocalEmailVerified passes)
    linking = AccountLinking(trusted_providers=["github"], require_local_email_verified=False)
    auth = gh_auth(UNVERIFIED, account=AccountOptions(account_linking=linking))
    async with make_client(auth) as client:
        await sign_up(client)
        client.cookies.clear()
        r = await start_and_callback(client)
        assert "error" not in r.headers["location"]
        assert len(await auth.adapter.find_many("account")) == 2


async def test_disable_implicit_linking_blocks_even_trusted():
    linking = AccountLinking(
        trusted_providers=["github"],
        require_local_email_verified=False,
        disable_implicit_linking=True,
    )
    auth = gh_auth(VERIFIED, account=AccountOptions(account_linking=linking))
    async with make_client(auth) as client:
        await sign_up(client)
        client.cookies.clear()
        r = await start_and_callback(client)
        assert "error=account_not_linked" in r.headers["location"]


async def test_trusted_providers_callable_resolved_per_request():
    linking = AccountLinking(
        trusted_providers=lambda request: ["github"], require_local_email_verified=False
    )
    auth = gh_auth(UNVERIFIED, account=AccountOptions(account_linking=linking))
    async with make_client(auth) as client:
        await sign_up(client)
        client.cookies.clear()
        r = await start_and_callback(client)
        assert "error" not in r.headers["location"]


async def test_re_signin_promotes_unverified_local_email():
    # existing github account whose local user is unverified; a re-sign-in with a verified
    # provider email self-heals emailVerified on the local row
    auth = gh_auth(VERIFIED)
    async with make_client(auth) as client:
        await start_and_callback(client)  # first sign-in creates user+account
        user = (await auth.adapter.find_many("user"))[0]
        await auth.adapter.update("user", [Where("id", user["id"])], {"emailVerified": False})
        client.cookies.clear()
        await start_and_callback(client)  # second sign-in
        user = await auth.adapter.find_one("user", [Where("id", user["id"])])
        assert user["emailVerified"] is True


# --- per-provider PKCE --------------------------------------------------------------------


async def test_google_uses_pkce_github_does_not():
    auth = make_auth(
        social_providers={
            "github": GitHub(client_id="c", client_secret="s"),
            "google": Google(client_id="c", client_secret="s"),
        }
    )
    async with make_client(auth) as client:
        gh = await client.post("/api/auth/sign-in/social", json={"provider": "github"})
        gq = parse_qs(urlsplit(gh.json()["url"]).query)
        assert "code_challenge" not in gq

        gg = await client.post("/api/auth/sign-in/social", json={"provider": "google"})
        gg_q = parse_qs(urlsplit(gg.json()["url"]).query)
        assert gg_q["code_challenge_method"] == ["S256"]
        assert "code_challenge" in gg_q
        assert "nonce" in gg_q  # google uses OIDC nonce


# --- SSRF guard ---------------------------------------------------------------------------


async def test_oauth_fetch_refuses_redirects():
    def handler(request):
        return httpx.Response(302, headers={"location": "http://169.254.169.254/"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        with pytest.raises(OAuthFetchError):
            await oauth_fetch(http, "GET", "https://provider.example/token")


async def test_callback_token_redirect_is_refused():
    def handler(request):
        if request.url.path == "/login/oauth/access_token":
            return httpx.Response(302, headers={"location": "http://internal/"})
        return httpx.Response(404)

    auth = gh_auth(VERIFIED, http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    async with make_client(auth) as client:
        r = await start_and_callback(client)
        assert "error=invalid_code" in r.headers["location"]


# --- token refresh + /refresh-token + /get-access-token -----------------------------------


async def _make_account(auth, user_id, **over):
    from datetime import datetime, timezone

    row = {
        "id": "acc1",
        "accountId": "4242",
        "providerId": "github",
        "userId": user_id,
        "accessToken": "old_access",
        "refreshToken": "rtok",
        "accessTokenExpiresAt": datetime(2000, 1, 1, tzinfo=timezone.utc),  # expired
        "scope": "read:user",
        "createdAt": datetime.now(timezone.utc),
        "updatedAt": datetime.now(timezone.utc),
    }
    row.update(over)
    await auth.adapter.create("account", row)


async def test_get_access_token_refreshes_when_expired():
    auth = gh_auth(VERIFIED, refresh_response={"access_token": "fresh", "expires_in": 3600})
    async with make_client(auth) as client:
        signup = await sign_up(client)
        await _make_account(auth, signup["user"]["id"])
        r = await client.post("/api/auth/get-access-token", json={"providerId": "github"})
        assert r.status_code == 200, r.text
        assert r.json()["accessToken"] == "fresh"
        acc = await auth.adapter.find_one("account", [Where("id", "acc1")])
        assert acc["accessToken"] == "fresh"  # persisted


async def test_refresh_token_endpoint():
    auth = gh_auth(VERIFIED, refresh_response={"access_token": "fresh2", "refresh_token": "newr"})
    async with make_client(auth) as client:
        signup = await sign_up(client)
        await _make_account(auth, signup["user"]["id"])
        r = await client.post("/api/auth/refresh-token", json={"providerId": "github"})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["accessToken"] == "fresh2"
        assert body["refreshToken"] == "newr"
        assert body["providerId"] == "github"


async def test_refresh_token_missing_account():
    auth = gh_auth(VERIFIED)
    async with make_client(auth) as client:
        await sign_up(client)
        r = await client.post("/api/auth/refresh-token", json={"providerId": "github"})
        assert r.status_code == 400
        assert r.json()["code"] == "ACCOUNT_NOT_FOUND"


async def test_get_access_token_requires_session():
    auth = gh_auth(VERIFIED)
    async with make_client(auth) as client:
        r = await client.post("/api/auth/get-access-token", json={"providerId": "github"})
        assert r.status_code == 401


# --- account-info returns real provider data ----------------------------------------------


async def test_account_info_returns_raw_profile():
    auth = gh_auth(VERIFIED)
    async with make_client(auth) as client:
        await start_and_callback(client)  # creates github account with access token
        r = await client.get("/api/auth/account-info?accountId=4242&providerId=github")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["user"]["email"] == SIGNUP["email"]
        assert body["data"]["login"] == "octocat"  # raw provider profile, not {}


# --- id-token verify (self-signed JWKS fixture) + idToken sign-in -------------------------


def _rsa_jwks_and_signer():
    # unique kid per fixture: the module-level JWKS cache is keyed by (uri, kid), so two
    # tests reusing a kid on the same jwks_url would collide on stale keys.
    import uuid

    kid = uuid.uuid4().hex
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    jwk["kid"] = kid
    jwk["alg"] = "RS256"
    jwks = {"keys": [jwk]}

    def sign(payload):
        return jwt.encode(payload, key, algorithm="RS256", headers={"kid": kid})

    return jwks, sign


def google_idtoken_http(jwks):
    def handler(request):
        if "certs" in request.url.path or request.url.path.endswith("/v3/certs"):
            return httpx.Response(200, json=jwks)
        return httpx.Response(404)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def test_verify_id_token_and_sign_in():
    jwks, sign = _rsa_jwks_and_signer()
    now = int(time.time())
    token = sign(
        {
            "iss": "https://accounts.google.com",
            "aud": "google-cid",
            "sub": "g-999",
            "email": "gid@example.com",
            "email_verified": True,
            "name": "Gid User",
            "nonce": "n0nce",
            "iat": now,
            "exp": now + 600,
        }
    )
    auth = make_auth(
        social_providers={"google": Google(client_id="google-cid", client_secret="s")},
        http_client=google_idtoken_http(jwks),
    )
    async with make_client(auth) as client:
        r = await client.post(
            "/api/auth/sign-in/social",
            json={"provider": "google", "idToken": {"token": token, "nonce": "n0nce"}},
        )
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["redirect"] is False
        assert body["token"]
        assert body["user"]["email"] == "gid@example.com"
        assert len(await auth.adapter.find_many("account")) == 1


async def test_id_token_wrong_nonce_rejected():
    jwks, sign = _rsa_jwks_and_signer()
    now = int(time.time())
    token = sign(
        {
            "iss": "https://accounts.google.com",
            "aud": "google-cid",
            "sub": "g-1",
            "email": "a@b.com",
            "nonce": "right",
            "iat": now,
            "exp": now + 600,
        }
    )
    auth = make_auth(
        social_providers={"google": Google(client_id="google-cid", client_secret="s")},
        http_client=google_idtoken_http(jwks),
    )
    async with make_client(auth) as client:
        r = await client.post(
            "/api/auth/sign-in/social",
            json={"provider": "google", "idToken": {"token": token, "nonce": "wrong"}},
        )
        assert r.status_code == 401
        assert r.json()["code"] == "INVALID_TOKEN"


async def test_id_token_not_supported_for_github():
    auth = gh_auth(VERIFIED)
    async with make_client(auth) as client:
        r = await client.post(
            "/api/auth/sign-in/social",
            json={"provider": "github", "idToken": {"token": "x"}},
        )
        assert r.status_code == 404
        assert r.json()["code"] == "ID_TOKEN_NOT_SUPPORTED"


# --- /link-social -------------------------------------------------------------------------


async def test_link_social_requires_session():
    auth = gh_auth(VERIFIED)
    async with make_client(auth) as client:
        r = await client.post("/api/auth/link-social", json={"provider": "github"})
        assert r.status_code == 401


async def test_link_social_redirect_flow_builds_url_and_links_on_callback():
    auth = gh_auth(VERIFIED, account=AccountOptions(account_linking=AccountLinking()))
    async with make_client(auth) as client:
        await sign_up(client)  # session established
        start = await client.post(
            "/api/auth/link-social", json={"provider": "github", "callbackURL": "/settings"}
        )
        assert start.status_code == 200, start.text
        body = start.json()
        assert body["redirect"] is True
        parts = urlsplit(body["url"])
        assert parts.netloc == "github.com"
        state = parse_qs(parts.query)["state"][0]

        cb = await client.get(f"/api/auth/callback/github?code=abc&state={state}")
        assert cb.status_code == 302
        assert cb.headers["location"] == "http://testserver/settings"
        accounts = await auth.adapter.find_many("account", [Where("providerId", "github")])
        assert len(accounts) == 1  # linked to the signed-in user, no new session/user
        assert len(await auth.adapter.find_many("user")) == 1


async def test_link_social_id_token_flow():
    jwks, sign = _rsa_jwks_and_signer()
    now = int(time.time())

    def handler(request):
        if "certs" in request.url.path:
            return httpx.Response(200, json=jwks)
        return httpx.Response(404)

    # session user must match the id-token email (allowDifferentEmails defaults False)
    auth = make_auth(
        social_providers={"google": Google(client_id="g", client_secret="s")},
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    async with make_client(auth) as client:
        await sign_up(client)  # ada@example.com
        token = sign(
            {
                "iss": "https://accounts.google.com",
                "aud": "g",
                "sub": "g-77",
                "email": SIGNUP["email"],
                "email_verified": True,
                "iat": now,
                "exp": now + 600,
            }
        )
        r = await client.post(
            "/api/auth/link-social", json={"provider": "google", "idToken": {"token": token}}
        )
        assert r.status_code == 200, r.text
        assert r.json()["status"] is True
        accounts = await auth.adapter.find_many("account", [Where("providerId", "google")])
        assert len(accounts) == 1
        assert accounts[0]["accountId"] == "g-77"


# ===================================================================================
# ctx threaded into verify_id_token — TS c4d1ddaa9 (feat: add `ctx` to `verifyIdToken`)
# ===================================================================================


@dataclass
class _CtxProvider(ProviderConfig):
    """Provider written against the new signature — records the ctx it was handed."""

    provider_id: str = "ctxp"
    jwks_url: str = "https://ctx.test/jwks"  # only gates `supports_id_token`
    seen: list[Any] = field(default_factory=list)

    async def verify_id_token(self, http, token, nonce=None, ctx=None):
        self.seen.append(ctx)
        return {"sub": "cx-1", "email": SIGNUP["email"], "email_verified": True}


@dataclass
class _LegacyProvider(ProviderConfig):
    """Third-party provider written against the pre-ctx signature — must keep working."""

    provider_id: str = "legacyp"
    jwks_url: str = "https://legacy.test/jwks"
    seen: list[Any] = field(default_factory=list)

    # the narrower (pre-ctx) signature is the point of this fixture
    async def verify_id_token(self, http, token, nonce=None):  # ty: ignore[invalid-method-override]
        self.seen.append(nonce)
        return {"sub": "lg-1", "email": SIGNUP["email"], "email_verified": True}


async def test_sign_in_id_token_passes_ctx_to_verify_id_token():
    provider = _CtxProvider(client_id="cid", client_secret="s")
    auth = make_auth(social_providers={"ctxp": provider})
    async with make_client(auth) as client:
        r = await client.post(
            "/api/auth/sign-in/social",
            json={"provider": "ctxp", "idToken": {"token": "tok", "nonce": "n"}},
            headers={"x-platform": "ios"},
        )
        assert r.status_code == 200, r.text
    assert len(provider.seen) == 1
    ctx = provider.seen[0]
    assert isinstance(ctx, Ctx)
    # the docs' motivating use case: branch on a request header
    assert ctx.request.headers["x-platform"] == "ios"
    assert ctx.request.path == "/sign-in/social"


async def test_link_social_id_token_passes_ctx_to_verify_id_token():
    provider = _CtxProvider(client_id="cid", client_secret="s")
    auth = make_auth(social_providers={"ctxp": provider})
    async with make_client(auth) as client:
        await sign_up(client)  # ada@example.com, matching the id-token email
        r = await client.post(
            "/api/auth/link-social",
            json={"provider": "ctxp", "idToken": {"token": "tok"}},
            headers={"x-platform": "ios"},
        )
        assert r.status_code == 200, r.text
    assert isinstance(provider.seen[0], Ctx)
    assert provider.seen[0].request.path == "/link-social"


async def test_verify_id_token_without_ctx_param_still_called():
    """Back-compat: an override on the old ``(http, token, nonce)`` signature is
    detected by arity and called without ``ctx`` (same seam as ``_accepts_ctx``
    for databaseHooks / magic-link callbacks)."""
    provider = _LegacyProvider(client_id="cid", client_secret="s")
    auth = make_auth(social_providers={"legacyp": provider})
    async with make_client(auth) as client:
        r = await client.post(
            "/api/auth/sign-in/social",
            json={"provider": "legacyp", "idToken": {"token": "tok", "nonce": "n"}},
        )
        assert r.status_code == 200, r.text
        assert r.json()["user"]["email"] == SIGNUP["email"]
    assert provider.seen == ["n"]
