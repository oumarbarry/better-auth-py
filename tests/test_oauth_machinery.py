"""OAuth machinery: linking decision tree, token refresh, id-token verify, SSRF, PKCE, link."""

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

from better_auth import AccountLinking, AccountOptions, Discord, GitHub, Google
from better_auth.adapters.base import Where
from better_auth.config import OnAPIError
from better_auth.oauth.flow import merge_scopes, parse_stored_scopes
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


async def test_google_and_github_use_pkce_discord_does_not():
    auth = make_auth(
        social_providers={
            "github": GitHub(client_id="c", client_secret="s"),
            "google": Google(client_id="c", client_secret="s"),
            "discord": Discord(client_id="c", client_secret="s"),
        }
    )
    async with make_client(auth) as client:
        # github.ts:67-91 passes codeVerifier; discord.ts:92-111 does not.
        gh = await client.post("/api/auth/sign-in/social", json={"provider": "github"})
        assert "code_challenge" in parse_qs(urlsplit(gh.json()["url"]).query)
        dc = await client.post("/api/auth/sign-in/social", json={"provider": "discord"})
        assert "code_challenge" not in parse_qs(urlsplit(dc.json()["url"]).query)

        gg = await client.post("/api/auth/sign-in/social", json={"provider": "google"})
        gg_q = parse_qs(urlsplit(gg.json()["url"]).query)
        assert gg_q["code_challenge_method"] == ["S256"]
        assert "code_challenge" in gg_q
        # TS v1.7.6 google.ts:177-196 sends no nonce: only providers that set
        # requiresIdTokenNonce (generic-oauth discovery) bind one to the redirect
        assert "nonce" not in gg_q


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
        r = await client.post("/api/auth/get-access-token", json={"accountId": "acc1"})
        assert r.status_code == 200, r.text
        assert r.json()["accessToken"] == "fresh"
        acc = await auth.adapter.find_one("account", [Where("id", "acc1")])
        assert acc["accessToken"] == "fresh"  # persisted


async def test_refresh_token_endpoint():
    auth = gh_auth(VERIFIED, refresh_response={"access_token": "fresh2", "refresh_token": "newr"})
    async with make_client(auth) as client:
        signup = await sign_up(client)
        await _make_account(auth, signup["user"]["id"])
        r = await client.post("/api/auth/refresh-token", json={"accountId": "acc1"})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["accessToken"] == "fresh2"
        assert body["refreshToken"] == "newr"
        assert body["providerId"] == "github"


async def test_refresh_token_missing_account():
    auth = gh_auth(VERIFIED)
    async with make_client(auth) as client:
        await sign_up(client)
        r = await client.post("/api/auth/refresh-token", json={"accountId": "acc1"})
        assert r.status_code == 400
        assert r.json()["code"] == "ACCOUNT_NOT_FOUND"


async def test_get_access_token_requires_session():
    auth = gh_auth(VERIFIED)
    async with make_client(auth) as client:
        r = await client.post("/api/auth/get-access-token", json={"accountId": "acc1"})
        assert r.status_code == 401


# --- account-info returns real provider data ----------------------------------------------


async def test_account_info_returns_raw_profile():
    auth = gh_auth(VERIFIED)
    async with make_client(auth) as client:
        await start_and_callback(client)  # creates github account with access token
        listed = (await client.get("/api/auth/list-accounts")).json()
        github = next(a for a in listed if a["providerId"] == "github")
        r = await client.get(f"/api/auth/account-info?accountId={github['id']}")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["user"]["email"] == SIGNUP["email"]
        assert body["data"]["login"] == "octocat"  # raw provider profile, not {}


async def test_account_info_profile_failure_is_failed_to_get_user_info():
    # TS v1.7.6 account.ts:1044-1053: a provider whose profile call fails yields no info,
    # which is a 401 FAILED_TO_GET_USER_INFO (github.ts:147, reddit.ts return null).
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"message": "down"})

    auth = gh_auth(VERIFIED, http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    async with make_client(auth) as client:
        signup = await sign_up(client)
        await _make_account(auth, signup["user"]["id"], accessTokenExpiresAt=None)
        r = await client.get("/api/auth/account-info?accountId=acc1")
        assert r.status_code == 401, r.text
        assert r.json()["code"] == "FAILED_TO_GET_USER_INFO"


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


# ===================================================================================
# Account identity, transactional sign-up and account.scope (TS v1.7.6)
# ===================================================================================


async def _seed_linked_account(auth, email, account_id="4242", **extra):
    user = await auth.internal.create_user({"name": "U", "email": email, "emailVerified": True})
    await auth.internal.create_account(
        {"userId": user["id"], "providerId": "github", "accountId": account_id, **extra}
    )
    return user


async def test_callback_ambiguous_account_key_issues_no_session():
    """TS v1.7.6 db/internal-adapter.ts:1022-1026 + oauth2/link-account.ts:191-204: two
    rows for one (providerId, accountId) fail the lookup; no session is issued and the
    redirect goes to ``${baseURL}/error``, not to the flow's error URL."""
    auth = gh_auth(VERIFIED)
    async with make_client(auth) as client:
        await _seed_linked_account(auth, "first@x.com")
        await _seed_linked_account(auth, "second@x.com")
        r = await client.post(
            "/api/auth/sign-in/social",
            json={"provider": "github", "errorCallbackURL": "/flow-error"},
        )
        state = parse_qs(urlsplit(r.json()["url"]).query)["state"][0]
        r = await client.get(f"/api/auth/callback/github?code=abc&state={state}")
        assert r.status_code == 302
        assert r.headers["location"] == (
            "http://testserver/api/auth/error?error=internal_server_error"
        )
        assert await auth.adapter.find_many("session") == []


async def test_callback_user_lookup_failure_uses_on_api_error_url(monkeypatch):
    """TS v1.7.6 oauth2/link-account.ts:259-268: a failed user lookup redirects to
    ``onAPIError.errorURL`` with ``internal_server_error``."""
    auth = gh_auth(VERIFIED, on_api_error=OnAPIError(error_url="https://app.test/oops"))
    real_find_one = auth.adapter.find_one

    async def failing_find_one(model, *args, **kwargs):
        if model == "user":
            raise RuntimeError("database down")
        return await real_find_one(model, *args, **kwargs)

    monkeypatch.setattr(auth.adapter, "find_one", failing_find_one)
    async with make_client(auth) as client:
        r = await start_and_callback(client)
        assert r.headers["location"] == "https://app.test/oops?error=internal_server_error"
        assert await auth.adapter.find_many("session") == []


async def test_callback_orphaned_account_does_not_fall_back_to_email():
    """TS v1.7.6 oauth2/link-account.ts:205-214: an account whose user row is missing
    is refused with ``unable_to_link_account``, never re-bound by email."""
    auth = gh_auth(VERIFIED)
    async with make_client(auth) as client:
        signup = await sign_up(client)
        await auth.adapter.update(
            "user", [Where("id", signup["user"]["id"])], {"emailVerified": True}
        )
        await auth.internal.create_account(
            {"userId": "missing-owner", "providerId": "github", "accountId": "4242"}
        )
        client.cookies.clear()
        sessions_before = len(await auth.adapter.find_many("session"))
        r = await start_and_callback(client)
        assert "error=unable_to_link_account" in r.headers["location"]
        assert len(await auth.adapter.find_many("session")) == sessions_before
        assert len(await auth.adapter.find_many("account", [Where("providerId", "github")])) == 1


async def test_callback_rolls_back_user_when_account_create_fails():
    """TS v1.7.6 oauth2/link-account.ts:542-588 (a83152e2e): user and first account are
    created in one transaction; a failed account insert leaves no user row."""

    def refuse(data, ctx=None):
        raise RuntimeError("account insert failed")

    auth = gh_auth(VERIFIED, database_hooks={"account": {"create": {"before": refuse}}})
    async with make_client(auth) as client:
        r = await start_and_callback(client)
        assert "error=unable_to_create_user" in r.headers["location"]
        assert await auth.adapter.find_many("user") == []
        assert await auth.adapter.find_many("session") == []


async def test_override_user_info_keeps_user_when_update_returns_none(caplog):
    """TS v1.7.6 oauth2/link-account.ts:493-508 (06daf7011): a user update that yields
    nothing keeps the resolved user for the session and logs a warning."""
    auth = make_auth(
        social_providers={
            "github": GitHub(
                client_id="cid", client_secret="csecret", override_user_info_on_sign_in=True
            )
        },
        http_client=github_http(VERIFIED),
        database_hooks={"user": {"update": {"before": lambda data, ctx=None: False}}},
    )
    async with make_client(auth) as client:
        await start_and_callback(client)
        client.cookies.clear()
        r = await start_and_callback(client)
        assert "error" not in r.headers["location"]
        session = await client.get("/api/auth/get-session")
        assert session.json()["user"]["email"] == SIGNUP["email"]
    assert "preserving existing user for session" in caplog.text


async def test_register_stores_scope_comma_joined():
    """TS v1.7.6 api/routes/callback.ts:262-266: ``scope: tokens.scopes?.join(",")``."""
    auth = gh_auth(VERIFIED, token_response={"access_token": "t", "scope": "read:user repo"})
    async with make_client(auth) as client:
        await start_and_callback(client)
    [account] = await auth.adapter.find_many("account", [Where("providerId", "github")])
    assert account["scope"] == "read:user,repo"


async def test_reauth_keeps_stored_scope_and_refresh_token():
    """TS v1.7.6 oauth2/link-account.ts:392-412 (97903c9cc): sign-in re-auth never
    writes ``scope`` and skips token fields the provider did not return."""
    auth = gh_auth(VERIFIED, token_response={"access_token": "t2", "scope": "read:user"})
    async with make_client(auth) as client:
        await _seed_linked_account(
            auth, SIGNUP["email"], scope="read:user,repo", refreshToken="r1", accessToken="t1"
        )
        await start_and_callback(client)
    [account] = await auth.adapter.find_many("account", [Where("providerId", "github")])
    assert account["scope"] == "read:user,repo"
    assert account["refreshToken"] == "r1"
    assert account["accessToken"] == "t2"


async def _link_callback(client, emails_user=None):
    start = await client.post(
        "/api/auth/link-social", json={"provider": "github", "callbackURL": "/settings"}
    )
    state = parse_qs(urlsplit(start.json()["url"]).query)["state"][0]
    return await client.get(f"/api/auth/callback/github?code=abc&state={state}")


async def test_link_social_callback_merges_scopes_on_existing_account():
    """TS v1.7.6 oauth2/link-account.ts:117-138: re-linking the same account merges the
    stored and granted scopes (core oauth2/utils.ts:71 ``mergeScopes``)."""
    auth = gh_auth(VERIFIED, token_response={"access_token": "t2", "scope": "repo read:user"})
    async with make_client(auth) as client:
        signup = await sign_up(client)
        await auth.internal.create_account(
            {
                "userId": signup["user"]["id"],
                "providerId": "github",
                "accountId": "4242",
                "scope": "read:user, gist",
            }
        )
        r = await _link_callback(client)
        assert r.headers["location"] == "http://testserver/settings"
    [account] = await auth.adapter.find_many("account", [Where("providerId", "github")])
    assert account["scope"] == "read:user,gist,repo"
    assert account["accessToken"] == "t2"


async def test_link_social_callback_new_account_stores_granted_scopes():
    auth = gh_auth(VERIFIED, token_response={"access_token": "t", "scope": "repo"})
    async with make_client(auth) as client:
        await sign_up(client)
        await _link_callback(client)
    [account] = await auth.adapter.find_many("account", [Where("providerId", "github")])
    assert account["scope"] == "repo"


async def test_link_social_callback_untrusted_unverified_is_unable_to_link():
    """TS v1.7.6 oauth2/link-account.ts:92-103 + oauth2/errors.ts:19."""
    auth = gh_auth(UNVERIFIED)
    async with make_client(auth) as client:
        await sign_up(client)
        r = await _link_callback(client)
        assert "error=unable_to_link_account" in r.headers["location"]


async def test_link_social_callback_email_mismatch():
    """TS v1.7.6 oauth2/link-account.ts:105-112 + oauth2/errors.ts:20."""
    other = [{"email": "other@example.com", "primary": True, "verified": True}]
    auth = gh_auth(other)
    async with make_client(auth) as client:
        await sign_up(client)
        r = await _link_callback(client)
        assert "error=email_does_not_match" in r.headers["location"]


async def test_link_social_callback_account_owned_by_another_user():
    """TS v1.7.6 oauth2/link-account.ts:114-122."""
    auth = gh_auth(VERIFIED)
    async with make_client(auth) as client:
        await _seed_linked_account(auth, "owner@x.com")
        await sign_up(client)
        r = await _link_callback(client)
        assert "error=account_already_linked_to_different_user" in r.headers["location"]


async def test_refresh_token_keeps_stored_scope():
    """TS v1.7.6 api/routes/account.ts:909-940 (97903c9cc): a narrower refresh response
    does not shrink ``account.scope``; the response echoes the stored grant."""
    auth = gh_auth(VERIFIED, refresh_response={"access_token": "fresh", "scope": "read:user"})
    async with make_client(auth) as client:
        signup = await sign_up(client)
        await _make_account(auth, signup["user"]["id"], scope="read:user,repo")
        r = await client.post("/api/auth/refresh-token", json={"accountId": "acc1"})
        assert r.status_code == 200, r.text
        assert r.json()["scope"] == "read:user,repo"
    account = await auth.adapter.find_one("account", [Where("id", "acc1")])
    assert account["scope"] == "read:user,repo"


def test_stored_scopes_read_legacy_space_separated_rows():
    """Rows written by the 1.0 port hold the raw space-separated scope string. A scope
    token never contains a space (RFC 6749 section 3.3), so whitespace is read as a
    separator too; comma-joined rows (the TS format) parse exactly as TS does."""
    assert parse_stored_scopes("openid email profile") == ["openid", "email", "profile"]
    assert parse_stored_scopes("read:user,repo") == ["read:user", "repo"]
    assert merge_scopes("openid email", ["email", "offline_access"]) == (
        "openid,email,offline_access"
    )


async def test_stored_scopes_are_trimmed_on_read():
    """TS v1.7.6 api/routes/account.ts:37-43 ``parseStoredScopes`` (list-accounts and
    get-access-token)."""
    auth = gh_auth(VERIFIED)
    async with make_client(auth) as client:
        signup = await sign_up(client)
        await _make_account(
            auth,
            signup["user"]["id"],
            scope="read:user, repo,,",
            accessTokenExpiresAt=None,
        )
        listed = await client.get("/api/auth/list-accounts")
        github = next(a for a in listed.json() if a["providerId"] == "github")
        assert github["scopes"] == ["read:user", "repo"]
        token = await client.post("/api/auth/get-access-token", json={"accountId": "acc1"})
        assert token.json()["scopes"] == ["read:user", "repo"]


async def test_link_social_id_token_refuses_account_of_another_user():
    """TS v1.7.6 api/routes/account.ts:327-364: the key lookup is global, so an account
    owned by someone else is a 409 instead of a silent success or a duplicate row."""
    provider = _CtxProvider(client_id="cid", client_secret="s")
    auth = make_auth(social_providers={"ctxp": provider})
    async with make_client(auth) as client:
        await _seed_linked_account(auth, "owner@x.com", providerId="ctxp", accountId="cx-1")
        await sign_up(client)
        r = await client.post(
            "/api/auth/link-social", json={"provider": "ctxp", "idToken": {"token": "tok"}}
        )
        assert r.status_code == 409
        assert r.json() == {
            "code": "SOCIAL_ACCOUNT_ALREADY_LINKED",
            "message": "Social account already linked",
        }
    assert len(await auth.adapter.find_many("account", [Where("providerId", "ctxp")])) == 1


async def test_link_social_id_token_updates_tokens_of_own_account():
    """TS v1.7.6 api/routes/account.ts:330-358: relinking your own account refreshes its
    tokens and leaves ``scope`` alone."""
    provider = _CtxProvider(client_id="cid", client_secret="s")
    auth = make_auth(social_providers={"ctxp": provider})
    async with make_client(auth) as client:
        signup = await sign_up(client)
        await auth.internal.create_account(
            {
                "userId": signup["user"]["id"],
                "providerId": "ctxp",
                "accountId": "cx-1",
                "scope": "openid",
                "accessToken": "old",
            }
        )
        r = await client.post(
            "/api/auth/link-social",
            json={
                "provider": "ctxp",
                "idToken": {"token": "tok", "accessToken": "new", "scopes": ["email"]},
            },
        )
        assert r.status_code == 200, r.text
    [account] = await auth.adapter.find_many("account", [Where("providerId", "ctxp")])
    assert account["accessToken"] == "new"
    assert account["idToken"] == "tok"
    assert account["scope"] == "openid"


@dataclass
class _NoSubjectProvider(ProviderConfig):
    """id-token provider whose claims carry no account subject."""

    provider_id: str = "nosub"
    jwks_url: str = "https://nosub.test/jwks"

    async def verify_id_token(self, http, token, nonce=None, ctx=None):
        return {"email": SIGNUP["email"], "email_verified": True}


async def test_id_token_sign_in_without_account_subject_is_rejected():
    """TS v1.7.6 oauth2/account-key.ts:29-37 + 50-62: an empty subject is
    FAILED_TO_GET_USER_INFO (401), never an account with an empty accountId."""
    auth = make_auth(social_providers={"nosub": _NoSubjectProvider(client_id="c")})
    async with make_client(auth) as client:
        r = await client.post(
            "/api/auth/sign-in/social", json={"provider": "nosub", "idToken": {"token": "t"}}
        )
        assert r.status_code == 401
        assert r.json()["code"] == "FAILED_TO_GET_USER_INFO"
    assert await auth.adapter.find_many("account") == []


async def test_callback_without_account_subject_is_unable_to_get_user_info():
    """TS v1.7.6 api/routes/callback.ts:240-255."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login/oauth/access_token":
            return httpx.Response(200, json={"access_token": "t"})
        if request.url.path == "/user":
            return httpx.Response(200, json={**PROFILE, "id": ""})
        return httpx.Response(200, json=VERIFIED)

    auth = gh_auth(VERIFIED, http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)))
    async with make_client(auth) as client:
        r = await start_and_callback(client)
        assert "error=unable_to_get_user_info" in r.headers["location"]
    assert await auth.adapter.find_many("account") == []


async def test_link_social_id_token_different_email_message():
    """TS v1.6.29 and v1.7.6 api/routes/account.ts (v1.7.6:380-388): exact message."""
    provider = _CtxProvider(client_id="cid", client_secret="s")
    auth = make_auth(social_providers={"ctxp": provider})
    async with make_client(auth) as client:
        await sign_up(client, email="someone-else@example.com")
        r = await client.post(
            "/api/auth/link-social", json={"provider": "ctxp", "idToken": {"token": "tok"}}
        )
        assert r.status_code == 401
        assert r.json() == {
            "code": "LINKING_DIFFERENT_EMAILS_NOT_ALLOWED",
            "message": "Account not linked - different emails not allowed",
        }


async def test_id_token_sign_in_does_not_store_scope():
    """TS v1.7.6 api/routes/sign-in.ts:322-345: the idToken account data carries no
    ``scope``, so the body's ``idToken.scopes`` is not stored."""
    provider = _CtxProvider(client_id="cid", client_secret="s")
    auth = make_auth(social_providers={"ctxp": provider})
    async with make_client(auth) as client:
        r = await client.post(
            "/api/auth/sign-in/social",
            json={"provider": "ctxp", "idToken": {"token": "tok", "scopes": ["openid", "email"]}},
        )
        assert r.status_code == 200, r.text
    [account] = await auth.adapter.find_many("account", [Where("providerId", "ctxp")])
    assert account.get("scope") is None


async def test_id_token_sign_in_does_not_store_refresh_token():
    """TS v1.7.6 api/routes/sign-in.ts:336-340 (and v1.6.29): the idToken account data is
    the key, ``accessToken`` and ``idToken``; a body ``idToken.refreshToken`` is not stored."""
    provider = _CtxProvider(client_id="cid", client_secret="s")
    auth = make_auth(social_providers={"ctxp": provider})
    async with make_client(auth) as client:
        r = await client.post(
            "/api/auth/sign-in/social",
            json={"provider": "ctxp", "idToken": {"token": "tok", "refreshToken": "rt"}},
        )
        assert r.status_code == 200, r.text
    [account] = await auth.adapter.find_many("account", [Where("providerId", "ctxp")])
    assert account.get("refreshToken") is None


async def test_token_routes_select_the_account_by_its_id():
    """TS v1.7.6 account.ts:547-632 (dbd302e42): ``accountId`` is the Better Auth account
    id; the provider comes from that account, and the old ``providerId`` body is refused."""
    auth = gh_auth(VERIFIED, refresh_response={"access_token": "fresh"})
    async with make_client(auth) as client:
        signup = await sign_up(client)
        await _make_account(auth, signup["user"]["id"])
        by_provider_account_id = await client.post(
            "/api/auth/get-access-token", json={"accountId": "4242"}
        )
        legacy = await client.post("/api/auth/refresh-token", json={"providerId": "github"})
    assert by_provider_account_id.json()["code"] == "ACCOUNT_NOT_FOUND"
    assert legacy.status_code == 400 and legacy.json()["code"] == "INVALID_BODY"


async def test_legacy_provider_selection_when_opted_in():
    """Port-only ``AccountOptions.legacy_account_selection``: the 1.0 body still works."""
    from better_auth.config import AccountOptions

    auth = gh_auth(
        VERIFIED,
        refresh_response={"access_token": "fresh"},
        account=AccountOptions(legacy_account_selection=True),
    )
    async with make_client(auth) as client:
        signup = await sign_up(client)
        await _make_account(auth, signup["user"]["id"])
        by_provider = await client.post("/api/auth/get-access-token", json={"providerId": "github"})
        by_pair = await client.post(
            "/api/auth/get-access-token", json={"providerId": "github", "accountId": "4242"}
        )
        by_row = await client.post("/api/auth/get-access-token", json={"accountId": "acc1"})
        refreshed = await client.post("/api/auth/refresh-token", json={"providerId": "github"})
        unknown = await client.post("/api/auth/get-access-token", json={"providerId": "gitlab"})
    for response in (by_provider, by_pair, by_row, refreshed):
        assert response.status_code == 200, response.text
    assert unknown.json()["code"] == "PROVIDER_NOT_SUPPORTED"


async def test_legacy_provider_selection_refused_by_default():
    auth = gh_auth(VERIFIED)
    async with make_client(auth) as client:
        signup = await sign_up(client)
        await _make_account(auth, signup["user"]["id"])
        r = await client.post("/api/auth/get-access-token", json={"providerId": "github"})
    assert r.status_code == 400 and r.json()["code"] == "INVALID_BODY"


def test_token_endpoint_auth_is_publicly_exported():
    """``TokenEndpointAuth`` (used by provider ``token_endpoint_auth`` fields) must be
    importable alongside the other public OAuth types, not only from ``oauth.machinery``."""
    from better_auth import TokenEndpointAuth as top_level
    from better_auth.oauth import TokenEndpointAuth as from_oauth
    from better_auth.oauth.machinery import TokenEndpointAuth as machinery

    assert top_level is machinery
    assert from_oauth is machinery
