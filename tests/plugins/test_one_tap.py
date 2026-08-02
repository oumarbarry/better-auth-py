"""Tests for the one-tap plugin (Google One Tap sign-in).

Mirrors better-auth's plugins/one-tap/one-tap.test.ts and the gap spec
(docs/plans/gap/06-plugins-advanced.md, "4. one-tap"). TS source verified against:
  packages/better-auth/src/plugins/one-tap/index.ts
  packages/better-auth/src/plugins/one-tap/client.ts
  packages/better-auth/src/plugins/one-tap/one-tap.test.ts
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from better_auth import AccountLinking, AccountOptions, Google
from better_auth.adapters.base import Where
from better_auth.plugins_ext.one_tap import OneTapPlugin
from conftest import make_auth, make_client

ONE_TAP_PATH = "/api/auth/one-tap/callback"


@pytest.fixture(autouse=True)
def _reset_jwks_cache():
    # The JWKS cache is a module-level singleton (TTL + no-kid-miss cooldown), keyed by
    # jwks_uri only. Every test here hits the same literal Google JWKS URL, so without a
    # reset a later test's fresh `kid` would be rate-limited behind an earlier test's
    # cache entry/miss timestamp. Mirrors test_oauth_machinery.py's fixture of the same name.
    from better_auth.oauth import verify

    verify._cache._cache.clear()
    verify._cache._last_miss.clear()
    yield


# --- fixtures: self-signed RSA JWKS + Google-shaped id token -------------------------------


def _rsa_jwks_and_signer():
    kid = uuid.uuid4().hex
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    jwk["kid"] = kid
    jwk["alg"] = "RS256"
    jwks = {"keys": [jwk]}

    def sign(payload: dict[str, Any]) -> str:
        return jwt.encode(payload, key, algorithm="RS256", headers={"kid": kid})

    return jwks, sign


def google_http(jwks: dict[str, Any]) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/v3/certs"):
            return httpx.Response(200, json=jwks)
        return httpx.Response(404)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def default_payload(**overrides: Any) -> dict[str, Any]:
    now = int(time.time())
    payload = {
        "iss": "https://accounts.google.com",
        "aud": "test-client",
        "sub": "google-sub-1",
        "email": "one-tap-user@example.com",
        "email_verified": True,
        "name": "One Tap User",
        "picture": "https://example.com/photo.jpg",
        "iat": now,
        "exp": now + 600,
    }
    payload.update(overrides)
    return payload


def one_tap_auth(*, jwks: dict[str, Any], google_kwargs=None, plugin_kwargs=None, **kwargs):
    plugin = OneTapPlugin(**(plugin_kwargs or {}))
    social = kwargs.pop("social_providers", None)
    if social is None:
        social = {
            "google": Google(client_id="test-client", client_secret="s", **(google_kwargs or {}))
        }
    return make_auth(
        social_providers=social,
        plugins=[plugin],
        http_client=kwargs.pop("http_client", google_http(jwks)),
        **kwargs,
    )


async def call_one_tap(client, token: str, **body_overrides: Any):
    return await client.post(ONE_TAP_PATH, json={"idToken": token, **body_overrides})


async def seed_user(auth, *, email: str, email_verified: bool, name: str = "Existing User"):
    return await auth.internal.create_user(
        {"email": email, "name": name, "emailVerified": email_verified}
    )


# --- valid sign-in / response shape ---------------------------------------------------------


async def test_valid_token_signs_in_new_user_with_exact_response_shape():
    jwks, sign = _rsa_jwks_and_signer()
    token = sign(default_payload())
    auth = one_tap_auth(jwks=jwks)
    async with make_client(auth) as client:
        r = await call_one_tap(client, token)
        assert r.status_code == 200, r.text
        body = r.json()
        assert set(body.keys()) == {"token", "user"}
        assert isinstance(body["token"], str) and body["token"]
        assert body["user"]["email"] == "one-tap-user@example.com"
        assert body["user"]["emailVerified"] is True
        assert body["user"]["name"] == "One Tap User"
        assert body["user"]["image"] == "https://example.com/photo.jpg"
        assert "set-cookie" in r.headers

        account = await auth.adapter.find_one("account", [Where("providerId", "google")])
        assert account["accountId"] == "google-sub-1"


async def test_onetap_level_client_id_used_as_audience_without_google_provider():
    jwks, sign = _rsa_jwks_and_signer()
    token = sign(default_payload(aud="explicit-one-tap-client"))
    auth = one_tap_auth(
        jwks=jwks,
        social_providers={},
        plugin_kwargs={"client_id": "explicit-one-tap-client"},
    )
    async with make_client(auth) as client:
        r = await call_one_tap(client, token)
        assert r.status_code == 200, r.text


# --- audience enforcement (fail closed) ------------------------------------------------------


async def test_missing_audience_returns_400_with_exact_message():
    jwks, sign = _rsa_jwks_and_signer()
    token = sign(default_payload())
    auth = one_tap_auth(jwks=jwks, social_providers={})
    async with make_client(auth) as client:
        r = await call_one_tap(client, token)
        assert r.status_code == 400
        body = r.json()
        assert body["code"] == "BAD_REQUEST"
        assert body["message"] == (
            "Google client ID is required for One Tap. Set it on the oneTap plugin "
            "(clientId) or on socialProviders.google."
        )


async def test_wrong_audience_rejected():
    jwks, sign = _rsa_jwks_and_signer()
    token = sign(default_payload(aud="someone-elses-client"))
    auth = one_tap_auth(jwks=jwks)  # configured audience is "test-client"
    async with make_client(auth) as client:
        r = await call_one_tap(client, token)
        assert r.status_code == 400
        assert r.json() == {"code": "BAD_REQUEST", "message": "invalid id token"}


# --- token verification failures -------------------------------------------------------------


async def test_bad_signature_rejected():
    jwks_a, sign_a = _rsa_jwks_and_signer()
    jwks_b, _sign_b = _rsa_jwks_and_signer()
    token = sign_a(default_payload())
    # Serve key B's public JWK under key A's kid: the token's `kid` resolves, but the
    # signature can't verify against the wrong key.
    tampered = {"keys": [{**jwks_b["keys"][0], "kid": jwks_a["keys"][0]["kid"]}]}
    auth = one_tap_auth(jwks=tampered)
    async with make_client(auth) as client:
        r = await call_one_tap(client, token)
        assert r.status_code == 400
        assert r.json()["message"] == "invalid id token"


async def test_wrong_issuer_rejected():
    jwks, sign = _rsa_jwks_and_signer()
    token = sign(default_payload(iss="https://evil.example.com"))
    auth = one_tap_auth(jwks=jwks)
    async with make_client(auth) as client:
        r = await call_one_tap(client, token)
        assert r.status_code == 400
        assert r.json()["message"] == "invalid id token"


async def test_expired_token_rejected():
    jwks, sign = _rsa_jwks_and_signer()
    now = int(time.time())
    token = sign(default_payload(iat=now - 7200, exp=now - 3600))
    auth = one_tap_auth(jwks=jwks)
    async with make_client(auth) as client:
        r = await call_one_tap(client, token)
        assert r.status_code == 400
        assert r.json()["message"] == "invalid id token"


async def test_token_older_than_max_age_rejected_even_when_not_expired():
    # TS verifyGoogleIdToken enforces maxTokenAge:"1h" on top of `exp` — an old `iat`
    # is rejected even when `exp` is still in the future.
    jwks, sign = _rsa_jwks_and_signer()
    now = int(time.time())
    token = sign(default_payload(iat=now - 7200, exp=now + 600))
    auth = one_tap_auth(jwks=jwks)
    async with make_client(auth) as client:
        r = await call_one_tap(client, token)
        assert r.status_code == 400


async def test_missing_sub_rejected():
    jwks, sign = _rsa_jwks_and_signer()
    payload = default_payload()
    del payload["sub"]
    token = sign(payload)
    auth = one_tap_auth(jwks=jwks)
    async with make_client(auth) as client:
        r = await call_one_tap(client, token)
        assert r.status_code == 400
        assert r.json()["message"] == "invalid id token"


# --- email handling ----------------------------------------------------------------------


async def test_missing_email_returns_200_with_error_body():
    jwks, sign = _rsa_jwks_and_signer()
    payload = default_payload()
    del payload["email"]
    token = sign(payload)
    auth = one_tap_auth(jwks=jwks)
    async with make_client(auth) as client:
        r = await call_one_tap(client, token)
        assert r.status_code == 200
        assert r.json() == {"error": "Email not available in token"}


async def test_email_is_lowercased():
    jwks, sign = _rsa_jwks_and_signer()
    token = sign(default_payload(email="Mixed-Case@Example.com"))
    auth = one_tap_auth(jwks=jwks)
    async with make_client(auth) as client:
        r = await call_one_tap(client, token)
        assert r.status_code == 200, r.text
        assert r.json()["user"]["email"] == "mixed-case@example.com"


# --- hosted domain (hd) ---------------------------------------------------------------------


async def test_hd_mismatch_rejected():
    jwks, sign = _rsa_jwks_and_signer()
    token = sign(default_payload(hd="other.com", email="user@other.com"))
    auth = one_tap_auth(jwks=jwks, google_kwargs={"authorize_params": {"hd": "company.com"}})
    async with make_client(auth) as client:
        r = await call_one_tap(client, token)
        assert r.status_code == 400
        assert r.json()["message"] == "invalid id token"


async def test_hd_missing_when_configured_rejected():
    jwks, sign = _rsa_jwks_and_signer()
    token = sign(default_payload())  # no hd claim at all
    auth = one_tap_auth(jwks=jwks, google_kwargs={"authorize_params": {"hd": "company.com"}})
    async with make_client(auth) as client:
        r = await call_one_tap(client, token)
        assert r.status_code == 400


async def test_hd_match_accepted():
    jwks, sign = _rsa_jwks_and_signer()
    token = sign(default_payload(hd="company.com", email="user@company.com"))
    auth = one_tap_auth(jwks=jwks, google_kwargs={"authorize_params": {"hd": "company.com"}})
    async with make_client(auth) as client:
        r = await call_one_tap(client, token)
        assert r.status_code == 200, r.text


async def test_hd_wildcard_accepts_any_workspace_domain():
    jwks, sign = _rsa_jwks_and_signer()
    token = sign(default_payload(hd="anything.com", email="user@anything.com"))
    auth = one_tap_auth(jwks=jwks, google_kwargs={"authorize_params": {"hd": "*"}})
    async with make_client(auth) as client:
        r = await call_one_tap(client, token)
        assert r.status_code == 200, r.text


async def test_hd_wildcard_rejects_missing_hd():
    jwks, sign = _rsa_jwks_and_signer()
    token = sign(default_payload())  # no hd claim
    auth = one_tap_auth(jwks=jwks, google_kwargs={"authorize_params": {"hd": "*"}})
    async with make_client(auth) as client:
        r = await call_one_tap(client, token)
        assert r.status_code == 400


async def test_hd_ignored_when_not_configured():
    jwks, sign = _rsa_jwks_and_signer()
    token = sign(default_payload(hd="anywhere.com", email="user@anywhere.com"))
    auth = one_tap_auth(jwks=jwks)  # no hd restriction configured
    async with make_client(auth) as client:
        r = await call_one_tap(client, token)
        assert r.status_code == 200, r.text


# --- disableSignup -----------------------------------------------------------------------


async def test_disable_signup_blocks_unknown_user():
    jwks, sign = _rsa_jwks_and_signer()
    token = sign(default_payload())
    auth = one_tap_auth(jwks=jwks, plugin_kwargs={"disable_signup": True})
    async with make_client(auth) as client:
        r = await call_one_tap(client, token)
        assert r.status_code == 401
        assert len(await auth.adapter.find_many("user")) == 0


# --- existing-user link semantics ---------------------------------------------------------


async def test_rejects_implicit_linking_when_local_user_unverified():
    """@see https://github.com/better-auth/better-auth/security/advisories/GHSA-g38m-r43w-p2q7"""
    jwks, sign = _rsa_jwks_and_signer()
    token = sign(default_payload(email="collision@example.com"))
    auth = one_tap_auth(jwks=jwks)
    async with make_client(auth) as client:
        await seed_user(auth, email="collision@example.com", email_verified=False)
        r = await call_one_tap(client, token)
        assert r.status_code == 401
        accounts = await auth.adapter.find_many("account", [Where("providerId", "google")])
        assert len(accounts) == 0


async def test_allows_implicit_linking_when_local_user_verified():
    """@see https://github.com/better-auth/better-auth/security/advisories/GHSA-g38m-r43w-p2q7"""
    jwks, sign = _rsa_jwks_and_signer()
    token = sign(default_payload(email="collision2@example.com"))
    auth = one_tap_auth(jwks=jwks)
    async with make_client(auth) as client:
        await seed_user(auth, email="collision2@example.com", email_verified=True)
        r = await call_one_tap(client, token)
        assert r.status_code == 200, r.text
        accounts = await auth.adapter.find_many("account", [Where("providerId", "google")])
        assert len(accounts) == 1


async def test_require_local_email_verified_opt_out_allows_link():
    """@see https://github.com/better-auth/better-auth/security/advisories/GHSA-g38m-r43w-p2q7"""
    jwks, sign = _rsa_jwks_and_signer()
    token = sign(default_payload(email="collision3@example.com"))
    auth = one_tap_auth(
        jwks=jwks,
        account=AccountOptions(account_linking=AccountLinking(require_local_email_verified=False)),
    )
    async with make_client(auth) as client:
        await seed_user(auth, email="collision3@example.com", email_verified=False)
        r = await call_one_tap(client, token)
        assert r.status_code == 200, r.text


async def test_disable_implicit_linking_blocks_even_verified_local_user():
    jwks, sign = _rsa_jwks_and_signer()
    token = sign(default_payload(email="collision4@example.com"))
    auth = one_tap_auth(
        jwks=jwks,
        account=AccountOptions(account_linking=AccountLinking(disable_implicit_linking=True)),
    )
    async with make_client(auth) as client:
        await seed_user(auth, email="collision4@example.com", email_verified=True)
        r = await call_one_tap(client, token)
        assert r.status_code == 401
        accounts = await auth.adapter.find_many("account", [Where("providerId", "google")])
        assert len(accounts) == 0


async def test_signs_in_account_that_owns_google_sub_not_email_matched_user():
    """@see https://github.com/better-auth/better-auth/issues/9502 — identity resolves by
    the Google `sub`, not the token email."""
    jwks, sign = _rsa_jwks_and_signer()
    shared_sub = "shared-sub-owner-a"
    token = sign(default_payload(sub=shared_sub, email="email-match-b@example.com"))
    auth = one_tap_auth(jwks=jwks)
    async with make_client(auth) as client:
        user_a = await seed_user(auth, email="owner-a@example.com", email_verified=True)
        await auth.internal.create_account(
            {"userId": user_a["id"], "providerId": "google", "accountId": shared_sub}
        )
        await seed_user(auth, email="email-match-b@example.com", email_verified=True)

        r = await call_one_tap(client, token)
        assert r.status_code == 200, r.text
        assert r.json()["user"]["id"] == user_a["id"]


async def test_repeat_sign_in_does_not_duplicate_google_account():
    """@see https://github.com/better-auth/better-auth/issues/9502"""
    jwks, sign = _rsa_jwks_and_signer()
    token = sign(default_payload(sub="returning-sub", email="returning@example.com"))
    auth = one_tap_auth(jwks=jwks)
    async with make_client(auth) as client:
        first = await call_one_tap(client, token)
        assert first.status_code == 200, first.text
        client.cookies.clear()
        second = await call_one_tap(client, token)
        assert second.status_code == 200, second.text

        accounts = await auth.adapter.find_many(
            "account", [Where("providerId", "google"), Where("accountId", "returning-sub")]
        )
        assert len(accounts) == 1


# --- callbackURL origin validation ---------------------------------------------------------


async def test_untrusted_callback_url_rejected():
    jwks, sign = _rsa_jwks_and_signer()
    token = sign(default_payload())
    auth = one_tap_auth(jwks=jwks)
    async with make_client(auth) as client:
        r = await call_one_tap(client, token, callbackURL="https://untrusted.example/callback")
        assert r.status_code == 403


async def test_relative_callback_url_accepted():
    jwks, sign = _rsa_jwks_and_signer()
    token = sign(default_payload())
    auth = one_tap_auth(jwks=jwks)
    async with make_client(auth) as client:
        r = await call_one_tap(client, token, callbackURL="/dashboard")
        assert r.status_code == 200, r.text
