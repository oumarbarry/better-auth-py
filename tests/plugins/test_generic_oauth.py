"""generic-oauth at better-auth v1.7.6: providers registered as first-class social providers.

TS sources: packages/better-auth/src/plugins/generic-oauth/{index,types,error-codes}.ts,
providers/*.ts and generic-oauth.test.ts. Flows go through the core routes
(``/sign-in/social``, ``/callback/:id``, ``/link-social``); outbound calls are stubbed with
``httpx.MockTransport`` injected via ``BetterAuth(http_client=...)``.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from better_auth import BetterAuth, EmailVerification, GitHub, Where
from better_auth.config import UserOptions
from better_auth.oauth import verify
from better_auth.oauth.machinery import TokenEndpointAuth
from better_auth.oauth.models import OAuthTokens
from better_auth.plugins_ext.generic_oauth import (
    GENERIC_OAUTH_ERROR_CODES,
    GenericOAuthConfig,
    GenericOAuthPlugin,
    auth0,
    gumroad,
    hubspot,
    keycloak,
    line,
    microsoft_entra_id,
    okta,
    patreon,
    slack,
    yandex,
)
from conftest import SIGNUP, make_auth, make_client, sign_up

IDP = "https://idp.example.com"
DISCOVERY = f"{IDP}/.well-known/openid-configuration"
PROFILE = {
    "sub": "generic-1",
    "email": "generic@test.com",
    "name": "Generic User",
    "picture": "https://test.com/pic.png",
    "email_verified": True,
}
KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
JWK = {**json.loads(RSAAlgorithm.to_jwk(KEY.public_key(), as_dict=False)), "kid": "k1"}


@pytest.fixture(autouse=True)
def _reset_jwks_cache():
    verify._cache._cache.clear()
    verify._cache._last_miss.clear()
    yield


def discovery_doc(**overrides: Any) -> dict[str, Any]:
    doc = {
        "issuer": IDP,
        "authorization_endpoint": f"{IDP}/authorize",
        "token_endpoint": f"{IDP}/token",
        "userinfo_endpoint": f"{IDP}/userinfo",
    }
    doc.update(overrides)
    return {k: v for k, v in doc.items() if v is not None}


def idp_http(
    *,
    token: dict[str, Any] | None = None,
    userinfo: dict[str, Any] | None = None,
    discovery: dict[str, Any] | None = None,
    record: list[httpx.Request] | None = None,
    discovery_status: int = 200,
) -> httpx.AsyncClient:
    disc = discovery if discovery is not None else discovery_doc()

    def handler(request: httpx.Request) -> httpx.Response:
        if record is not None:
            record.append(request)
        path = request.url.path
        if path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(discovery_status, json=disc)
        if path == "/token":
            return httpx.Response(200, json=token or {"access_token": "at", "token_type": "bearer"})
        if path == "/userinfo":
            return httpx.Response(200, json=PROFILE if userinfo is None else userinfo)
        if path == "/jwks":
            return httpx.Response(200, json={"keys": [JWK]})
        return httpx.Response(404, json={"error": "not_found"})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def cfg(**over: Any) -> GenericOAuthConfig:
    base: dict[str, Any] = {
        "provider_id": "acme",
        "client_id": "cid",
        "client_secret": "sec",
        "authorization_url": f"{IDP}/authorize",
        "token_url": f"{IDP}/token",
        "user_info_url": f"{IDP}/userinfo",
    }
    base.update(over)
    return GenericOAuthConfig(**base)


def plugin_auth(*configs: GenericOAuthConfig, legacy: bool = False, **over: Any) -> BetterAuth:
    over.setdefault("http_client", idp_http())
    return make_auth(
        plugins=[GenericOAuthPlugin(config=list(configs), legacy_routes=legacy)], **over
    )


async def sign_in(client: httpx.AsyncClient, provider: str = "acme", **body: Any) -> httpx.Response:
    return await client.post(
        "/api/auth/sign-in/social",
        json={"provider": provider, "callbackURL": "http://testserver/dashboard", **body},
    )


def query_of(response: httpx.Response) -> dict[str, list[str]]:
    return parse_qs(urlsplit(response.json()["url"]).query)


async def run_flow(
    auth: BetterAuth, provider: str = "acme", extra: str = "", **body: Any
) -> tuple[httpx.Response, httpx.Response, Any]:
    async with make_client(auth) as client:
        started = await sign_in(client, provider, **body)
        assert started.status_code == 200, started.text
        state = query_of(started)["state"][0]
        callback = await client.get(f"/api/auth/callback/{provider}?code=c&state={state}{extra}")
        session = (await client.get("/api/auth/get-session")).json()
        return started, callback, session


async def acme_account(auth: BetterAuth) -> dict[str, Any]:
    account = await auth.adapter.find_one("account", [Where("providerId", "acme")])
    assert account is not None
    return account


def signed_id_token(**claims: Any) -> str:
    now = int(time.time())
    payload = {"iss": IDP, "aud": "cid", "iat": now, "exp": now + 600, **PROFILE}
    payload.update(claims)
    return jwt.encode(payload, KEY, algorithm="RS256", headers={"kid": "k1"})


# --- plugin surface -----------------------------------------------------------------------


def test_error_codes_exact_strings():
    # error-codes.ts at v1.7.6 keeps only the two provider-configuration codes
    assert GENERIC_OAUTH_ERROR_CODES == {
        "INVALID_OAUTH_CONFIGURATION": "Invalid OAuth configuration",
        "TOKEN_URL_NOT_FOUND": "Invalid OAuth configuration. Token URL not found.",
    }


def test_duplicate_provider_ids_warn(caplog):
    with caplog.at_level(logging.WARNING, logger="better_auth"):
        GenericOAuthPlugin(config=[cfg(), cfg(), cfg(provider_id="b"), cfg(provider_id="b")])
    assert "Duplicate provider IDs found: acme, b" in caplog.text


def test_shadowing_a_builtin_provider_warns(caplog):
    with caplog.at_level(logging.WARNING, logger="better_auth"):
        auth = make_auth(
            social_providers={"github": GitHub(client_id="x", client_secret="y")},
            plugins=[GenericOAuthPlugin(config=[cfg(provider_id="github")])],
        )
    assert 'Generic OAuth provider "github" shadows a built-in social provider' in caplog.text
    assert type(auth.social_providers["github"]).__name__ == "_GenericProvider"


async def test_no_plugin_routes_by_default():
    # c7d22539e: providers use signIn.social + callback/:id, no dedicated endpoints
    async with make_client(plugin_auth(cfg())) as client:
        r = await client.post("/api/auth/sign-in/oauth2", json={"providerId": "acme"})
        assert r.status_code == 404


def test_secretless_auth_with_secret_is_a_config_error():
    with pytest.raises(ValueError, match='"none" cannot be combined with clientSecret'):
        plugin_auth(cfg(token_endpoint_auth=TokenEndpointAuth("none")))
    with pytest.raises(ValueError, match="requires clientSecret"):
        plugin_auth(
            cfg(client_secret="", token_endpoint_auth=TokenEndpointAuth("client_secret_post"))
        )
    with pytest.raises(ValueError, match='authentication "basic" requires clientSecret'):
        plugin_auth(cfg(client_secret="", authentication="basic"))


def test_required_id_token_verification_without_discovery_is_a_config_error():
    with pytest.raises(ValueError, match="requires verified ID tokens"):
        plugin_auth(cfg(require_id_token_verification=True))


# --- authorization URL --------------------------------------------------------------------


async def test_sign_in_builds_authorize_url_with_pkce_by_default():
    async with make_client(plugin_auth(cfg(scopes=["email"]))) as client:
        r = await sign_in(client, scopes=["extra"])
        q = query_of(r)
        assert r.json()["redirect"] is True
        assert urlsplit(r.json()["url"]).path == "/authorize"
        assert q["client_id"] == ["cid"]
        assert q["redirect_uri"] == ["http://testserver/api/auth/callback/acme"]
        assert q["scope"] == ["extra email"]
        assert q["code_challenge_method"] == ["S256"]  # pkce ?? true


async def test_pkce_false_omits_challenge():
    async with make_client(plugin_auth(cfg(pkce=False))) as client:
        assert "code_challenge" not in query_of(await sign_in(client))


async def test_authorization_url_params_and_request_params_merge():
    auth = plugin_auth(cfg(authorization_url_params={"a": "1", "b": "cfg", "nonce": "x"}))
    async with make_client(auth) as client:
        q = query_of(await sign_in(client, additionalParams={"b": "req"}, loginHint="u@x"))
        assert q["a"] == ["1"] and q["b"] == ["req"] and q["login_hint"] == ["u@x"]
        assert "nonce" not in q  # reserved keys are dropped


async def test_oidc_discovery_adds_openid_scope():
    http = idp_http(discovery=discovery_doc(id_token_signing_alg_values_supported=["RS256"]))
    auth = plugin_auth(cfg(discovery_url=DISCOVERY, scopes=["email"]), http_client=http)
    async with make_client(auth) as client:
        assert query_of(await sign_in(client))["scope"] == ["openid email"]


async def test_unknown_provider_is_not_found():
    async with make_client(plugin_auth(cfg())) as client:
        r = await sign_in(client, "nope")
        assert r.status_code == 404
        assert r.json()["code"] == "PROVIDER_NOT_FOUND"


async def test_unreachable_discovery_skips_only_that_provider():
    # 5fe5bc21d: a provider whose discovery fails is skipped; the API keeps working
    http = idp_http(discovery_status=500)
    auth = plugin_auth(
        cfg(provider_id="broken", discovery_url=DISCOVERY, authorization_url=None, token_url=None),
        cfg(),
        http_client=http,
    )
    async with make_client(auth) as client:
        assert (await sign_in(client, "broken")).status_code == 404
        assert (await sign_in(client, "acme")).status_code == 200


async def test_discovery_is_fetched_once_and_headers_forwarded():
    record: list[httpx.Request] = []
    http = idp_http(record=record)
    auth = plugin_auth(
        cfg(
            discovery_url=DISCOVERY,
            authorization_url=None,
            token_url=None,
            discovery_headers={"Epic-Client-ID": "e"},
        ),
        http_client=http,
    )
    async with make_client(auth) as client:
        await sign_in(client)
        await sign_in(client)
    discoveries = [r for r in record if r.url.path.endswith("openid-configuration")]
    assert len(discoveries) == 1
    assert discoveries[0].headers["epic-client-id"] == "e"


# --- callback: identity, profile and sign-up -----------------------------------------------


async def test_full_flow_new_user_then_returning_user():
    auth = plugin_auth(cfg(), http_client=idp_http(userinfo={**PROFILE, "id": "u1"}))
    _s, cb, session = await run_flow(auth, newUserCallbackURL="http://testserver/welcome")
    assert cb.headers["location"] == "http://testserver/welcome"
    assert session["user"]["email"] == "generic@test.com"
    account = await acme_account(auth)
    assert account["accountId"] == "u1"  # plain OAuth reads `id`
    _s, cb, _ = await run_flow(auth)
    assert cb.headers["location"] == "http://testserver/dashboard"


async def test_plain_oauth_uses_id_even_when_sub_is_present():
    # index.ts:311-313: plain OAuth reads `id`, OIDC reads `sub`; never switches at runtime
    http = idp_http(userinfo={**PROFILE, "id": 42})
    auth = plugin_auth(cfg(), http_client=http)
    await run_flow(auth)
    account = await acme_account(auth)
    assert account["accountId"] == "42"


async def test_oidc_uses_sub_even_when_id_is_present():
    http = idp_http(
        userinfo={**PROFILE, "id": 42},
        discovery=discovery_doc(id_token_signing_alg_values_supported=["RS256"]),
    )
    auth = plugin_auth(cfg(discovery_url=DISCOVERY), http_client=http)
    await run_flow(auth)
    account = await acme_account(auth)
    assert account["accountId"] == "generic-1"


async def test_account_subject_and_map_profile_to_user():
    def subject(context: dict[str, Any]) -> int:
        assert isinstance(context["tokens"], OAuthTokens)
        return context["profile"]["athlete"]["id"]

    async def mapper(profile: dict[str, Any]) -> dict[str, Any]:
        return {"id": "ignored", "name": "Mapped", "email": "mapped@test.com"}

    http = idp_http(userinfo={"athlete": {"id": 7}, "email": "raw@test.com"})
    auth = plugin_auth(cfg(account_subject=subject, map_profile_to_user=mapper), http_client=http)
    _s, _cb, session = await run_flow(auth)
    assert session["user"]["name"] == "Mapped"
    assert session["user"]["email"] == "mapped@test.com"
    account = await acme_account(auth)
    assert account["accountId"] == "7"


async def test_missing_subject_is_unable_to_get_user_info():
    http = idp_http(userinfo={"email": "x@test.com", "id": None})
    _s, cb, _ = await run_flow(plugin_auth(cfg(), http_client=http))
    assert cb.headers["location"].endswith("error=unable_to_get_user_info")


async def test_missing_email_is_email_not_found():
    http = idp_http(userinfo={"id": "1", "name": "No Mail"})
    _s, cb, _ = await run_flow(plugin_auth(cfg(), http_client=http))
    assert cb.headers["location"].endswith("error=email_not_found")


async def test_token_exchange_failure_is_invalid_code():
    auth = plugin_auth(cfg(token_url=f"{IDP}/missing"))
    _s, cb, _ = await run_flow(auth)
    assert cb.headers["location"].endswith("error=invalid_code")


async def test_disable_sign_up_and_implicit_sign_up():
    http = idp_http(userinfo={**PROFILE, "id": "u1"})
    _s, cb, _ = await run_flow(plugin_auth(cfg(disable_sign_up=True), http_client=http))
    assert cb.headers["location"].endswith("error=signup_disabled")
    auth = plugin_auth(cfg(disable_implicit_sign_up=True), http_client=http)
    _s, cb, _ = await run_flow(auth)
    assert cb.headers["location"].endswith("error=signup_disabled")
    _s, cb, session = await run_flow(auth, requestSignUp=True)
    assert session["user"]["email"] == "generic@test.com"


async def test_require_email_verification_blocks_the_session():
    sent: list[str] = []

    async def send(user, url, token):
        sent.append(url)

    auth = plugin_auth(
        cfg(require_email_verification=True),
        http_client=idp_http(userinfo={**PROFILE, "email_verified": False, "id": "u1"}),
        email_verification=EmailVerification(send_verification_email=send),
    )
    _s, cb, session = await run_flow(auth)
    assert cb.headers["location"].endswith("error=email_not_verified")
    assert session is None
    assert len(sent) == 1


async def test_validate_user_info_sees_generic_provider_and_raw_profile():
    calls: list[dict[str, Any]] = []

    def validate(data, ctx):
        calls.append(data)
        return {"error": "blocked"}

    auth = plugin_auth(
        cfg(),
        http_client=idp_http(userinfo={**PROFILE, "id": "u1"}),
        user=UserOptions(validate_user_info=validate),
    )
    _s, cb, _ = await run_flow(auth)
    assert "error=blocked" in cb.headers["location"]
    assert calls[0]["source"]["oauth"]["providerId"] == "acme"
    assert calls[0]["source"]["oauth"]["profile"]["sub"] == "generic-1"


# --- token endpoint ------------------------------------------------------------------------


async def test_token_request_basic_auth_headers_and_params():
    record: list[httpx.Request] = []
    auth = plugin_auth(
        cfg(
            authentication="basic",
            authorization_headers={"X-Qonto": "t"},
            token_url_params={"audience": "api", "client_id": "evil"},
            pkce=False,
        ),
        http_client=idp_http(record=record, userinfo={**PROFILE, "id": "u1"}),
    )
    await run_flow(auth)
    (token_request,) = [r for r in record if r.url.path == "/token"]
    body = parse_qs(token_request.content.decode())
    assert token_request.headers["authorization"].startswith("Basic ")
    assert token_request.headers["x-qonto"] == "t"
    assert body["audience"] == ["api"]
    assert "client_id" in body and body["client_id"] == ["evil"]  # additional param kept
    assert "client_secret" not in body and "code_verifier" not in body


async def test_custom_get_token_and_default_expiry():
    seen: dict[str, Any] = {}

    async def get_token(data: dict[str, Any]) -> dict[str, Any]:
        seen.update(data)
        return {"access_token": "custom", "refresh_token": "r"}

    auth = plugin_auth(
        cfg(get_token=get_token, token_url=None, access_token_expires_in=3600),
        http_client=idp_http(userinfo={**PROFILE, "id": "u1"}),
    )
    await run_flow(auth)
    assert seen["code"] == "c"
    assert seen["redirectURI"] == "http://testserver/api/auth/callback/acme"
    assert seen["codeVerifier"]
    account = await acme_account(auth)
    assert account["accessTokenExpiresAt"] is not None


async def test_refresh_token_params_static_and_per_request():
    record: list[httpx.Request] = []
    seen_ctx: list[Any] = []

    def params(ctx):
        seen_ctx.append(ctx)
        return {"scope": f"org:{ctx.request.headers.get('x-org')}", "grant_type": "password"}

    auth = plugin_auth(
        cfg(refresh_token_params=params),
        http_client=idp_http(
            record=record,
            token={"access_token": "at", "refresh_token": "rt"},
            userinfo={**PROFILE, "id": "u1"},
        ),
    )
    async with make_client(auth) as client:
        started = await sign_in(client)
        await client.get(f"/api/auth/callback/acme?code=c&state={query_of(started)['state'][0]}")
        account = await auth.adapter.find_one("account", [Where("providerId", "acme")])
        assert account is not None
        r = await client.post(
            "/api/auth/refresh-token", json={"accountId": account["id"]}, headers={"x-org": "9"}
        )
        assert r.status_code == 200, r.text
    refresh = parse_qs([r for r in record if r.url.path == "/token"][-1].content.decode())
    assert refresh["scope"] == ["org:9"]
    assert refresh["grant_type"] == ["refresh_token"]
    assert seen_ctx


# --- RFC 9207 issuer -------------------------------------------------------------------------


async def test_discovered_issuer_is_enforced():
    http = idp_http(discovery=discovery_doc(), userinfo={**PROFILE, "id": "u1"})
    auth = plugin_auth(cfg(discovery_url=DISCOVERY), http_client=http)
    _s, cb, _ = await run_flow(auth, extra="&iss=https://evil.example.com")
    assert cb.headers["location"].endswith("error=issuer_mismatch")
    _s, cb, _ = await run_flow(auth, extra=f"&iss={IDP}")
    assert cb.headers["location"] == "http://testserver/dashboard"


async def test_deprecated_issuer_options_still_apply():
    auth = plugin_auth(
        cfg(issuer=IDP, require_issuer_validation=True),
        http_client=idp_http(userinfo={**PROFILE, "id": "u1"}),
    )
    _s, cb, _ = await run_flow(auth)
    assert cb.headers["location"].endswith("error=issuer_missing")


# --- id_token verification against the discovery JWKS (ec8a38c08, 27b5d8022) ---------------


def jwks_http(id_token_factory) -> tuple[httpx.AsyncClient, dict[str, Any]]:
    doc = discovery_doc(jwks_uri="/jwks", id_token_signing_alg_values_supported=["RS256"])
    state: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("openid-configuration"):
            return httpx.Response(200, json=doc)
        if path == "/authorize":
            return httpx.Response(200)
        if path == "/token":
            return httpx.Response(
                200, json={"access_token": "at", "id_token": id_token_factory(state)}
            )
        if path == "/jwks":
            return httpx.Response(200, json={"keys": [JWK]})
        return httpx.Response(404)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler)), state


async def _jwks_flow(factory, **cfg_over: Any):
    http, state = jwks_http(factory)
    auth = plugin_auth(cfg(discovery_url=DISCOVERY, **cfg_over), http_client=http)
    async with make_client(auth) as client:
        started = await sign_in(client)
        q = query_of(started)
        state["nonce"] = q.get("nonce", [None])[0]
        cb = await client.get(f"/api/auth/callback/acme?code=c&state={q['state'][0]}")
        return q, cb


async def test_discovery_id_token_bound_to_nonce_signs_in():
    q, cb = await _jwks_flow(lambda s: signed_id_token(nonce=s["nonce"]))
    assert q["nonce"][0]
    assert cb.headers["location"] == "http://testserver/dashboard"


async def test_discovery_id_token_with_wrong_or_missing_nonce_is_refused():
    _q, cb = await _jwks_flow(lambda s: signed_id_token(nonce="other"))
    assert cb.headers["location"].endswith("error=unable_to_get_user_info")
    _q, cb = await _jwks_flow(lambda s: signed_id_token())
    assert cb.headers["location"].endswith("error=unable_to_get_user_info")


async def test_discovery_id_token_not_signed_by_jwks_is_refused():
    _q, cb = await _jwks_flow(
        lambda s: jwt.encode({**PROFILE, "nonce": s["nonce"]}, "x" * 32, algorithm="HS256")
    )
    assert cb.headers["location"].endswith("error=unable_to_get_user_info")


async def test_nonce_binding_can_be_disabled():
    q, cb = await _jwks_flow(lambda s: signed_id_token(), disable_id_token_nonce_binding=True)
    assert "nonce" not in q
    assert cb.headers["location"] == "http://testserver/dashboard"


async def test_client_submitted_id_token_for_discovery_provider():
    http, _ = jwks_http(lambda s: "")
    auth = plugin_auth(cfg(discovery_url=DISCOVERY), http_client=http)
    async with make_client(auth) as client:
        r = await client.post(
            "/api/auth/sign-in/social",
            json={"provider": "acme", "idToken": {"token": signed_id_token()}},
        )
        assert r.status_code == 200, r.text
        assert r.json()["user"]["email"] == "generic@test.com"


async def test_required_id_token_verification_skips_provider_without_jwks():
    auth = plugin_auth(cfg(discovery_url=DISCOVERY, require_id_token_verification=True))
    async with make_client(auth) as client:
        assert (await sign_in(client)).status_code == 404


# --- IdP-initiated bounce, link, legacy routes, logout ---------------------------------------


async def test_idp_initiated_callback_bounces():
    auth = plugin_auth(cfg(allow_idp_initiated=True))
    async with make_client(auth) as client:
        r = await client.get("/api/auth/callback/acme?code=c")
        assert r.headers["location"].startswith(f"{IDP}/authorize?")
    async with make_client(plugin_auth(cfg())) as client:
        r = await client.get("/api/auth/callback/acme?code=c")
        assert r.headers["location"].endswith("error=state_not_found")


async def test_link_social_attaches_generic_account():
    http = idp_http(userinfo={**PROFILE, "id": "u1", "email": SIGNUP["email"]})
    auth = plugin_auth(cfg(), http_client=http)
    async with make_client(auth) as client:
        user = (await sign_up(client))["user"]
        r = await client.post(
            "/api/auth/link-social", json={"provider": "acme", "callbackURL": "/settings"}
        )
        state = query_of(r)["state"][0]
        cb = await client.get(f"/api/auth/callback/acme?code=c&state={state}")
        assert cb.headers["location"] == "http://testserver/settings"
    account = await acme_account(auth)
    assert account["userId"] == user["id"]


async def test_legacy_routes_keep_the_pre_17_paths():
    auth = plugin_auth(cfg(), legacy=True, http_client=idp_http(userinfo={**PROFILE, "id": "u"}))
    async with make_client(auth) as client:
        r = await client.post(
            "/api/auth/sign-in/oauth2", json={"providerId": "acme", "callbackURL": "/dash"}
        )
        q = query_of(r)
        assert q["redirect_uri"] == ["http://testserver/api/auth/oauth2/callback/acme"]
        cb = await client.get(f"/api/auth/oauth2/callback/acme?code=c&state={q['state'][0]}")
        assert cb.headers["location"] == "http://testserver/dash"
        linked = await client.post(
            "/api/auth/oauth2/link", json={"providerId": "acme", "callbackURL": "/s"}
        )
        assert linked.status_code == 200 and "state=" in linked.json()["url"]


async def test_end_session_url_from_discovery():
    http = idp_http(discovery=discovery_doc(end_session_endpoint=f"{IDP}/logout"))
    auth = plugin_auth(
        cfg(discovery_url=DISCOVERY, post_logout_redirect_uri="/bye"), http_client=http
    )
    provider: Any = auth.social_providers["acme"]
    assert await provider.ensure_ready(auth.http)
    url = await provider.create_end_session_url(id_token="idt", state="s")
    q = parse_qs(urlsplit(url).query)
    assert url.startswith(f"{IDP}/logout?")
    assert q == {
        "id_token_hint": ["idt"],
        "post_logout_redirect_uri": ["http://testserver/bye"],
        "client_id": ["cid"],
        "state": ["s"],
    }
    # index.ts:354-356: no id_token and no post-logout URI only sends client_id
    bare: Any = plugin_auth(cfg(end_session_endpoint=f"{IDP}/logout")).social_providers["acme"]
    assert await bare.ensure_ready(auth.http)
    assert parse_qs(urlsplit(await bare.create_end_session_url()).query) == {"client_id": ["cid"]}
    disabled = plugin_auth(cfg(end_session_endpoint=f"{IDP}/logout", disable_provider_logout=True))
    assert await disabled.social_providers["acme"].create_end_session_url(id_token="x") is None


# --- presets (providers/*.ts) ----------------------------------------------------------------


def test_discovery_presets():
    assert okta(issuer="https://o.okta.com/oauth2/default/", client_id="c").discovery_url == (
        "https://o.okta.com/oauth2/default/.well-known/openid-configuration"
    )
    assert keycloak(issuer="https://k/realms/r", client_id="c").scopes == [
        "openid",
        "profile",
        "email",
    ]
    # c47b76517: only the host of the Auth0 domain is kept
    for domain in ("tenant.auth0.com", "https://tenant.auth0.com/extra/path"):
        assert auth0(domain=domain, client_id="c").discovery_url == (
            "https://tenant.auth0.com/.well-known/openid-configuration"
        )
    custom = okta(issuer="https://o", client_id="c", scopes=["openid"], pkce=False)
    assert custom.scopes == ["openid"] and custom.pkce is False


def test_endpoint_presets():
    assert slack(client_id="c").token_url == "https://slack.com/api/openid.connect.token"
    assert hubspot(client_id="c").scopes == ["oauth"]
    assert gumroad(client_id="c").scopes == ["view_profile"]
    assert patreon(client_id="c").scopes == ["identity[email]"]
    assert yandex(client_id="c").scopes == ["login:info", "login:email", "login:avatar"]
    assert line(client_id="c", provider_id="line-jp").provider_id == "line-jp"


def test_microsoft_entra_id_preset_requires_a_tenant_guid():
    with pytest.raises(ValueError, match="concrete Microsoft Entra tenant GUID"):
        microsoft_entra_id(tenant_id="common", client_id="c")
    tenant = "0000aaaa-11bb-22cc-33dd-444444eeeeee"
    config = microsoft_entra_id(tenant_id=tenant.upper(), client_id="c")
    assert config.require_id_token_verification is True
    assert config.discovery_url == (
        f"https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration"
    )
    subject: Any = config.account_subject
    assert subject({"profile": {"oid": "o-1", "sub": "s"}}) == "o-1"


async def test_microsoft_entra_id_preset_profile_uses_oid_placeholder():
    config = microsoft_entra_id(tenant_id="0000aaaa-11bb-22cc-33dd-444444eeeeee", client_id="c")
    token = jwt.encode({"oid": "o-1", "sub": "s", "given_name": "Ada"}, "k" * 32)
    async with httpx.AsyncClient() as http:
        getter: Any = config.get_user_info
        profile = await getter.fetch(OAuthTokens(id_token=token), http)
    assert profile["email"] == "o-1@microsoft-entra-id.placeholder.invalid"
    assert profile["emailVerified"] is False
    assert profile["name"] == "Ada"


async def test_yandex_preset_without_email_returns_none():
    config = yandex(client_id="c")
    http = httpx.AsyncClient(
        transport=httpx.MockTransport(lambda r: httpx.Response(200, json={"id": "1", "login": "l"}))
    )
    getter: Any = config.get_user_info
    assert await getter.fetch(OAuthTokens(access_token="a"), http) is None
