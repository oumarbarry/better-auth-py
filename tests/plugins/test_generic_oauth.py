"""Tests for the generic-oauth plugin (user-configured OAuth2/OIDC providers).

Ports better-auth's plugins/generic-oauth. TS source verified against:
  packages/better-auth/src/plugins/generic-oauth/index.ts
  packages/better-auth/src/plugins/generic-oauth/routes.ts
  packages/better-auth/src/plugins/generic-oauth/types.ts
  packages/better-auth/src/plugins/generic-oauth/error-codes.ts
  packages/better-auth/src/plugins/generic-oauth/providers/*.ts

Drives the full authorize -> callback -> session flow through a real HTTP round trip
(``make_client`` / FastAPI ASGI); outbound OAuth calls (discovery/token/userinfo) are
stubbed with ``httpx.MockTransport`` injected via ``BetterAuth(http_client=...)`` — the
same idiom as tests/test_oauth_machinery.py and tests/plugins/test_captcha.py.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, parse_qsl, urlsplit

import httpx
import jwt

from better_auth import BetterAuth, Where
from better_auth.plugins_ext.generic_oauth import (
    GENERIC_OAUTH_ERROR_CODES,
    GenericOAuthConfig,
    GenericOAuthPlugin,
    auth0,
    keycloak,
    okta,
)
from conftest import make_auth, make_client

IDP = "https://idp.example.com"
DISCOVERY = f"{IDP}/.well-known/openid-configuration"


def discovery_doc(issuer: str = IDP, **overrides: Any) -> dict[str, Any]:
    doc = {
        "issuer": issuer,
        "authorization_endpoint": f"{IDP}/authorize",
        "token_endpoint": f"{IDP}/token",
        "userinfo_endpoint": f"{IDP}/userinfo",
    }
    doc.update(overrides)
    return doc


def oidc_http(
    *,
    token: dict[str, Any] | None = None,
    userinfo: dict[str, Any] | None = None,
    discovery: dict[str, Any] | None = None,
    record: list[dict[str, Any]] | None = None,
) -> httpx.AsyncClient:
    """MockTransport routing by path: discovery / token / userinfo."""
    disc = discovery if discovery is not None else discovery_doc()
    tok = token if token is not None else {"access_token": "at", "token_type": "bearer"}
    ui = userinfo if userinfo is not None else {}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if record is not None:
            record.append(
                {
                    "path": path,
                    "headers": dict(request.headers),
                    "body": request.content.decode() if request.content else "",
                }
            )
        if path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json=disc)
        if path == "/token":
            return httpx.Response(200, json=tok)
        if path == "/userinfo":
            return httpx.Response(200, json=ui)
        return httpx.Response(404, json={"error": "not_found"})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def make_id_token(**claims: Any) -> str:
    # generic-oauth decodes the id token WITHOUT verifying its signature (TS `decodeJwt`),
    # so any signing key works here (key length only needs to appease the encoder).
    return jwt.encode(claims, "x" * 32, algorithm="HS256")


def plugin_auth(configs: list[GenericOAuthConfig], **overrides: Any) -> BetterAuth:
    return make_auth(plugins=[GenericOAuthPlugin(config=configs)], **overrides)


async def start_signin(
    client: httpx.AsyncClient, provider_id: str, **body: Any
) -> httpx.Response:
    payload = {"providerId": provider_id, "callbackURL": "http://testserver/dashboard"}
    payload.update(body)
    return await client.post("/api/auth/sign-in/oauth2", json=payload)


def state_of(signin_response: httpx.Response) -> str:
    url = signin_response.json()["url"]
    return parse_qs(urlsplit(url).query)["state"][0]


async def run_flow(
    auth: BetterAuth, provider_id: str, *, code: str = "the-code", **body: Any
) -> tuple[httpx.Response, httpx.Response, httpx.AsyncClient]:
    async with make_client(auth) as client:
        signin = await start_signin(client, provider_id, **body)
        assert signin.status_code == 200, signin.text
        state = state_of(signin)
        callback = await client.get(
            f"/api/auth/oauth2/callback/{provider_id}?code={code}&state={state}",
            follow_redirects=False,
        )
        return signin, callback, client


VERIFIED_PROFILE = {
    "sub": "generic-1",
    "email": "generic@test.com",
    "name": "Generic User",
    "picture": "https://test.com/pic.png",
    "email_verified": True,
}


# --- error codes (exact TS strings) ------------------------------------------------------


def test_error_codes_exact_strings():
    assert GENERIC_OAUTH_ERROR_CODES == {
        "INVALID_OAUTH_CONFIGURATION": "Invalid OAuth configuration",
        "TOKEN_URL_NOT_FOUND": "Invalid OAuth configuration. Token URL not found.",
        "PROVIDER_CONFIG_NOT_FOUND": "No config found for provider",
        "PROVIDER_ID_REQUIRED": "Provider ID is required",
        "INVALID_OAUTH_CONFIG": "Invalid OAuth configuration.",
        "SESSION_REQUIRED": "Session is required",
        "ISSUER_MISMATCH": (
            "OAuth issuer mismatch. The authorization server issuer does not match "
            "the expected value (RFC 9207)."
        ),
        "ISSUER_MISSING": (
            "OAuth issuer parameter missing. The authorization server did not include "
            "the required iss parameter (RFC 9207)."
        ),
    }


def test_error_codes_surface_on_auth_instance():
    auth = plugin_auth([GenericOAuthConfig(provider_id="p", client_id="cid")])
    assert auth.error_codes["SESSION_REQUIRED"] == "Session is required"


def test_duplicate_provider_ids_warn_but_do_not_throw(caplog):
    import logging

    with caplog.at_level(logging.WARNING, logger="better_auth"):
        plugin = GenericOAuthPlugin(
            config=[
                GenericOAuthConfig(provider_id="dup", client_id="a"),
                GenericOAuthConfig(provider_id="dup", client_id="b"),
            ]
        )
    assert plugin is not None
    assert any("dup" in r.message for r in caplog.records)


def test_init_registers_providers_into_social_providers():
    auth = plugin_auth(
        [GenericOAuthConfig(provider_id="acme", client_id="cid", token_url=f"{IDP}/token")]
    )
    assert "acme" in auth.social_providers
    assert auth.social_providers["acme"].provider_id == "acme"


# --- sign-in endpoint: authorization URL construction ------------------------------------


async def test_signin_returns_authorization_url_and_redirect_true():
    auth = plugin_auth(
        [GenericOAuthConfig(provider_id="acme", client_id="cid", discovery_url=DISCOVERY)],
        http_client=oidc_http(),
    )
    async with make_client(auth) as client:
        r = await start_signin(client, "acme")
    assert r.status_code == 200
    data = r.json()
    assert data["redirect"] is True
    assert data["url"].startswith(f"{IDP}/authorize?")
    q = dict(parse_qsl(urlsplit(data["url"]).query))
    assert q["response_type"] == "code"
    assert q["client_id"] == "cid"
    assert q["redirect_uri"] == "http://testserver/api/auth/oauth2/callback/acme"
    assert "state" in q


async def test_signin_disable_redirect_sets_redirect_false():
    auth = plugin_auth(
        [GenericOAuthConfig(provider_id="acme", client_id="cid", discovery_url=DISCOVERY)],
        http_client=oidc_http(),
    )
    async with make_client(auth) as client:
        r = await start_signin(client, "acme", disableRedirect=True)
    assert r.json()["redirect"] is False


async def test_signin_unknown_provider_returns_provider_config_not_found():
    auth = plugin_auth([GenericOAuthConfig(provider_id="acme", client_id="cid")])
    async with make_client(auth) as client:
        r = await start_signin(client, "nope")
    assert r.status_code == 400
    assert "No config found for provider" in r.json()["message"]


async def test_signin_missing_endpoints_returns_invalid_oauth_configuration():
    # no discoveryUrl and no authorizationUrl/tokenUrl -> INVALID_OAUTH_CONFIGURATION
    auth = plugin_auth([GenericOAuthConfig(provider_id="acme", client_id="cid")])
    async with make_client(auth) as client:
        r = await start_signin(client, "acme")
    assert r.status_code == 400
    assert r.json()["message"] == "Invalid OAuth configuration"


async def test_signin_pkce_adds_code_challenge_s256():
    auth = plugin_auth(
        [
            GenericOAuthConfig(
                provider_id="acme", client_id="cid", discovery_url=DISCOVERY, pkce=True
            )
        ],
        http_client=oidc_http(),
    )
    async with make_client(auth) as client:
        r = await start_signin(client, "acme")
    q = dict(parse_qsl(urlsplit(r.json()["url"]).query))
    assert q["code_challenge_method"] == "S256"
    assert q["code_challenge"]


async def test_signin_no_pkce_omits_code_challenge():
    auth = plugin_auth(
        [GenericOAuthConfig(provider_id="acme", client_id="cid", discovery_url=DISCOVERY)],
        http_client=oidc_http(),
    )
    async with make_client(auth) as client:
        r = await start_signin(client, "acme")
    q = dict(parse_qsl(urlsplit(r.json()["url"]).query))
    assert "code_challenge" not in q


async def test_signin_merges_body_scopes_before_config_scopes_and_passes_extras():
    auth = plugin_auth(
        [
            GenericOAuthConfig(
                provider_id="acme",
                client_id="cid",
                authorization_url=f"{IDP}/authorize",
                token_url=f"{IDP}/token",
                scopes=["email"],
                prompt="consent",
                access_type="offline",
                authorization_url_params={"audience": "urn:api"},
            )
        ],
    )
    async with make_client(auth) as client:
        r = await start_signin(client, "acme", scopes=["profile"])
    q = dict(parse_qsl(urlsplit(r.json()["url"]).query))
    assert q["scope"] == "profile email"
    assert q["prompt"] == "consent"
    assert q["access_type"] == "offline"
    assert q["audience"] == "urn:api"


async def test_signin_explicit_redirect_uri_overrides_computed():
    auth = plugin_auth(
        [
            GenericOAuthConfig(
                provider_id="acme",
                client_id="cid",
                authorization_url=f"{IDP}/authorize",
                token_url=f"{IDP}/token",
                redirect_uri="https://app.example.com/cb",
            )
        ],
    )
    async with make_client(auth) as client:
        r = await start_signin(client, "acme")
    q = dict(parse_qsl(urlsplit(r.json()["url"]).query))
    assert q["redirect_uri"] == "https://app.example.com/cb"


# --- full flow: userinfo path ------------------------------------------------------------


async def test_full_flow_existing_user_signs_in_and_redirects_callback():
    auth = plugin_auth(
        [
            GenericOAuthConfig(
                provider_id="acme", client_id="cid", discovery_url=DISCOVERY, pkce=True
            )
        ],
        http_client=oidc_http(
            token={"access_token": "at", "token_type": "bearer", "expires_in": 3600},
            userinfo=VERIFIED_PROFILE,
        ),
    )
    # seed the user so this is a sign-in (not a register)
    await auth.internal.create(
        "user",
        {
            "id": "u1",
            "email": "generic@test.com",
            "name": "Generic User",
            "emailVerified": True,
        },
    )
    _signin, callback, _client = await run_flow(auth, "acme")
    assert callback.status_code in (302, 307)
    assert callback.headers["location"] == "http://testserver/dashboard"
    assert any(h.lower() == "set-cookie" for h, _ in callback.headers.multi_items())


async def test_full_flow_new_user_redirects_new_user_url():
    auth = plugin_auth(
        [
            GenericOAuthConfig(
                provider_id="acme", client_id="cid", discovery_url=DISCOVERY, pkce=True
            )
        ],
        http_client=oidc_http(
            token={"access_token": "at", "token_type": "bearer", "expires_in": 3600},
            userinfo=VERIFIED_PROFILE,
        ),
    )
    _signin, callback, _client = await run_flow(
        auth, "acme", newUserCallbackURL="http://testserver/welcome"
    )
    assert callback.headers["location"] == "http://testserver/welcome"
    user = await auth.adapter.find_one("user", [Where("email", "generic@test.com")])
    assert user is not None


async def test_callback_accepts_post_form_body_response_mode():
    # GET+POST /oauth2/callback: a form_post provider POSTs code/state as urlencoded body,
    # and _callback_params merges them. NB: core origin.check_origin JSON-parses any POST
    # body (origin.py:202), so a form-encoded callback POST is blocked at the core layer for
    # BOTH built-in and generic OAuth (a pre-existing core seam, outside this plugin's files);
    # disable_origin_check for this path isolates the plugin's own form-body handling.
    auth = plugin_auth(
        [GenericOAuthConfig(provider_id="acme", client_id="cid", discovery_url=DISCOVERY)],
        http_client=oidc_http(
            token={"access_token": "at", "token_type": "bearer"}, userinfo=VERIFIED_PROFILE
        ),
        disable_origin_check=["/oauth2/callback"],
    )
    async with make_client(auth) as client:
        signin = await start_signin(client, "acme")
        state = state_of(signin)
        cb = await client.post(
            "/api/auth/oauth2/callback/acme",
            content=f"code=abc&state={state}",
            headers={"content-type": "application/x-www-form-urlencoded"},
            follow_redirects=False,
        )
    assert cb.status_code in (302, 307)
    assert cb.headers["location"] == "http://testserver/dashboard"


async def test_account_row_uses_generic_provider_id_and_sub_account_id():
    auth = plugin_auth(
        [GenericOAuthConfig(provider_id="acme", client_id="cid", discovery_url=DISCOVERY)],
        http_client=oidc_http(
            token={"access_token": "at", "token_type": "bearer"}, userinfo=VERIFIED_PROFILE
        ),
    )
    await run_flow(auth, "acme")
    accounts = await auth.adapter.find_many("account")
    assert len(accounts) == 1
    assert accounts[0]["providerId"] == "acme"
    assert accounts[0]["accountId"] == "generic-1"


# --- id_token path -----------------------------------------------------------------------


async def test_id_token_path_signs_in_without_userinfo_fetch():
    record: list[dict[str, Any]] = []
    id_token = make_id_token(
        sub="idt-1",
        email="idtoken@test.com",
        email_verified=True,
        name="Id Token User",
        picture="https://test.com/idt.png",
    )
    auth = plugin_auth(
        [GenericOAuthConfig(provider_id="acme", client_id="cid", discovery_url=DISCOVERY)],
        http_client=oidc_http(
            token={"access_token": "at", "token_type": "bearer", "id_token": id_token},
            userinfo={"should": "not be fetched"},
            record=record,
        ),
    )
    _signin, callback, _client = await run_flow(auth, "acme")
    assert callback.headers["location"] == "http://testserver/dashboard"
    accounts = await auth.adapter.find_many("account")
    assert accounts[0]["accountId"] == "idt-1"
    # userinfo endpoint must not be hit when the id token already carries sub+email
    assert not any(c["path"] == "/userinfo" for c in record)


# --- iss (RFC 9207) validation -----------------------------------------------------------


async def _flow_with_iss(auth: BetterAuth, provider_id: str, iss: str | None):
    async with make_client(auth) as client:
        signin = await start_signin(client, provider_id)
        state = state_of(signin)
        q = f"code=abc&state={state}"
        if iss is not None:
            q += f"&iss={httpx.QueryParams({'iss': iss})['iss']}"
        return await client.get(
            f"/api/auth/oauth2/callback/{provider_id}?{q}", follow_redirects=False
        )


async def test_iss_match_allows_callback():
    auth = plugin_auth(
        [
            GenericOAuthConfig(
                provider_id="acme",
                client_id="cid",
                discovery_url=DISCOVERY,
                issuer=IDP,
            )
        ],
        http_client=oidc_http(
            token={"access_token": "at", "token_type": "bearer"}, userinfo=VERIFIED_PROFILE
        ),
    )
    cb = await _flow_with_iss(auth, "acme", IDP)
    assert cb.headers["location"] == "http://testserver/dashboard"


async def test_iss_mismatch_redirects_error():
    auth = plugin_auth(
        [
            GenericOAuthConfig(
                provider_id="acme",
                client_id="cid",
                discovery_url=DISCOVERY,
                issuer=IDP,
            )
        ],
        http_client=oidc_http(
            token={"access_token": "at", "token_type": "bearer"}, userinfo=VERIFIED_PROFILE
        ),
    )
    cb = await _flow_with_iss(auth, "acme", "https://evil.example.com")
    assert "error=issuer_mismatch" in cb.headers["location"]


async def test_iss_missing_with_require_issuer_validation_redirects_error():
    auth = plugin_auth(
        [
            GenericOAuthConfig(
                provider_id="acme",
                client_id="cid",
                discovery_url=DISCOVERY,
                issuer=IDP,
                require_issuer_validation=True,
            )
        ],
        http_client=oidc_http(
            token={"access_token": "at", "token_type": "bearer"}, userinfo=VERIFIED_PROFILE
        ),
    )
    cb = await _flow_with_iss(auth, "acme", None)
    assert "error=issuer_missing" in cb.headers["location"]


async def test_iss_missing_without_require_issuer_validation_allowed():
    auth = plugin_auth(
        [
            GenericOAuthConfig(
                provider_id="acme",
                client_id="cid",
                discovery_url=DISCOVERY,
                issuer=IDP,
            )
        ],
        http_client=oidc_http(
            token={"access_token": "at", "token_type": "bearer"}, userinfo=VERIFIED_PROFILE
        ),
    )
    cb = await _flow_with_iss(auth, "acme", None)
    assert cb.headers["location"] == "http://testserver/dashboard"


async def test_iss_from_discovery_when_not_configured():
    auth = plugin_auth(
        [
            GenericOAuthConfig(
                provider_id="acme",
                client_id="cid",
                discovery_url=DISCOVERY,
                require_issuer_validation=True,
            )
        ],
        http_client=oidc_http(
            token={"access_token": "at", "token_type": "bearer"}, userinfo=VERIFIED_PROFILE
        ),
    )
    # issuer comes from the discovery doc (IDP); a mismatching iss must be rejected
    cb = await _flow_with_iss(auth, "acme", "https://evil.example.com")
    assert "error=issuer_mismatch" in cb.headers["location"]


# --- sign-up gating ----------------------------------------------------------------------


async def test_disable_implicit_sign_up_blocks_new_user():
    auth = plugin_auth(
        [
            GenericOAuthConfig(
                provider_id="acme",
                client_id="cid",
                discovery_url=DISCOVERY,
                disable_implicit_sign_up=True,
            )
        ],
        http_client=oidc_http(
            token={"access_token": "at", "token_type": "bearer"}, userinfo=VERIFIED_PROFILE
        ),
    )
    async with make_client(auth) as client:
        signin = await start_signin(
            client, "acme", errorCallbackURL="http://testserver/error"
        )
        state = state_of(signin)
        cb = await client.get(
            f"/api/auth/oauth2/callback/acme?code=abc&state={state}",
            follow_redirects=False,
        )
    assert cb.headers["location"] == "http://testserver/error?error=signup_disabled"


async def test_disable_implicit_sign_up_with_request_sign_up_creates_user():
    auth = plugin_auth(
        [
            GenericOAuthConfig(
                provider_id="acme",
                client_id="cid",
                discovery_url=DISCOVERY,
                disable_implicit_sign_up=True,
            )
        ],
        http_client=oidc_http(
            token={"access_token": "at", "token_type": "bearer"}, userinfo=VERIFIED_PROFILE
        ),
    )
    _signin, cb, _client = await run_flow(auth, "acme", requestSignUp=True)
    assert cb.headers["location"] == "http://testserver/dashboard"
    accounts = await auth.adapter.find_many("account")
    assert len(accounts) == 1


async def test_disable_sign_up_blocks_even_with_request_sign_up():
    auth = plugin_auth(
        [
            GenericOAuthConfig(
                provider_id="acme",
                client_id="cid",
                discovery_url=DISCOVERY,
                disable_sign_up=True,
            )
        ],
        http_client=oidc_http(
            token={"access_token": "at", "token_type": "bearer"}, userinfo=VERIFIED_PROFILE
        ),
    )
    async with make_client(auth) as client:
        signin = await start_signin(
            client, "acme", errorCallbackURL="http://testserver/error", requestSignUp=True
        )
        state = state_of(signin)
        cb = await client.get(
            f"/api/auth/oauth2/callback/acme?code=abc&state={state}",
            follow_redirects=False,
        )
    assert "error=signup_disabled" in cb.headers["location"]


# --- callback error paths ----------------------------------------------------------------


async def test_callback_missing_code_redirects_default_error():
    auth = plugin_auth(
        [GenericOAuthConfig(provider_id="acme", client_id="cid", discovery_url=DISCOVERY)],
        http_client=oidc_http(userinfo=VERIFIED_PROFILE),
    )
    async with make_client(auth) as client:
        signin = await start_signin(client, "acme")
        state = state_of(signin)
        cb = await client.get(
            f"/api/auth/oauth2/callback/acme?state={state}", follow_redirects=False
        )
    assert "error=oAuth_code_missing" in cb.headers["location"]


async def test_callback_provider_error_redirects_that_error():
    auth = plugin_auth(
        [GenericOAuthConfig(provider_id="acme", client_id="cid", discovery_url=DISCOVERY)],
        http_client=oidc_http(userinfo=VERIFIED_PROFILE),
    )
    async with make_client(auth) as client:
        signin = await start_signin(client, "acme")
        state = state_of(signin)
        cb = await client.get(
            f"/api/auth/oauth2/callback/acme?error=access_denied&state={state}",
            follow_redirects=False,
        )
    assert "error=access_denied" in cb.headers["location"]


async def test_callback_missing_email_redirects_email_is_missing():
    auth = plugin_auth(
        [GenericOAuthConfig(provider_id="acme", client_id="cid", discovery_url=DISCOVERY)],
        http_client=oidc_http(
            token={"access_token": "at", "token_type": "bearer"},
            userinfo={"sub": "no-email", "name": "No Email"},
        ),
    )
    async with make_client(auth) as client:
        signin = await start_signin(
            client, "acme", errorCallbackURL="http://testserver/err"
        )
        state = state_of(signin)
        cb = await client.get(
            f"/api/auth/oauth2/callback/acme?code=abc&state={state}",
            follow_redirects=False,
        )
    assert "error=email_is_missing" in cb.headers["location"]


async def test_callback_token_exchange_failure_redirects_verification_failed():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json=discovery_doc())
        if request.url.path == "/token":
            return httpx.Response(400, json={"error": "invalid_grant"})
        return httpx.Response(404)

    auth = plugin_auth(
        [GenericOAuthConfig(provider_id="acme", client_id="cid", discovery_url=DISCOVERY)],
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    async with make_client(auth) as client:
        signin = await start_signin(
            client, "acme", errorCallbackURL="http://testserver/err"
        )
        state = state_of(signin)
        cb = await client.get(
            f"/api/auth/oauth2/callback/acme?code=abc&state={state}",
            follow_redirects=False,
        )
    assert "error=oauth_code_verification_failed" in cb.headers["location"]


# --- token endpoint authentication (basic vs post) ---------------------------------------


async def test_token_exchange_defaults_to_post_client_auth():
    record: list[dict[str, Any]] = []
    auth = plugin_auth(
        [GenericOAuthConfig(provider_id="acme", client_id="cid", client_secret="sec",
                            discovery_url=DISCOVERY)],
        http_client=oidc_http(
            token={"access_token": "at", "token_type": "bearer"},
            userinfo=VERIFIED_PROFILE,
            record=record,
        ),
    )
    await run_flow(auth, "acme")
    token_call = next(c for c in record if c["path"] == "/token")
    body = dict(parse_qsl(token_call["body"]))
    assert body["client_id"] == "cid"
    assert body["client_secret"] == "sec"
    assert "authorization" not in {k.lower() for k in token_call["headers"]}


async def test_token_exchange_basic_auth_sends_authorization_header():
    record: list[dict[str, Any]] = []
    auth = plugin_auth(
        [GenericOAuthConfig(provider_id="acme", client_id="cid", client_secret="sec",
                            discovery_url=DISCOVERY, authentication="basic")],
        http_client=oidc_http(
            token={"access_token": "at", "token_type": "bearer"},
            userinfo=VERIFIED_PROFILE,
            record=record,
        ),
    )
    await run_flow(auth, "acme")
    token_call = next(c for c in record if c["path"] == "/token")
    assert token_call["headers"]["authorization"].startswith("Basic ")


# --- PKCE round-trip ---------------------------------------------------------------------


async def test_pkce_code_verifier_reaches_token_endpoint():
    record: list[dict[str, Any]] = []
    auth = plugin_auth(
        [GenericOAuthConfig(provider_id="acme", client_id="cid", discovery_url=DISCOVERY,
                            pkce=True)],
        http_client=oidc_http(
            token={"access_token": "at", "token_type": "bearer"},
            userinfo=VERIFIED_PROFILE,
            record=record,
        ),
    )
    await run_flow(auth, "acme")
    token_call = next(c for c in record if c["path"] == "/token")
    body = dict(parse_qsl(token_call["body"]))
    assert body.get("code_verifier")


async def test_no_pkce_omits_code_verifier_at_token_endpoint():
    record: list[dict[str, Any]] = []
    auth = plugin_auth(
        [GenericOAuthConfig(provider_id="acme", client_id="cid", discovery_url=DISCOVERY)],
        http_client=oidc_http(
            token={"access_token": "at", "token_type": "bearer"},
            userinfo=VERIFIED_PROFILE,
            record=record,
        ),
    )
    await run_flow(auth, "acme")
    token_call = next(c for c in record if c["path"] == "/token")
    body = dict(parse_qsl(token_call["body"]))
    assert "code_verifier" not in body


# --- mapProfileToUser / getUserInfo overrides --------------------------------------------


async def test_map_profile_to_user_derives_id_from_custom_field():
    auth = plugin_auth(
        [
            GenericOAuthConfig(
                provider_id="acme",
                client_id="cid",
                discovery_url=DISCOVERY,
                map_profile_to_user=lambda p: {
                    "id": p["custom_id"],
                    "email": p["mail"],
                    "name": p["display"],
                },
            )
        ],
        http_client=oidc_http(
            token={"access_token": "at", "token_type": "bearer"},
            userinfo={"custom_id": "strava-9", "mail": "strava@test.com", "display": "Strava"},
        ),
    )
    _signin, cb, _client = await run_flow(auth, "acme")
    assert cb.headers["location"] == "http://testserver/dashboard"
    accounts = await auth.adapter.find_many("account")
    assert accounts[0]["accountId"] == "strava-9"


async def test_custom_get_user_info_used_and_empty_id_rejected():
    async def get_user_info(_tokens: Any) -> dict[str, Any]:
        return {"id": "", "email": "x@test.com", "name": "X"}

    auth = plugin_auth(
        [
            GenericOAuthConfig(
                provider_id="acme",
                client_id="cid",
                discovery_url=DISCOVERY,
                get_user_info=get_user_info,
            )
        ],
        http_client=oidc_http(token={"access_token": "at", "token_type": "bearer"}),
    )
    async with make_client(auth) as client:
        signin = await start_signin(
            client, "acme", errorCallbackURL="http://testserver/err"
        )
        state = state_of(signin)
        cb = await client.get(
            f"/api/auth/oauth2/callback/acme?code=abc&state={state}",
            follow_redirects=False,
        )
    assert "error=id_is_missing" in cb.headers["location"]


async def test_custom_get_user_info_numeric_id_stringified():
    async def get_user_info(_tokens: Any) -> dict[str, Any]:
        return {"id": 12345, "email": "num@test.com", "name": "Numeric"}

    auth = plugin_auth(
        [
            GenericOAuthConfig(
                provider_id="acme",
                client_id="cid",
                discovery_url=DISCOVERY,
                get_user_info=get_user_info,
            )
        ],
        http_client=oidc_http(token={"access_token": "at", "token_type": "bearer"}),
    )
    await run_flow(auth, "acme")
    accounts = await auth.adapter.find_many("account")
    assert accounts[0]["accountId"] == "12345"


async def test_userinfo_sub_fallback_for_account_id():
    auth = plugin_auth(
        [GenericOAuthConfig(provider_id="acme", client_id="cid", discovery_url=DISCOVERY)],
        http_client=oidc_http(
            token={"access_token": "at", "token_type": "bearer"},
            userinfo={"sub": "sub-only", "email": "sub@test.com", "name": "Sub"},
        ),
    )
    await run_flow(auth, "acme")
    accounts = await auth.adapter.find_many("account")
    assert accounts[0]["accountId"] == "sub-only"


# --- custom getToken ---------------------------------------------------------------------


async def test_custom_get_token_bypasses_token_exchange():
    record: list[dict[str, Any]] = []

    async def get_token(_data: Any) -> dict[str, Any]:
        return {"access_token": "custom-at", "token_type": "bearer"}

    auth = plugin_auth(
        [
            GenericOAuthConfig(
                provider_id="acme",
                client_id="cid",
                discovery_url=DISCOVERY,
                get_token=get_token,
            )
        ],
        http_client=oidc_http(userinfo=VERIFIED_PROFILE, record=record),
    )
    _signin, cb, _client = await run_flow(auth, "acme")
    assert cb.headers["location"] == "http://testserver/dashboard"
    assert not any(c["path"] == "/token" for c in record)


# --- discovery: one fetch per endpoint call ----------------------------------------------


async def test_discovery_fetched_once_per_signin_call():
    record: list[dict[str, Any]] = []
    auth = plugin_auth(
        [GenericOAuthConfig(provider_id="acme", client_id="cid", discovery_url=DISCOVERY)],
        http_client=oidc_http(userinfo=VERIFIED_PROFILE, record=record),
    )
    async with make_client(auth) as client:
        await start_signin(client, "acme")
    discovery_hits = [
        c for c in record if c["path"].endswith("/.well-known/openid-configuration")
    ]
    # sign-in needs both authorization + token endpoints but resolves them from ONE fetch
    assert len(discovery_hits) == 1


async def test_discovery_headers_forwarded():
    record: list[dict[str, Any]] = []
    auth = plugin_auth(
        [
            GenericOAuthConfig(
                provider_id="acme",
                client_id="cid",
                discovery_url=DISCOVERY,
                discovery_headers={"x-epic-client-id": "epic-123"},
            )
        ],
        http_client=oidc_http(userinfo=VERIFIED_PROFILE, record=record),
    )
    async with make_client(auth) as client:
        await start_signin(client, "acme")
    disc = next(
        c for c in record if c["path"].endswith("/.well-known/openid-configuration")
    )
    assert disc["headers"]["x-epic-client-id"] == "epic-123"


# --- /oauth2/link ------------------------------------------------------------------------


async def _sign_up(client: httpx.AsyncClient, email: str = "linker@test.com") -> None:
    r = await client.post(
        "/api/auth/sign-up/email",
        json={"name": "Linker", "email": email, "password": "s3cret-password"},
    )
    assert r.status_code == 200, r.text


async def test_link_requires_session():
    auth = plugin_auth(
        [GenericOAuthConfig(provider_id="acme", client_id="cid", discovery_url=DISCOVERY)],
        http_client=oidc_http(),
    )
    async with make_client(auth) as client:
        r = await client.post(
            "/api/auth/oauth2/link",
            json={"providerId": "acme", "callbackURL": "http://testserver/done"},
        )
    assert r.status_code == 401
    assert r.json()["message"] == "Session is required"


async def test_link_returns_authorization_url():
    auth = plugin_auth(
        [GenericOAuthConfig(provider_id="acme", client_id="cid", discovery_url=DISCOVERY)],
        http_client=oidc_http(),
    )
    async with make_client(auth) as client:
        await _sign_up(client)
        r = await client.post(
            "/api/auth/oauth2/link",
            json={"providerId": "acme", "callbackURL": "http://testserver/done"},
        )
    assert r.status_code == 200
    data = r.json()
    assert data["redirect"] is True
    assert data["url"].startswith(f"{IDP}/authorize?")


async def test_link_unknown_provider_404():
    auth = plugin_auth(
        [GenericOAuthConfig(provider_id="acme", client_id="cid", discovery_url=DISCOVERY)],
        http_client=oidc_http(),
    )
    async with make_client(auth) as client:
        await _sign_up(client)
        r = await client.post(
            "/api/auth/oauth2/link",
            json={"providerId": "ghost", "callbackURL": "http://testserver/done"},
        )
    assert r.status_code == 404


async def test_link_attaches_account_to_current_user():
    auth = plugin_auth(
        [GenericOAuthConfig(provider_id="acme", client_id="cid", discovery_url=DISCOVERY)],
        http_client=oidc_http(
            token={"access_token": "at", "token_type": "bearer"},
            userinfo={
                "sub": "link-1",
                "email": "linker@test.com",
                "name": "Linker",
                "email_verified": True,
            },
        ),
    )
    async with make_client(auth) as client:
        await _sign_up(client, "linker@test.com")
        link = await client.post(
            "/api/auth/oauth2/link",
            json={"providerId": "acme", "callbackURL": "http://testserver/done"},
        )
        state = state_of(link)
        cb = await client.get(
            f"/api/auth/oauth2/callback/acme?code=abc&state={state}",
            follow_redirects=False,
        )
    assert cb.headers["location"] == "http://testserver/done"
    accounts = await auth.adapter.find_many("account", [Where("providerId", "acme")])
    assert len(accounts) == 1


async def test_link_email_mismatch_redirects_error():
    auth = plugin_auth(
        [GenericOAuthConfig(provider_id="acme", client_id="cid", discovery_url=DISCOVERY)],
        http_client=oidc_http(
            token={"access_token": "at", "token_type": "bearer"},
            userinfo={
                "sub": "link-2",
                "email": "different@test.com",
                "name": "Other",
                "email_verified": True,
            },
        ),
    )
    async with make_client(auth) as client:
        await _sign_up(client, "linker@test.com")
        link = await client.post(
            "/api/auth/oauth2/link",
            json={
                "providerId": "acme",
                "callbackURL": "http://testserver/done",
                "errorCallbackURL": "http://testserver/err",
            },
        )
        state = state_of(link)
        cb = await client.get(
            f"/api/auth/oauth2/callback/acme?code=abc&state={state}",
            follow_redirects=False,
        )
    assert "error=email_doesn" in cb.headers["location"]


# --- provider presets --------------------------------------------------------------------


def test_okta_preset_builds_discovery_url():
    cfg = okta(client_id="cid", client_secret="sec", issuer="https://dev-12345.okta.com/oauth2/default")
    assert cfg.provider_id == "okta"
    assert cfg.discovery_url == (
        "https://dev-12345.okta.com/oauth2/default/.well-known/openid-configuration"
    )
    assert cfg.scopes == ["openid", "profile", "email"]


def test_okta_preset_strips_trailing_slash_on_issuer():
    cfg = okta(client_id="cid", client_secret="sec", issuer="https://dev-12345.okta.com/oauth2/default/")
    assert cfg.discovery_url == (
        "https://dev-12345.okta.com/oauth2/default/.well-known/openid-configuration"
    )


def test_auth0_preset_builds_discovery_url():
    cfg = auth0(client_id="cid", client_secret="sec", domain="dev-xxx.eu.auth0.com")
    assert cfg.provider_id == "auth0"
    assert cfg.discovery_url == "https://dev-xxx.eu.auth0.com/.well-known/openid-configuration"


def test_keycloak_preset_builds_discovery_url():
    cfg = keycloak(
        client_id="cid", client_secret="sec", issuer="https://my-domain.com/realms/MyRealm"
    )
    assert cfg.provider_id == "keycloak"
    assert cfg.discovery_url == (
        "https://my-domain.com/realms/MyRealm/.well-known/openid-configuration"
    )


def test_preset_passes_through_disable_implicit_sign_up():
    cfg = okta(
        client_id="cid",
        client_secret="sec",
        issuer="https://dev.okta.com",
        disable_implicit_sign_up=True,
    )
    assert cfg.disable_implicit_sign_up is True
