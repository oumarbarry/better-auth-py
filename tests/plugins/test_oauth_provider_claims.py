"""oauth-provider: OIDC authorization inputs, the claim registry, and UserInfo.

Anchored to TS v1.7.6 ``authorize.ts`` (0e1770ac7 max_age, a966815b1 ACR, 267229bd2 inputs,
132e293d7 response_type, 396120120 openid for claims, 5c6de4ed2 RFC error redirects),
``claims-request.ts`` / ``standard-claims.ts`` / ``userinfo.ts`` (e3125e872, d368217ef,
5ac62493e), ``token.ts`` createIdToken (335cda702) and ``oauth.ts`` (0cbaf81be server-trusted
OAuth state).
"""

from __future__ import annotations

import json
from datetime import timedelta
from urllib.parse import parse_qs, urlsplit

from test_oauth_provider_token import (
    CB,
    ISSUER,
    LOGIN,
    SECRET,
    authorize_url,
    get_code,
    make_client,
    provider_auth,
    seed,
    token,
    unverified,
)

from better_auth.adapters.base import Where
from better_auth.oauth.flow import get_oauth_state as flow_state
from better_auth.plugins_ext.oauth_provider.utils import sign_oauth_query
from better_auth.session import utcnow
from better_auth.types import AuthRequest, Ctx
from conftest import sign_up


def rp_error(res):
    assert res.status_code == 302, res.text
    location = res.headers["location"]
    assert location.startswith(CB + "?"), location
    return {k: v[0] for k, v in parse_qs(urlsplit(location).query).items()}


async def tokens(c, *, scope, **authz):
    code = await get_code(c, scope=scope, **authz)
    res = await token(
        c,
        grant_type="authorization_code",
        client_id="client-1",
        client_secret=SECRET,
        code=code,
        redirect_uri=CB,
    )
    assert res.status_code == 200, res.text
    return res.json()


async def userinfo(c, tok, **kwargs):
    return await c.get(
        "/api/auth/oauth2/userinfo", headers={"authorization": f"Bearer {tok}"}, **kwargs
    )


# --- claim authority ----------------------------------------------------------------


async def test_profile_and_email_claims_live_at_userinfo_not_in_the_id_token():
    # token.ts:75 ID_TOKEN_SCOPE_CLAIM_GUARDS (d368217ef) + userinfo.ts:32.
    auth = provider_auth()
    await seed(auth)
    async with make_client(auth) as c:
        await sign_up(c)
        body = await tokens(c, scope="openid profile email")
        id_claims = unverified(body["id_token"])
        for name in ("name", "email", "email_verified", "picture"):
            assert name not in id_claims
        assert id_claims["acr"] == "0"
        info = (await userinfo(c, body["access_token"])).json()
        assert info["email"] == "ada@example.com"
        assert info["name"] == "Ada Lovelace"
        assert info["given_name"] == "Ada"


async def test_claims_userinfo_request_adds_individual_claims():
    # e3125e872: claims.userinfo names are bounded to claims_supported and persisted.
    auth = provider_auth()
    await seed(auth)
    async with make_client(auth) as c:
        await sign_up(c)
        claims = json.dumps({"userinfo": {"email": None, "phone_number": None}})
        body = await tokens(c, scope="openid", claims=claims)
        rows = await auth.adapter.find_many("oauthAccessToken", [])
        assert rows[0]["requestedUserInfoClaims"] == ["email"]
        res = await userinfo(c, body["access_token"])
        assert res.json()["email"] == "ada@example.com"
        assert "name" not in res.json()
        assert res.headers["cache-control"] == "no-store"


async def test_userinfo_accepts_a_form_body_token_but_not_two_transports():
    # userinfo.ts:83 (5ac62493e).
    auth = provider_auth()
    await seed(auth)
    async with make_client(auth) as c:
        await sign_up(c)
        body = await tokens(c, scope="openid email")
        res = await c.post("/api/auth/oauth2/userinfo", data={"access_token": body["access_token"]})
        assert res.status_code == 200, res.text
        assert res.json()["email"] == "ada@example.com"
        res = await c.post(
            "/api/auth/oauth2/userinfo",
            data={"access_token": body["access_token"]},
            headers={"authorization": f"Bearer {body['access_token']}"},
        )
        assert res.status_code == 400
        assert res.json() == {
            "error": "invalid_request",
            "error_description": "Multiple access token transport methods are not allowed",
        }


async def test_consent_with_accepted_claims_filters_the_request():
    # consent.ts:59 "Claim not originally requested".
    auth = provider_auth()
    await seed(auth, skipConsent=False)
    async with make_client(auth) as c:
        await sign_up(c)
        claims = json.dumps({"userinfo": {"email": None}})
        res = await c.get(authorize_url(scope="openid", claims=claims))
        signed = urlsplit(res.headers["location"]).query
        res = await c.post(
            "/api/auth/oauth2/consent",
            json={"accept": True, "oauth_query": signed, "claims": {"userinfo": {"name": None}}},
        )
        assert res.status_code == 400
        assert res.json()["error_description"] == "Claim not originally requested"
        res = await c.post(
            "/api/auth/oauth2/consent",
            json={"accept": True, "oauth_query": signed, "claims": {"userinfo": {}}},
        )
        assert res.status_code == 200, res.text
        consent = (await auth.adapter.find_many("oauthConsent", []))[0]
        assert consent["requestedUserInfoClaims"] == []


# --- authorization request inputs ---------------------------------------------------


async def test_claims_require_openid():
    # authorize.ts:552 (396120120).
    auth = provider_auth()
    await seed(auth, scopes=["profile", "openid"])
    async with make_client(auth) as c:
        await sign_up(c)
        res = await c.get(authorize_url(scope="profile", claims='{"userinfo":{}}'))
        assert rp_error(res)["error_description"] == (
            "openid scope must be requested when using the claims parameter"
        )
        res = await c.get(authorize_url(scope="openid", claims="not json"))
        assert rp_error(res)["error_description"] == "claims must be a valid Claims request object"


async def test_essential_acr_that_cannot_be_met_is_access_denied():
    # authorize.ts:574 + claims-request.ts:76 (a966815b1): acr_values stays voluntary.
    auth = provider_auth()
    await seed(auth)
    async with make_client(auth) as c:
        await sign_up(c)
        essential = json.dumps({"id_token": {"acr": {"essential": True, "values": ["2"]}}})
        err = rp_error(await c.get(authorize_url(scope="openid", claims=essential)))
        assert err["error"] == "access_denied"
        assert err["error_description"] == "essential acr requirement cannot be met"
        ok = json.dumps({"id_token": {"acr": {"essential": True, "value": "0"}}})
        assert (
            "code=" in (await c.get(authorize_url(scope="openid", claims=ok))).headers["location"]
        )
        res = await c.get(authorize_url(scope="openid", acr_values="urn:gold"))
        assert "code=" in res.headers["location"]


async def test_max_age_forces_login_when_the_session_is_too_old():
    # authorize.ts:686-715 (0e1770ac7).
    auth = provider_auth()
    await seed(auth)
    async with make_client(auth) as c:
        await sign_up(c)
        res = await c.get(authorize_url(scope="openid", max_age="3600"))
        assert "code=" in res.headers["location"]
        session = (await auth.adapter.find_many("session", []))[0]
        await auth.adapter.update(
            "session",
            [Where("id", session["id"])],
            {"createdAt": utcnow() - timedelta(hours=2)},
        )
        res = await c.get(authorize_url(scope="openid", max_age="3600"))
        assert res.headers["location"].startswith(LOGIN + "?")
        assert "max_age=3600" in res.headers["location"]
        res = await c.get(authorize_url(scope="openid", max_age="0", prompt="none"))
        assert rp_error(res)["error"] == "login_required"


async def test_invalid_authorization_inputs_redirect_to_the_client():
    # authorize.ts:486 mapIssuesToOAuthError + authorizeRedirectOnError (5c6de4ed2).
    auth = provider_auth()
    await seed(auth)
    async with make_client(auth) as c:
        await sign_up(c)
        err = rp_error(await c.get(authorize_url(scope="openid", max_age="abc", state="s")))
        assert err == {
            "error": "invalid_request",
            "error_description": "max_age: max_age must be a non-negative integer",
            "state": "s",
            "iss": ISSUER,
        }
        # A token-bearing response_type gets the error in the fragment (authorize.ts:106).
        res = await c.get(authorize_url(scope="openid", response_type="token"))
        location = res.headers["location"]
        assert location.startswith(CB + "#")
        err = {k: v[0] for k, v in parse_qs(location.split("#", 1)[1]).items()}
        assert err["error"] == "unsupported_response_type"
        assert err["error_description"] == "response_type must be one of: code"
        err = rp_error(await c.get(authorize_url(scope="openid", prompt="none login")))
        assert err["error_description"] == (
            "prompt: prompt=none cannot be combined with other prompt values"
        )
        err = rp_error(await c.get(authorize_url(scope="openid", request="eyJ.x.y")))
        assert err["error"] == "request_not_supported"


async def test_missing_response_type_redirects_to_the_client():
    # authorize.ts:500 (132e293d7).
    auth = provider_auth()
    await seed(auth)
    async with make_client(auth) as c:
        res = await c.get(authorize_url(scope="openid", response_type=None))
        err = rp_error(res)
        assert err["error"] == "invalid_request"
        assert err["error_description"] == "response_type is required"


async def test_untrusted_redirect_uri_errors_go_to_the_error_page():
    auth = provider_auth()
    await seed(auth)
    async with make_client(auth) as c:
        res = await c.get(
            authorize_url(
                scope="openid", response_type=None, redirect_uri="https://evil.example/cb"
            )
        )
        assert res.headers["location"].startswith(f"{ISSUER}/error?error=invalid_request")


async def test_state_is_optional_and_post_form_authorize_works():
    # b7850f90a + oauth.ts:267 (267229bd2).
    auth = provider_auth()
    await seed(auth)
    async with make_client(auth) as c:
        await sign_up(c)
        res = await c.get(authorize_url(scope="openid"))
        q = parse_qs(urlsplit(res.headers["location"]).query)
        assert "state" not in q and q["code"]
        res = await c.post(
            "/api/auth/oauth2/authorize",
            data={
                "client_id": "client-1",
                "response_type": "code",
                "redirect_uri": CB,
                "scope": "openid",
                "state": "posted",
            },
        )
        q = parse_qs(urlsplit(res.headers["location"]).query)
        assert q["state"] == ["posted"] and q["code"]


async def test_discovery_advertises_claims_and_request_support():
    # metadata.ts:100-199.
    auth = provider_auth()
    async with make_client(auth) as c:
        doc = (await c.get("/api/auth/.well-known/openid-configuration")).json()
    assert doc["claims_parameter_supported"] is True
    assert doc["acr_values_supported"] == ["0"]
    assert doc["request_parameter_supported"] is False
    assert doc["request_uri_parameter_supported"] is False
    assert doc["dpop_signing_alg_values_supported"] == ["EdDSA", "ES256", "ES512", "PS256", "RS256"]
    assert doc["claims_supported"][8:] == [
        "name",
        "picture",
        "given_name",
        "family_name",
        "email",
        "email_verified",
    ]


# --- server-trusted OAuth state (0cbaf81be) -------------------------------------------


async def test_social_sign_in_carries_the_query_in_server_context_not_the_body():
    # oauth.ts:641: addOAuthServerContext, never body.additionalData.query.
    auth = provider_auth()
    plugin = auth.plugins[-1]
    signed = sign_oauth_query(
        [("client_id", "client-1"), ("scope", "openid")],
        auth.secret,
        exp=int(utcnow().timestamp()) + 600,
        issued_at_ms=int(utcnow().timestamp() * 1000),
    )
    body = {"provider": "github", "oauth_query": signed, "additionalData": {"query": "evil=1"}}
    ctx = Ctx(
        auth=auth,
        request=AuthRequest(method="POST", path="/sign-in/social", body=json.dumps(body).encode()),
    )
    await plugin._before_stash_oauth_query(ctx)
    assert ctx.body()["additionalData"] == {"query": "evil=1"}
    server = vars(ctx)["_oauth_server_context"]
    assert server["query"].startswith("client_id=client-1&scope=openid&")
    assert "sig=" not in server["query"] and "exp=" not in server["query"]
    assert isinstance(server["signedQueryIssuedAtMs"], int)
    assert flow_state(ctx) is None


async def test_social_login_resumes_the_authorize_request_from_server_context():
    # oauth.ts:673-712: the after hook reads serverContext.query on the provider callback.
    from better_auth import GitHub
    from better_auth.plugins_ext.jwt import JWTPlugin
    from better_auth.plugins_ext.oauth_provider import OAuthProviderPlugin
    from conftest import make_auth
    from test_oauth import github_http

    auth = make_auth(
        base_url="http://localhost:3000",
        social_providers={"github": GitHub(client_id="cid", client_secret="csecret")},
        http_client=github_http(),
        plugins=[JWTPlugin(), OAuthProviderPlugin(login_page=LOGIN, consent_page=LOGIN)],
    )
    await seed(auth)
    async with make_client(auth) as c:
        res = await c.get(authorize_url(scope="openid", state="resume-me"))
        signed = urlsplit(res.headers["location"]).query
        res = await c.post(
            "/api/auth/sign-in/social",
            json={
                "provider": "github",
                "callbackURL": "/",
                "oauth_query": signed,
                "additionalData": {"query": "client_id=evil"},
            },
        )
        assert res.status_code == 200, res.text
        state = parse_qs(urlsplit(res.json()["url"]).query)["state"][0]
        res = await c.get(f"/api/auth/callback/github?code=abc&state={state}")
        body = res.json()
        assert body["redirect"] is True
        q = parse_qs(urlsplit(body["url"]).query)
        assert body["url"].startswith(CB + "?")
        assert q["state"] == ["resume-me"] and q["code"]


def test_format_error_url_appends_before_the_fragment():
    # authorize.ts:76 appendQueryParams (79904f0be, authorize.test.ts formatErrorURL).
    from better_auth.plugins_ext.oauth_provider.utils import format_error_url

    assert (
        format_error_url("/error?source=oauth#retry", "invalid_request", "Missing parameter")
        == "/error?source=oauth&error=invalid_request&error_description=Missing+parameter#retry"
    )
    assert format_error_url("https://rp.example", "access_denied", "no") == (
        "https://rp.example/?error=access_denied&error_description=no"
    )


async def test_legacy_id_token_profile_claims_default_off():
    # TS default (token.ts:75 guards, d368217ef): no profile or email claims in the ID token.
    auth = provider_auth()
    await seed(auth)
    async with make_client(auth) as c:
        await sign_up(c)
        id_claims = unverified((await tokens(c, scope="openid profile email"))["id_token"])
        assert not {"name", "email", "email_verified", "picture", "given_name"} & set(id_claims)


async def test_legacy_id_token_profile_claims_opt_in_restores_1_0_claims():
    # Port-only opt-in: 1.0 scope-based claims, protocol claims still AS-owned.
    auth = provider_auth(
        legacy_id_token_profile_claims=True,
        custom_id_token_claims=lambda info: {"acr": "custom", "iss": "evil"},
    )
    await seed(auth)
    async with make_client(auth) as c:
        await sign_up(c)
        id_claims = unverified((await tokens(c, scope="openid profile email"))["id_token"])
        assert id_claims["name"] == "Ada Lovelace"
        assert id_claims["given_name"] == "Ada"
        assert id_claims["family_name"] == "Lovelace"
        assert id_claims["email"] == "ada@example.com"
        assert id_claims["email_verified"] is False
        assert id_claims["acr"] == "0"
        assert id_claims["iss"] == ISSUER
        only_openid = unverified((await tokens(c, scope="openid"))["id_token"])
        assert "email" not in only_openid and "name" not in only_openid
