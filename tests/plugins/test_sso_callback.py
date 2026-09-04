"""Tests for the SSO OIDC callback (GET /sso/callback/:providerId and /sso/callback).

TS source verified against packages/sso/src/routes/sso.ts (handleOIDCCallback sso.ts:1449,
callbackSSO :1835, callbackSSOShared :1850) and packages/better-auth/src/oauth2/link-account.ts
(handleOAuthUserInfo trust-flag semantics).

End-to-end with a stubbed IdP: token endpoint + JWKS (id-token verified) / userinfo. Covers
mapping application, provisioning, trust-flag linking, state-bound shared callback, and the
error-redirect shapes.
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import timedelta
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from better_auth import AccountLinking, AccountOptions, BetterAuth, Where
from better_auth.crypto import generate_id, sign_value
from better_auth.oauth.flow import STATE_COOKIE
from better_auth.plugins_ext.sso import SSOPlugin
from better_auth.session import cookie_name, utcnow
from conftest import make_auth, make_client

IDP = "https://idp.example.com"


@pytest.fixture(autouse=True)
def _reset_jwks_cache():
    from better_auth.oauth import verify

    verify._cache._cache.clear()
    verify._cache._last_miss.clear()
    yield


def _rsa_jwks_and_signer():
    kid = uuid.uuid4().hex
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    jwk["kid"] = kid
    jwk["alg"] = "RS256"

    def sign(payload: dict[str, Any]) -> str:
        return jwt.encode(payload, key, algorithm="RS256", headers={"kid": kid})

    return {"keys": [jwk]}, sign


def id_token_claims(**overrides: Any) -> dict[str, Any]:
    now = int(time.time())
    claims = {
        "iss": IDP,
        "aud": "client-1",
        "sub": "sso-sub-1",
        "email": "worker@corp.example",
        "email_verified": True,
        "name": "SSO Worker",
        "picture": "https://corp.example/p.png",
        "iat": now,
        "exp": now + 600,
    }
    claims.update(overrides)
    return claims


def idp_http(
    jwks: dict[str, Any],
    id_token: str | None = None,
    *,
    userinfo: dict[str, Any] | None = None,
    token_status: int = 200,
) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/token"):
            body: dict[str, Any] = {"access_token": "at-1", "token_type": "bearer"}
            if id_token is not None:
                body["id_token"] = id_token
            return httpx.Response(token_status, json=body)
        if path.endswith("/jwks"):
            return httpx.Response(200, json=jwks)
        if path.endswith("/userinfo"):
            return httpx.Response(200, json=userinfo or {})
        return httpx.Response(404, json={})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def oidc_config(**overrides: Any) -> dict[str, Any]:
    cfg = {
        "issuer": IDP,
        "clientId": "client-1",
        "clientSecret": "secret",
        "authorizationEndpoint": f"{IDP}/authorize",
        "tokenEndpoint": f"{IDP}/token",
        "jwksEndpoint": f"{IDP}/jwks",
        "tokenEndpointAuthentication": "client_secret_basic",
        "pkce": False,
        "scopes": ["openid", "email"],
        "mapping": {"id": "sub", "email": "email", "name": "name"},
        "overrideUserInfo": False,
    }
    cfg.update(overrides)
    return cfg


async def seed_provider(
    auth: BetterAuth,
    *,
    provider_id: str = "corp",
    domain: str = "corp.example",
    config: dict[str, Any] | None = None,
    organization_id: str | None = None,
    domain_verified: bool | None = None,
) -> None:
    row: dict[str, Any] = {
        "providerId": provider_id,
        "issuer": IDP,
        "domain": domain,
        "organizationId": organization_id,
        "userId": "seed",
        "oidcConfig": json.dumps(config or oidc_config()),
        "samlConfig": None,
    }
    if domain_verified is not None:
        row["domainVerified"] = domain_verified
    await auth.adapter.create("ssoProvider", row)


async def seed_state(
    auth: BetterAuth,
    *,
    callback_url: str = "/dash",
    error_url: str | None = None,
    additional: dict[str, Any] | None = None,
) -> str:
    """Write a state row directly (bypassing sign-in) and return the state token."""
    state = generate_id()
    now = utcnow()
    payload: dict[str, Any] = {
        "callbackURL": callback_url,
        "codeVerifier": "cv-1",
        "errorURL": error_url,
        "newUserURL": None,
        "expiresAt": int(now.timestamp() * 1000) + 600_000,
    }
    if additional:
        payload["additionalData"] = additional
    await auth.adapter.create(
        "verification",
        {
            "id": generate_id(),
            "identifier": state,
            "value": json.dumps(payload),
            "expiresAt": now + timedelta(seconds=600),
            "createdAt": now,
            "updatedAt": now,
        },
    )
    return state


def state_cookie_header(auth: BetterAuth, state: str) -> dict[str, str]:
    signed = sign_value(auth.secret, state)
    return {"cookie": f"{cookie_name(auth, STATE_COOKIE)}={signed}"}


async def callback(
    client: httpx.AsyncClient,
    auth: BetterAuth,
    *,
    provider_id: str | None = "corp",
    state: str,
    code: str = "auth-code",
    extra_query: str = "",
) -> httpx.Response:
    path = f"/sso/callback/{provider_id}" if provider_id else "/sso/callback"
    url = f"/api/auth{path}?state={state}&code={code}{extra_query}"
    return await client.get(url, headers=state_cookie_header(auth, state), follow_redirects=False)


# --- id-token happy path -------------------------------------------------------------


async def test_callback_id_token_registers_new_user() -> None:
    jwks, sign = _rsa_jwks_and_signer()
    auth = make_auth(
        plugins=[SSOPlugin()],
        trusted_origins=[IDP],
        http_client=idp_http(jwks, sign(id_token_claims())),
    )
    async with make_client(auth) as client:
        await seed_provider(auth)
        state = await seed_state(auth)
        res = await callback(client, auth, state=state)
    assert res.status_code in (302, 307), res.text
    assert res.headers["location"] == "http://testserver/dash"
    user = await auth.adapter.find_one("user", [Where("email", "worker@corp.example")])
    assert user is not None
    account = await auth.adapter.find_one("account", [Where("providerId", "corp")])
    assert account is not None
    assert account["accountId"] == "sso-sub-1"
    # a session cookie was set
    assert any(k.lower() == "set-cookie" for k, _ in res.headers.multi_items())


async def test_callback_userinfo_mapping_applied() -> None:
    jwks, _sign = _rsa_jwks_and_signer()
    cfg = oidc_config(
        userInfoEndpoint=f"{IDP}/userinfo",
        mapping={"id": "user_id", "email": "mail", "name": "full_name"},
    )
    userinfo = {"user_id": "uid-9", "mail": "u9@corp.example", "full_name": "Nine"}
    auth = make_auth(
        plugins=[SSOPlugin()],
        trusted_origins=[IDP],
        http_client=idp_http(jwks, userinfo=userinfo),
    )
    async with make_client(auth) as client:
        await seed_provider(auth, config=cfg)
        state = await seed_state(auth)
        res = await callback(client, auth, state=state)
    assert res.status_code in (302, 307), res.text
    user = await auth.adapter.find_one("user", [Where("email", "u9@corp.example")])
    assert user is not None
    account = await auth.adapter.find_one("account", [Where("providerId", "corp")])
    assert account is not None and account["accountId"] == "uid-9"


# --- id-token verification is real ---------------------------------------------------


async def test_callback_rejects_untrusted_id_token_signature() -> None:
    jwks_a, _sign_a = _rsa_jwks_and_signer()
    _jwks_b, sign_b = _rsa_jwks_and_signer()  # token signed with a foreign key
    auth = make_auth(
        plugins=[SSOPlugin()],
        trusted_origins=[IDP],
        http_client=idp_http(jwks_a, sign_b(id_token_claims())),
    )
    async with make_client(auth) as client:
        await seed_provider(auth)
        state = await seed_state(auth)
        res = await callback(client, auth, state=state)
    assert res.status_code in (302, 307)
    query = parse_qs(urlsplit(res.headers["location"]).query)
    assert query["error"] == ["invalid_provider"]
    assert query["error_description"] == ["token_not_verified"]
    assert await auth.adapter.find_one("account", [Where("providerId", "corp")]) is None


# --- trust flags ---------------------------------------------------------------------


async def _seed_local_user(auth: BetterAuth, *, email: str, email_verified: bool) -> str:
    row = await auth.internal.create_user(
        {"email": email, "name": "Existing", "emailVerified": email_verified}
    )
    assert row is not None
    return row["id"]


async def test_verified_domain_links_to_existing_user() -> None:
    # is_trusted_provider = domainVerified && email-domain match. The incoming id-token email
    # is NOT trusted (trustEmailVerified off -> email_verified forced false); linking only
    # proceeds because is_trusted_provider bypasses the incoming-email-verified gate.
    jwks, sign = _rsa_jwks_and_signer()
    auth = make_auth(
        plugins=[SSOPlugin(domain_verification={"enabled": True})],
        trusted_origins=[IDP],
        http_client=idp_http(jwks, sign(id_token_claims())),
    )
    async with make_client(auth) as client:
        await _seed_local_user(auth, email="worker@corp.example", email_verified=True)
        await seed_provider(auth, domain_verified=True)
        state = await seed_state(auth)
        res = await callback(client, auth, state=state)
    assert res.status_code in (302, 307), res.text
    assert res.headers["location"] == "http://testserver/dash"
    account = await auth.adapter.find_one("account", [Where("providerId", "corp")])
    assert account is not None  # linked


async def test_untrusted_provider_does_not_inherit_name_trust() -> None:
    # trustProviderByName:false — even with the providerId in the global trustedProviders
    # list, an unverified-domain provider does NOT inherit trust by name. The local user is
    # verified (so only the name-trust clause decides): link is refused.
    jwks, sign = _rsa_jwks_and_signer()
    auth = make_auth(
        plugins=[SSOPlugin()],
        trusted_origins=[IDP],
        http_client=idp_http(jwks, sign(id_token_claims())),
        account=AccountOptions(account_linking=AccountLinking(trusted_providers=["corp"])),
    )
    async with make_client(auth) as client:
        await _seed_local_user(auth, email="worker@corp.example", email_verified=True)
        await seed_provider(auth)  # not domainVerified -> is_trusted_provider False
        state = await seed_state(auth)
        res = await callback(client, auth, state=state)
    assert res.status_code in (302, 307)
    query = parse_qs(urlsplit(res.headers["location"]).query)
    assert query["error"] == ["account_not_linked"]
    assert await auth.adapter.find_one("account", [Where("providerId", "corp")]) is None


# --- provisionUser -------------------------------------------------------------------


async def test_provision_user_called_on_register() -> None:
    jwks, sign = _rsa_jwks_and_signer()
    calls: list[dict[str, Any]] = []

    async def provision(data: dict[str, Any]) -> None:
        calls.append(data)

    auth = make_auth(
        plugins=[SSOPlugin(provision_user=provision)],
        trusted_origins=[IDP],
        http_client=idp_http(jwks, sign(id_token_claims())),
    )
    async with make_client(auth) as client:
        await seed_provider(auth)
        state = await seed_state(auth)
        await callback(client, auth, state=state)
    assert len(calls) == 1
    assert calls[0]["userInfo"]["email"] == "worker@corp.example"
    assert calls[0]["provider"]["providerId"] == "corp"


# --- shared callback: state-bound provider id ----------------------------------------


async def test_shared_callback_reads_provider_id_from_state() -> None:
    jwks, sign = _rsa_jwks_and_signer()
    auth = make_auth(
        plugins=[SSOPlugin(redirect_uri="/sso/callback")],
        trusted_origins=[IDP],
        http_client=idp_http(jwks, sign(id_token_claims())),
    )
    async with make_client(auth) as client:
        await seed_provider(auth)
        state = await seed_state(auth, additional={"ssoProviderId": "corp"})
        res = await callback(client, auth, provider_id=None, state=state)
    assert res.status_code in (302, 307), res.text
    assert res.headers["location"] == "http://testserver/dash"


async def test_shared_callback_missing_provider_id_rejected() -> None:
    auth = make_auth(plugins=[SSOPlugin(redirect_uri="/sso/callback")], trusted_origins=[IDP])
    async with make_client(auth) as client:
        state = await seed_state(auth)  # no ssoProviderId
        res = await callback(client, auth, provider_id=None, state=state)
    assert res.status_code in (302, 307)
    query = parse_qs(urlsplit(res.headers["location"]).query)
    assert query["error"] == ["invalid_state"]
    assert query["error_description"] == ["missing_provider_id"]


async def test_shared_callback_forged_provider_id_not_found() -> None:
    auth = make_auth(plugins=[SSOPlugin(redirect_uri="/sso/callback")], trusted_origins=[IDP])
    async with make_client(auth) as client:
        state = await seed_state(auth, additional={"ssoProviderId": "ghost"})
        res = await callback(client, auth, provider_id=None, state=state)
    assert res.status_code in (302, 307)
    query = parse_qs(urlsplit(res.headers["location"]).query)
    assert query["error"] == ["invalid_provider"]


# --- error-redirect shapes -----------------------------------------------------------


async def test_callback_no_state_row_redirects_invalid_state() -> None:
    auth = make_auth(plugins=[SSOPlugin()])
    async with make_client(auth) as client:
        res = await client.get(
            "/api/auth/sso/callback/corp?state=nope&code=x", follow_redirects=False
        )
    assert res.status_code in (302, 307)
    loc = res.headers["location"]
    assert "error=invalid_state" in loc
    assert loc.startswith("http://testserver/api/auth/error")


async def test_callback_provider_error_param_redirects() -> None:
    auth = make_auth(plugins=[SSOPlugin()], trusted_origins=[IDP])
    async with make_client(auth) as client:
        await seed_provider(auth)
        state = await seed_state(auth, error_url="/oops")
        res = await callback(client, auth, state=state, code="", extra_query="&error=access_denied")
    assert res.status_code in (302, 307)
    query = parse_qs(urlsplit(res.headers["location"]).query)
    assert query["error"] == ["access_denied"]
    assert urlsplit(res.headers["location"]).path == "/oops"


async def test_callback_token_exchange_failure_redirects() -> None:
    jwks, sign = _rsa_jwks_and_signer()
    auth = make_auth(
        plugins=[SSOPlugin()],
        trusted_origins=[IDP],
        http_client=idp_http(jwks, sign(id_token_claims()), token_status=400),
    )
    async with make_client(auth) as client:
        await seed_provider(auth)
        state = await seed_state(auth)
        res = await callback(client, auth, state=state)
    assert res.status_code in (302, 307)
    query = parse_qs(urlsplit(res.headers["location"]).query)
    assert query["error"] == ["invalid_provider"]
    assert query["error_description"] == ["token_response_not_found"]


async def test_callback_state_cookie_mismatch_redirects() -> None:
    jwks, sign = _rsa_jwks_and_signer()
    auth = make_auth(
        plugins=[SSOPlugin()],
        trusted_origins=[IDP],
        http_client=idp_http(jwks, sign(id_token_claims())),
    )
    async with make_client(auth) as client:
        await seed_provider(auth)
        state = await seed_state(auth)
        # send NO state cookie -> mismatch
        res = await client.get(
            f"/api/auth/sso/callback/corp?state={state}&code=x", follow_redirects=False
        )
    assert res.status_code in (302, 307)
    assert "error=state_mismatch" in res.headers["location"]
