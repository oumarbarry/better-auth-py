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
    provider_id: str = "corp",
    **body: Any,
) -> str:
    """Start the flow through POST /sign-in/sso and return the state it minted."""
    payload: dict[str, Any] = {"providerId": provider_id, "callbackURL": callback_url, **body}
    if error_url:
        payload["errorCallbackURL"] = error_url
    async with make_client(auth) as client:
        res = await client.post("/api/auth/sign-in/sso", json=payload)
    assert res.status_code == 200, res.text
    return parse_qs(urlsplit(res.json()["url"]).query)["state"][0]


async def raw_state(auth: BetterAuth, **extra: Any) -> str:
    """Write a state value directly (no provider reference unless given)."""
    state = generate_id()
    now = utcnow()
    payload: dict[str, Any] = {
        "callbackURL": "/dash",
        "codeVerifier": "cv-1",
        "expiresAt": int(now.timestamp() * 1000) + 600_000,
        **extra,
    }
    await auth.internal.create_verification_value(
        {
            "identifier": state,
            "value": json.dumps(payload),
            "expiresAt": now + timedelta(seconds=600),
        }
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
    # TS v1.7.6 sso.ts:1552: the account id is always the `sub` claim (mapping.id is gone).
    cfg = oidc_config(
        userInfoEndpoint=f"{IDP}/userinfo",
        mapping={"email": "mail", "name": "full_name"},
    )
    userinfo = {
        "sub": "uid-9",
        "user_id": "not-used",
        "mail": "u9@corp.example",
        "full_name": "Nine",
    }
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
    # TS v1.7.6 sso.ts:1768: the resolution error string is sent as is
    assert query["error"] == ["account not linked"]
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
        state = await seed_state(auth)
        res = await callback(client, auth, provider_id=None, state=state)
    assert res.status_code in (302, 307), res.text
    assert res.headers["location"] == "http://testserver/dash"


async def test_shared_callback_missing_provider_id_rejected() -> None:
    auth = make_auth(plugins=[SSOPlugin(redirect_uri="/sso/callback")], trusted_origins=[IDP])
    async with make_client(auth) as client:
        state = await raw_state(auth)  # no provider reference
        res = await callback(client, auth, provider_id=None, state=state)
    assert res.status_code in (302, 307)
    query = parse_qs(urlsplit(res.headers["location"]).query)
    assert query["error"] == ["invalid_state"]
    assert query["error_description"] == ["missing_sso_provider_reference"]


async def test_shared_callback_forged_provider_id_not_found() -> None:
    auth = make_auth(plugins=[SSOPlugin(redirect_uri="/sso/callback")], trusted_origins=[IDP])
    async with make_client(auth) as client:
        forged = {
            "providerId": "ghost",
            "source": {"type": "configured"},
            "authenticationConfigurationFingerprint": "x",
        }
        state = await raw_state(auth, serverContext={"ssoProviderReference": forged})
        res = await callback(client, auth, provider_id=None, state=state)
    assert res.status_code in (302, 307)
    query = parse_qs(urlsplit(res.headers["location"]).query)
    assert query["error"] == ["invalid_provider"]


# --- error-redirect shapes -----------------------------------------------------------


async def test_callback_no_state_row_redirects_state_mismatch() -> None:
    # TS v1.7.6 sso.ts:1314 parseState -> state.ts:223-229
    auth = make_auth(plugins=[SSOPlugin()])
    async with make_client(auth) as client:
        res = await client.get(
            "/api/auth/sso/callback/corp?state=nope&code=x", follow_redirects=False
        )
    assert res.status_code in (302, 307)
    loc = res.headers["location"]
    assert "error=state_mismatch" in loc
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
    # TS v1.7.6 sso.ts:1275-1298 getOIDCErrorDescription falls back to the status text
    assert query["error"] == ["invalid_provider"]
    assert query["error_description"] == ["Bad Request"]


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


# --- better-auth v1.7.6: sign-in state, provider fence, resolveUser --------------------


def _query(res: httpx.Response) -> dict[str, list[str]]:
    assert res.status_code in (302, 307), res.text
    return parse_qs(urlsplit(res.headers["location"]).query)


async def _state_value(auth: BetterAuth, state: str) -> dict[str, Any]:
    row = await auth.internal.find_verification_value(state)
    assert row is not None
    return json.loads(row["value"])


async def test_sign_in_state_carries_the_provider_reference() -> None:
    # TS v1.7.6 sso.ts:1141-1144: the reference rides serverContext; requestSignUp is a
    # top-level state key.
    from better_auth.plugins_ext.sso.provider_reference import compute_sso_provider_reference

    auth = make_auth(plugins=[SSOPlugin()], trusted_origins=[IDP])
    await seed_provider(auth)
    state = await seed_state(auth, requestSignUp=True)
    value = await _state_value(auth, state)
    row = await auth.adapter.find_one("ssoProvider", [Where("providerId", "corp")])
    assert row is not None
    parsed = {**row, "oidcConfig": json.loads(row["oidcConfig"])}
    assert value["serverContext"] == {
        "ssoProviderReference": compute_sso_provider_reference(parsed)
    }
    assert value["requestSignUp"] is True
    assert "additionalData" not in value


async def test_sign_in_forwards_additional_params() -> None:
    auth = make_auth(plugins=[SSOPlugin()], trusted_origins=[IDP])
    await seed_provider(auth)
    async with make_client(auth) as client:
        ok = await client.post(
            "/api/auth/sign-in/sso",
            json={"providerId": "corp", "callbackURL": "/", "additionalParams": {"acr": "mfa"}},
        )
        reserved = await client.post(
            "/api/auth/sign-in/sso",
            json={"providerId": "corp", "callbackURL": "/", "additionalParams": {"state": "x"}},
        )
    assert parse_qs(urlsplit(ok.json()["url"]).query)["acr"] == ["mfa"]
    assert reserved.status_code == 400


async def test_provider_edited_after_sign_in_is_refused() -> None:
    jwks, sign = _rsa_jwks_and_signer()
    auth = make_auth(
        plugins=[SSOPlugin()],
        trusted_origins=[IDP],
        http_client=idp_http(jwks, sign(id_token_claims())),
    )
    await seed_provider(auth)
    state = await seed_state(auth)
    await auth.adapter.update(
        "ssoProvider",
        [Where("providerId", "corp")],
        {"oidcConfig": json.dumps(oidc_config(clientId="client-2"))},
    )
    async with make_client(auth) as client:
        query = _query(await callback(client, auth, state=state))
    assert query["error"] == ["invalid_state"]
    assert query["error_description"] == ["sso_provider_changed_during_authentication"]


async def test_provider_edited_during_the_exchange_is_refused_under_lock() -> None:
    # TS v1.7.6 sso.ts:1670-1690 + providers.ts:334-359: the row is locked inside the
    # account-link transaction and its identity boundary re-checked.
    jwks, sign = _rsa_jwks_and_signer()
    token = sign(id_token_claims())
    holder: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/token"):
            store = holder["auth"].adapter._store["ssoProvider"]
            store[0]["oidcConfig"] = json.dumps(oidc_config(tokenEndpoint=f"{IDP}/token2"))
            return httpx.Response(200, json={"access_token": "at", "id_token": token})
        return httpx.Response(200, json=jwks)

    auth = make_auth(
        plugins=[SSOPlugin()],
        trusted_origins=[IDP],
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    holder["auth"] = auth
    await seed_provider(auth)
    state = await seed_state(auth)
    async with make_client(auth) as client:
        query = _query(await callback(client, auth, state=state))
    assert query["error"] == ["SSO_PROVIDER_CHANGED"]
    assert query["error_description"] == [
        "SSO provider changed while account linking was in progress"
    ]
    assert await auth.adapter.find_one("user", [Where("email", "worker@corp.example")]) is None


async def test_userinfo_subject_must_match_the_id_token() -> None:
    jwks, sign = _rsa_jwks_and_signer()
    auth = make_auth(
        plugins=[SSOPlugin()],
        trusted_origins=[IDP],
        http_client=idp_http(
            jwks, sign(id_token_claims()), userinfo={"sub": "someone-else", "email": "x@y.z"}
        ),
    )
    await seed_provider(auth, config=oidc_config(userInfoEndpoint=f"{IDP}/userinfo"))
    state = await seed_state(auth)
    async with make_client(auth) as client:
        query = _query(await callback(client, auth, state=state))
    assert query["error_description"] == ["id_token_userinfo_subject_mismatch"]


async def test_id_token_without_subject_is_refused() -> None:
    jwks, sign = _rsa_jwks_and_signer()
    claims = id_token_claims()
    del claims["sub"]
    auth = make_auth(
        plugins=[SSOPlugin()], trusted_origins=[IDP], http_client=idp_http(jwks, sign(claims))
    )
    await seed_provider(auth)
    state = await seed_state(auth)
    async with make_client(auth) as client:
        query = _query(await callback(client, auth, state=state))
    assert query["error_description"] == ["id_token_subject_missing"]


async def test_validate_user_info_sees_the_sso_source() -> None:
    from better_auth.config import UserOptions

    calls: list[dict[str, Any]] = []

    async def validate(data: dict[str, Any], _ctx: Any) -> None:
        calls.append(data)

    jwks, sign = _rsa_jwks_and_signer()
    auth = make_auth(
        plugins=[SSOPlugin()],
        trusted_origins=[IDP],
        http_client=idp_http(jwks, sign(id_token_claims())),
        user=UserOptions(validate_user_info=validate),
    )
    await seed_provider(auth)
    state = await seed_state(auth)
    async with make_client(auth) as client:
        await callback(client, auth, state=state)
    source = calls[0]["source"]
    assert source["method"] == "sso-oidc"
    assert source["sso"]["providerId"] == "corp"
    assert source["sso"]["profile"]["sub"] == "sso-sub-1"


async def test_resolve_user_links_the_selected_user() -> None:
    inputs: list[dict[str, Any]] = []

    async def resolve(data: dict[str, Any], context: dict[str, Any]) -> dict[str, Any]:
        inputs.append(data)
        user = await context["database"].find_one("user", [Where("email", "boss@corp.example")])
        return {"action": "link", "userId": user["id"], "profile": "preserve"}

    jwks, sign = _rsa_jwks_and_signer()
    auth = make_auth(
        plugins=[SSOPlugin(resolve_user=resolve)],
        trusted_origins=[IDP],
        http_client=idp_http(jwks, sign(id_token_claims())),
    )
    target = await _seed_local_user(auth, email="boss@corp.example", email_verified=False)
    await seed_provider(auth)
    state = await seed_state(auth)
    async with make_client(auth) as client:
        res = await callback(client, auth, state=state)
    assert res.headers["location"] == "http://testserver/dash"
    account = await auth.adapter.find_one("account", [Where("providerId", "corp")])
    assert account is not None and account["userId"] == target
    (data,) = inputs
    assert data["protocol"] == "oidc"
    assert data["accountKey"] == {"issuer": IDP, "accountId": "sso-sub-1"}
    assert data["providerUser"]["email"] == "worker@corp.example"
    assert data["verifiedIdTokenClaims"]["sub"] == "sso-sub-1"
    assert data["providerReference"]["providerId"] == "corp"


async def test_resolve_user_reject_redirects_with_its_code() -> None:
    def resolve(_data: dict[str, Any], _context: dict[str, Any]) -> dict[str, Any]:
        return {"action": "reject", "code": "tenant_closed", "message": "Closed"}

    jwks, sign = _rsa_jwks_and_signer()
    auth = make_auth(
        plugins=[SSOPlugin(resolve_user=resolve)],
        trusted_origins=[IDP],
        http_client=idp_http(jwks, sign(id_token_claims())),
    )
    await seed_provider(auth)
    state = await seed_state(auth)
    async with make_client(auth) as client:
        query = _query(await callback(client, auth, state=state))
    assert query == {"error": ["tenant_closed"], "error_description": ["Closed"]}
    assert await auth.adapter.find_one("user", [Where("email", "worker@corp.example")]) is None


async def test_resolve_user_invalid_decision_fails_closed() -> None:
    def resolve(_data: dict[str, Any], _context: dict[str, Any]) -> dict[str, Any]:
        return {"action": "link"}

    jwks, sign = _rsa_jwks_and_signer()
    auth = make_auth(
        plugins=[SSOPlugin(resolve_user=resolve)],
        trusted_origins=[IDP],
        http_client=idp_http(jwks, sign(id_token_claims())),
    )
    await seed_provider(auth)
    state = await seed_state(auth)
    async with make_client(auth) as client:
        query = _query(await callback(client, auth, state=state))
    assert query == {
        "error": ["SSO_USER_RESOLUTION_FAILED"],
        "error_description": ["Unable to resolve the SSO user"],
    }


async def test_resolve_user_requires_a_verified_id_token() -> None:
    jwks, _sign = _rsa_jwks_and_signer()
    auth = make_auth(
        plugins=[SSOPlugin(resolve_user=lambda _d, _c: {"action": "continue"})],
        trusted_origins=[IDP],
        http_client=idp_http(jwks, userinfo={"sub": "u", "email": "u@corp.example"}),
    )
    await seed_provider(auth, config=oidc_config(userInfoEndpoint=f"{IDP}/userinfo"))
    state = await seed_state(auth)
    async with make_client(auth) as client:
        query = _query(await callback(client, auth, state=state))
    assert query["error_description"] == ["id_token_required_for_user_resolution"]


async def test_resolve_user_refuses_secondary_storage_sessions() -> None:
    from better_auth.secondary_storage import MemorySecondaryStorage

    jwks, sign = _rsa_jwks_and_signer()
    auth = make_auth(
        plugins=[SSOPlugin(resolve_user=lambda _d, _c: {"action": "continue"})],
        trusted_origins=[IDP],
        http_client=idp_http(jwks, sign(id_token_claims())),
        secondary_storage=MemorySecondaryStorage(),
    )
    await seed_provider(auth)
    state = await seed_state(auth)
    async with make_client(auth) as client:
        query = _query(await callback(client, auth, state=state))
    assert query["error"] == ["SSO_USER_RESOLUTION_REQUIRES_DATABASE_SESSIONS"]


async def test_private_key_jwt_token_exchange() -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    from cryptography.hazmat.primitives import serialization

    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    jwks, sign = _rsa_jwks_and_signer()
    token = sign(id_token_claims())
    seen: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/token"):
            seen["body"] = parse_qs(request.content.decode())
            seen["auth"] = request.headers.get("authorization")
            return httpx.Response(200, json={"access_token": "at", "id_token": token})
        return httpx.Response(200, json=jwks)

    async def resolve_key(params: dict[str, Any]) -> dict[str, Any]:
        seen["params"] = params
        return {"privateKeyPem": pem, "kid": "k1"}

    auth = make_auth(
        plugins=[SSOPlugin(resolve_private_key=resolve_key)],
        trusted_origins=[IDP],
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    await seed_provider(
        auth, config=oidc_config(tokenEndpointAuthentication="private_key_jwt", privateKeyId="k1")
    )
    state = await seed_state(auth)
    async with make_client(auth) as client:
        res = await callback(client, auth, state=state)
    assert res.headers["location"] == "http://testserver/dash"
    assert seen["params"] == {"providerId": "corp", "keyId": "k1", "issuer": IDP}
    assert seen["auth"] is None and "client_secret" not in seen["body"]
    assert seen["body"]["client_assertion_type"] == [
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
    ]
    assertion = jwt.decode(seen["body"]["client_assertion"][0], options={"verify_signature": False})
    assert assertion["iss"] == "client-1" and assertion["aud"] == f"{IDP}/token"


async def test_private_key_jwt_without_a_key_source() -> None:
    jwks, sign = _rsa_jwks_and_signer()
    auth = make_auth(
        plugins=[SSOPlugin()],
        trusted_origins=[IDP],
        http_client=idp_http(jwks, sign(id_token_claims())),
    )
    await seed_provider(auth, config=oidc_config(tokenEndpointAuthentication="private_key_jwt"))
    state = await seed_state(auth)
    async with make_client(auth) as client:
        query = _query(await callback(client, auth, state=state))
    assert query["error_description"] == ["no_private_key_available"]


async def test_idp_initiated_callback_restarts_the_flow() -> None:
    # TS v1.7.6 sso.ts:1903-1972 (03e6c94e9)
    auth = make_auth(plugins=[SSOPlugin()], trusted_origins=[IDP])
    await seed_provider(auth, config=oidc_config(allowIdpInitiated=True))
    async with make_client(auth) as client:
        res = await client.get("/api/auth/sso/callback/corp?code=x", follow_redirects=False)
    assert res.status_code in (302, 307)
    target = urlsplit(res.headers["location"])
    assert f"{target.scheme}://{target.netloc}{target.path}" == f"{IDP}/authorize"
    state = parse_qs(target.query)["state"][0]
    value = await _state_value(auth, state)
    assert value["serverContext"]["ssoProviderReference"]["providerId"] == "corp"


async def test_callback_without_state_or_opt_in_is_state_not_found() -> None:
    auth = make_auth(plugins=[SSOPlugin()], trusted_origins=[IDP])
    await seed_provider(auth)
    async with make_client(auth) as client:
        res = await client.get("/api/auth/sso/callback/corp?code=x", follow_redirects=False)
    assert res.headers["location"] == "http://testserver/api/auth/error?error=state_not_found"


async def test_legacy_mapping_id_keeps_pre_17_account_ids() -> None:
    jwks, _sign = _rsa_jwks_and_signer()
    userinfo = {"sub": "s-1", "user_id": "legacy-7", "email": "l@corp.example"}
    auth = make_auth(
        plugins=[SSOPlugin(legacy_mapping_id=True)],
        trusted_origins=[IDP],
        http_client=idp_http(jwks, userinfo=userinfo),
    )
    cfg = oidc_config(
        userInfoEndpoint=f"{IDP}/userinfo",
        mapping={"id": "user_id", "email": "email", "name": "name"},
    )
    await seed_provider(auth, config=cfg)
    state = await seed_state(auth)
    async with make_client(auth) as client:
        await callback(client, auth, state=state)
    account = await auth.adapter.find_one("account", [Where("providerId", "corp")])
    assert account is not None and account["accountId"] == "legacy-7"


async def test_resolve_user_rolls_back_on_sqlalchemy() -> None:
    # TS v1.7.6 sso.ts:1668-1778: resolution, account binding and session share one
    # transaction; a hook that moves the binding undoes the whole sign-up.
    from sqlalchemy.ext.asyncio import create_async_engine
    from sqlalchemy.pool import StaticPool

    from better_auth.adapters.sqlalchemy import SQLAlchemyAdapter

    async def rebind(_data: dict[str, Any], _ctx: Any) -> dict[str, Any]:
        return {"data": {"accountId": "moved"}}

    engine = create_async_engine("sqlite+aiosqlite://", poolclass=StaticPool)
    adapter = SQLAlchemyAdapter(engine)
    jwks, sign = _rsa_jwks_and_signer()
    auth = make_auth(
        adapter=adapter,
        plugins=[SSOPlugin(resolve_user=lambda _d, _c: {"action": "continue"})],
        trusted_origins=[IDP],
        http_client=idp_http(jwks, sign(id_token_claims())),
        database_hooks={"account": {"create": {"before": rebind}}},
    )
    await adapter.create_tables()
    try:
        await seed_provider(auth)
        state = await seed_state(auth)
        async with make_client(auth) as client:
            query = _query(await callback(client, auth, state=state))
        assert query["error"] == ["account_hook_binding_conflict"]
        assert await auth.adapter.find_many("user") == []
        assert await auth.adapter.find_many("account") == []
        assert await auth.adapter.find_many("session") == []
    finally:
        await engine.dispose()
