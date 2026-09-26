"""Tests for the sso plugin: provider register + CRUD + sanitize + access control.

TS source verified against:
  packages/sso/src/routes/sso.ts  (registerSSOProvider, buildOIDCConfig)
  packages/sso/src/routes/providers.ts  (list/get/update/delete, sanitizeProvider, hasOrgAdminRole)
  packages/sso/src/index.ts  (ssoProvider schema)
"""

from __future__ import annotations

from typing import Any

import httpx

from better_auth import BetterAuth, Where
from better_auth.plugins_ext.organization import OrganizationPlugin
from better_auth.plugins_ext.sso import SSOPlugin, has_plugin
from conftest import make_auth, make_client, sign_up

IDP = "https://idp.example.com"


def oidc_body(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "providerId": "test",
        "issuer": IDP,
        "domain": "example.com",
        "oidcConfig": {
            "clientId": "client-123456",
            "clientSecret": "s3cr3t",
            "authorizationEndpoint": f"{IDP}/authorize",
            "tokenEndpoint": f"{IDP}/token",
            "jwksEndpoint": f"{IDP}/jwks",
            "skipDiscovery": True,
            "scopes": ["openid", "email"],
            "mapping": {"id": "sub", "email": "email", "name": "name"},
        },
    }
    body.update(overrides)
    return body


def discovery_http() -> httpx.AsyncClient:
    doc = {
        "issuer": IDP,
        "authorization_endpoint": f"{IDP}/authorize",
        "token_endpoint": f"{IDP}/token",
        "jwks_uri": f"{IDP}/jwks",
        "userinfo_endpoint": f"{IDP}/userinfo",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json=doc)
        return httpx.Response(404, json={})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def user_id(auth: BetterAuth, email: str = "ada@example.com") -> str:
    row = await auth.adapter.find_one("user", [Where("email", email)])
    assert row is not None
    return row["id"]


async def register(client: httpx.AsyncClient, **overrides: Any) -> httpx.Response:
    return await client.post("/api/auth/sso/register", json=oidc_body(**overrides))


# --- has_plugin ----------------------------------------------------------------------


def test_has_plugin() -> None:
    auth = make_auth(plugins=[SSOPlugin()])
    assert has_plugin(auth, "sso") is True
    assert has_plugin(auth, "organization") is False


# --- register: skipDiscovery ---------------------------------------------------------


async def test_register_requires_session() -> None:
    auth = make_auth(plugins=[SSOPlugin()])
    async with make_client(auth) as client:
        res = await register(client)
    assert res.status_code == 401


async def test_register_skip_discovery_success() -> None:
    auth = make_auth(plugins=[SSOPlugin()])
    async with make_client(auth) as client:
        await sign_up(client)
        res = await register(client)
    assert res.status_code == 200, res.text
    body = res.json()
    assert body["providerId"] == "test"
    assert body["issuer"] == IDP
    assert body["domain"] == "example.com"
    # register echoes the full config (incl. secret) back to the registrant (TS parity)
    assert body["oidcConfig"]["clientId"] == "client-123456"
    assert body["oidcConfig"]["clientSecret"] == "s3cr3t"
    assert body["redirectURI"] == "http://testserver/api/auth/sso/callback/test"


async def test_register_stores_exact_oidc_config_blob() -> None:
    auth = make_auth(plugins=[SSOPlugin()])
    async with make_client(auth) as client:
        await sign_up(client)
        await register(client)
    row = await auth.adapter.find_one("ssoProvider", [Where("providerId", "test")])
    assert row is not None
    expected = (
        '{"issuer":"https://idp.example.com","clientId":"client-123456",'
        '"clientSecret":"s3cr3t","authorizationEndpoint":"https://idp.example.com/authorize",'
        '"tokenEndpoint":"https://idp.example.com/token",'
        '"tokenEndpointAuthentication":"client_secret_basic",'
        '"jwksEndpoint":"https://idp.example.com/jwks","pkce":true,'
        '"discoveryEndpoint":"https://idp.example.com/.well-known/openid-configuration",'
        '"mapping":{"id":"sub","email":"email","name":"name"},'
        '"scopes":["openid","email"],"overrideUserInfo":false}'
    )
    assert row["oidcConfig"] == expected
    # clientSecret persisted in PLAINTEXT (cross-runtime DB-compat contract)
    assert '"clientSecret":"s3cr3t"' in row["oidcConfig"]


async def test_register_invalid_issuer_rejected() -> None:
    auth = make_auth(plugins=[SSOPlugin()])
    async with make_client(auth) as client:
        await sign_up(client)
        res = await register(client, issuer="not-a-url")
    assert res.status_code == 400
    assert res.json()["message"] == "Invalid issuer. Must be a valid URL"


async def test_register_reserved_provider_id_rejected() -> None:
    auth = make_auth(plugins=[SSOPlugin()])
    async with make_client(auth) as client:
        await sign_up(client)
        res = await register(client, providerId="credential")
    assert res.status_code == 422


async def test_register_duplicate_provider_id_rejected() -> None:
    auth = make_auth(plugins=[SSOPlugin()])
    async with make_client(auth) as client:
        await sign_up(client)
        assert (await register(client)).status_code == 200
        res = await register(client)
    assert res.status_code == 422


# --- register: providersLimit --------------------------------------------------------


async def test_register_limit_zero_disabled() -> None:
    auth = make_auth(plugins=[SSOPlugin(providers_limit=0)])
    async with make_client(auth) as client:
        await sign_up(client)
        res = await register(client)
    assert res.status_code == 403
    assert res.json()["message"] == "SSO provider registration is disabled"


async def test_register_limit_reached() -> None:
    auth = make_auth(plugins=[SSOPlugin(providers_limit=1)])
    async with make_client(auth) as client:
        await sign_up(client)
        assert (await register(client)).status_code == 200
        res = await register(client, providerId="second")
    assert res.status_code == 403
    assert res.json()["message"] == "You have reached the maximum number of SSO providers"


# --- register: discovery-hydrated path -----------------------------------------------


async def test_register_hydrated_via_discovery() -> None:
    auth = make_auth(
        plugins=[SSOPlugin()],
        trusted_origins=[IDP],
        http_client=discovery_http(),
    )
    async with make_client(auth) as client:
        await sign_up(client)
        res = await client.post(
            "/api/auth/sso/register",
            json={
                "providerId": "test",
                "issuer": IDP,
                "domain": "example.com",
                "oidcConfig": {"clientId": "c-1234", "clientSecret": "sec"},
            },
        )
    assert res.status_code == 200, res.text
    row = await auth.adapter.find_one("ssoProvider", [Where("providerId", "test")])
    assert row is not None
    expected = (
        '{"issuer":"https://idp.example.com","clientId":"c-1234","clientSecret":"sec",'
        '"authorizationEndpoint":"https://idp.example.com/authorize",'
        '"tokenEndpoint":"https://idp.example.com/token",'
        '"tokenEndpointAuthentication":"client_secret_basic",'
        '"jwksEndpoint":"https://idp.example.com/jwks","pkce":true,'
        '"discoveryEndpoint":"https://idp.example.com/.well-known/openid-configuration",'
        '"userInfoEndpoint":"https://idp.example.com/userinfo","overrideUserInfo":false}'
    )
    assert row["oidcConfig"] == expected


async def test_register_discovery_untrusted_origin_rejected() -> None:
    # public issuer but not in trustedOrigins -> discovery URL untrusted (TS parity)
    auth = make_auth(plugins=[SSOPlugin()], http_client=discovery_http())
    async with make_client(auth) as client:
        await sign_up(client)
        res = await client.post(
            "/api/auth/sso/register",
            json={
                "providerId": "test",
                "issuer": IDP,
                "domain": "example.com",
                "oidcConfig": {"clientId": "c-1234", "clientSecret": "sec"},
            },
        )
    assert res.status_code == 400
    assert res.json()["code"] == "discovery_untrusted_origin"


async def test_register_private_endpoint_rejected() -> None:
    auth = make_auth(plugins=[SSOPlugin()])
    async with make_client(auth) as client:
        await sign_up(client)
        res = await register(
            client,
            oidcConfig={
                "clientId": "c",
                "clientSecret": "s",
                "tokenEndpoint": "http://127.0.0.1/token",
                "skipDiscovery": True,
            },
        )
    assert res.status_code == 400
    assert res.json()["code"] == "discovery_private_host"


# --- get / list: sanitize ------------------------------------------------------------


async def test_get_provider_sanitized() -> None:
    auth = make_auth(plugins=[SSOPlugin()])
    async with make_client(auth) as client:
        await sign_up(client)
        await register(client)
        res = await client.get("/api/auth/sso/get-provider?providerId=test")
    assert res.status_code == 200
    body = res.json()
    assert body["type"] == "oidc"
    assert body["providerId"] == "test"
    cfg = body["oidcConfig"]
    assert cfg["clientIdLastFour"] == "****3456"
    assert "clientId" not in cfg
    assert "clientSecret" not in cfg
    # never leak the secret anywhere in the response
    assert "s3cr3t" not in res.text


async def test_get_provider_not_found() -> None:
    auth = make_auth(plugins=[SSOPlugin()])
    async with make_client(auth) as client:
        await sign_up(client)
        res = await client.get("/api/auth/sso/get-provider?providerId=nope")
    assert res.status_code == 404


async def test_get_provider_forbidden_for_non_owner() -> None:
    auth = make_auth(plugins=[SSOPlugin()])
    async with make_client(auth) as owner:
        await sign_up(owner)
        await register(owner)
    async with make_client(auth) as other:
        await sign_up(other, email="grace@example.com", name="Grace")
        res = await other.get("/api/auth/sso/get-provider?providerId=test")
    assert res.status_code == 403


async def test_list_providers_sanitized() -> None:
    auth = make_auth(plugins=[SSOPlugin()])
    async with make_client(auth) as client:
        await sign_up(client)
        await register(client)
        res = await client.get("/api/auth/sso/providers")
    assert res.status_code == 200
    providers = res.json()["providers"]
    assert len(providers) == 1
    assert providers[0]["oidcConfig"]["clientIdLastFour"] == "****3456"
    assert "s3cr3t" not in res.text


# --- update --------------------------------------------------------------------------


async def test_update_no_fields_rejected() -> None:
    auth = make_auth(plugins=[SSOPlugin()])
    async with make_client(auth) as client:
        await sign_up(client)
        await register(client)
        res = await client.post("/api/auth/sso/update-provider", json={"providerId": "test"})
    assert res.status_code == 400
    assert res.json()["message"] == "No fields provided for update"


async def test_update_client_secret_rotation_allowed() -> None:
    auth = make_auth(plugins=[SSOPlugin()])
    async with make_client(auth) as client:
        await sign_up(client)
        await register(client)
        res = await client.post(
            "/api/auth/sso/update-provider",
            json={"providerId": "test", "oidcConfig": {"clientSecret": "rotated"}},
        )
    assert res.status_code == 200
    row = await auth.adapter.find_one("ssoProvider", [Where("providerId", "test")])
    assert row is not None
    assert '"clientSecret":"rotated"' in row["oidcConfig"]


async def test_update_identity_boundary_conflict_when_linked_account_exists() -> None:
    auth = make_auth(plugins=[SSOPlugin()])
    async with make_client(auth) as client:
        await sign_up(client)
        await register(client)
        uid = await user_id(auth)
        await auth.adapter.create(
            "account",
            {"accountId": "acc-1", "providerId": "test", "userId": uid},
        )
        res = await client.post(
            "/api/auth/sso/update-provider",
            json={"providerId": "test", "oidcConfig": {"clientId": "changed-id"}},
        )
    assert res.status_code == 409
    assert "identity fields" in res.json()["message"]


async def test_update_identity_boundary_allows_when_no_linked_account() -> None:
    auth = make_auth(plugins=[SSOPlugin()])
    async with make_client(auth) as client:
        await sign_up(client)
        await register(client)
        res = await client.post(
            "/api/auth/sso/update-provider",
            json={"providerId": "test", "oidcConfig": {"clientId": "changed-id"}},
        )
    assert res.status_code == 200


async def test_update_domain_change_resets_domain_verified() -> None:
    auth = make_auth(plugins=[SSOPlugin(domain_verification={"enabled": True})])
    async with make_client(auth) as client:
        await sign_up(client)
        await register(client)
        await auth.adapter.update(
            "ssoProvider", [Where("providerId", "test")], {"domainVerified": True}
        )
        res = await client.post(
            "/api/auth/sso/update-provider",
            json={"providerId": "test", "domain": "changed.com"},
        )
    assert res.status_code == 200
    row = await auth.adapter.find_one("ssoProvider", [Where("providerId", "test")])
    assert row is not None
    assert row["domain"] == "changed.com"
    assert row["domainVerified"] is False


# --- delete --------------------------------------------------------------------------


async def test_delete_provider_and_linked_accounts() -> None:
    auth = make_auth(plugins=[SSOPlugin()])
    async with make_client(auth) as client:
        await sign_up(client)
        await register(client)
        uid = await user_id(auth)
        await auth.adapter.create(
            "account", {"accountId": "acc-1", "providerId": "test", "userId": uid}
        )
        res = await client.post("/api/auth/sso/delete-provider", json={"providerId": "test"})
    assert res.status_code == 200
    assert res.json() == {"success": True}
    assert await auth.adapter.find_one("ssoProvider", [Where("providerId", "test")]) is None
    assert await auth.adapter.find_one("account", [Where("providerId", "test")]) is None


# --- domain verification token seeding at register -----------------------------------


async def test_register_seeds_domain_verification_token() -> None:
    auth = make_auth(plugins=[SSOPlugin(domain_verification={"enabled": True})])
    async with make_client(auth) as client:
        await sign_up(client)
        res = await register(client)
    body = res.json()
    assert body["domainVerified"] is False
    assert isinstance(body["domainVerificationToken"], str)
    assert len(body["domainVerificationToken"]) == 24
    verification = await auth.adapter.find_one(
        "verification", [Where("identifier", "_better-auth-token-test")]
    )
    assert verification is not None
    assert verification["value"] == body["domainVerificationToken"]


# --- organization-scoped access control (hasOrgAdminRole) ----------------------------


async def make_member(auth: BetterAuth, uid: str, org_id: str, role: str) -> None:
    await auth.adapter.create("member", {"organizationId": org_id, "userId": uid, "role": role})


async def test_register_org_requires_membership() -> None:
    auth = make_auth(plugins=[SSOPlugin(), OrganizationPlugin()])
    async with make_client(auth) as client:
        await sign_up(client)
        res = await register(client, organizationId="org-1")
    assert res.status_code == 400
    assert res.json()["message"] == "You are not a member of the organization"


async def test_register_org_requires_admin_role() -> None:
    auth = make_auth(plugins=[SSOPlugin(), OrganizationPlugin()])
    async with make_client(auth) as client:
        await sign_up(client)
        uid = await user_id(auth)
        await make_member(auth, uid, "org-1", "member")
        res = await register(client, organizationId="org-1")
    assert res.status_code == 403


async def test_register_org_admin_allowed() -> None:
    auth = make_auth(plugins=[SSOPlugin(), OrganizationPlugin()])
    async with make_client(auth) as client:
        await sign_up(client)
        uid = await user_id(auth)
        await make_member(auth, uid, "org-1", "owner,admin")
        res = await register(client, organizationId="org-1")
    assert res.status_code == 200


async def test_org_provider_access_requires_admin() -> None:
    auth = make_auth(plugins=[SSOPlugin(), OrganizationPlugin()])
    async with make_client(auth) as client:
        await sign_up(client)
        uid = await user_id(auth)
        await make_member(auth, uid, "org-1", "admin")
        await register(client, organizationId="org-1")
    # a different admin of the same org can access; a non-admin member cannot
    async with make_client(auth) as other:
        await sign_up(other, email="grace@example.com", name="Grace")
        other_id = await user_id(auth, "grace@example.com")
        await make_member(auth, other_id, "org-1", "member")
        res = await other.get("/api/auth/sso/get-provider?providerId=test")
    assert res.status_code == 403


# --- better-auth v1.7.6: private_key_jwt, mutation guard, lock, additional fields -------


async def test_register_private_key_jwt_needs_a_key_source() -> None:
    # TS v1.7.6 sso.ts:684-700
    config = {**oidc_body()["oidcConfig"], "tokenEndpointAuthentication": "private_key_jwt"}
    del config["clientSecret"]
    auth = make_auth(plugins=[SSOPlugin()])
    async with make_client(auth) as client:
        await sign_up(client)
        res = await register(client, oidcConfig=config)
    assert res.status_code == 400
    assert res.json()["message"] == (
        "private_key_jwt authentication requires either a resolvePrivateKey callback or a "
        "privateKey in defaultSSO"
    )


async def test_register_private_key_jwt_stores_key_reference() -> None:
    config = {
        **oidc_body()["oidcConfig"],
        "tokenEndpointAuthentication": "private_key_jwt",
        "privateKeyId": "kid-1",
        "privateKeyAlgorithm": "ES256",
    }
    del config["clientSecret"]
    auth = make_auth(plugins=[SSOPlugin(resolve_private_key=lambda _p: {})])
    async with make_client(auth) as client:
        await sign_up(client)
        res = await register(client, oidcConfig=config)
    assert res.status_code == 200, res.text
    row = await auth.adapter.find_one("ssoProvider", [Where("providerId", "test")])
    assert row is not None
    assert '"privateKeyId":"kid-1","privateKeyAlgorithm":"ES256"' in row["oidcConfig"]
    assert "clientSecret" not in row["oidcConfig"]


async def test_register_client_secret_required_for_secret_methods() -> None:
    config = dict(oidc_body()["oidcConfig"])
    del config["clientSecret"]
    auth = make_auth(plugins=[SSOPlugin()])
    async with make_client(auth) as client:
        await sign_up(client)
        res = await register(client, oidcConfig=config)
    assert res.status_code == 400
    assert res.json()["message"] == (
        "clientSecret is required when using client_secret_basic or client_secret_post "
        "authentication"
    )


async def test_update_mapping_is_not_an_identity_boundary() -> None:
    # TS v1.7.6 providers.ts:79-86: mapping left the boundary with mapping.id
    auth = make_auth(plugins=[SSOPlugin()])
    async with make_client(auth) as client:
        await sign_up(client)
        await register(client)
        uid = await user_id(auth)
        await auth.adapter.create(
            "account", {"accountId": "acc-1", "providerId": "test", "userId": uid}
        )
        res = await client.post(
            "/api/auth/sso/update-provider",
            json={
                "providerId": "test",
                "oidcConfig": {"mapping": {"email": "mail", "name": "name"}},
            },
        )
    assert res.status_code == 200, res.text


async def test_guard_provider_mutation_sees_the_boundary_and_can_refuse() -> None:
    seen: list[dict[str, Any]] = []

    def guard(data: dict[str, Any], context: dict[str, Any]) -> None:
        seen.append(data)
        assert context["database"] is not None
        if data["action"] == "delete":
            raise RuntimeError("keep it")

    auth = make_auth(plugins=[SSOPlugin(guard_provider_mutation=guard)])
    async with make_client(auth) as client:
        await sign_up(client)
        await register(client)
        updated = await client.post(
            "/api/auth/sso/update-provider",
            json={"providerId": "test", "oidcConfig": {"clientId": "changed-id"}},
        )
        refused = await client.post("/api/auth/sso/delete-provider", json={"providerId": "test"})
    assert updated.status_code == 200
    assert seen[0]["action"] == "update"
    assert seen[0]["isAuthenticationBoundaryChange"] is True
    assert seen[0]["provider"]["providerId"] == "test"
    assert seen[0]["providerReference"]["source"]["type"] == "persisted"
    # TS v1.7.6 providers.ts:292-302
    assert refused.status_code == 409
    assert refused.json() == {
        "code": "SSO_PROVIDER_MUTATION_REJECTED",
        "message": "SSO provider mutation is not allowed",
    }
    assert await auth.adapter.find_one("ssoProvider", [Where("providerId", "test")]) is not None


async def test_account_link_lock_refuses_a_changed_provider() -> None:
    from better_auth.plugins_ext.sso.providers import lock_sso_provider_for_account_link
    from better_auth.types import APIError

    plugin = SSOPlugin()
    auth = make_auth(plugins=[plugin])
    async with make_client(auth) as client:
        await sign_up(client)
        await register(client)
    row = await auth.adapter.find_one("ssoProvider", [Where("providerId", "test")])
    assert row is not None
    import json

    snapshot = {**row, "oidcConfig": json.loads(row["oidcConfig"])}
    await lock_sso_provider_for_account_link(plugin, auth.adapter, snapshot)  # unchanged: ok
    stale = {**snapshot, "oidcConfig": {**snapshot["oidcConfig"], "tokenEndpoint": "https://x/t"}}
    for candidate in (stale, {**snapshot, "id": "gone"}):
        try:
            await lock_sso_provider_for_account_link(plugin, auth.adapter, candidate)
        except APIError as error:
            assert (error.status, error.code) == (409, "SSO_PROVIDER_CHANGED")
        else:
            raise AssertionError("expected SSO_PROVIDER_CHANGED")


async def test_additional_fields_round_trip() -> None:
    from better_auth.schema import Field

    plugin = SSOPlugin(
        schema={
            "ssoProvider": {
                "additionalFields": {
                    "tenant": Field("string"),
                    "secretNote": Field("string", returned=False),
                    "locked": Field("boolean", input=False),
                }
            }
        }
    )
    auth = make_auth(plugins=[plugin])
    async with make_client(auth) as client:
        await sign_up(client)
        created = await register(client, tenant="acme", secretNote="hidden")
        blocked = await register(client, providerId="other", locked=False)
        updated = await client.post(
            "/api/auth/sso/update-provider", json={"providerId": "test", "tenant": "globex"}
        )
        listed = await client.get("/api/auth/sso/providers")
    assert created.status_code == 200, created.text
    assert created.json()["tenant"] == "acme" and "secretNote" not in created.json()
    # TS v1.7.6 schemas.ts:44-55
    assert blocked.status_code == 400
    assert blocked.json()["message"] == "locked is not allowed to be set"
    assert updated.status_code == 200 and updated.json()["tenant"] == "globex"
    (provider,) = listed.json()["providers"]
    assert provider["tenant"] == "globex" and "secretNote" not in provider
    row = await auth.adapter.find_one("ssoProvider", [Where("providerId", "test")])
    assert row is not None and row["secretNote"] == "hidden"


def test_additional_field_collision_is_refused() -> None:
    import pytest

    from better_auth.schema import Field

    with pytest.raises(ValueError, match="conflicts with a built-in field"):
        SSOPlugin(schema={"ssoProvider": {"additionalFields": {"domain": Field("string")}}})
    with pytest.raises(ValueError, match="conflicts with a returned provider field"):
        SSOPlugin(schema={"ssoProvider": {"additionalFields": {"type": Field("string")}}})


async def test_update_and_delete_run_in_a_sqlalchemy_transaction() -> None:
    from sqlalchemy.ext.asyncio import create_async_engine
    from sqlalchemy.pool import StaticPool

    from better_auth.adapters.sqlalchemy import SQLAlchemyAdapter

    engine = create_async_engine("sqlite+aiosqlite://", poolclass=StaticPool)
    adapter = SQLAlchemyAdapter(engine)
    auth = make_auth(adapter=adapter, plugins=[SSOPlugin()])
    await adapter.create_tables()
    try:
        async with make_client(auth) as client:
            await sign_up(client)
            assert (await register(client)).status_code == 200
            updated = await client.post(
                "/api/auth/sso/update-provider", json={"providerId": "test", "domain": "b.com"}
            )
            deleted = await client.post(
                "/api/auth/sso/delete-provider", json={"providerId": "test"}
            )
        assert updated.status_code == 200 and updated.json()["domain"] == "b.com"
        assert deleted.json() == {"success": True}
        assert await auth.adapter.find_many("ssoProvider") == []
    finally:
        await engine.dispose()
