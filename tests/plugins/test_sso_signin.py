"""Tests for POST /sign-in/sso — provider resolution precedence + authorize URL.

TS source verified against packages/sso/src/routes/sso.ts (signInSSO, sso.ts:1002).
Resolution precedence: defaultSSO > providerId > organizationId (from slug) >
domain (exact) > domain (comma-scan).
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qs, urlsplit

from better_auth import BetterAuth, Where
from better_auth.plugins_ext.organization import OrganizationPlugin
from better_auth.plugins_ext.sso import SSOPlugin
from conftest import make_auth, make_client

IDP = "https://idp.example.com"


def oidc_config(client_id: str, issuer: str = IDP, **overrides: Any) -> dict[str, Any]:
    cfg = {
        "issuer": issuer,
        "clientId": client_id,
        "clientSecret": "secret",
        "authorizationEndpoint": f"{issuer}/authorize",
        "tokenEndpoint": f"{issuer}/token",
        "jwksEndpoint": f"{issuer}/jwks",
        "tokenEndpointAuthentication": "client_secret_basic",
        "pkce": True,
        "scopes": ["openid", "email"],
    }
    cfg.update(overrides)
    return cfg


async def seed_provider(
    auth: BetterAuth,
    *,
    provider_id: str,
    domain: str,
    client_id: str,
    organization_id: str | None = None,
    issuer: str = IDP,
) -> None:
    await auth.adapter.create(
        "ssoProvider",
        {
            "providerId": provider_id,
            "issuer": issuer,
            "domain": domain,
            "organizationId": organization_id,
            "userId": "seed",
            "oidcConfig": json.dumps(oidc_config(client_id, issuer)),
            "samlConfig": None,
        },
    )


async def signin(client: Any, **body: Any) -> Any:
    return await client.post("/api/auth/sign-in/sso", json=body)


def authorize_client_id(url: str) -> str:
    return parse_qs(urlsplit(url).query)["client_id"][0]


# --- guard ---------------------------------------------------------------------------


async def test_signin_requires_an_identifier() -> None:
    auth = make_auth(plugins=[SSOPlugin()])
    async with make_client(auth) as client:
        res = await signin(client, callbackURL="/dash")
    assert res.status_code == 400
    assert "providerId" in res.json()["message"]


async def test_signin_no_provider_found() -> None:
    auth = make_auth(plugins=[SSOPlugin()])
    async with make_client(auth) as client:
        res = await signin(client, callbackURL="/dash", domain="example.com")
    assert res.status_code == 404


# --- resolution precedence matrix ----------------------------------------------------


async def test_default_sso_beats_db_provider_id() -> None:
    auth = make_auth(
        plugins=[
            SSOPlugin(
                default_sso=[
                    {
                        "providerId": "acme",
                        "domain": "example.com",
                        "oidcConfig": oidc_config("default-client"),
                    }
                ]
            )
        ]
    )
    async with make_client(auth) as client:
        await seed_provider(auth, provider_id="acme", domain="example.com", client_id="db-client")
        res = await signin(client, callbackURL="/dash", providerId="acme")
    assert res.status_code == 200, res.text
    assert authorize_client_id(res.json()["url"]) == "default-client"


async def test_db_provider_id_beats_organization_id() -> None:
    auth = make_auth(plugins=[SSOPlugin(), OrganizationPlugin()])
    async with make_client(auth) as client:
        await seed_provider(
            auth, provider_id="by-org", domain="a.com", client_id="org-client",
            organization_id="org-1",
        )
        await seed_provider(auth, provider_id="by-id", domain="b.com", client_id="id-client")
        await auth.adapter.create("organization", {"id": "org-1", "slug": "acme", "name": "Acme"})
        # both providerId and organizationSlug given -> providerId wins
        res = await signin(
            client, callbackURL="/dash", providerId="by-id", organizationSlug="acme"
        )
    assert res.status_code == 200, res.text
    assert authorize_client_id(res.json()["url"]) == "id-client"


async def test_organization_slug_beats_domain() -> None:
    auth = make_auth(plugins=[SSOPlugin(), OrganizationPlugin()])
    async with make_client(auth) as client:
        await seed_provider(
            auth, provider_id="org-prov", domain="a.com", client_id="org-client",
            organization_id="org-1",
        )
        await seed_provider(
            auth, provider_id="dom-prov", domain="example.com", client_id="dom-client"
        )
        await auth.adapter.create("organization", {"id": "org-1", "slug": "acme", "name": "Acme"})
        res = await signin(
            client, callbackURL="/dash", organizationSlug="acme", domain="example.com"
        )
    assert res.status_code == 200, res.text
    assert authorize_client_id(res.json()["url"]) == "org-client"


async def test_domain_exact_beats_comma_scan() -> None:
    auth = make_auth(plugins=[SSOPlugin()])
    async with make_client(auth) as client:
        await seed_provider(
            auth, provider_id="exact", domain="example.com", client_id="exact-client"
        )
        await seed_provider(
            auth, provider_id="multi", domain="other.com,example.com", client_id="scan-client"
        )
        res = await signin(client, callbackURL="/dash", domain="example.com")
    assert res.status_code == 200, res.text
    assert authorize_client_id(res.json()["url"]) == "exact-client"


async def test_domain_comma_scan_last_resort() -> None:
    auth = make_auth(plugins=[SSOPlugin()])
    async with make_client(auth) as client:
        await seed_provider(
            auth, provider_id="multi", domain="other.com,example.com", client_id="scan-client"
        )
        res = await signin(client, callbackURL="/dash", domain="example.com")
    assert res.status_code == 200, res.text
    assert authorize_client_id(res.json()["url"]) == "scan-client"


async def test_domain_from_email() -> None:
    auth = make_auth(plugins=[SSOPlugin()])
    async with make_client(auth) as client:
        await seed_provider(auth, provider_id="p", domain="example.com", client_id="email-client")
        res = await signin(client, callbackURL="/dash", email="ada@example.com")
    assert res.status_code == 200, res.text
    assert authorize_client_id(res.json()["url"]) == "email-client"


# --- authorize URL shape -------------------------------------------------------------


async def test_authorize_url_has_pkce_scopes_login_hint() -> None:
    auth = make_auth(plugins=[SSOPlugin()])
    async with make_client(auth) as client:
        await seed_provider(auth, provider_id="p", domain="example.com", client_id="c")
        res = await signin(
            client, callbackURL="/dash", email="ada@example.com", loginHint="ada@example.com"
        )
    url = res.json()["url"]
    query = parse_qs(urlsplit(url).query)
    assert url.startswith(f"{IDP}/authorize?")
    assert query["code_challenge_method"] == ["S256"]
    assert query["scope"] == ["openid email"]
    assert query["login_hint"] == ["ada@example.com"]
    assert query["redirect_uri"] == ["http://testserver/api/auth/sso/callback/p"]
    assert res.json()["redirect"] is True


async def test_signin_domain_verification_gate_blocks_unverified() -> None:
    auth = make_auth(plugins=[SSOPlugin(domain_verification={"enabled": True})])
    async with make_client(auth) as client:
        await auth.adapter.create(
            "ssoProvider",
            {
                "providerId": "p",
                "issuer": IDP,
                "domain": "example.com",
                "userId": "seed",
                "oidcConfig": json.dumps(oidc_config("c")),
                "samlConfig": None,
                "domainVerified": False,
            },
        )
        res = await signin(client, callbackURL="/dash", domain="example.com")
    assert res.status_code == 401
    assert res.json()["message"] == "Provider domain has not been verified"


async def test_signin_shared_callback_state_carries_provider_id() -> None:
    auth = make_auth(plugins=[SSOPlugin(redirect_uri="/sso/callback")])
    async with make_client(auth) as client:
        await seed_provider(auth, provider_id="p", domain="example.com", client_id="c")
        res = await signin(client, callbackURL="/dash", domain="example.com")
    url = res.json()["url"]
    state = parse_qs(urlsplit(url).query)["state"][0]
    row = await auth.adapter.find_one("verification", [Where("identifier", state)])
    assert row is not None
    data = json.loads(row["value"])
    assert data["additionalData"]["ssoProviderId"] == "p"
    # shared redirect_uri is used for the callback target
    assert parse_qs(urlsplit(url).query)["redirect_uri"] == ["http://testserver/api/auth/sso/callback"]
