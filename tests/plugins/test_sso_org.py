"""Tests for organization auto-assignment (linking/org-assignment.ts).

Two seams:
- assign_organization_from_provider: inline in the OIDC callback when the provider carries
  an organizationId.
- assign_organization_by_domain: the after-hook on /callback/* for non-SSO social logins
  whose email domain maps to an org-linked SSO provider.
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx

from better_auth import BetterAuth, GitHub, Where
from better_auth.crypto import generate_id, sign_value
from better_auth.oauth.flow import STATE_COOKIE
from better_auth.plugins_ext.organization import OrganizationPlugin
from better_auth.plugins_ext.sso import SSOPlugin
from better_auth.session import cookie_name, utcnow
from conftest import make_auth, make_client

IDP = "https://idp.example.com"


# --- SSO callback (userinfo path) for the from-provider seam -------------------------


def sso_http(userinfo: dict[str, Any]) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/token"):
            return httpx.Response(200, json={"access_token": "at-1", "token_type": "bearer"})
        if request.url.path.endswith("/userinfo"):
            return httpx.Response(200, json=userinfo)
        return httpx.Response(404, json={})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def sso_config() -> dict[str, Any]:
    return {
        "issuer": IDP,
        "clientId": "client-1",
        "clientSecret": "secret",
        "authorizationEndpoint": f"{IDP}/authorize",
        "tokenEndpoint": f"{IDP}/token",
        "jwksEndpoint": f"{IDP}/jwks",
        "userInfoEndpoint": f"{IDP}/userinfo",
        "tokenEndpointAuthentication": "client_secret_basic",
        "pkce": False,
        "scopes": ["openid", "email"],
        "mapping": {"id": "sub", "email": "email", "name": "name"},
    }


async def seed_org_provider(
    auth: BetterAuth, *, organization_id: str, domain: str = "corp.example"
) -> None:
    await auth.adapter.create(
        "ssoProvider",
        {
            "providerId": "corp",
            "issuer": IDP,
            "domain": domain,
            "organizationId": organization_id,
            "userId": "seed",
            "oidcConfig": json.dumps(sso_config()),
            "samlConfig": None,
        },
    )


async def seed_state(auth: BetterAuth) -> str:
    state = generate_id()
    now = utcnow()
    payload = {
        "callbackURL": "/dash",
        "codeVerifier": "cv-1",
        "errorURL": None,
        "newUserURL": None,
        "expiresAt": int(now.timestamp() * 1000) + 600_000,
    }
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


def state_cookie(auth: BetterAuth, state: str) -> dict[str, str]:
    return {"cookie": f"{cookie_name(auth, STATE_COOKIE)}={sign_value(auth.secret, state)}"}


async def sso_callback(client: httpx.AsyncClient, auth: BetterAuth, state: str) -> httpx.Response:
    return await client.get(
        f"/api/auth/sso/callback/corp?state={state}&code=c",
        headers=state_cookie(auth, state),
        follow_redirects=False,
    )


async def members(auth: BetterAuth, org_id: str) -> list[dict[str, Any]]:
    return await auth.adapter.find_many("member", [Where("organizationId", org_id)])


# --- from-provider (inline in callback) ----------------------------------------------


async def test_from_provider_assigns_membership() -> None:
    userinfo = {"sub": "u-1", "email": "worker@corp.example", "name": "Worker"}
    auth = make_auth(
        plugins=[SSOPlugin(), OrganizationPlugin()],
        trusted_origins=[IDP],
        http_client=sso_http(userinfo),
    )
    async with make_client(auth) as client:
        await auth.adapter.create("organization", {"id": "org-1", "slug": "acme", "name": "Acme"})
        await seed_org_provider(auth, organization_id="org-1")
        state = await seed_state(auth)
        res = await sso_callback(client, auth, state)
    assert res.status_code in (302, 307), res.text
    rows = await members(auth, "org-1")
    assert len(rows) == 1
    assert rows[0]["role"] == "member"


async def test_from_provider_get_role_resolution() -> None:
    userinfo = {"sub": "u-1", "email": "worker@corp.example", "name": "Worker"}

    async def get_role(data: dict[str, Any]) -> str:
        assert data["userInfo"]["email"] == "worker@corp.example"
        return "admin"

    auth = make_auth(
        plugins=[
            SSOPlugin(organization_provisioning={"getRole": get_role}),
            OrganizationPlugin(),
        ],
        trusted_origins=[IDP],
        http_client=sso_http(userinfo),
    )
    async with make_client(auth) as client:
        await auth.adapter.create("organization", {"id": "org-1", "slug": "acme", "name": "Acme"})
        await seed_org_provider(auth, organization_id="org-1")
        state = await seed_state(auth)
        await sso_callback(client, auth, state)
    rows = await members(auth, "org-1")
    assert len(rows) == 1 and rows[0]["role"] == "admin"


async def test_from_provider_default_role() -> None:
    userinfo = {"sub": "u-1", "email": "worker@corp.example", "name": "Worker"}
    auth = make_auth(
        plugins=[
            SSOPlugin(organization_provisioning={"defaultRole": "admin"}),
            OrganizationPlugin(),
        ],
        trusted_origins=[IDP],
        http_client=sso_http(userinfo),
    )
    async with make_client(auth) as client:
        await auth.adapter.create("organization", {"id": "org-1", "slug": "acme", "name": "Acme"})
        await seed_org_provider(auth, organization_id="org-1")
        state = await seed_state(auth)
        await sso_callback(client, auth, state)
    rows = await members(auth, "org-1")
    assert rows[0]["role"] == "admin"


async def test_from_provider_skipped_without_org_plugin() -> None:
    # org plugin absent -> no membership attempted, sign-in still succeeds
    userinfo = {"sub": "u-1", "email": "worker@corp.example", "name": "Worker"}
    auth = make_auth(plugins=[SSOPlugin()], trusted_origins=[IDP], http_client=sso_http(userinfo))
    async with make_client(auth) as client:
        await seed_org_provider(auth, organization_id="org-1")
        state = await seed_state(auth)
        res = await sso_callback(client, auth, state)
    assert res.status_code in (302, 307)
    user = await auth.adapter.find_one("user", [Where("email", "worker@corp.example")])
    assert user is not None


async def test_from_provider_no_duplicate_membership() -> None:
    userinfo = {"sub": "u-1", "email": "worker@corp.example", "name": "Worker"}
    auth = make_auth(
        plugins=[SSOPlugin(), OrganizationPlugin()],
        trusted_origins=[IDP],
        http_client=sso_http(userinfo),
    )
    async with make_client(auth) as client:
        await auth.adapter.create("organization", {"id": "org-1", "slug": "acme", "name": "Acme"})
        await seed_org_provider(auth, organization_id="org-1")
        await sso_callback(client, auth, await seed_state(auth))
        client.cookies.clear()
        await sso_callback(client, auth, await seed_state(auth))  # second login
    rows = await members(auth, "org-1")
    assert len(rows) == 1


# --- by-domain (after-hook on /callback/*) -------------------------------------------


def github_http(email: str = "octo@corp.example") -> httpx.AsyncClient:
    profile = {"id": 4242, "login": "octo", "name": "Octo", "avatar_url": "http://img/x.png"}
    emails = [{"email": email, "primary": True, "verified": True}]

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/login/oauth/access_token":
            return httpx.Response(200, json={"access_token": "gh"})
        if request.url.path == "/user":
            return httpx.Response(200, json=profile)
        if request.url.path == "/user/emails":
            return httpx.Response(200, json=emails)
        return httpx.Response(404)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


async def social_sign_in(client: httpx.AsyncClient) -> httpx.Response:
    res = await client.post(
        "/api/auth/sign-in/social", json={"provider": "github", "callbackURL": "/dash"}
    )
    state = parse_qs(urlsplit(res.json()["url"]).query)["state"][0]
    return await client.get(f"/api/auth/callback/github?code=abc&state={state}")


def github_auth(**plugin_kwargs: Any) -> BetterAuth:
    return make_auth(
        social_providers={"github": GitHub(client_id="cid", client_secret="cs")},
        plugins=[SSOPlugin(**plugin_kwargs), OrganizationPlugin()],
        http_client=github_http(),
    )


async def test_by_domain_assigns_social_login_to_org() -> None:
    auth = github_auth()
    async with make_client(auth) as client:
        await auth.adapter.create("organization", {"id": "org-1", "slug": "acme", "name": "Acme"})
        await seed_org_provider(auth, organization_id="org-1")
        res = await social_sign_in(client)
    assert res.status_code == 302
    rows = await members(auth, "org-1")
    assert len(rows) == 1


async def test_by_domain_no_match_no_membership() -> None:
    auth = github_auth()
    async with make_client(auth) as client:
        await auth.adapter.create("organization", {"id": "org-1", "slug": "acme", "name": "Acme"})
        await seed_org_provider(auth, organization_id="org-1", domain="other.com")
        await social_sign_in(client)
    assert await members(auth, "org-1") == []


async def test_by_domain_gated_on_verified_when_enabled() -> None:
    # domainVerification enabled + provider not verified -> no by-domain assignment
    auth = make_auth(
        social_providers={"github": GitHub(client_id="cid", client_secret="cs")},
        plugins=[SSOPlugin(domain_verification={"enabled": True}), OrganizationPlugin()],
        http_client=github_http(),
    )
    async with make_client(auth) as client:
        await auth.adapter.create("organization", {"id": "org-1", "slug": "acme", "name": "Acme"})
        await auth.adapter.create(
            "ssoProvider",
            {
                "providerId": "corp",
                "issuer": IDP,
                "domain": "corp.example",
                "organizationId": "org-1",
                "userId": "seed",
                "oidcConfig": json.dumps(sso_config()),
                "samlConfig": None,
                "domainVerified": False,
            },
        )
        await social_sign_in(client)
    assert await members(auth, "org-1") == []


async def test_by_domain_no_duplicate_on_second_login() -> None:
    auth = github_auth()
    async with make_client(auth) as client:
        await auth.adapter.create("organization", {"id": "org-1", "slug": "acme", "name": "Acme"})
        await seed_org_provider(auth, organization_id="org-1")
        await social_sign_in(client)
        client.cookies.clear()
        await social_sign_in(client)
    rows = await members(auth, "org-1")
    assert len(rows) == 1
