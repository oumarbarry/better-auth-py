"""Tests for organization auto-assignment (linking/org-assignment.ts).

Two seams:
- assign_organization_from_provider: inline in the OIDC callback when the provider carries
  an organizationId — explicit org-bound provisioning, independent of domain trust.
- assign_organization_by_domain: the after-hook on /callback/* for non-SSO social logins.
  Since 999acbd41 (GHSA-phx7-w8x2-3xgf) this requires domain verification to be enabled, a
  *domain-verified* provider, a verified canonical user email, and exactly one candidate
  organization.
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from better_auth import BetterAuth, GitHub, Where
from better_auth.crypto import generate_id, sign_value
from better_auth.oauth.flow import STATE_COOKIE
from better_auth.plugins_ext.organization import OrganizationPlugin
from better_auth.plugins_ext.sso import SSOPlugin
from better_auth.plugins_ext.sso.org_assignment import (
    assign_organization_by_domain,
    assign_organization_from_provider,
)
from better_auth.session import cookie_name, utcnow
from better_auth.types import AuthRequest, Ctx
from conftest import SIGNUP, make_auth, make_client, sign_up

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
    auth: BetterAuth,
    *,
    organization_id: str | None,
    domain: str = "corp.example",
    provider_id: str = "corp",
    domain_verified: bool | None = None,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "providerId": provider_id,
        "issuer": IDP,
        "domain": domain,
        "organizationId": organization_id,
        "userId": "seed",
        "oidcConfig": json.dumps(sso_config()),
        "samlConfig": None,
    }
    if domain_verified is not None:
        row["domainVerified"] = domain_verified
    return await auth.adapter.create("ssoProvider", row)


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


async def test_from_provider_ignores_domain_verification() -> None:
    """Explicit org-bound provisioning stays independent of domain trust
    (org-assignment.test.ts "preserve direct oidc organization provisioning")."""
    auth, plugin, ctx = domain_ctx(verification=False)
    user = await seed_user(auth, email="worker@enterprise.example")
    provider = await seed_org_provider(
        auth, organization_id="org-1", provider_id="enterprise-provider", domain="example.com"
    )
    await assign_organization_from_provider(
        ctx,
        plugin,
        user=user,
        profile={"providerType": "oidc", "email": user["email"], "emailVerified": True},
        provider=provider,
    )
    rows = await members(auth, "org-1")
    assert len(rows) == 1
    assert rows[0]["userId"] == user["id"] and rows[0]["role"] == "member"


# --- by-domain: direct-call matrix (linking/org-assignment.test.ts) -------------------


def domain_ctx(
    *, verification: bool = True, **plugin_kwargs: Any
) -> tuple[BetterAuth, SSOPlugin, Ctx]:
    plugin = SSOPlugin(
        domain_verification={"enabled": True} if verification else None, **plugin_kwargs
    )
    auth = make_auth(plugins=[plugin, OrganizationPlugin()])
    request = AuthRequest(method="GET", path="/callback/github")
    return auth, plugin, Ctx(auth=auth, request=request)


async def seed_user(
    auth: BetterAuth, *, email: str = "alice@example.com", email_verified: bool = True
) -> dict[str, Any]:
    return await auth.adapter.create(
        "user", {"email": email, "name": "Alice", "emailVerified": email_verified}
    )


async def user_members(auth: BetterAuth, user_id: str) -> list[dict[str, Any]]:
    return await auth.adapter.find_many("member", [Where("userId", user_id)])


async def seed_domain_provider(auth: BetterAuth, **overrides: Any) -> dict[str, Any]:
    """seed_org_provider with the by-domain matrix defaults (org-1 / example.com / verified)."""
    defaults: dict[str, Any] = {
        "organization_id": "org-1",
        "domain": "example.com",
        "domain_verified": True,
    }
    return await seed_org_provider(auth, **{**defaults, **overrides})


async def test_by_domain_skips_unverified_provider() -> None:
    auth, plugin, ctx = domain_ctx()
    await seed_domain_provider(auth, domain_verified=False)
    user = await seed_user(auth)
    await assign_organization_by_domain(ctx, plugin, user=user)
    assert await user_members(auth, user["id"]) == []


async def test_by_domain_assigns_for_verified_provider() -> None:
    auth, plugin, ctx = domain_ctx()
    await seed_domain_provider(auth)
    user = await seed_user(auth)
    await assign_organization_by_domain(ctx, plugin, user=user)
    rows = await user_members(auth, user["id"])
    assert len(rows) == 1
    assert rows[0]["organizationId"] == "org-1" and rows[0]["role"] == "member"


async def test_by_domain_matches_normalized_multi_domain() -> None:
    auth, plugin, ctx = domain_ctx()
    await seed_domain_provider(auth, domain="https://attacker.com/path,victim.com")
    user = await seed_user(auth, email="alice@victim.com")
    await assign_organization_by_domain(ctx, plugin, user=user)
    rows = await user_members(auth, user["id"])
    assert len(rows) == 1 and rows[0]["organizationId"] == "org-1"


async def test_by_domain_rejects_malformed_email_domain() -> None:
    auth, plugin, ctx = domain_ctx()
    await seed_domain_provider(auth, domain="victim.com")
    user = await seed_user(auth, email="alice@https://victim.com/path")
    await assign_organization_by_domain(ctx, plugin, user=user)
    assert await user_members(auth, user["id"]) == []


async def test_by_domain_no_provider_match() -> None:
    auth, plugin, ctx = domain_ctx()
    await seed_domain_provider(auth)
    user = await seed_user(auth, email="alice@other-domain.com")
    await assign_organization_by_domain(ctx, plugin, user=user)
    assert await user_members(auth, user["id"]) == []


async def test_by_domain_provider_without_organization() -> None:
    auth, plugin, ctx = domain_ctx()
    await seed_domain_provider(auth, organization_id=None)
    user = await seed_user(auth)
    await assign_organization_by_domain(ctx, plugin, user=user)
    assert await user_members(auth, user["id"]) == []


async def test_by_domain_provider_missing_verified_bit() -> None:
    # the bit was never stored -> the provider is not trusted for domain-derived routing
    auth, plugin, ctx = domain_ctx()
    await seed_domain_provider(auth, domain_verified=None)
    user = await seed_user(auth)
    await assign_organization_by_domain(ctx, plugin, user=user)
    assert await user_members(auth, user["id"]) == []


async def test_by_domain_skipped_when_domain_verification_disabled() -> None:
    auth, plugin, ctx = domain_ctx(verification=False)
    await seed_domain_provider(auth, domain_verified=None)
    user = await seed_user(auth)
    await assign_organization_by_domain(ctx, plugin, user=user)
    assert await user_members(auth, user["id"]) == []


async def test_by_domain_keeps_existing_membership() -> None:
    auth, plugin, ctx = domain_ctx()
    await seed_domain_provider(auth)
    user = await seed_user(auth)
    await auth.adapter.create(
        "member",
        {"organizationId": "org-1", "userId": user["id"], "role": "admin", "createdAt": utcnow()},
    )
    await assign_organization_by_domain(ctx, plugin, user=user)
    rows = await user_members(auth, user["id"])
    assert len(rows) == 1 and rows[0]["role"] == "admin"


@pytest.mark.parametrize("order", [("unverified", "verified"), ("verified", "unverified")])
async def test_by_domain_only_trusts_the_verified_provider(order: tuple[str, str]) -> None:
    auth, plugin, ctx = domain_ctx()
    seeds = {
        "unverified": {
            "provider_id": "attacker-provider",
            "organization_id": "attacker-org",
            "domain_verified": False,
        },
        "verified": {
            "provider_id": "legit-provider",
            "organization_id": "legit-org",
            "domain_verified": True,
        },
    }
    for key in order:
        await seed_domain_provider(auth, **seeds[key])
    user = await seed_user(auth)
    await assign_organization_by_domain(ctx, plugin, user=user)
    rows = await user_members(auth, user["id"])
    assert len(rows) == 1 and rows[0]["organizationId"] == "legit-org"


@pytest.mark.parametrize("order", [("first", "second"), ("second", "first")])
async def test_by_domain_skips_ambiguous_domain(order: tuple[str, str]) -> None:
    auth, plugin, ctx = domain_ctx()
    seeds = {
        "first": {"provider_id": "first-provider", "organization_id": "first-org"},
        "second": {"provider_id": "second-provider", "organization_id": "second-org"},
    }
    for key in order:
        await seed_domain_provider(auth, **seeds[key])
    user = await seed_user(auth)
    await assign_organization_by_domain(ctx, plugin, user=user)
    assert await user_members(auth, user["id"]) == []


async def test_by_domain_assigns_once_for_duplicate_providers() -> None:
    auth, plugin, ctx = domain_ctx()
    for provider_id in ("second-provider", "first-provider"):
        await seed_domain_provider(auth, provider_id=provider_id)
    user = await seed_user(auth)
    await assign_organization_by_domain(ctx, plugin, user=user)
    rows = await user_members(auth, user["id"])
    assert len(rows) == 1 and rows[0]["organizationId"] == "org-1"


async def test_by_domain_requires_verified_canonical_email() -> None:
    auth, plugin, ctx = domain_ctx()
    await seed_domain_provider(auth)
    stored = await seed_user(auth, email_verified=False)
    # the callback's copy claims a verified email; the stored row is what counts
    await assign_organization_by_domain(ctx, plugin, user={**stored, "emailVerified": True})
    assert await user_members(auth, stored["id"]) == []


async def test_by_domain_uses_canonical_user_over_stale_callback_state() -> None:
    auth, plugin, ctx = domain_ctx()
    await seed_domain_provider(auth)
    stored = await seed_user(auth, email_verified=True)
    await assign_organization_by_domain(ctx, plugin, user={**stored, "emailVerified": False})
    rows = await user_members(auth, stored["id"])
    assert len(rows) == 1 and rows[0]["organizationId"] == "org-1"


async def test_by_domain_skips_while_invitation_pending() -> None:
    auth, plugin, ctx = domain_ctx()
    await seed_domain_provider(auth)
    user = await seed_user(auth)
    await auth.adapter.create(
        "invitation",
        {
            "organizationId": "org-1",
            "email": user["email"],
            "role": "admin",
            "status": "pending",
            "inviterId": "inviter-1",
            "expiresAt": utcnow() + timedelta(minutes=1),
            "createdAt": utcnow(),
        },
    )
    await assign_organization_by_domain(ctx, plugin, user=user)
    assert await user_members(auth, user["id"]) == []
    invitations = await auth.adapter.find_many("invitation", [Where("organizationId", "org-1")])
    assert len(invitations) == 1 and invitations[0]["status"] == "pending"


async def test_by_domain_surfaces_adapter_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    auth, plugin, ctx = domain_ctx()
    user = await seed_user(auth)

    async def boom(*args: Any, **kwargs: Any) -> Any:
        raise RuntimeError("provider lookup failed")

    monkeypatch.setattr(auth.adapter, "find_many", boom)
    with pytest.raises(RuntimeError, match="provider lookup failed"):
        await assign_organization_by_domain(ctx, plugin, user=user)


# --- by-domain: end-to-end social sign-in (org-assignment.security.test.ts) -----------


def github_http(email: str = "octo@corp.example", *, verified: bool = True) -> httpx.AsyncClient:
    profile = {"id": 4242, "login": "octo", "name": "Octo", "avatar_url": "http://img/x.png"}
    emails = [{"email": email, "primary": True, "verified": verified}]

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


def github_auth(
    *, email: str = "octo@corp.example", verified: bool = True, **plugin_kwargs: Any
) -> BetterAuth:
    return make_auth(
        social_providers={"github": GitHub(client_id="cid", client_secret="cs")},
        plugins=[SSOPlugin(**plugin_kwargs), OrganizationPlugin()],
        http_client=github_http(email, verified=verified),
    )


async def test_social_login_not_joined_without_domain_verification() -> None:
    auth = github_auth()
    async with make_client(auth) as client:
        await auth.adapter.create("organization", {"id": "org-1", "slug": "acme", "name": "Acme"})
        await seed_org_provider(auth, organization_id="org-1")
        res = await social_sign_in(client)
    assert res.status_code == 302
    assert await members(auth, "org-1") == []


async def test_social_login_joins_verified_domain() -> None:
    auth = github_auth(domain_verification={"enabled": True})
    async with make_client(auth) as client:
        await auth.adapter.create("organization", {"id": "org-1", "slug": "acme", "name": "Acme"})
        await seed_org_provider(auth, organization_id="org-1", domain_verified=True)
        res = await social_sign_in(client)
    assert res.status_code == 302
    assert len(await members(auth, "org-1")) == 1


async def test_social_login_with_unverified_email_not_joined() -> None:
    auth = github_auth(verified=False, domain_verification={"enabled": True})
    async with make_client(auth) as client:
        await auth.adapter.create("organization", {"id": "org-1", "slug": "acme", "name": "Acme"})
        await seed_org_provider(auth, organization_id="org-1", domain_verified=True)
        await social_sign_in(client)
    user = await auth.adapter.find_one("user", [Where("email", "octo@corp.example")])
    assert user is not None and not user["emailVerified"]
    assert await members(auth, "org-1") == []


async def test_social_login_no_duplicate_on_second_login() -> None:
    auth = github_auth(domain_verification={"enabled": True})
    async with make_client(auth) as client:
        await auth.adapter.create("organization", {"id": "org-1", "slug": "acme", "name": "Acme"})
        await seed_org_provider(auth, organization_id="org-1", domain_verified=True)
        await social_sign_in(client)
        client.cookies.clear()
        await social_sign_in(client)
    assert len(await members(auth, "org-1")) == 1


async def test_account_linking_does_not_provision() -> None:
    # linking creates no session, so the /callback/* after-hook never runs
    auth = github_auth(email=SIGNUP["email"], domain_verification={"enabled": True})
    async with make_client(auth) as client:
        signed = await sign_up(client)
        await auth.adapter.update(
            "user", [Where("id", signed["user"]["id"])], {"emailVerified": True}
        )
        await auth.adapter.create("organization", {"id": "org-1", "slug": "acme", "name": "Acme"})
        await seed_domain_provider(auth)
        start = await client.post(
            "/api/auth/link-social", json={"provider": "github", "callbackURL": "/settings"}
        )
        state = parse_qs(urlsplit(start.json()["url"]).query)["state"][0]
        linked = await client.get(f"/api/auth/callback/github?code=abc&state={state}")
        assert linked.status_code == 302
        assert len(await auth.adapter.find_many("account", [Where("providerId", "github")])) == 1
        assert await members(auth, "org-1") == []

        # ... but the next social sign-in provisions the same user
        client.cookies.clear()
        await social_sign_in(client)
    rows = await members(auth, "org-1")
    assert len(rows) == 1 and rows[0]["userId"] == signed["user"]["id"]
