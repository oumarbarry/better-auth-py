"""Tests for DNS-TXT domain verification (POST /sso/request-domain-verification,
POST /sso/verify-domain).

TS source verified against packages/sso/src/routes/domain-verification.ts. The DNS TXT
resolver is injected (plugin.dns_resolver) so tests never touch the network.
"""

from __future__ import annotations

from typing import Any

from better_auth import BetterAuth, Where
from better_auth.plugins_ext.sso import SSOPlugin
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
        },
    }
    body.update(overrides)
    return body


def make() -> tuple[BetterAuth, SSOPlugin, dict[str, list[str]]]:
    records: dict[str, list[str]] = {}

    async def resolver(name: str) -> list[str]:
        return records.get(name, [])

    plugin = SSOPlugin(domain_verification={"enabled": True}, dns_resolver=resolver)
    auth = make_auth(plugins=[plugin])
    return auth, plugin, records


async def register(client: Any, **overrides: Any) -> Any:
    return await client.post("/api/auth/sso/register", json=oidc_body(**overrides))


# --- request-domain-verification -----------------------------------------------------


async def test_request_returns_active_seeded_token() -> None:
    auth, _plugin, _records = make()
    async with make_client(auth) as client:
        await sign_up(client)
        seeded = (await register(client)).json()["domainVerificationToken"]
        res = await client.post(
            "/api/auth/sso/request-domain-verification", json={"providerId": "test"}
        )
    assert res.status_code == 201
    # an active (register-seeded) token is returned rather than a fresh one
    assert res.json()["domainVerificationToken"] == seeded


async def test_request_conflict_when_already_verified() -> None:
    auth, _plugin, _records = make()
    async with make_client(auth) as client:
        await sign_up(client)
        await register(client)
        await auth.adapter.update(
            "ssoProvider", [Where("providerId", "test")], {"domainVerified": True}
        )
        res = await client.post(
            "/api/auth/sso/request-domain-verification", json={"providerId": "test"}
        )
    assert res.status_code == 409
    assert res.json()["code"] == "DOMAIN_VERIFIED"


# --- verify-domain -------------------------------------------------------------------


async def test_verify_domain_success_with_identifier_equals_value() -> None:
    auth, _plugin, records = make()
    async with make_client(auth) as client:
        await sign_up(client)
        token = (await register(client)).json()["domainVerificationToken"]
        records["_better-auth-token-test.example.com"] = [f"_better-auth-token-test={token}"]
        res = await client.post("/api/auth/sso/verify-domain", json={"providerId": "test"})
    assert res.status_code == 204, res.text
    row = await auth.adapter.find_one("ssoProvider", [Where("providerId", "test")])
    assert row is not None and row["domainVerified"] is True


async def test_verify_domain_success_with_bare_value() -> None:
    auth, _plugin, records = make()
    async with make_client(auth) as client:
        await sign_up(client)
        token = (await register(client)).json()["domainVerificationToken"]
        records["_better-auth-token-test.example.com"] = [token]
        res = await client.post("/api/auth/sso/verify-domain", json={"providerId": "test"})
    assert res.status_code == 204


async def test_verify_domain_substring_rejected() -> None:
    auth, _plugin, records = make()
    async with make_client(auth) as client:
        await sign_up(client)
        token = (await register(client)).json()["domainVerificationToken"]
        # the token only appears as a substring of a longer record -> rejected
        records["_better-auth-token-test.example.com"] = [f"prefix-{token}-suffix"]
        res = await client.post("/api/auth/sso/verify-domain", json={"providerId": "test"})
    assert res.status_code == 502
    assert res.json()["code"] == "DOMAIN_VERIFICATION_FAILED"
    row = await auth.adapter.find_one("ssoProvider", [Where("providerId", "test")])
    assert row is not None and not row["domainVerified"]


async def test_verify_domain_absent_record_fails() -> None:
    auth, _plugin, _records = make()
    async with make_client(auth) as client:
        await sign_up(client)
        await register(client)  # no TXT record configured
        res = await client.post("/api/auth/sso/verify-domain", json={"providerId": "test"})
    assert res.status_code == 502
    assert res.json()["code"] == "DOMAIN_VERIFICATION_FAILED"


async def test_verify_domain_multi_domain_all_or_nothing() -> None:
    auth, _plugin, records = make()
    async with make_client(auth) as client:
        await sign_up(client)
        token = (await register(client, domain="a.com,b.com")).json()["domainVerificationToken"]
        # only a.com has the record; b.com is missing -> whole verification fails
        records["_better-auth-token-test.a.com"] = [token]
        res = await client.post("/api/auth/sso/verify-domain", json={"providerId": "test"})
    assert res.status_code == 502
    row = await auth.adapter.find_one("ssoProvider", [Where("providerId", "test")])
    assert row is not None and not row["domainVerified"]


async def test_verify_domain_multi_domain_all_present_succeeds() -> None:
    auth, _plugin, records = make()
    async with make_client(auth) as client:
        await sign_up(client)
        token = (await register(client, domain="a.com,b.com")).json()["domainVerificationToken"]
        records["_better-auth-token-test.a.com"] = [token]
        records["_better-auth-token-test.b.com"] = [f"_better-auth-token-test={token}"]
        res = await client.post("/api/auth/sso/verify-domain", json={"providerId": "test"})
    assert res.status_code == 204
    row = await auth.adapter.find_one("ssoProvider", [Where("providerId", "test")])
    assert row is not None and row["domainVerified"] is True


async def test_verify_domain_expired_token_fails() -> None:
    from datetime import timedelta

    from better_auth.session import utcnow

    auth, _plugin, _records = make()
    async with make_client(auth) as client:
        await sign_up(client)
        await register(client)
        # expire the seeded verification row
        await auth.adapter.update(
            "verification",
            [Where("identifier", "_better-auth-token-test")],
            {"expiresAt": utcnow() - timedelta(days=1)},
        )
        res = await client.post("/api/auth/sso/verify-domain", json={"providerId": "test"})
    assert res.status_code == 404
    assert res.json()["code"] == "NO_PENDING_VERIFICATION"


async def test_verify_domain_already_verified_conflict() -> None:
    auth, _plugin, _records = make()
    async with make_client(auth) as client:
        await sign_up(client)
        await register(client)
        await auth.adapter.update(
            "ssoProvider", [Where("providerId", "test")], {"domainVerified": True}
        )
        res = await client.post("/api/auth/sso/verify-domain", json={"providerId": "test"})
    assert res.status_code == 409
    assert res.json()["code"] == "DOMAIN_VERIFIED"


async def test_domain_verification_endpoints_absent_when_disabled() -> None:
    auth = make_auth(plugins=[SSOPlugin()])
    async with make_client(auth) as client:
        await sign_up(client)
        res = await client.post("/api/auth/sso/verify-domain", json={"providerId": "test"})
    assert res.status_code == 404
