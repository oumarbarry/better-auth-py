"""Tests for DNS-TXT domain verification (POST /sso/request-domain-verification,
POST /sso/verify-domain).

TS source verified against packages/sso/src/routes/domain-verification.ts. The DNS TXT
resolver is injected (plugin.dns_resolver) so tests never touch the network.

The concurrency block ports domain-verification-concurrency.test.ts (999acbd41,
GHSA-8c5h-wx78-2cfg): the completion write is a compare-and-swap on the provider row's
``id`` + the exact ``domain`` snapshot the DNS proof was collected for, so a provider
mutated mid-flight yields 409 SSO_PROVIDER_CHANGED instead of verifying a domain nobody
proved.
"""

from __future__ import annotations

import asyncio
from typing import Any

from better_auth import BetterAuth, MemoryAdapter, Where
from better_auth.plugins_ext.sso import SSOPlugin
from conftest import make_auth, make_client, sign_up

IDP = "https://idp.example.com"

STALE_PROVIDER_ERROR = {
    "code": "SSO_PROVIDER_CHANGED",
    "message": (
        "SSO provider changed while domain verification was in progress. "
        "Reload the provider and try again"
    ),
}


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


# --- concurrency: proof bound to provider state (domain-verification-concurrency.test.ts) --


class GatedResolver:
    """DNS resolver that parks in-flight lookups until ``release`` fires (the TS suite's
    ``createDeferred`` pair), recording every name it was asked to resolve."""

    def __init__(self, *, start_after: int = 1) -> None:
        self.started = asyncio.Event()
        self.release = asyncio.Event()
        self.names: list[str] = []
        self.records: list[str] = []
        self._start_after = start_after

    async def __call__(self, name: str) -> list[str]:
        self.names.append(name)
        if len(self.names) >= self._start_after:
            self.started.set()
        await self.release.wait()
        return self.records


def make_gated(*, start_after: int = 1) -> tuple[BetterAuth, GatedResolver]:
    gate = GatedResolver(start_after=start_after)
    return make_auth(
        plugins=[SSOPlugin(domain_verification={"enabled": True}, dns_resolver=gate)]
    ), gate


def verify(client: Any) -> Any:
    return asyncio.create_task(
        client.post("/api/auth/sso/verify-domain", json={"providerId": "test"})
    )


async def provider_row(auth: BetterAuth) -> dict[str, Any]:
    row = await auth.adapter.find_one("ssoProvider", [Where("providerId", "test")])
    assert row is not None
    return row


async def test_verify_domain_conflict_when_domain_changes_in_flight() -> None:
    auth, gate = make_gated()
    async with make_client(auth) as client:
        await sign_up(client)
        gate.records = [(await register(client)).json()["domainVerificationToken"]]
        pending = verify(client)
        await gate.started.wait()
        update = await client.post(
            "/api/auth/sso/update-provider",
            json={"providerId": "test", "domain": "victim.example"},
        )
        assert update.status_code == 200, update.text
        gate.release.set()
        res = await pending
    assert res.status_code == 409, res.text
    assert res.json() == STALE_PROVIDER_ERROR
    # the proof was collected for the domain held at request start, not the swapped-in one
    assert gate.names == ["_better-auth-token-test.example.com"]
    row = await provider_row(auth)
    assert row["domain"] == "victim.example"
    assert not row["domainVerified"]


async def test_unguarded_completion_would_verify_the_swapped_domain() -> None:
    """The compare-and-swap write is load-bearing. Replaying the pre-fix write (keyed
    on providerId alone) against the same swapped state flips ``domainVerified`` on a
    domain whose ownership nobody proved, exactly what the guarded write above
    refuses."""
    auth, gate = make_gated()
    async with make_client(auth) as client:
        await sign_up(client)
        gate.records = [(await register(client)).json()["domainVerificationToken"]]
        pending = verify(client)
        await gate.started.wait()
        await client.post(
            "/api/auth/sso/update-provider",
            json={"providerId": "test", "domain": "victim.example"},
        )
        gate.release.set()
        await pending
        await auth.adapter.update(
            "ssoProvider", [Where("providerId", "test")], {"domainVerified": True}
        )
    row = await provider_row(auth)
    assert row["domain"] == "victim.example" and row["domainVerified"] is True


async def test_verify_domain_conflict_after_provider_deleted() -> None:
    auth, gate = make_gated()
    async with make_client(auth) as client:
        await sign_up(client)
        gate.records = [(await register(client)).json()["domainVerificationToken"]]
        pending = verify(client)
        await gate.started.wait()
        deleted = await client.post("/api/auth/sso/delete-provider", json={"providerId": "test"})
        assert deleted.status_code == 200, deleted.text
        gate.release.set()
        res = await pending
    assert res.status_code == 409
    assert res.json() == STALE_PROVIDER_ERROR
    assert await auth.adapter.find_one("ssoProvider", [Where("providerId", "test")]) is None


async def test_verify_domain_conflict_for_replacement_with_same_provider_id() -> None:
    auth, gate = make_gated()
    async with make_client(auth) as client:
        await sign_up(client)
        gate.records = [(await register(client)).json()["domainVerificationToken"]]
        pending = verify(client)
        await gate.started.wait()
        await client.post("/api/auth/sso/delete-provider", json={"providerId": "test"})
        replacement = await register(client, domain="replacement.example")
        assert replacement.status_code == 200, replacement.text
        gate.release.set()
        res = await pending
    assert res.status_code == 409
    assert res.json() == STALE_PROVIDER_ERROR
    row = await provider_row(auth)
    assert row["domain"] == "replacement.example"
    assert not row["domainVerified"]


async def test_verify_domain_simultaneous_requests_both_succeed() -> None:
    # both proved the domain that is still stored, so neither is stale: a conflict here
    # would tell a retrying client the provider changed when nothing did
    auth, gate = make_gated(start_after=2)
    async with make_client(auth) as client:
        await sign_up(client)
        gate.records = [(await register(client)).json()["domainVerificationToken"]]
        first, second = verify(client), verify(client)
        await gate.started.wait()
        gate.release.set()
        results = await asyncio.gather(first, second)
    assert [res.status_code for res in results] == [204, 204]
    row = await provider_row(auth)
    assert row["domain"] == "example.com" and row["domainVerified"] is True


async def test_verify_domain_allows_unrelated_provider_update_in_flight() -> None:
    auth, gate = make_gated()
    async with make_client(auth) as client:
        await sign_up(client)
        gate.records = [(await register(client)).json()["domainVerificationToken"]]
        pending = verify(client)
        await gate.started.wait()
        update = await client.post(
            "/api/auth/sso/update-provider",
            json={"providerId": "test", "issuer": "https://idp2.example.com"},
        )
        assert update.status_code == 200, update.text
        gate.release.set()
        res = await pending
    assert res.status_code == 204, res.text
    row = await provider_row(auth)
    assert row["issuer"] == "https://idp2.example.com"
    assert row["domain"] == "example.com" and row["domainVerified"] is True


async def test_later_domain_update_drops_verification() -> None:
    auth, _plugin, records = make()
    async with make_client(auth) as client:
        await sign_up(client)
        token = (await register(client)).json()["domainVerificationToken"]
        records["_better-auth-token-test.example.com"] = [token]
        assert (
            await client.post("/api/auth/sso/verify-domain", json={"providerId": "test"})
        ).status_code == 204
        update = await client.post(
            "/api/auth/sso/update-provider",
            json={"providerId": "test", "domain": "changed.example"},
        )
        assert update.status_code == 200
    row = await provider_row(auth)
    assert row["domain"] == "changed.example" and not row["domainVerified"]


async def test_verify_domain_when_stored_bit_was_never_written() -> None:
    """A provider registered before domainVerification was enabled has no stored bit;
    enabling the option later must not strand it (the CAS deliberately omits
    ``domainVerified`` from the guard)."""
    adapter = MemoryAdapter()
    records: dict[str, list[str]] = {}

    async def resolver(name: str) -> list[str]:
        return records.get(name, [])

    legacy = make_auth(adapter=adapter, plugins=[SSOPlugin()])
    async with make_client(legacy) as client:
        await sign_up(client)
        assert (await register(client)).status_code == 200
    row = await legacy.adapter.find_one("ssoProvider", [Where("providerId", "test")])
    assert row is not None and "domainVerified" not in row  # precondition: never stored

    auth = make_auth(
        adapter=adapter,
        plugins=[SSOPlugin(domain_verification={"enabled": True}, dns_resolver=resolver)],
    )
    async with make_client(auth) as client:
        await client.post(
            "/api/auth/sign-in/email",
            json={"email": "ada@example.com", "password": "s3cret-password"},
        )
        token = (
            await client.post(
                "/api/auth/sso/request-domain-verification", json={"providerId": "test"}
            )
        ).json()["domainVerificationToken"]
        records["_better-auth-token-test.example.com"] = [token]
        res = await client.post("/api/auth/sso/verify-domain", json={"providerId": "test"})
    assert res.status_code == 204, res.text
    assert (await provider_row(auth))["domainVerified"] is True
