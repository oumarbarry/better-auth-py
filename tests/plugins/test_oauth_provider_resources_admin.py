"""oauth-provider: SERVER_ONLY admin CRUD for OAuth protected resources.

Mirrors TS ``packages/oauth-provider/src/oauthResource/endpoints.test.ts`` (v1.7.6,
d2a79bae7). Handlers: ``oauthResource/endpoints.ts``; body schema: ``oauthResource/index.ts:20``.
Validation messages were captured from zod 4.5.4 (the TS catalog version) through
better-call's ``fromError`` (``[body.<path>] <message>`` joined by ``; ``).
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import quote

import pytest

from better_auth.adapters.base import Where
from better_auth.plugins_ext.jwt import JWTPlugin
from better_auth.plugins_ext.oauth_provider import OAuthProviderPlugin
from better_auth.plugins_ext.oauth_provider.resources import (
    get_resource,
    invalidate_resource_cache,
)
from better_auth.types import APIError, AuthRequest, AuthResponse, Ctx
from conftest import make_auth, make_client, sign_up

RAW = "https://api.example.com/path-decode"


@pytest.fixture(autouse=True)
def _clear_cache():
    yield
    invalidate_resource_cache()


class Admin:
    """A booted auth instance with a signed-in session, driving the SERVER_ONLY methods."""

    def __init__(self, **options: Any) -> None:
        self.auth = make_auth(plugins=[JWTPlugin(), OAuthProviderPlugin(**options)])
        self.plugin: Any = next(p for p in self.auth.plugins if p.id == "oauth-provider")
        self.cookie = ""

    async def sign_in(self) -> Admin:
        async with make_client(self.auth) as client:
            await sign_up(client)
            self.cookie = "; ".join(f"{k}={v}" for k, v in client.cookies.items())
        return self

    def ctx(self, method: str, body: Any = None, *, cookie: str | None = None) -> Ctx:
        headers = {"origin": "http://testserver"}
        if cookie if cookie is not None else self.cookie:
            headers["cookie"] = cookie if cookie is not None else self.cookie
        request = AuthRequest(
            method=method,
            path="/admin/oauth2/resources",
            headers=headers,
            body=json.dumps(body).encode() if body is not None else b"",
        )
        return Ctx(auth=self.auth, request=request)

    async def create(self, body: dict[str, Any]) -> AuthResponse:
        return await self.plugin.admin_create_oauth_resource(self.ctx("POST", body))

    async def get(self, identifier: str) -> Any:
        return await self.plugin.admin_get_oauth_resource(self.ctx("GET"), identifier)

    async def update(self, identifier: str, body: dict[str, Any]) -> Any:
        return await self.plugin.admin_update_oauth_resource(self.ctx("PATCH", body), identifier)

    async def delete(self, identifier: str) -> Any:
        return await self.plugin.admin_delete_oauth_resource(self.ctx("DELETE"), identifier)

    async def link(self, identifier: str, client_id: str) -> Any:
        return await self.plugin.admin_link_client_resource(self.ctx("POST"), identifier, client_id)

    async def unlink(self, identifier: str, client_id: str) -> Any:
        return await self.plugin.admin_unlink_client_resource(
            self.ctx("DELETE"), identifier, client_id
        )

    async def seed_client(self, client_id: str) -> None:
        await self.auth.adapter.create(
            "oauthClient", {"clientId": client_id, "redirectUris": ["https://example.com/cb"]}
        )

    async def links(self, **where: str) -> list[dict[str, Any]]:
        return await self.auth.adapter.find_many(
            "oauthClientResource", [Where(k, v) for k, v in where.items()]
        )


async def admin(**options: Any) -> Admin:
    return await Admin(**options).sign_in()


def assert_oauth_error(response: Any, status: int, error: str, description: str) -> None:
    assert isinstance(response, AuthResponse)
    assert response.status == status
    assert response.body == {"error": error, "error_description": description}


# --- resource admin CRUD (endpoints.test.ts:51) --------------------------------------


async def test_create_and_read_round_trip():
    a = await admin()
    created = await a.create(
        {
            "identifier": "https://api.example.com/created",
            "name": "Created Resource",
            "accessTokenTtl": 300,
        }
    )
    # endpoints.ts:164 answers 201 with the stored row.
    assert created.status == 201
    assert created.body["identifier"] == "https://api.example.com/created"
    fetched = await a.get("https://api.example.com/created")
    assert fetched["name"] == "Created Resource"
    assert fetched["accessTokenTtl"] == 300


async def test_create_fills_the_seed_defaults():
    # endpoints.ts:102 buildResourceRow: name falls back to the identifier, policyVersion 1.
    a = await admin()
    created = await a.create({"identifier": "https://api.example.com/defaults"})
    row = created.body
    assert row["name"] == "https://api.example.com/defaults"
    assert row["policyVersion"] == 1
    assert row["disabled"] is False
    assert row["dpopBoundAccessTokensRequired"] is False
    for key in ("accessTokenTtl", "signingAlgorithm", "allowedScopes", "customClaims"):
        assert row[key] is None


async def test_create_rejects_a_relative_identifier():
    a = await admin()
    response = await a.create({"identifier": "not-a-uri"})
    assert_oauth_error(
        response,
        400,
        "invalid_target",
        "resource identifier not-a-uri must be an absolute URI (RFC 8707 §2)",
    )


async def test_create_rejects_a_fragment_identifier():
    a = await admin()
    response = await a.create({"identifier": "https://api.example.com/x#fragment"})
    assert response.status == 400
    assert response.body["error"] == "invalid_target"


async def test_create_rejects_duplicates():
    a = await admin()
    await a.create({"identifier": "https://api.example.com/dup"})
    response = await a.create({"identifier": "https://api.example.com/dup"})
    # endpoints.ts:152
    assert_oauth_error(
        response, 400, "invalid_request", "resource https://api.example.com/dup already exists"
    )
    rows = await a.auth.adapter.find_many("oauthResource", [])
    assert len(rows) == 1


async def test_update_only_touches_given_fields():
    a = await admin()
    await a.create(
        {
            "identifier": "https://api.example.com/update-me",
            "name": "Original",
            "accessTokenTtl": 600,
            "allowedScopes": ["read"],
        }
    )
    updated = await a.update("https://api.example.com/update-me", {"accessTokenTtl": 60})
    assert updated["accessTokenTtl"] == 60
    fetched = await a.get("https://api.example.com/update-me")
    assert fetched["accessTokenTtl"] == 60
    assert fetched["name"] == "Original"
    assert fetched["allowedScopes"] == ["read"]


async def test_update_can_clear_a_policy_field_with_null():
    # endpoints.ts:237 copies every key present in the body, including explicit nulls.
    a = await admin()
    await a.create({"identifier": "https://api.example.com/nullable", "accessTokenTtl": 600})
    updated = await a.update("https://api.example.com/nullable", {"accessTokenTtl": None})
    assert updated["accessTokenTtl"] is None


async def test_update_ignores_the_identifier_and_unknown_keys():
    a = await admin()
    await a.create({"identifier": "https://api.example.com/fixed"})
    updated = await a.update(
        "https://api.example.com/fixed",
        {"identifier": "https://api.example.com/other", "policyVersion": 9, "name": "N"},
    )
    assert updated["identifier"] == "https://api.example.com/fixed"
    assert updated["policyVersion"] == 1
    assert updated["name"] == "N"


async def test_update_on_a_missing_identifier_returns_404():
    a = await admin()
    response = await a.update("https://api.example.com/missing", {"accessTokenTtl": 120})
    assert_oauth_error(
        response, 404, "not_found", "resource https://api.example.com/missing not found"
    )


async def test_delete_removes_the_row_then_reads_404():
    a = await admin()
    await a.create({"identifier": "https://api.example.com/delete-me"})
    assert await a.delete("https://api.example.com/delete-me") == {"deleted": True}
    response = await a.get("https://api.example.com/delete-me")
    assert_oauth_error(
        response, 404, "not_found", "resource https://api.example.com/delete-me not found"
    )


async def test_delete_on_a_missing_identifier_returns_404():
    a = await admin()
    response = await a.delete("https://api.example.com/ghost")
    assert_oauth_error(
        response, 404, "not_found", "resource https://api.example.com/ghost not found"
    )


async def test_list_returns_every_resource():
    a = await admin()
    await a.create({"identifier": "https://api.example.com/a"})
    await a.create({"identifier": "https://api.example.com/b"})
    rows = await a.plugin.admin_list_oauth_resources(a.ctx("GET"))
    assert sorted(r["identifier"] for r in rows) == [
        "https://api.example.com/a",
        "https://api.example.com/b",
    ]


# --- resourcePrivileges gate (endpoints.test.ts:203, endpoints.ts:38) ----------------


async def test_every_action_requires_a_session():
    a = await admin()
    calls = [
        a.plugin.admin_create_oauth_resource(
            a.ctx("POST", {"identifier": "https://api.example.com/x"}, cookie="")
        ),
        a.plugin.admin_list_oauth_resources(a.ctx("GET", cookie="")),
        a.plugin.admin_get_oauth_resource(a.ctx("GET", cookie=""), "https://x.example"),
        a.plugin.admin_update_oauth_resource(a.ctx("PATCH", {}, cookie=""), "https://x.example"),
        a.plugin.admin_delete_oauth_resource(a.ctx("DELETE", cookie=""), "https://x.example"),
        a.plugin.admin_link_client_resource(a.ctx("POST", cookie=""), "https://x.example", "c"),
        a.plugin.admin_unlink_client_resource(a.ctx("DELETE", cookie=""), "https://x.example", "c"),
    ]
    for call in calls:
        with pytest.raises(APIError) as exc:
            await call
        assert (exc.value.status, exc.value.code) == (401, "UNAUTHORIZED")


async def test_privileges_block_create():
    a = await admin(resource_privileges=lambda c: c["action"] != "create")
    with pytest.raises(APIError) as exc:
        await a.create({"identifier": "https://api.example.com/gated"})
    assert (exc.value.status, exc.value.code) == (401, "UNAUTHORIZED")
    assert await a.auth.adapter.find_many("oauthResource", []) == []


async def test_privileges_allow_approved_actions_and_see_the_context():
    seen: list[dict[str, Any]] = []

    async def privileges(context: dict[str, Any]) -> bool:
        seen.append(context)
        return context["action"] in ("create", "read")

    a = await admin(resource_privileges=privileges)
    await a.create({"identifier": "https://api.example.com/approved"})
    fetched = await a.get(quote("https://api.example.com/approved", safe=""))
    assert fetched["identifier"] == "https://api.example.com/approved"
    assert [c["action"] for c in seen] == ["create", "read"]
    # endpoints.ts:53: resourceId is the decoded identifier, absent on create.
    assert seen[0]["resourceId"] is None
    assert seen[1]["resourceId"] == "https://api.example.com/approved"
    assert seen[1]["user"]["email"]
    assert seen[1]["session"]["userId"] == seen[1]["user"]["id"]
    assert "cookie" in seen[1]["headers"]


async def test_privileges_block_list_independently_of_read():
    a = await admin(resource_privileges=lambda c: c["action"] != "list")
    with pytest.raises(APIError) as exc:
        await a.plugin.admin_list_oauth_resources(a.ctx("GET"))
    assert exc.value.status == 401


async def test_privileges_gate_link_and_unlink():
    a = await admin(resource_privileges=lambda c: c["action"] not in ("link", "unlink"))
    for call in (a.link, a.unlink):
        with pytest.raises(APIError) as exc:
            await call("https://api.example.com/r", "c")
        assert exc.value.status == 401


# --- client/resource linking (endpoints.test.ts:246) ---------------------------------


async def test_link_creates_the_join_row_and_unlink_removes_it():
    a = await admin()
    await a.seed_client("test-client")
    await a.create({"identifier": "https://api.example.com/linked"})
    assert await a.link("https://api.example.com/linked", "test-client") == {"linked": True}
    links = await a.links(clientId="test-client")
    assert [link["resourceId"] for link in links] == ["https://api.example.com/linked"]
    assert await a.unlink("https://api.example.com/linked", "test-client") == {"unlinked": True}
    assert await a.links(clientId="test-client") == []


async def test_link_is_idempotent():
    a = await admin()
    await a.seed_client("idempotent-client")
    await a.create({"identifier": "https://api.example.com/idempotent"})
    await a.link("https://api.example.com/idempotent", "idempotent-client")
    second = await a.link("https://api.example.com/idempotent", "idempotent-client")
    # endpoints.ts:352
    assert second == {"linked": True, "alreadyLinked": True}
    assert len(await a.links(clientId="idempotent-client")) == 1


async def test_link_rejects_an_unknown_resource():
    a = await admin()
    await a.seed_client("client-x")
    response = await a.link("https://api.example.com/nope", "client-x")
    assert_oauth_error(
        response, 404, "not_found", "resource https://api.example.com/nope not found"
    )


async def test_link_rejects_an_unknown_client():
    a = await admin()
    await a.create({"identifier": "https://api.example.com/orphan"})
    response = await a.link("https://api.example.com/orphan", "no-such-client")
    assert_oauth_error(response, 404, "not_found", "client no-such-client not found")


async def test_concurrent_links_produce_one_row():
    import asyncio

    a = await admin()
    await a.seed_client("race-client")
    await a.create({"identifier": "https://api.example.com/race"})
    results = await asyncio.gather(
        *(a.link("https://api.example.com/race", "race-client") for _ in range(5))
    )
    assert all(r["linked"] is True for r in results)
    assert len(await a.links(clientId="race-client")) == 1


async def test_unlink_of_a_missing_pair_still_succeeds():
    # endpoints.ts:365 deletes with deleteMany and never 404s.
    a = await admin()
    assert await a.unlink("https://api.example.com/none", "none") == {"unlinked": True}


# --- signingAlgorithm and body validation (endpoints.test.ts:431, index.ts:20) -------


@pytest.mark.parametrize("alg", ["HS256", "not-an-alg"])
async def test_create_rejects_an_unsupported_signing_algorithm(alg: str):
    a = await admin()
    with pytest.raises(APIError) as exc:
        await a.create({"identifier": "https://api.example.com/bad-alg", "signingAlgorithm": alg})
    assert (exc.value.status, exc.value.code) == (400, "VALIDATION_ERROR")
    assert exc.value.message == (
        '[body.signingAlgorithm] Invalid option: expected one of "EdDSA"|"ES256"|"ES512"|'
        '"PS256"|"RS256"'
    )
    assert await a.auth.adapter.find_many("oauthResource", []) == []


async def test_create_accepts_every_supported_algorithm():
    a = await admin()
    for alg in ("EdDSA", "ES256", "ES512", "PS256", "RS256"):
        response = await a.create(
            {"identifier": f"https://api.example.com/alg-{alg.lower()}", "signingAlgorithm": alg}
        )
        assert response.status == 201


async def test_update_rejects_a_bad_signing_algorithm():
    a = await admin()
    await a.create({"identifier": "https://api.example.com/upd-alg"})
    with pytest.raises(APIError) as exc:
        await a.update("https://api.example.com/upd-alg", {"signingAlgorithm": "HS256"})
    assert exc.value.code == "VALIDATION_ERROR"


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ({}, "[body.identifier] Invalid input: expected nonoptional, received undefined"),
        (
            {"identifier": ""},
            "[body.identifier] Too small: expected string to have >=1 characters",
        ),
        ({"identifier": None}, "[body.identifier] Invalid input: expected string, received null"),
        ({"identifier": 5}, "[body.identifier] Invalid input: expected string, received number"),
    ],
)
async def test_create_requires_an_identifier(body: dict[str, Any], message: str):
    a = await admin()
    with pytest.raises(APIError) as exc:
        await a.create(body)
    assert (exc.value.status, exc.value.code, exc.value.message) == (
        400,
        "VALIDATION_ERROR",
        message,
    )


@pytest.mark.parametrize(
    ("body", "message"),
    [
        ({"name": None}, "[body.name] Invalid input: expected string, received null"),
        ({"accessTokenTtl": 0}, "[body.accessTokenTtl] Too small: expected number to be >0"),
        ({"refreshTokenTtl": -1}, "[body.refreshTokenTtl] Too small: expected number to be >0"),
        (
            {"accessTokenTtl": 1.5},
            "[body.accessTokenTtl] Invalid input: expected int, received number",
        ),
        (
            {"accessTokenTtl": "5"},
            "[body.accessTokenTtl] Invalid input: expected number, received string",
        ),
        (
            {"accessTokenTtl": True},
            "[body.accessTokenTtl] Invalid input: expected number, received boolean",
        ),
        (
            {"accessTokenTtl": {}},
            "[body.accessTokenTtl] Invalid input: expected number, received object",
        ),
        (
            {"accessTokenTtl": 2**53},
            "[body.accessTokenTtl] Too big: expected int to be <=9007199254740991",
        ),
        (
            {"accessTokenTtl": -(2**53)},
            "[body.accessTokenTtl] Too small: expected int to be >=-9007199254740991; "
            "[body.accessTokenTtl] Too small: expected number to be >0",
        ),
        (
            {"signingKeyId": 3},
            "[body.signingKeyId] Invalid input: expected string, received number",
        ),
        (
            {"allowedScopes": "a"},
            "[body.allowedScopes] Invalid input: expected array, received string",
        ),
        (
            {"allowedScopes": ["a", 1, 2]},
            "[body.allowedScopes.1] Invalid input: expected string, received number; "
            "[body.allowedScopes.2] Invalid input: expected string, received number",
        ),
        (
            {"customClaims": []},
            "[body.customClaims] Invalid input: expected record, received array",
        ),
        ({"metadata": 3}, "[body.metadata] Invalid input: expected record, received number"),
        ({"disabled": None}, "[body.disabled] Invalid input: expected boolean, received null"),
        (
            {"dpopBoundAccessTokensRequired": "x"},
            "[body.dpopBoundAccessTokensRequired] Invalid input: expected boolean, received string",
        ),
        (
            {"accessTokenTtl": 0, "signingAlgorithm": "x", "disabled": 1},
            "[body.accessTokenTtl] Too small: expected number to be >0; "
            '[body.signingAlgorithm] Invalid option: expected one of "EdDSA"|"ES256"|"ES512"|'
            '"PS256"|"RS256"; [body.disabled] Invalid input: expected boolean, received number',
        ),
    ],
)
async def test_update_body_validation_messages(body: dict[str, Any], message: str):
    a = await admin()
    with pytest.raises(APIError) as exc:
        await a.update("https://api.example.com/anything", body)
    assert (exc.value.status, exc.value.code, exc.value.message) == (
        400,
        "VALIDATION_ERROR",
        message,
    )


async def test_validation_runs_before_the_session_check():
    # better-call validates the body before the handler runs.
    a = await admin()
    with pytest.raises(APIError) as exc:
        await a.plugin.admin_create_oauth_resource(a.ctx("POST", {}, cookie=""))
    assert exc.value.code == "VALIDATION_ERROR"


async def test_nullable_fields_accept_null_on_create():
    a = await admin()
    response = await a.create(
        {
            "identifier": "https://api.example.com/nulls",
            "accessTokenTtl": None,
            "signingAlgorithm": None,
            "allowedScopes": None,
            "customClaims": None,
            "metadata": None,
        }
    )
    assert response.status == 201


# --- path-param decoding (endpoints.test.ts:495, endpoints.ts:84) ---------------------


async def test_read_decodes_a_percent_encoded_identifier():
    a = await admin()
    await a.create({"identifier": RAW, "name": "Path Decode"})
    fetched = await a.get(quote(RAW, safe=""))
    assert fetched["identifier"] == RAW
    assert fetched["name"] == "Path Decode"


async def test_update_decodes_a_percent_encoded_identifier():
    a = await admin()
    await a.create({"identifier": RAW, "accessTokenTtl": 600})
    await a.update(quote(RAW, safe=""), {"accessTokenTtl": 90})
    assert (await a.get(RAW))["accessTokenTtl"] == 90


async def test_delete_decodes_a_percent_encoded_identifier():
    a = await admin()
    await a.create({"identifier": RAW})
    await a.delete(quote(RAW, safe=""))
    assert (await a.get(RAW)).status == 404


async def test_link_and_unlink_decode_both_segments():
    a = await admin()
    await a.create({"identifier": RAW})
    await a.seed_client("client with space")
    await a.link(quote(RAW, safe=""), quote("client with space", safe=""))
    links = await a.links(resourceId=RAW)
    assert [link["clientId"] for link in links] == ["client with space"]
    await a.unlink(quote(RAW, safe=""), quote("client with space", safe=""))
    assert await a.links(resourceId=RAW) == []


@pytest.mark.parametrize("raw", ["%ZZ-not-valid", "%41%ZZ", "%C3%28"])
async def test_a_malformed_escape_falls_back_to_the_raw_value(raw: str):
    # decodeURIComponent throws on these, so TS keeps the raw string (endpoints.ts:84).
    a = await admin()
    response = await a.get(raw)
    assert_oauth_error(response, 404, "not_found", f"resource {raw} not found")


# --- cache invalidation (endpoints.ts:163,247,294) ------------------------------------


async def test_mutations_invalidate_the_resource_cache():
    identifier = "https://api.example.com/cached"
    a = await admin(cached_resources={identifier})
    await a.create({"identifier": identifier, "accessTokenTtl": 600})
    ctx = a.ctx("GET")
    assert (await get_resource(ctx, a.plugin, identifier) or {}).get("accessTokenTtl") == 600
    await a.update(identifier, {"accessTokenTtl": 60})
    assert (await get_resource(ctx, a.plugin, identifier) or {}).get("accessTokenTtl") == 60
    await a.delete(identifier)
    assert await get_resource(ctx, a.plugin, identifier) is None
