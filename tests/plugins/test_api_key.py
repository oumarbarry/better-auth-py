"""api-key plugin — database mode.

Verified against TS ``packages/api-key/src/`` at v1.6.23 (index.ts, schema.ts,
error-codes.ts, rate-limit.ts, routes/*.ts, org-authorization.ts).
"""

from __future__ import annotations

import asyncio
from datetime import timedelta
from typing import Any

import pytest

from better_auth import Where
from better_auth.crypto import default_key_hasher
from better_auth.plugins_ext.api_key import API_KEY_ERROR_CODES, ApiKeyPlugin
from better_auth.plugins_ext.organization import OrganizationPlugin
from better_auth.session import utcnow
from better_auth.types import APIError, AuthRequest, Ctx
from conftest import make_auth, make_client, sign_up


def ak_auth(config: Any = None, **overrides: Any):
    return make_auth(plugins=[ApiKeyPlugin(config)], **overrides)


def _plugin(auth) -> ApiKeyPlugin:
    return next(p for p in auth.plugins if isinstance(p, ApiKeyPlugin))


def server_ctx(auth, path: str = "/api-key/verify") -> Ctx:
    return Ctx(auth=auth, request=AuthRequest(method="POST", path=path))


async def _row(auth, key_id: str) -> dict[str, Any]:
    return await auth.adapter.find_one("apikey", [Where("id", key_id)])


# ---------------------------------------------------------------------------
# Key hashing — cross-runtime vector
# ---------------------------------------------------------------------------


def test_key_hasher_vector():
    # base64url-nopad SHA-256 of "hello" — must match the TS defaultKeyHasher byte-for-byte.
    assert default_key_hasher("hello") == "LPJNul-wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ"


# ---------------------------------------------------------------------------
# Error codes — exact strings
# ---------------------------------------------------------------------------


def test_error_codes_exact():
    assert API_KEY_ERROR_CODES["METADATA_DISABLED"] == "Metadata is disabled."
    assert API_KEY_ERROR_CODES["USER_BANNED"] == "User is banned"
    assert API_KEY_ERROR_CODES["KEY_NOT_FOUND"] == "API Key not found"
    assert API_KEY_ERROR_CODES["INVALID_API_KEY"] == "Invalid API key."
    assert API_KEY_ERROR_CODES["SERVER_ONLY_PROPERTY"] == (
        "The property you're trying to set can only be set from the server auth instance only."
    )
    assert API_KEY_ERROR_CODES["NO_VALUES_TO_UPDATE"] == "No values to update."
    # exposed on auth.error_codes
    auth = ak_auth()
    assert auth.error_codes["RATE_LIMIT_EXCEEDED"] == "Rate limit exceeded."


# ---------------------------------------------------------------------------
# Create (HTTP client surface)
# ---------------------------------------------------------------------------


async def test_create_returns_raw_key_and_stores_hash():
    auth = ak_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        resp = await client.post("/api/auth/api-key/create", json={"name": "ci"})
        assert resp.status_code == 200, resp.text
        body = resp.json()
        raw = body["key"]
        assert len(raw) == 64  # defaultKeyLength, no prefix
        assert body["name"] == "ci"
        assert body["start"] == raw[:6]
        row = await _row(auth, body["id"])
        assert row["key"] == default_key_hasher(raw)  # hashed, prefix inside hash
        assert row["referenceId"]  # owner set to session user


async def test_create_prefix_is_inside_hash_and_start():
    auth = ak_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        resp = await client.post("/api/auth/api-key/create", json={"prefix": "ba_"})
        body = resp.json()
        raw = body["key"]
        assert raw.startswith("ba_")
        assert len(raw) == 64 + 3
        assert body["start"] == raw[:6]
        row = await _row(auth, body["id"])
        assert row["key"] == default_key_hasher(raw)


async def test_create_client_cannot_set_server_only_props():
    auth = ak_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        for prop in [
            {"remaining": 5},
            {"refillAmount": 5, "refillInterval": 1000},
            {"rateLimitMax": 3},
            {"rateLimitTimeWindow": 1000},
            {"rateLimitEnabled": False},
            {"permissions": {"files": ["read"]}},
        ]:
            resp = await client.post("/api/auth/api-key/create", json=prop)
            assert resp.status_code == 400, prop
            assert resp.json()["code"] == "SERVER_ONLY_PROPERTY"


async def test_create_metadata_disabled_and_type():
    auth = ak_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        resp = await client.post(
            "/api/auth/api-key/create", json={"metadata": {"a": 1}}
        )
        assert resp.status_code == 400
        assert resp.json()["code"] == "METADATA_DISABLED"

    auth = ak_auth({"enable_metadata": True})
    async with make_client(auth) as client:
        await sign_up(client)
        resp = await client.post("/api/auth/api-key/create", json={"metadata": "nope"})
        assert resp.status_code == 400
        assert resp.json()["code"] == "INVALID_METADATA_TYPE"


async def test_create_metadata_round_trip():
    auth = ak_auth({"enable_metadata": True})
    async with make_client(auth) as client:
        await sign_up(client)
        created = await client.post(
            "/api/auth/api-key/create", json={"metadata": {"tier": "gold"}}
        )
        assert created.json()["metadata"] == {"tier": "gold"}
        key_id = created.json()["id"]
        row = await _row(auth, key_id)
        assert row["metadata"] == '{"tier": "gold"}'  # stored stringified
        got = await client.get(f"/api/auth/api-key/get?id={key_id}")
        assert got.json()["metadata"] == {"tier": "gold"}


async def test_create_refill_pair_required():
    auth = ak_auth()
    ctx = server_ctx(auth, "/api-key/create")
    with pytest.raises(APIError) as e:
        await _plugin(auth).create_api_key(ctx, userId="u1", refillAmount=5)
    assert e.value.code == "REFILL_AMOUNT_AND_INTERVAL_REQUIRED"
    with pytest.raises(APIError) as e:
        await _plugin(auth).create_api_key(ctx, userId="u1", refillInterval=1000)
    assert e.value.code == "REFILL_INTERVAL_AND_AMOUNT_REQUIRED"


async def test_create_expires_in_range_and_disabled():
    auth = ak_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        # minExpiresIn 1 day -> 3600s (0.04 days) is too small
        resp = await client.post("/api/auth/api-key/create", json={"expiresIn": 3600})
        assert resp.json()["code"] == "EXPIRES_IN_IS_TOO_SMALL"
        # maxExpiresIn 365 days
        resp = await client.post(
            "/api/auth/api-key/create", json={"expiresIn": 400 * 86400}
        )
        assert resp.json()["code"] == "EXPIRES_IN_IS_TOO_LARGE"

    auth = ak_auth({"key_expiration": {"disable_custom_expires_time": True}})
    async with make_client(auth) as client:
        await sign_up(client)
        resp = await client.post(
            "/api/auth/api-key/create", json={"expiresIn": 10 * 86400}
        )
        assert resp.json()["code"] == "KEY_DISABLED_EXPIRATION"


async def test_create_prefix_and_name_length_and_required():
    auth = ak_auth({"maximum_prefix_length": 4})
    async with make_client(auth) as client:
        await sign_up(client)
        resp = await client.post(
            "/api/auth/api-key/create", json={"prefix": "toolongprefix"}
        )
        assert resp.json()["code"] == "INVALID_PREFIX_LENGTH"

    auth = ak_auth({"maximum_name_length": 3})
    async with make_client(auth) as client:
        await sign_up(client)
        resp = await client.post("/api/auth/api-key/create", json={"name": "waytoolong"})
        assert resp.json()["code"] == "INVALID_NAME_LENGTH"

    auth = ak_auth({"require_name": True})
    async with make_client(auth) as client:
        await sign_up(client)
        resp = await client.post("/api/auth/api-key/create", json={})
        assert resp.json()["code"] == "NAME_REQUIRED"


async def test_create_requires_session():
    auth = ak_auth()
    async with make_client(auth) as client:
        resp = await client.post("/api/auth/api-key/create", json={"name": "x"})
        assert resp.status_code == 401
        assert resp.json()["code"] == "UNAUTHORIZED_SESSION"


# ---------------------------------------------------------------------------
# Verify (server-only) + validate pipeline
# ---------------------------------------------------------------------------


async def _create_server_key(auth, **body) -> str:
    ctx = server_ctx(auth, "/api-key/create")
    created = await _plugin(auth).create_api_key(ctx, **body)
    return created["key"]


async def test_verify_happy_path_strips_key_and_decrements():
    auth = ak_auth()
    raw = await _create_server_key(auth, userId="u1", remaining=3)
    ctx = server_ctx(auth)
    result = await _plugin(auth).verify_api_key(ctx, key=raw)
    assert result["valid"] is True
    assert result["error"] is None
    assert "key" not in result["key"]  # raw/hashed key stripped from returned row
    assert result["key"]["remaining"] == 2


async def test_verify_invalid_key():
    auth = ak_auth()
    ctx = server_ctx(auth)
    result = await _plugin(auth).verify_api_key(ctx, key="does-not-exist" + "x" * 60)
    assert result["valid"] is False
    assert result["error"]["code"] == "INVALID_API_KEY"
    assert result["key"] is None


async def test_verify_disabled_key():
    auth = ak_auth()
    raw = await _create_server_key(auth, userId="u1")
    row = await auth.adapter.find_one("apikey", [Where("key", default_key_hasher(raw))])
    await auth.adapter.update("apikey", [Where("id", row["id"])], {"enabled": False})
    result = await _plugin(auth).verify_api_key(server_ctx(auth), key=raw)
    assert result["valid"] is False
    assert result["error"]["code"] == "KEY_DISABLED"


async def test_verify_expired_key_is_deleted():
    auth = ak_auth()
    raw = await _create_server_key(auth, userId="u1")
    row = await auth.adapter.find_one("apikey", [Where("key", default_key_hasher(raw))])
    await auth.adapter.update(
        "apikey", [Where("id", row["id"])], {"expiresAt": utcnow() - timedelta(days=1)}
    )
    result = await _plugin(auth).verify_api_key(server_ctx(auth), key=raw)
    assert result["valid"] is False
    assert result["error"]["code"] == "KEY_EXPIRED"
    assert await _row(auth, row["id"]) is None  # deleted


async def test_verify_exhausted_non_refillable_is_deleted():
    auth = ak_auth()
    raw = await _create_server_key(auth, userId="u1", remaining=1)
    ctx = server_ctx(auth)
    first = await _plugin(auth).verify_api_key(ctx, key=raw)  # 1 -> 0
    assert first["valid"] is True
    second = await _plugin(auth).verify_api_key(ctx, key=raw)  # exhausted
    assert second["valid"] is False
    assert second["error"]["code"] == "USAGE_EXCEEDED"


async def test_verify_permissions_gate():
    auth = ak_auth()
    raw = await _create_server_key(
        auth, userId="u1", permissions={"files": ["read", "write"]}
    )
    ctx = server_ctx(auth)
    ok = await _plugin(auth).verify_api_key(ctx, key=raw, permissions={"files": ["read"]})
    assert ok["valid"] is True
    bad = await _plugin(auth).verify_api_key(
        ctx, key=raw, permissions={"files": ["delete"]}
    )
    assert bad["valid"] is False
    assert bad["error"]["code"] == "KEY_NOT_FOUND"


async def test_verify_config_scoping():
    auth = ak_auth([{"config_id": "default"}, {"config_id": "other"}])
    raw = await _create_server_key(auth, userId="u1", configId="other")
    ctx = server_ctx(auth)
    # verifying under the wrong scoped config fails
    wrong = await _plugin(auth).verify_api_key(ctx, key=raw, config_id="default")
    assert wrong["valid"] is False
    assert wrong["error"]["code"] == "INVALID_API_KEY"
    # scoped to its own config, or unscoped, succeeds
    right = await _plugin(auth).verify_api_key(ctx, key=raw, config_id="other")
    assert right["valid"] is True
    unscoped = await _plugin(auth).verify_api_key(ctx, key=raw)
    assert unscoped["valid"] is True


async def test_verify_rate_limited_returns_wrapped_error():
    auth = ak_auth()
    raw = await _create_server_key(
        auth, userId="u1", rateLimitMax=1, rateLimitTimeWindow=100000
    )
    ctx = server_ctx(auth)
    first = await _plugin(auth).verify_api_key(ctx, key=raw)
    assert first["valid"] is True
    second = await _plugin(auth).verify_api_key(ctx, key=raw)
    assert second["valid"] is False
    assert second["error"]["code"] == "RATE_LIMITED"
    # verify-api-key.ts:579 spreads `...error.body` (details: {tryAgainIn}) into the
    # wrapped error object — nested under "details", not a top-level "tryAgainIn".
    assert second["error"]["details"]["tryAgainIn"] >= 1


# ---------------------------------------------------------------------------
# Get / Update / Delete / List
# ---------------------------------------------------------------------------


async def test_get_ownership_isolation():
    auth = ak_auth()
    async with make_client(auth) as owner:
        await sign_up(owner)
        created = await owner.post("/api/auth/api-key/create", json={"name": "mine"})
        key_id = created.json()["id"]
        got = await owner.get(f"/api/auth/api-key/get?id={key_id}")
        assert got.status_code == 200
        assert "key" not in got.json()  # stripped

    async with make_client(auth) as other:
        await sign_up(other, email="eve@example.com")
        got = await other.get(f"/api/auth/api-key/get?id={key_id}")
        assert got.status_code == 404
        assert got.json()["code"] == "KEY_NOT_FOUND"


async def test_update_no_values_and_fields():
    auth = ak_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        created = await client.post("/api/auth/api-key/create", json={"name": "a"})
        key_id = created.json()["id"]
        empty = await client.post("/api/auth/api-key/update", json={"keyId": key_id})
        assert empty.status_code == 400
        assert empty.json()["code"] == "NO_VALUES_TO_UPDATE"
        upd = await client.post(
            "/api/auth/api-key/update", json={"keyId": key_id, "name": "b", "enabled": False}
        )
        assert upd.status_code == 200
        assert upd.json()["name"] == "b"
        assert upd.json()["enabled"] is False


async def test_update_client_cannot_set_server_only():
    auth = ak_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        created = await client.post("/api/auth/api-key/create", json={"name": "a"})
        key_id = created.json()["id"]
        resp = await client.post(
            "/api/auth/api-key/update", json={"keyId": key_id, "remaining": 5}
        )
        assert resp.status_code == 400
        assert resp.json()["code"] == "SERVER_ONLY_PROPERTY"


async def test_delete_and_banned_gate():
    auth = ak_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        created = await client.post("/api/auth/api-key/create", json={"name": "a"})
        key_id = created.json()["id"]
        resp = await client.post("/api/auth/api-key/delete", json={"keyId": key_id})
        assert resp.status_code == 200
        assert resp.json()["success"] is True
        assert await _row(auth, key_id) is None

    async with make_client(auth) as client:
        data = await sign_up(client, email="ban@example.com")
        created = await client.post("/api/auth/api-key/create", json={"name": "b"})
        key_id = created.json()["id"]
        await auth.adapter.update(
            "user", [Where("id", data["user"]["id"])], {"banned": True}
        )
        resp = await client.post("/api/auth/api-key/delete", json={"keyId": key_id})
        assert resp.status_code == 401
        assert resp.json()["code"] == "USER_BANNED"


async def test_list_filters_and_pagination():
    auth = ak_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        for i in range(3):
            await client.post("/api/auth/api-key/create", json={"name": f"k{i}"})
        listed = await client.get("/api/auth/api-key/list")
        assert listed.status_code == 200
        body = listed.json()
        assert body["total"] == 3
        assert len(body["apiKeys"]) == 3
        assert all("key" not in k for k in body["apiKeys"])
        page = await client.get("/api/auth/api-key/list?limit=2&offset=1")
        assert len(page.json()["apiKeys"]) == 2


async def test_list_isolated_per_user():
    auth = ak_auth()
    async with make_client(auth) as a:
        await sign_up(a)
        await a.post("/api/auth/api-key/create", json={"name": "a"})
    async with make_client(auth) as b:
        await sign_up(b, email="b@example.com")
        listed = await b.get("/api/auth/api-key/list")
        assert listed.json()["total"] == 0


# ---------------------------------------------------------------------------
# /get-session session-mock before-hook
# ---------------------------------------------------------------------------


async def _seed_user_key(auth) -> tuple[str, str]:
    """Sign a user up (creating the user row), return (user_id, raw_key)."""
    async with make_client(auth) as client:
        data = await sign_up(client)
    raw = await _create_server_key(auth, userId=data["user"]["id"])
    return data["user"]["id"], raw


async def test_session_mock_valid_key_returns_session():
    auth = ak_auth({"enable_session_for_api_keys": True})
    user_id, raw = await _seed_user_key(auth)
    async with make_client(auth) as client:
        resp = await client.get("/api/auth/get-session", headers={"x-api-key": raw})
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["user"]["id"] == user_id
        assert body["session"]["userId"] == user_id
        assert body["session"]["token"] == raw


async def test_session_mock_length_gate():
    auth = ak_auth({"enable_session_for_api_keys": True})
    async with make_client(auth) as client:
        resp = await client.get("/api/auth/get-session", headers={"x-api-key": "short"})
        assert resp.status_code == 403
        assert resp.json()["code"] == "INVALID_API_KEY"


async def test_session_mock_disabled_key():
    auth = ak_auth({"enable_session_for_api_keys": True})
    _, raw = await _seed_user_key(auth)
    row = await auth.adapter.find_one("apikey", [Where("key", default_key_hasher(raw))])
    await auth.adapter.update("apikey", [Where("id", row["id"])], {"enabled": False})
    async with make_client(auth) as client:
        resp = await client.get("/api/auth/get-session", headers={"x-api-key": raw})
        assert resp.status_code == 401
        assert resp.json()["code"] == "KEY_DISABLED"


async def test_session_mock_consumes_rate_limit():
    auth = ak_auth({"enable_session_for_api_keys": True})
    async with make_client(auth) as client:
        data = await sign_up(client)
    raw = await _create_server_key(
        auth, userId=data["user"]["id"], rateLimitMax=1, rateLimitTimeWindow=100000
    )
    async with make_client(auth) as client:
        first = await client.get("/api/auth/get-session", headers={"x-api-key": raw})
        assert first.status_code == 200
        second = await client.get("/api/auth/get-session", headers={"x-api-key": raw})
        assert second.status_code == 429
        # rate-limit.ts:87 + verify-api-key.ts:293-297 — the thrown 429 carries
        # `code: "RATE_LIMITED"` and `details: {tryAgainIn}` on the JSON body itself
        # (better-call serializes APIError.body verbatim), not just inside the
        # server-only verify wrapper's `error` object.
        body = second.json()
        assert body["code"] == "RATE_LIMITED"
        assert body["details"]["tryAgainIn"] >= 1


async def test_session_mock_rejects_org_owned_key():
    # references:"organization" keys must never mock a session.
    org = OrganizationPlugin()
    auth = make_auth(
        plugins=[
            ApiKeyPlugin({"references": "organization", "enable_session_for_api_keys": True}),
            org,
        ]
    )
    async with make_client(auth) as client:
        data = await sign_up(client)
    org_id = "org-1"
    await auth.adapter.create(
        "organization", {"id": org_id, "name": "Acme", "slug": "acme", "createdAt": utcnow()}
    )
    await auth.adapter.create(
        "member",
        {
            "id": "m1",
            "organizationId": org_id,
            "userId": data["user"]["id"],
            "role": "owner",
            "createdAt": utcnow(),
        },
    )
    raw = await _create_server_key(
        auth, userId=data["user"]["id"], organizationId=org_id
    )
    async with make_client(auth) as client:
        resp = await client.get("/api/auth/get-session", headers={"x-api-key": raw})
        assert resp.status_code == 401
        assert resp.json()["code"] == "INVALID_REFERENCE_ID_FROM_API_KEY"


# ---------------------------------------------------------------------------
# Concurrency — the guarded-CAS trio (single-winner)
# ---------------------------------------------------------------------------


async def test_cas_remaining_single_winner():
    auth = ak_auth()
    raw = await _create_server_key(auth, userId="u1", remaining=1)
    plugin = _plugin(auth)
    results = await asyncio.gather(
        *(plugin.verify_api_key(server_ctx(auth), key=raw) for _ in range(8))
    )
    successes = [r for r in results if r["valid"]]
    assert len(successes) == 1


async def test_cas_rate_limit_single_winner():
    auth = ak_auth()
    raw = await _create_server_key(
        auth, userId="u1", rateLimitMax=1, rateLimitTimeWindow=100000
    )
    plugin = _plugin(auth)
    results = await asyncio.gather(
        *(plugin.verify_api_key(server_ctx(auth), key=raw) for _ in range(8))
    )
    successes = [r for r in results if r["valid"]]
    denied = [r for r in results if not r["valid"] and r["error"]["code"] == "RATE_LIMITED"]
    assert len(successes) == 1
    assert len(denied) == 7


async def test_cas_refill_single_winner():
    auth = ak_auth()
    raw = await _create_server_key(
        auth, userId="u1", remaining=1, refillAmount=10, refillInterval=1000
    )
    row = await auth.adapter.find_one("apikey", [Where("key", default_key_hasher(raw))])
    # make the refill due
    await auth.adapter.update(
        "apikey",
        [Where("id", row["id"])],
        {"lastRefillAt": utcnow() - timedelta(seconds=5)},
    )
    plugin = _plugin(auth)
    n = 10
    results = await asyncio.gather(
        *(plugin.verify_api_key(server_ctx(auth), key=raw) for _ in range(n))
    )
    assert all(r["valid"] for r in results)
    final = await _row(auth, row["id"])
    # exactly one refill happened (remaining reset once to refillAmount), then n decrements
    assert final["remaining"] == 10 - n


# ---------------------------------------------------------------------------
# Organization-owned keys
# ---------------------------------------------------------------------------


def _org_auth():
    org = OrganizationPlugin()
    return make_auth(plugins=[ApiKeyPlugin({"references": "organization"}), org])


async def _seed_org(auth, user_id: str, role: str = "owner") -> str:
    org_id = "org-1"
    await auth.adapter.create(
        "organization", {"id": org_id, "name": "Acme", "slug": "acme", "createdAt": utcnow()}
    )
    await auth.adapter.create(
        "member",
        {
            "id": "m1",
            "organizationId": org_id,
            "userId": user_id,
            "role": role,
            "createdAt": utcnow(),
        },
    )
    return org_id


async def test_org_create_requires_org_plugin():
    auth = ak_auth({"references": "organization"})  # no organization plugin
    ctx = server_ctx(auth, "/api-key/create")
    with pytest.raises(APIError) as e:
        await _plugin(auth).create_api_key(ctx, userId="u1", organizationId="org-1")
    assert e.value.code == "ORGANIZATION_PLUGIN_REQUIRED"


async def test_org_create_requires_organization_id():
    auth = _org_auth()
    ctx = server_ctx(auth, "/api-key/create")
    with pytest.raises(APIError) as e:
        await _plugin(auth).create_api_key(ctx, userId="u1")
    assert e.value.code == "ORGANIZATION_ID_REQUIRED"


async def test_org_owner_can_create():
    auth = _org_auth()
    async with make_client(auth) as client:
        data = await sign_up(client)
    org_id = await _seed_org(auth, data["user"]["id"], role="owner")
    ctx = server_ctx(auth, "/api-key/create")
    created = await _plugin(auth).create_api_key(
        ctx, userId=data["user"]["id"], organizationId=org_id
    )
    row = await _row(auth, created["id"])
    assert row["referenceId"] == org_id


async def test_org_non_member_rejected():
    auth = _org_auth()
    async with make_client(auth) as client:
        data = await sign_up(client)
    await _seed_org(auth, "someone-else", role="owner")
    ctx = server_ctx(auth, "/api-key/create")
    with pytest.raises(APIError) as e:
        await _plugin(auth).create_api_key(
            ctx, userId=data["user"]["id"], organizationId="org-1"
        )
    assert e.value.code == "USER_NOT_MEMBER_OF_ORGANIZATION"


async def test_org_insufficient_permission():
    auth = _org_auth()
    async with make_client(auth) as client:
        data = await sign_up(client)
    org_id = await _seed_org(auth, data["user"]["id"], role="member")
    ctx = server_ctx(auth, "/api-key/create")
    with pytest.raises(APIError) as e:
        await _plugin(auth).create_api_key(
            ctx, userId=data["user"]["id"], organizationId=org_id
        )
    assert e.value.code == "INSUFFICIENT_API_KEY_PERMISSIONS"


# ---------------------------------------------------------------------------
# delete-all-expired (server-only)
# ---------------------------------------------------------------------------


async def test_delete_all_expired():
    auth = ak_auth()
    raw = await _create_server_key(auth, userId="u1")
    row = await auth.adapter.find_one("apikey", [Where("key", default_key_hasher(raw))])
    await auth.adapter.update(
        "apikey", [Where("id", row["id"])], {"expiresAt": utcnow() - timedelta(days=1)}
    )
    result = await _plugin(auth).delete_all_expired_api_keys(server_ctx(auth))
    assert result["success"] is True
    assert await _row(auth, row["id"]) is None


# ---------------------------------------------------------------------------
# Config normalization
# ---------------------------------------------------------------------------


def test_secondary_storage_raises_not_implemented():
    with pytest.raises(NotImplementedError):
        ApiKeyPlugin({"storage": "secondary-storage"})


def test_duplicate_config_id_rejected():
    with pytest.raises(ValueError, match="unique"):
        ApiKeyPlugin([{"config_id": "dup"}, {"config_id": "dup"}])
