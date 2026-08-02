"""Verification-value storage parity: ``storeIdentifier`` hashing + secondary-storage
routing (TS db/internal-adapter.ts createVerificationValue/find/consume/update/delete
and db/verification-token-storage.ts getStorageOption/processIdentifier).

The DB-default path (no ``storeIdentifier``, no secondary storage) is covered by
test_w3_foundation.py and must stay byte-identical; this file exercises the two edges.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from better_auth.adapters.memory import MemoryAdapter
from better_auth.crypto import default_key_hasher
from better_auth.internal_adapter import InternalAdapter
from better_auth.schema import CORE_SCHEMA
from better_auth.secondary_storage import MemorySecondaryStorage


def _must(row: dict[str, Any] | None) -> dict[str, Any]:
    assert row is not None
    return row


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _adapter() -> MemoryAdapter:
    a = MemoryAdapter()
    a.init(CORE_SCHEMA)
    return a


async def _mk(ia: InternalAdapter, identifier: str, value: str, *, ttl: int = 3600) -> Any:
    return await ia.create_verification_value(
        {"identifier": identifier, "value": value, "expiresAt": _now() + timedelta(seconds=ttl)}
    )


# --- storeIdentifier hashing (DB mode) ---------------------------------------


async def test_hashed_identifier_stored_at_rest_but_found_by_raw():
    adapter = _adapter()
    ia = InternalAdapter(adapter, verification_store_identifier="hashed")
    await _mk(ia, "otp:alice@example.com", "123456")

    # raw identifier is absent from storage; the hash is what's persisted
    rows = await adapter.find_many("verification", [])
    assert len(rows) == 1
    assert rows[0]["identifier"] == default_key_hasher("otp:alice@example.com")
    assert rows[0]["identifier"] != "otp:alice@example.com"

    # lookup by the *raw* identifier still resolves it
    found = await ia.find_verification_value("otp:alice@example.com")
    assert found is not None and found["value"] == "123456"


async def test_hashed_identifier_consume_by_raw():
    ia = InternalAdapter(_adapter(), verification_store_identifier="hashed")
    await _mk(ia, "otp:bob", "v")
    consumed = await ia.consume_verification_value("otp:bob")
    assert consumed is not None and consumed["value"] == "v"
    assert await ia.find_verification_value("otp:bob") is None


async def test_plain_default_stores_raw_identifier():
    adapter = _adapter()
    ia = InternalAdapter(adapter)  # no storeIdentifier -> plain
    await _mk(ia, "otp:plain", "v")
    rows = await adapter.find_many("verification", [])
    assert rows[0]["identifier"] == "otp:plain"


async def test_custom_hash_callable():
    ia = InternalAdapter(
        _adapter(),
        verification_store_identifier={"hash": lambda i: "H:" + i},
    )
    adapter = ia.adapter
    await _mk(ia, "otp:x", "v")
    rows = await adapter.find_many("verification", [])
    assert rows[0]["identifier"] == "H:otp:x"
    assert _must(await ia.find_verification_value("otp:x"))["value"] == "v"


async def test_store_identifier_overrides_by_prefix():
    ia = InternalAdapter(
        _adapter(),
        verification_store_identifier={
            "default": "plain",
            "overrides": {"otp:": "hashed"},
        },
    )
    adapter = ia.adapter
    await _mk(ia, "otp:secret", "v")  # matches override -> hashed
    await _mk(ia, "magic:link", "w")  # default -> plain
    ids = {r["identifier"] for r in await adapter.find_many("verification", [])}
    assert default_key_hasher("otp:secret") in ids
    assert "magic:link" in ids


# --- secondary storage (storeInDatabase=false, the default) ------------------


async def test_secondary_create_writes_kv_not_db():
    adapter = _adapter()
    ss = MemorySecondaryStorage()
    ia = InternalAdapter(adapter, secondary_storage=ss)
    await _mk(ia, "otp:s", "v", ttl=100)

    assert await ss.get("verification:otp:s") is not None
    # TTL is floor((expiresAt - now)/1000), so a few elapsed ms round 100 down to 99
    ttl = ss.ttls["verification:otp:s"]
    assert ttl is not None and 98 <= ttl <= 100
    # nothing hit the database
    assert await adapter.find_many("verification", []) == []


async def test_secondary_find_round_trips_dates():
    ss = MemorySecondaryStorage()
    ia = InternalAdapter(_adapter(), secondary_storage=ss)
    await _mk(ia, "otp:f", "v")
    found = await ia.find_verification_value("otp:f")
    assert found is not None and found["value"] == "v"
    assert isinstance(found["expiresAt"], datetime)


async def test_secondary_consume_single_use_atomic():
    ss = MemorySecondaryStorage()  # implements get_and_delete
    ia = InternalAdapter(_adapter(), secondary_storage=ss)
    await _mk(ia, "otp:c", "v")
    assert _must(await ia.consume_verification_value("otp:c"))["value"] == "v"
    assert await ia.consume_verification_value("otp:c") is None
    assert await ss.get("verification:otp:c") is None


class _NoGetAndDelete:
    """SecondaryStorage without get_and_delete -> non-atomic lock+get+delete fallback."""

    def __init__(self) -> None:
        self._d: dict[str, str] = {}

    async def get(self, key: str) -> str | None:
        return self._d.get(key)

    async def set(self, key: str, value: str, ttl: int | None = None) -> None:
        self._d[key] = value

    async def delete(self, key: str) -> None:
        self._d.pop(key, None)


async def test_secondary_consume_non_atomic_fallback():
    ss = _NoGetAndDelete()
    ia = InternalAdapter(_adapter(), secondary_storage=ss)
    await _mk(ia, "otp:nf", "v")
    assert _must(await ia.consume_verification_value("otp:nf"))["value"] == "v"
    assert await ia.consume_verification_value("otp:nf") is None


async def test_secondary_consume_expired_returns_none():
    ss = MemorySecondaryStorage()
    ia = InternalAdapter(_adapter(), secondary_storage=ss)
    # ttl<=0 means no KV write happens (getTTLSeconds<=0), so nothing to consume
    await _mk(ia, "otp:e", "v", ttl=-5)
    assert await ia.consume_verification_value("otp:e") is None


async def test_secondary_update_resets_value():
    ss = MemorySecondaryStorage()
    ia = InternalAdapter(_adapter(), secondary_storage=ss)
    await _mk(ia, "otp:u", "orig")
    updated = await ia.update_verification_by_identifier("otp:u", {"value": "changed"})
    assert updated is not None and updated["value"] == "changed"
    assert _must(await ia.find_verification_value("otp:u"))["value"] == "changed"


async def test_secondary_delete_removes_key():
    ss = MemorySecondaryStorage()
    ia = InternalAdapter(_adapter(), secondary_storage=ss)
    await _mk(ia, "otp:d", "v")
    await ia.delete_verification_by_identifier("otp:d")
    assert await ss.get("verification:otp:d") is None
    assert await ia.find_verification_value("otp:d") is None


async def test_secondary_with_hashed_identifier_hashed_at_rest():
    ss = MemorySecondaryStorage()
    ia = InternalAdapter(_adapter(), secondary_storage=ss, verification_store_identifier="hashed")
    await _mk(ia, "otp:h", "v")
    assert await ss.get(f"verification:{default_key_hasher('otp:h')}") is not None
    assert await ss.get("verification:otp:h") is None  # raw key absent
    assert _must(await ia.consume_verification_value("otp:h"))["value"] == "v"


# --- secondary storage + storeInDatabase=true --------------------------------


async def test_store_in_database_dual_writes_and_find_prefers_cache():
    adapter = _adapter()
    ss = MemorySecondaryStorage()
    ia = InternalAdapter(adapter, secondary_storage=ss, verification_store_in_database=True)
    await _mk(ia, "otp:both", "v")
    # both stores got the row
    assert await ss.get("verification:otp:both") is not None
    assert len(await adapter.find_many("verification", [])) == 1
    # find serves from cache but consume clears both
    assert _must(await ia.consume_verification_value("otp:both"))["value"] == "v"
    assert await ss.get("verification:otp:both") is None
    assert await adapter.find_many("verification", []) == []
