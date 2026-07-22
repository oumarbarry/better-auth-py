"""Internal-adapter seam: database hooks, id-strip semantics, secondary-storage sessions."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

import pytest

from better_auth.adapters.memory import MemoryAdapter
from better_auth.internal_adapter import InternalAdapter, _js_iso
from better_auth.schema import CORE_SCHEMA
from better_auth.secondary_storage import MemorySecondaryStorage


def _row(value: dict[str, Any] | None) -> dict[str, Any]:
    assert value is not None
    return value


def _raw(value: str | None) -> str:
    assert value is not None
    return value


def _adapter() -> MemoryAdapter:
    a = MemoryAdapter()
    a.init(CORE_SCHEMA)
    return a


async def _user(ia: InternalAdapter, **overrides: Any) -> dict[str, Any]:
    data = {"name": "Ada", "email": "ada@example.com"}
    data.update(overrides)
    return _row(await ia.create_user(data))


# --- id-strip semantics (A1 deviation (a), fixed at the seam) -----------------


async def test_create_user_strips_caller_id():
    ia = InternalAdapter(_adapter())
    row = _row(await ia.create_user({"name": "Ada", "email": "a@x.com", "id": "attacker-id"}))
    assert row["id"] != "attacker-id"
    assert len(row["id"]) == 32  # a freshly generated base62 id


async def test_force_allow_id_keeps_caller_id():
    ia = InternalAdapter(_adapter())
    row = _row(
        await ia.create_user(
            {"name": "Ada", "email": "a@x.com", "id": "trusted-id"}, force_allow_id=True
        )
    )
    assert row["id"] == "trusted-id"


async def test_create_lowercases_email():
    ia = InternalAdapter(_adapter())
    row = _row(await ia.create_user({"name": "Ada", "email": "Ada@Example.COM"}))
    assert row["email"] == "ada@example.com"


# --- database hooks: abort / merge / after ------------------------------------


async def test_before_create_merge():
    hooks = {"user": {"create": {"before": lambda data: {"data": {"name": "Merged"}}}}}
    ia = InternalAdapter(_adapter(), database_hooks=hooks)
    row = await _user(ia)
    assert row["name"] == "Merged"


async def test_before_create_abort_returns_none_and_creates_nothing():
    ia_adapter = _adapter()
    hooks = {"user": {"create": {"before": lambda data: False}}}
    ia = InternalAdapter(ia_adapter, database_hooks=hooks)
    assert await ia.create_user({"name": "A", "email": "a@x.com"}) is None
    assert await ia_adapter.count("user") == 0


async def test_after_create_fires_with_row():
    seen: list[Any] = []
    hooks = {"user": {"create": {"after": lambda row: seen.append(row)}}}
    ia = InternalAdapter(_adapter(), database_hooks=hooks)
    row = await _user(ia)
    assert seen == [row]


async def test_before_update_merge_and_abort():
    ia = InternalAdapter(
        _adapter(),
        database_hooks={"user": {"update": {"before": lambda data: {"data": {"name": "Hooked"}}}}},
    )
    row = await _user(ia)
    updated = _row(await ia.update_user(row["id"], {"name": "Ignored"}))
    assert updated["name"] == "Hooked"


async def test_before_delete_abort_keeps_row():
    adapter = _adapter()
    ia = InternalAdapter(adapter, database_hooks={"user": {"delete": {"before": lambda e: False}}})
    row = await _user(ia)
    await ia.delete_user(row["id"])
    assert await adapter.count("user") == 1


async def test_after_delete_receives_snapshot():
    seen: list[Any] = []
    ia = InternalAdapter(
        _adapter(), database_hooks={"user": {"delete": {"after": lambda e: seen.append(e)}}}
    )
    row = await _user(ia)
    await ia.delete_user(row["id"])
    assert len(seen) == 1 and seen[0]["id"] == row["id"]


async def test_async_hooks_supported():
    seen: list[Any] = []

    async def before(data: Any) -> Any:
        return {"data": {"name": "Async"}}

    async def after(row: Any) -> None:
        seen.append(row)

    ia = InternalAdapter(
        _adapter(), database_hooks={"user": {"create": {"before": before, "after": after}}}
    )
    row = await _user(ia)
    assert row["name"] == "Async"
    assert seen == [row]


# --- after-transaction queue --------------------------------------------------


async def test_after_hooks_deferred_until_commit():
    order: list[str] = []
    hooks = {"user": {"create": {"after": lambda row: order.append("after")}}}
    ia = InternalAdapter(_adapter(), database_hooks=hooks)

    async def work(tx: InternalAdapter) -> None:
        await tx.create_user({"name": "A", "email": "a@x.com"})
        order.append("inside-tx")  # runs before any queued after-hook

    await ia.transaction(work)
    assert order == ["inside-tx", "after"]


async def test_after_hooks_not_fired_on_rollback():
    fired: list[Any] = []
    adapter = _adapter()
    ia = InternalAdapter(adapter, database_hooks={"user": {"create": {"after": fired.append}}})

    async def work(tx: InternalAdapter) -> None:
        await tx.create_user({"name": "A", "email": "a@x.com"})
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError):
        await ia.transaction(work)
    assert fired == []
    assert await adapter.count("user") == 0


# --- secondary-storage session wire format ------------------------------------


async def test_session_kv_wire_format():
    ss = MemorySecondaryStorage()
    adapter = _adapter()
    ia = InternalAdapter(adapter, secondary_storage=ss, session_expires_in=3600)
    user = _row(await ia.create_user({"name": "Ada", "email": "ada@x.com"}, force_allow_id=True))

    session = _row(await ia.create_session(user["id"]))
    token = session["token"]

    # session must NOT be in the database (KV-only mode)
    assert await adapter.count("session") == 0

    # key = token -> {"session": ..., "user": ...}
    payload = json.loads(_raw(await ss.get(token)))
    assert list(payload.keys()) == ["session", "user"]
    assert payload["session"]["token"] == token
    assert payload["user"]["id"] == user["id"]
    # dates serialized as JS ISO strings (millisecond precision, Z suffix)
    assert payload["session"]["expiresAt"].endswith("Z")
    assert payload["session"]["expiresAt"] == _js_iso(session["expiresAt"])

    # key = active-sessions-<userId> -> [{"token", "expiresAt": <epoch ms int>}]
    list_raw = _raw(await ss.get(f"active-sessions-{user['id']}"))
    assert list_raw.startswith('[{"token":')  # compact, token first
    entries = json.loads(list_raw)
    assert entries == [{"token": token, "expiresAt": int(session["expiresAt"].timestamp() * 1000)}]
    assert isinstance(entries[0]["expiresAt"], int)


async def test_session_kv_ttl_matches_expiry():
    ss = MemorySecondaryStorage()
    ia = InternalAdapter(_adapter(), secondary_storage=ss, session_expires_in=3600)
    user = _row(await ia.create_user({"name": "Ada", "email": "ada@x.com"}, force_allow_id=True))
    session = _row(await ia.create_session(user["id"]))
    # TTL is seconds-to-expiry, ~= session_expires_in
    assert 3595 <= _ttl(ss, session["token"]) <= 3600
    assert 3595 <= _ttl(ss, f"active-sessions-{user['id']}") <= 3600


def _ttl(ss: MemorySecondaryStorage, key: str) -> int:
    value = ss.ttls[key]
    assert value is not None
    return value


async def test_find_session_from_kv_round_trips_dates():
    ss = MemorySecondaryStorage()
    ia = InternalAdapter(_adapter(), secondary_storage=ss)
    user = _row(await ia.create_user({"name": "Ada", "email": "ada@x.com"}, force_allow_id=True))
    session = _row(await ia.create_session(user["id"]))

    found = _row(await ia.find_session(session["token"]))
    assert found["user"]["id"] == user["id"]
    # expiresAt comes back as a tz-aware datetime, not the wire string
    assert isinstance(found["session"]["expiresAt"], datetime)


async def test_find_session_missing_returns_none():
    ss = MemorySecondaryStorage()
    ia = InternalAdapter(_adapter(), secondary_storage=ss)
    assert await ia.find_session("nope") is None


async def test_delete_session_prunes_kv_and_list():
    ss = MemorySecondaryStorage()
    ia = InternalAdapter(_adapter(), secondary_storage=ss)
    user = _row(await ia.create_user({"name": "Ada", "email": "ada@x.com"}, force_allow_id=True))
    session = _row(await ia.create_session(user["id"]))

    await ia.delete_session(session["token"])
    assert await ss.get(session["token"]) is None
    # the only session is gone, so its active-sessions list is removed
    assert await ss.get(f"active-sessions-{user['id']}") is None


async def test_list_sessions_from_kv():
    ss = MemorySecondaryStorage()
    ia = InternalAdapter(_adapter(), secondary_storage=ss)
    user = _row(await ia.create_user({"name": "Ada", "email": "ada@x.com"}, force_allow_id=True))
    s1 = _row(await ia.create_session(user["id"]))
    s2 = _row(await ia.create_session(user["id"]))

    tokens = {s["token"] for s in await ia.list_sessions(user["id"])}
    assert tokens == {s1["token"], s2["token"]}


async def test_active_sessions_list_ttl_is_furthest():
    ss = MemorySecondaryStorage()
    ia = InternalAdapter(_adapter(), secondary_storage=ss, session_expires_in=3600)
    user = _row(await ia.create_user({"name": "Ada", "email": "ada@x.com"}, force_allow_id=True))
    # a short "don't remember" session (1 day) then a long one (default) -> list TTL tracks longest
    await ia.create_session(user["id"], dont_remember_me=True)  # 1 day
    await ia.create_session(user["id"])  # 3600s
    # list holds both; furthest expiry is the 1-day session
    assert _ttl(ss, f"active-sessions-{user['id']}") > 3600  # dominated by the 1-day session


# --- session in database (no secondary storage) -------------------------------


async def test_session_goes_to_database_without_secondary_storage():
    adapter = _adapter()
    ia = InternalAdapter(adapter)
    user = await _user(ia)
    session = _row(await ia.create_session(user["id"]))
    assert await adapter.count("session") == 1
    found = _row(await ia.find_session(session["token"]))
    assert found["user"]["id"] == user["id"]
