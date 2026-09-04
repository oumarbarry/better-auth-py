"""Internal-adapter seam: database hooks, id-strip semantics, secondary-storage sessions."""

from __future__ import annotations

import json
import logging
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


@pytest.mark.parametrize("stored", ["invalid-json{{{", "null"])
async def test_list_sessions_skips_corrupt_entry_without_discarding_valid(stored: str):
    """TS ea38fcac7 (`if (!s) continue`, db/internal-adapter.ts:563) — a corrupt or
    JSON-`null` secondary-storage payload is skipped, never aborting the whole list
    (same guard TS already carries in `listSessions`, db/internal-adapter.ts:247-263)."""
    ss = MemorySecondaryStorage()
    ia = InternalAdapter(_adapter(), secondary_storage=ss)
    user = _row(await ia.create_user({"name": "Ada", "email": "ada@x.com"}, force_allow_id=True))
    s1 = _row(await ia.create_session(user["id"]))
    s2 = _row(await ia.create_session(user["id"]))
    s3 = _row(await ia.create_session(user["id"]))

    await ss.set(s2["token"], stored)

    tokens = [s["token"] for s in await ia.list_sessions(user["id"])]
    assert tokens == [s1["token"], s3["token"]]


async def test_list_sessions_returns_empty_when_active_list_is_corrupt():
    """TS `safeJSONParse(currentList) || []` (db/internal-adapter.ts:232-233) — a
    corrupt active-sessions list yields no sessions instead of raising."""
    ss = MemorySecondaryStorage()
    ia = InternalAdapter(_adapter(), secondary_storage=ss)
    user = _row(await ia.create_user({"name": "Ada", "email": "ada@x.com"}, force_allow_id=True))
    await ia.create_session(user["id"])

    await ss.set(f"active-sessions-{user['id']}", "invalid-json{{{")

    assert await ia.list_sessions(user["id"]) == []


# --- corrupt KV payloads: json.loads -> safeJSONParse parity (TS ea38fcac7) ----
#
# The same class of bug list_sessions was fixed for above: one corrupt KV entry must
# degrade gracefully (TS safeJSONParse), never 500 the request that carries it.


async def test_store_session_kv_recovers_from_corrupt_active_sessions_list():
    """TS internal-adapter.ts:413-414 (createSession's KV fn) —
    ``list = safeJSONParse(currentList) || [];`` A corrupt active-sessions list is
    treated as empty instead of raising when a new session is stored."""
    ss = MemorySecondaryStorage()
    ia = InternalAdapter(_adapter(), secondary_storage=ss, session_expires_in=3600)
    user = _row(await ia.create_user({"name": "Ada", "email": "ada@x.com"}, force_allow_id=True))
    await ss.set(f"active-sessions-{user['id']}", "invalid-json{{{")

    session = _row(await ia.create_session(user["id"]))

    entries = json.loads(_raw(await ss.get(f"active-sessions-{user['id']}")))
    assert entries == [
        {"token": session["token"], "expiresAt": int(session["expiresAt"].timestamp() * 1000)}
    ]


async def test_find_session_returns_none_on_corrupt_kv_payload_even_with_db_fallback():
    """TS internal-adapter.ts:489-493 — ``const s = safeJSONParse(sessionStringified);
    if (!s) return null;`` A corrupt KV blob is a hard miss returned immediately, with
    no fallback to the database even when store_session_in_database keeps the row
    there (the fallback branch only runs when the KV key is absent, not when it's
    corrupt)."""
    adapter = _adapter()
    ss = MemorySecondaryStorage()
    ia = InternalAdapter(adapter, secondary_storage=ss, store_session_in_database=True)
    user = _row(await ia.create_user({"name": "Ada", "email": "ada@x.com"}, force_allow_id=True))
    session = _row(await ia.create_session(user["id"]))
    assert await adapter.count("session") == 1  # the DB row still exists

    await ss.set(session["token"], "invalid-json{{{")

    assert await ia.find_session(session["token"]) is None


async def test_update_session_returns_none_on_corrupt_kv_payload():
    """TS internal-adapter.ts:644-648 (updateSession's KV fn) — ``const parsedSession =
    safeJSONParse(currentSession); if (!parsedSession) return null;`` A corrupt session
    KV blob degrades update_session to None instead of raising."""
    ss = MemorySecondaryStorage()
    ia = InternalAdapter(_adapter(), secondary_storage=ss)
    user = _row(await ia.create_user({"name": "Ada", "email": "ada@x.com"}, force_allow_id=True))
    session = _row(await ia.create_session(user["id"]))
    await ss.set(session["token"], "invalid-json{{{")

    assert await ia.update_session(session["token"], {"ipAddress": "1.2.3.4"}) is None


async def test_delete_session_survives_sessionless_payload_and_logs(
    caplog: pytest.LogCaptureFixture,
):
    """TS internal-adapter.ts:722-730 — ``const { session } = safeJSONParse(data) ?? {};
    if (!session) { logger.error("Session not found in secondary storage"); return; }``
    When the KV payload parses but carries no ``session`` key, TS logs and returns
    without deleting anything: the key survives."""
    ss = MemorySecondaryStorage()
    ia = InternalAdapter(_adapter(), secondary_storage=ss)
    await ss.set("stray-token", json.dumps({"user": {"id": "u1"}}))  # no "session" key

    with caplog.at_level(logging.ERROR, logger="better_auth"):
        await ia.delete_session("stray-token")

    assert await ss.get("stray-token") == json.dumps({"user": {"id": "u1"}})
    assert any("Session not found in secondary storage" in r.message for r in caplog.records)


async def test_delete_session_survives_corrupt_payload_and_logs(
    caplog: pytest.LogCaptureFixture,
):
    """TS internal-adapter.ts:722-730 — ``safeJSONParse(data) ?? {}`` unifies a corrupt
    (unparseable) payload with a parsed-but-sessionless one: both destructure to an
    undefined ``session``, hit the same ``if (!session)`` branch, and the key survives
    the failed delete."""
    ss = MemorySecondaryStorage()
    ia = InternalAdapter(_adapter(), secondary_storage=ss)
    await ss.set("stray-token", "invalid-json{{{")

    with caplog.at_level(logging.ERROR, logger="better_auth"):
        await ia.delete_session("stray-token")

    assert await ss.get("stray-token") == "invalid-json{{{"
    assert any("Session not found in secondary storage" in r.message for r in caplog.records)


# --- delete_user owns session cleanup (TS a03e4c186) --------------------------


async def test_delete_user_clears_secondary_storage_sessions():
    """TS a03e4c186: `deleteUser` calls `deleteSecondaryStorageSessions` first
    (db/internal-adapter.ts:123-137, 321-326) — before, a KV-only deployment left
    the session blob and the active-sessions list behind on user deletion."""
    ss = MemorySecondaryStorage()
    ia = InternalAdapter(_adapter(), secondary_storage=ss)
    user = _row(await ia.create_user({"name": "Ada", "email": "ada@x.com"}, force_allow_id=True))
    session = _row(await ia.create_session(user["id"]))

    await ia.delete_user(user["id"])

    assert await ss.get(session["token"]) is None
    assert await ss.get(f"active-sessions-{user['id']}") is None


async def test_delete_user_clears_kv_and_database_sessions():
    """TS secondary-storage.test.ts:242-289 — with `storeSessionInDatabase`, both the
    KV entries and the `session` rows are gone after `deleteUser`."""
    adapter = _adapter()
    ss = MemorySecondaryStorage()
    ia = InternalAdapter(adapter, secondary_storage=ss, store_session_in_database=True)
    user = _row(await ia.create_user({"name": "Ada", "email": "ada@x.com"}, force_allow_id=True))
    session = _row(await ia.create_session(user["id"]))
    assert await adapter.count("session") == 1

    await ia.delete_user(user["id"])

    assert await ss.get(session["token"]) is None
    assert await ss.get(f"active-sessions-{user['id']}") is None
    assert await adapter.count("session") == 0


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


# --- admin plugin helpers: list_users / count_total_users / update_password ----
#
# These back the admin plugin's /admin/list-users, its `total`, and set-user-password.
# (link_account is NOT added: TS `createAccount` and `linkAccount` are byte-identical,
# so `create_account` already covers it — see admin.py.)
from better_auth.adapters.base import Where  # noqa: E402


async def _seed_users(ia: InternalAdapter) -> None:
    await ia.create_user({"name": "Ada", "email": "ada@example.com"})
    await ia.create_user({"name": "Bob", "email": "bob@other.com"})
    await ia.create_user({"name": "Cy", "email": "cy@example.com"})


async def test_list_users_returns_all_without_filters():
    ia = InternalAdapter(_adapter())
    await _seed_users(ia)
    users = await ia.list_users()
    assert {u["email"] for u in users} == {"ada@example.com", "bob@other.com", "cy@example.com"}


async def test_list_users_limit_and_offset_paginate():
    ia = InternalAdapter(_adapter())
    await _seed_users(ia)
    page = await ia.list_users(limit=2, offset=0, sort_by={"field": "email", "direction": "asc"})
    assert [u["email"] for u in page] == ["ada@example.com", "bob@other.com"]
    page2 = await ia.list_users(limit=2, offset=2, sort_by={"field": "email", "direction": "asc"})
    assert [u["email"] for u in page2] == ["cy@example.com"]


async def test_list_users_sort_direction_desc():
    ia = InternalAdapter(_adapter())
    await _seed_users(ia)
    users = await ia.list_users(sort_by={"field": "name", "direction": "desc"})
    assert [u["name"] for u in users] == ["Cy", "Bob", "Ada"]


async def test_list_users_where_filters():
    ia = InternalAdapter(_adapter())
    await _seed_users(ia)
    users = await ia.list_users(
        where=[Where("email", "@example.com", "ends_with")],
        sort_by={"field": "email", "direction": "asc"},
    )
    assert [u["email"] for u in users] == ["ada@example.com", "cy@example.com"]


async def test_count_total_users_all_and_filtered():
    ia = InternalAdapter(_adapter())
    await _seed_users(ia)
    assert await ia.count_total_users() == 3
    assert await ia.count_total_users([Where("email", "@example.com", "ends_with")]) == 2


async def test_update_password_updates_credential_account():
    ia = InternalAdapter(_adapter())
    user = _row(await ia.create_user({"name": "Ada", "email": "ada@x.com"}))
    await ia.create_account(
        {
            "userId": user["id"],
            "accountId": user["id"],
            "providerId": "credential",
            "password": "old-hash",
        }
    )
    await ia.update_password(user["id"], "new-hash")
    account = await ia.adapter.find_one(
        "account", [Where("userId", user["id"]), Where("providerId", "credential")]
    )
    assert _row(account)["password"] == "new-hash"


async def test_update_password_only_touches_credential_provider():
    ia = InternalAdapter(_adapter())
    user = _row(await ia.create_user({"name": "Ada", "email": "ada@x.com"}))
    await ia.create_account(
        {"userId": user["id"], "accountId": "g1", "providerId": "google", "accessToken": "t"}
    )
    await ia.create_account(
        {
            "userId": user["id"],
            "accountId": user["id"],
            "providerId": "credential",
            "password": "old-hash",
        }
    )
    await ia.update_password(user["id"], "new-hash")
    google = await ia.adapter.find_one(
        "account", [Where("userId", user["id"]), Where("providerId", "google")]
    )
    assert _row(google).get("password") is None


# --- delete_sessions: plain parallel deletes (TS e6e1b4e81) --------------------


class _SpyStorage(MemorySecondaryStorage):
    """Records get/delete calls so tests can pin the KV access pattern."""

    def __init__(self) -> None:
        super().__init__()
        self.gets: list[str] = []
        self.deletes: list[str] = []

    async def get(self, key: str) -> str | None:
        self.gets.append(key)
        return await super().get(key)

    async def delete(self, key: str) -> None:
        self.deletes.append(key)
        await super().delete(key)


async def test_delete_sessions_plain_deletes_no_get_absent_key_included():
    """TS e6e1b4e81 (db/internal-adapter.ts:811-815): ``deleteSessions`` issues plain
    deletes — no get-before-delete, and an absent key still gets its delete (deleting
    a missing KV key is a no-op; the read was pure waste)."""
    ss = _SpyStorage()
    ia = InternalAdapter(_adapter(), secondary_storage=ss)
    user = _row(await ia.create_user({"name": "Ada", "email": "ada@x.com"}, force_allow_id=True))
    session = _row(await ia.create_session(user["id"]))
    ss.gets.clear()
    ss.deletes.clear()

    await ia.delete_sessions([session["token"], "absent-token"])

    assert ss.gets == []
    assert sorted(ss.deletes) == sorted([session["token"], "absent-token"])
    assert await ss.get(session["token"]) is None
