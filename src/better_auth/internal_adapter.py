"""Internal adapter — the domain layer core calls (mirrors better-auth's ``createInternalAdapter``).

Sits between the endpoints and the raw ``BaseAdapter``. This is the single place where:

- ``databaseHooks`` run (per-model before/after create/update/delete, abort on ``False``,
  ``{"data": ...}`` merge, after-hooks queued post-transaction);
- caller-supplied ids are stripped (domain callers don't set ids — ids come from
  generation) unless ``force_allow_id`` is passed;
- secondary storage is consulted/updated for sessions.

Endpoints, ``session.py``, and the OAuth flow write through this seam (via ``ctx.internal``
/ ``auth.internal``) so ``databaseHooks`` fire on every core create/update/delete.
"""

from __future__ import annotations

import inspect
import json
from collections.abc import Awaitable, Callable
from datetime import datetime, timedelta, timezone
from typing import Any

from .adapters.base import BaseAdapter, Where
from .crypto import generate_id
from .secondary_storage import SecondaryStorage

DAY = 60 * 60 * 24

# A single database-hook entry: {model: {op: {"before"|"after": callable}}}.
DatabaseHooks = dict[str, Any]


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _now_ms() -> int:
    return int(_now().timestamp() * 1000)


def _dt_ms(dt: datetime) -> int:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


def _ttl_seconds(expires_ms: float, now_ms: float) -> int:
    return max(int((expires_ms - now_ms) // 1000), 0)


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


async def _call_hook(fn: Callable[..., Any], data: Any, ctx: Any) -> Any:
    """Invoke a databaseHook, passing ``ctx`` only if it accepts a second positional arg.

    TS databaseHooks receive ``(value, context)``; Python hooks may be written with just
    ``(value)``. We adapt to the callable's arity so both spellings work.
    """
    try:
        params = inspect.signature(fn).parameters.values()
        takes_ctx = any(
            p.kind == inspect.Parameter.VAR_POSITIONAL for p in params
        ) or sum(
            p.kind
            in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD)
            for p in params
        ) >= 2
    except (ValueError, TypeError):
        takes_ctx = True
    return await _maybe_await(fn(data, ctx) if takes_ctx else fn(data))


def _js_iso(dt: datetime) -> str:
    """Format a datetime the way JS ``Date.toISOString()`` does (millisecond precision, ``Z``)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


class _Encoder(json.JSONEncoder):
    def default(self, o: Any) -> Any:
        if isinstance(o, datetime):
            return _js_iso(o)
        return super().default(o)


def _dumps(obj: Any) -> str:
    """Compact JSON matching ``JSON.stringify`` (no spaces, datetimes as JS ISO strings)."""
    return json.dumps(obj, cls=_Encoder, separators=(",", ":"))


_DATE_KEYS = {"expiresAt", "createdAt", "updatedAt"}


def _parse_dates(row: dict[str, Any]) -> dict[str, Any]:
    out = dict(row)
    for key in _DATE_KEYS:
        value = out.get(key)
        if isinstance(value, str):
            out[key] = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return out


def _normalize_hooks(database_hooks: DatabaseHooks | list[Any] | None) -> list[DatabaseHooks]:
    """Accept a single hooks dict or a list of entries; return a list of hooks dicts."""
    if not database_hooks:
        return []
    if isinstance(database_hooks, dict):
        return [database_hooks]
    out: list[DatabaseHooks] = []
    for entry in database_hooks:
        # plugin entries may be {"source", "hooks"}; a bare dict is the hooks itself
        out.append(entry["hooks"] if isinstance(entry, dict) and "hooks" in entry else entry)
    return out


# A custom op body: {"fn": callable, "execute_main_fn": bool}. ``fn`` runs the side effect
# (e.g. secondary-storage write); ``execute_main_fn`` decides whether the DB op also runs.
CustomFn = dict[str, Any]


class InternalAdapter:
    def __init__(
        self,
        adapter: BaseAdapter,
        *,
        secondary_storage: SecondaryStorage | None = None,
        database_hooks: DatabaseHooks | list[Any] | None = None,
        session_expires_in: int = 7 * DAY,
        store_session_in_database: bool = False,
    ) -> None:
        self.adapter = adapter
        self.secondary_storage = secondary_storage
        self.hooks = _normalize_hooks(database_hooks)
        self.session_expires_in = session_expires_in
        self.store_session_in_database = store_session_in_database
        #: non-None while inside ``transaction`` — after-hooks are deferred until commit
        self._after_queue: list[Callable[[], Awaitable[None]]] | None = None

    # --- with-hooks core ---------------------------------------------------------------

    def _hook(self, model: str, op: str, phase: str) -> list[Callable[..., Any]]:
        found = []
        for hooks in self.hooks:
            fn = ((hooks.get(model) or {}).get(op) or {}).get(phase)
            if fn is not None:
                found.append(fn)
        return found

    async def _run_before(
        self, model: str, op: str, data: dict[str, Any], ctx: Any
    ) -> tuple[dict, bool]:
        """Run before hooks; return (possibly-merged data, aborted).

        Hooks receive ``(data, ctx)`` where ``ctx`` is the request context
        (``None`` for internal callers), matching TS ``databaseHooks``.
        """
        actual = data
        for fn in self._hook(model, op, "before"):
            result = await _call_hook(fn, actual, ctx)
            if result is False:
                return actual, True
            if isinstance(result, dict) and "data" in result:
                actual = {**actual, **result["data"]}
        return actual, False

    async def _queue_after(self, model: str, op: str, payload: Any, ctx: Any) -> None:
        fns = self._hook(model, op, "after")
        if not fns:
            return

        async def run() -> None:
            for fn in fns:
                await _call_hook(fn, payload, ctx)

        if self._after_queue is not None:
            self._after_queue.append(run)
        else:
            await run()

    async def _create(
        self,
        model: str,
        data: dict[str, Any],
        *,
        force_allow_id: bool,
        custom_fn: CustomFn | None,
        ctx: Any = None,
    ) -> dict[str, Any] | None:
        if not force_allow_id:
            data = {k: v for k, v in data.items() if k != "id"}
        data, aborted = await self._run_before(model, "create", data, ctx)
        if aborted:
            return None
        created: Any = None
        if custom_fn is None or custom_fn.get("execute_main_fn", True):
            created = await self.adapter.create(model, data, force_allow_id=True)
        if custom_fn and custom_fn.get("fn"):
            created = await _maybe_await(custom_fn["fn"](created if created is not None else data))
        await self._queue_after(model, "create", created, ctx)
        return created

    async def _update(
        self,
        model: str,
        where: list[Where],
        data: dict[str, Any],
        *,
        custom_fn: CustomFn | None,
        ctx: Any = None,
    ) -> dict[str, Any] | None:
        data, aborted = await self._run_before(model, "update", data, ctx)
        if aborted:
            return None
        custom_result = None
        if custom_fn and custom_fn.get("fn"):
            custom_result = await _maybe_await(custom_fn["fn"](data))
        if custom_fn is None or custom_fn.get("execute_main_fn", True):
            updated = await self.adapter.update(model, where, data)
        else:
            updated = custom_result
        await self._queue_after(model, "update", updated, ctx)
        return updated

    async def _delete(self, model: str, where: list[Where], ctx: Any = None) -> None:
        entity = None
        try:
            rows = await self.adapter.find_many(model, where, limit=1)
            entity = rows[0] if rows else None
        except Exception:
            entity = None
        if entity is not None:
            _, aborted = await self._run_before(model, "delete", entity, ctx)
            if aborted:
                return
        await self.adapter.delete(model, where)
        if entity is not None:
            await self._queue_after(model, "delete", entity, ctx)

    async def _delete_many(self, model: str, where: list[Where], ctx: Any = None) -> int:
        try:
            entities = await self.adapter.find_many(model, where)
        except Exception:
            entities = []
        for entity in entities:
            _, aborted = await self._run_before(model, "delete", entity, ctx)
            if aborted:
                return 0
        deleted = await self.adapter.delete_many(model, where)
        for entity in entities:
            await self._queue_after(model, "delete", entity, ctx)
        return deleted

    # --- generic hook-running CRUD (the seam endpoints/session.py write through) --------
    #
    # Endpoints build the full row (id, timestamps) themselves, so ``create`` defaults to
    # ``force_allow_id=True``: behaviour-identical to a raw ``adapter.create`` when no
    # databaseHooks are configured, but runs the per-model before/after hooks with ``ctx``.

    async def create(
        self, model: str, data: dict[str, Any], *, ctx: Any = None, force_allow_id: bool = True
    ) -> dict[str, Any] | None:
        return await self._create(
            model, data, force_allow_id=force_allow_id, custom_fn=None, ctx=ctx
        )

    async def update(
        self, model: str, where: list[Where], data: dict[str, Any], *, ctx: Any = None
    ) -> dict[str, Any] | None:
        return await self._update(model, where, data, custom_fn=None, ctx=ctx)

    async def delete_one(self, model: str, where: list[Where], *, ctx: Any = None) -> None:
        await self._delete(model, where, ctx)

    async def delete_many(self, model: str, where: list[Where], *, ctx: Any = None) -> int:
        return await self._delete_many(model, where, ctx)

    async def transaction(self, callback: Callable[[InternalAdapter], Awaitable[Any]]) -> Any:
        """Run ``callback`` in a DB transaction, flushing after-hooks once it commits."""
        outermost = self._after_queue is None
        if outermost:
            self._after_queue = []

        async def _cb(tx_adapter: BaseAdapter) -> Any:
            tx = InternalAdapter(
                tx_adapter,
                secondary_storage=self.secondary_storage,
                database_hooks=None,
                session_expires_in=self.session_expires_in,
                store_session_in_database=self.store_session_in_database,
            )
            tx.hooks = self.hooks
            tx._after_queue = self._after_queue
            return await callback(tx)

        try:
            result = await self.adapter.transaction(_cb)
        except Exception:
            if outermost:
                self._after_queue = None
            raise
        if outermost:
            queued = self._after_queue or []
            self._after_queue = None
            for run in queued:
                await run()
        return result

    # --- user --------------------------------------------------------------------------

    async def create_user(
        self, user: dict[str, Any], *, force_allow_id: bool = False
    ) -> dict[str, Any] | None:
        now = _now()
        data = {"createdAt": now, "updatedAt": now, **user}
        if data.get("email"):
            data["email"] = data["email"].lower()
        return await self._create("user", data, force_allow_id=force_allow_id, custom_fn=None)

    async def update_user(self, user_id: str, data: dict[str, Any]) -> dict[str, Any] | None:
        return await self._update("user", [Where("id", user_id)], data, custom_fn=None)

    async def delete_user(self, user_id: str) -> None:
        if not self.secondary_storage or self.store_session_in_database:
            await self._delete_many("session", [Where("userId", user_id)])
        await self._delete_many("account", [Where("userId", user_id)])
        await self._delete("user", [Where("id", user_id)])

    # --- account -----------------------------------------------------------------------

    async def create_account(
        self, account: dict[str, Any], *, force_allow_id: bool = False
    ) -> dict[str, Any] | None:
        now = _now()
        data = {"createdAt": now, "updatedAt": now, **account}
        return await self._create("account", data, force_allow_id=force_allow_id, custom_fn=None)

    async def update_account(self, account_id: str, data: dict[str, Any]) -> dict[str, Any] | None:
        return await self._update("account", [Where("id", account_id)], data, custom_fn=None)

    async def delete_account(self, account_id: str) -> None:
        await self._delete("account", [Where("id", account_id)])

    # --- verification ------------------------------------------------------------------

    async def create_verification_value(
        self, data: dict[str, Any], *, force_allow_id: bool = False
    ) -> dict[str, Any] | None:
        now = _now()
        payload = {"createdAt": now, "updatedAt": now, **data}
        return await self._create(
            "verification", payload, force_allow_id=force_allow_id, custom_fn=None
        )

    async def find_verification_value(self, identifier: str) -> dict[str, Any] | None:
        rows = await self.adapter.find_many(
            "verification",
            [Where("identifier", identifier)],
            sort_by={"field": "createdAt", "direction": "desc"},
            limit=1,
        )
        return rows[0] if rows else None

    async def delete_verification_value(self, verification_id: str) -> None:
        await self._delete("verification", [Where("id", verification_id)])

    # --- session (secondary-storage aware) ---------------------------------------------

    async def create_session(
        self,
        user_id: str,
        *,
        dont_remember_me: bool = False,
        override: dict[str, Any] | None = None,
        ip_address: str = "",
        user_agent: str = "",
    ) -> dict[str, Any] | None:
        store_in_db = self.store_session_in_database
        rest = dict(override or {})
        rest.pop("id", None)  # always ignore an override id — new sessions get new ids
        session_id = generate_id() if (self.secondary_storage and not store_in_db) else None
        now = _now()
        expires_in = DAY if dont_remember_me else self.session_expires_in
        data: dict[str, Any] = {
            **({"id": session_id} if session_id else {}),
            "ipAddress": ip_address,
            "userAgent": user_agent,
            **rest,
            "expiresAt": now + timedelta(seconds=expires_in),
            "userId": user_id,
            "token": generate_id(32),
            "createdAt": now,
            "updatedAt": now,
        }
        custom_fn: CustomFn | None = None
        if self.secondary_storage:

            async def _fn(session_data: dict[str, Any]) -> dict[str, Any]:
                await self._store_session_kv(user_id, data, session_data)
                return session_data

            custom_fn = {"fn": _fn, "execute_main_fn": store_in_db}
        return await self._create("session", data, force_allow_id=True, custom_fn=custom_fn)

    async def _store_session_kv(
        self, user_id: str, data: dict[str, Any], session_data: dict[str, Any]
    ) -> None:
        ss = self.secondary_storage
        assert ss is not None
        now_ms = _now_ms()
        token = data["token"]
        expires_ms = _dt_ms(data["expiresAt"])
        list_key = f"active-sessions-{user_id}"

        current = await ss.get(list_key)
        entries: list[dict[str, Any]] = []
        if current:
            entries = [
                s
                for s in json.loads(current)
                if s["expiresAt"] > now_ms and s["token"] != token
            ]
        entries = sorted(
            [*entries, {"token": token, "expiresAt": expires_ms}], key=lambda s: s["expiresAt"]
        )
        furthest = entries[-1]["expiresAt"] if entries else expires_ms
        furthest_ttl = _ttl_seconds(furthest, now_ms)
        if furthest_ttl > 0:
            await ss.set(list_key, _dumps(entries), furthest_ttl)

        user = await self.adapter.find_one("user", [Where("id", user_id)])
        session_ttl = _ttl_seconds(expires_ms, now_ms)
        if session_ttl > 0:
            await ss.set(token, _dumps({"session": session_data, "user": user}), session_ttl)

    async def find_session(self, token: str) -> dict[str, Any] | None:
        if self.secondary_storage:
            raw = await self.secondary_storage.get(token)
            if not raw and not self.store_session_in_database:
                return None
            if raw:
                s = json.loads(raw)
                return {
                    "session": _parse_dates(s["session"]),
                    "user": _parse_dates(s["user"]),
                }
        session = await self.adapter.find_one("session", [Where("token", token)])
        if session is None:
            return None
        user = await self.adapter.find_one("user", [Where("id", session["userId"])])
        if user is None:
            return None
        return {"session": session, "user": user}

    async def list_sessions(self, user_id: str) -> list[dict[str, Any]]:
        if self.secondary_storage:
            raw = await self.secondary_storage.get(f"active-sessions-{user_id}")
            if not raw:
                return []
            now_ms = _now_ms()
            seen: set[str] = set()
            sessions: list[dict[str, Any]] = []
            for entry in json.loads(raw):
                token = entry["token"]
                if entry["expiresAt"] <= now_ms or token in seen:
                    continue
                seen.add(token)
                data = await self.secondary_storage.get(token)
                if not data:
                    continue
                parsed = json.loads(data)
                if not parsed.get("session"):
                    continue
                sessions.append(_parse_dates(parsed["session"]))
            return sessions
        return await self.adapter.find_many("session", [Where("userId", user_id)])

    async def update_session(
        self, token: str, values: dict[str, Any]
    ) -> dict[str, Any] | None:
        custom_fn: CustomFn | None = None
        if self.secondary_storage:

            async def _fn(data: dict[str, Any]) -> dict[str, Any] | None:
                return await self._update_session_kv(token, data)

            custom_fn = {"fn": _fn, "execute_main_fn": self.store_session_in_database}
        return await self._update("session", [Where("token", token)], values, custom_fn=custom_fn)

    async def _update_session_kv(
        self, token: str, data: dict[str, Any]
    ) -> dict[str, Any] | None:
        ss = self.secondary_storage
        assert ss is not None
        current = await ss.get(token)
        if not current:
            return None
        parsed = json.loads(current)
        merged = _parse_dates({**parsed["session"], **data})
        now_ms = _now_ms()
        expires_ms = _dt_ms(merged["expiresAt"])
        session_ttl = _ttl_seconds(expires_ms, now_ms)
        if session_ttl > 0:
            await ss.set(token, _dumps({"session": merged, "user": parsed["user"]}), session_ttl)
            list_key = f"active-sessions-{merged['userId']}"
            raw = await ss.get(list_key)
            entries = [
                s
                for s in (json.loads(raw) if raw else [])
                if s["token"] != token and s["expiresAt"] > now_ms
            ]
            entries = sorted(
                [*entries, {"token": token, "expiresAt": expires_ms}],
                key=lambda s: s["expiresAt"],
            )
            # entries always holds the just-added token, so it is never empty
            furthest = int(entries[-1]["expiresAt"])
            if furthest > now_ms:
                await ss.set(list_key, _dumps(entries), _ttl_seconds(furthest, now_ms))
            else:
                await ss.delete(list_key)
        return merged

    async def delete_session(self, token: str) -> None:
        if self.secondary_storage:
            raw = await self.secondary_storage.get(token)
            if raw:
                session = json.loads(raw).get("session")
                if session:
                    user_id = session["userId"]
                    list_key = f"active-sessions-{user_id}"
                    current = await self.secondary_storage.get(list_key)
                    if current:
                        now_ms = _now_ms()
                        filtered = [
                            s
                            for s in json.loads(current)
                            if s["expiresAt"] > now_ms and s["token"] != token
                        ]
                        filtered.sort(key=lambda s: s["expiresAt"])
                        furthest = filtered[-1]["expiresAt"] if filtered else None
                        if filtered and furthest and furthest > now_ms:
                            await self.secondary_storage.set(
                                list_key, _dumps(filtered), _ttl_seconds(furthest, now_ms)
                            )
                        else:
                            await self.secondary_storage.delete(list_key)
            await self.secondary_storage.delete(token)
            if not self.store_session_in_database:
                return
        await self._delete("session", [Where("token", token)])

    async def delete_sessions(self, tokens: list[str]) -> None:
        if self.secondary_storage:
            for token in tokens:
                if await self.secondary_storage.get(token):
                    await self.secondary_storage.delete(token)
            if not self.store_session_in_database:
                return
        await self._delete_many("session", [Where("token", tokens, "in")])

    async def delete_user_sessions(self, user_id: str) -> None:
        if self.secondary_storage:
            raw = await self.secondary_storage.get(f"active-sessions-{user_id}")
            for entry in json.loads(raw) if raw else []:
                await self.secondary_storage.delete(entry["token"])
            await self.secondary_storage.delete(f"active-sessions-{user_id}")
            if not self.store_session_in_database:
                return
        await self._delete_many("session", [Where("userId", user_id)])
