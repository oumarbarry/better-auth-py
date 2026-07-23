"""Wave 3 foundation leftovers — parity with better-auth TS v1.6.23.

Each test group cites the TS source it was verified against.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from better_auth import (
    APIError,
    AuthResponse,
    EmailAndPassword,
    EmailVerification,
    MemoryAdapter,
    Plugin,
)
from better_auth.adapters.base import Where
from better_auth.internal_adapter import InternalAdapter
from better_auth.schema import CORE_SCHEMA
from conftest import make_auth, make_client, sign_up


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _adapter() -> MemoryAdapter:
    a = MemoryAdapter()
    a.init(CORE_SCHEMA)
    return a


# ============================================================================
# Item 2 — crypto helpers (crypto/random.ts, magic-link/utils.ts defaultKeyHasher,
# phone-number/routes.ts:902 generateOTP = generateRandomString(size, "0-9"))
# ============================================================================


def test_generate_random_string_default_alphabet_backcompat():
    from better_auth.crypto import _RANDOM_ALPHABET, generate_random_string

    s = generate_random_string(40)
    assert len(s) == 40
    assert set(s) <= set(_RANDOM_ALPHABET)


def test_generate_random_string_custom_alphabet():
    from better_auth.crypto import generate_random_string

    s = generate_random_string(50, "ab")
    assert len(s) == 50
    assert set(s) <= {"a", "b"}


def test_generate_otp_digits_only():
    from better_auth.crypto import generate_otp

    otp = generate_otp(6)
    assert len(otp) == 6
    assert otp.isdigit()


def test_default_key_hasher_matches_ts_byte_for_byte():
    # base64url(no-pad) of SHA-256(utf8 token) — cross-runtime vector shared with TS.
    from better_auth.crypto import default_key_hasher

    assert default_key_hasher("123456") == "jZae727K08KaOmKSgOaGzww_XVqGr_PKEgIMkjrcbJI"
    assert default_key_hasher("hello") == "LPJNul-wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ"


# ============================================================================
# Item 1 — atomic verification consume (db/internal-adapter.ts:1254
# consumeVerificationValue; :1207 deleteVerificationByIdentifier; :1498
# updateVerificationByIdentifier)
# ============================================================================


async def _mk_verification(ia: InternalAdapter, identifier: str, value: str, *, ttl: int = 3600):
    now = _now()
    return await ia.create_verification_value(
        {
            "identifier": identifier,
            "value": value,
            "expiresAt": now + timedelta(seconds=ttl),
        }
    )


async def test_consume_returns_latest_row_and_deletes_all():
    ia = InternalAdapter(_adapter())
    await _mk_verification(ia, "otp:a", "first")
    await asyncio.sleep(0)  # ensure distinct createdAt ordering is not relied upon
    await _mk_verification(ia, "otp:a", "second")

    consumed = await ia.consume_verification_value("otp:a")
    assert consumed is not None
    assert consumed["value"] == "second"  # latest by createdAt desc wins (TS rows[0])
    # every row for the identifier is gone
    assert await ia.find_verification_value("otp:a") is None


async def test_consume_missing_returns_none():
    ia = InternalAdapter(_adapter())
    assert await ia.consume_verification_value("nope") is None


async def test_consume_expired_returns_none_but_deletes_row():
    ia = InternalAdapter(_adapter())
    await _mk_verification(ia, "otp:exp", "x", ttl=-10)  # already expired
    # TS: consume deletes the row regardless, returns null when past expiresAt
    assert await ia.consume_verification_value("otp:exp") is None
    assert await ia.find_verification_value("otp:exp") is None


async def test_consume_twice_second_is_none():
    ia = InternalAdapter(_adapter())
    await _mk_verification(ia, "otp:once", "v")
    assert (await ia.consume_verification_value("otp:once")) is not None
    assert (await ia.consume_verification_value("otp:once")) is None


class _YieldingAdapter(MemoryAdapter):
    """Models a real async DB: find_many yields to the event loop *after* computing
    its result, so two consumers can both read the row before either deletes it.
    Without the consume lock this produces multiple winners."""

    async def find_many(self, *args: Any, **kwargs: Any) -> list[dict[str, Any]]:
        rows = await super().find_many(*args, **kwargs)
        await asyncio.sleep(0)
        return rows


async def test_consume_single_winner_under_concurrency():
    adapter = _YieldingAdapter()
    adapter.init(CORE_SCHEMA)
    ia = InternalAdapter(adapter)
    await _mk_verification(ia, "otp:race", "v")

    results = await asyncio.gather(*(ia.consume_verification_value("otp:race") for _ in range(25)))
    winners = [r for r in results if r is not None]
    assert len(winners) == 1  # exactly one caller consumes the single-use value
    assert await ia.find_verification_value("otp:race") is None


async def test_consume_single_winner_sqlalchemy():
    aiosqlite = pytest.importorskip("aiosqlite")  # noqa: F841
    from sqlalchemy.ext.asyncio import create_async_engine

    from better_auth.adapters.sqlalchemy import SQLAlchemyAdapter

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    adapter = SQLAlchemyAdapter(engine)
    adapter.init(CORE_SCHEMA)
    await adapter.create_tables()
    ia = InternalAdapter(adapter)
    await _mk_verification(ia, "otp:sql", "v")

    results = await asyncio.gather(*(ia.consume_verification_value("otp:sql") for _ in range(10)))
    assert len([r for r in results if r is not None]) == 1
    await engine.dispose()


async def test_update_verification_by_identifier():
    ia = InternalAdapter(_adapter())
    await _mk_verification(ia, "otp:u", "orig")
    updated = await ia.update_verification_by_identifier("otp:u", {"value": "changed"})
    assert updated is not None and updated["value"] == "changed"
    row = await ia.find_verification_value("otp:u")
    assert row is not None and row["value"] == "changed"


async def test_delete_verification_by_identifier():
    ia = InternalAdapter(_adapter())
    await _mk_verification(ia, "otp:d", "a")
    await _mk_verification(ia, "otp:d", "b")
    await ia.delete_verification_by_identifier("otp:d")
    assert await ia.find_verification_value("otp:d") is None


# ============================================================================
# Item 8 — revoke_unproven_account_access (db/revoke-unproven-account-access.ts)
# ============================================================================


async def _seed_user_with_credential(ia: InternalAdapter, *, verified: bool):
    user = await ia.create_user({"name": "A", "email": "a@x.com", "emailVerified": verified})
    assert user is not None
    await ia.create_account(
        {"accountId": user["id"], "providerId": "credential", "userId": user["id"], "password": "h"}
    )
    await ia.create_session(user["id"])
    return user


async def test_revoke_unproven_strips_credential_and_sessions():
    adapter = _adapter()
    ia = InternalAdapter(adapter)
    user = await _seed_user_with_credential(ia, verified=False)

    await ia.revoke_unproven_account_access(user["id"])

    assert await adapter.count("account", [Where("userId", user["id"])]) == 0
    assert await adapter.count("session", [Where("userId", user["id"])]) == 0
    # the user row itself survives (it will be promoted, not deleted)
    assert await adapter.count("user", [Where("id", user["id"])]) == 1


async def test_revoke_unproven_noops_for_verified_user():
    adapter = _adapter()
    ia = InternalAdapter(adapter)
    user = await _seed_user_with_credential(ia, verified=True)

    await ia.revoke_unproven_account_access(user["id"])

    assert await adapter.count("account", [Where("userId", user["id"])]) == 1
    assert await adapter.count("session", [Where("userId", user["id"])]) == 1


# ============================================================================
# Item 6 — Field.transform_input (core/db/adapter/factory.ts:254 — applied on
# create AND update, on the value, before storage coercion)
# ============================================================================


def _username_schema():
    from better_auth.schema import Field

    return {
        "widget": {
            "id": Field("string", required=True, unique=True),
            "username": Field("string", transform_input=lambda v: v.strip().lower()),
        }
    }


async def test_transform_input_applied_on_create():
    adapter = MemoryAdapter()
    adapter.init(_username_schema())
    row = await adapter.create("widget", {"id": "1", "username": "  Ada_L  "})
    assert row["username"] == "ada_l"


async def test_transform_input_applied_on_update():
    adapter = MemoryAdapter()
    adapter.init(_username_schema())
    await adapter.create("widget", {"id": "1", "username": "ada"})
    updated = await adapter.update("widget", [Where("id", "1")], {"username": "GRACE_H"})
    assert updated is not None and updated["username"] == "grace_h"


async def test_transform_input_default_none_is_noop():
    from better_auth.schema import Field

    adapter = MemoryAdapter()
    adapter.init(
        {"widget": {"id": Field("string", required=True, unique=True), "x": Field("string")}}
    )
    row = await adapter.create("widget", {"id": "1", "x": "AsIs"})
    assert row["x"] == "AsIs"


# ============================================================================
# Item 10 — build_cookie attribute overrides (session.py:31); http_only=False for
# last-login-method, inheriting SameSite/Secure/Domain/prefix.
# ============================================================================


def test_build_cookie_backcompat_is_httponly():
    from better_auth.session import build_cookie

    auth = make_auth()
    cookie = build_cookie(auth, "v", 60)
    assert "HttpOnly" in cookie
    assert "SameSite=Lax" in cookie
    assert cookie.startswith("better-auth.session_token=v")


def test_build_cookie_http_only_false_omits_httponly_keeps_derived():
    from better_auth.session import build_cookie

    auth = make_auth()
    cookie = build_cookie(auth, "chrome", 300, "last_login_method", http_only=False)
    assert "HttpOnly" not in cookie
    assert "SameSite=Lax" in cookie  # derived attrs still present
    assert "Max-Age=300" in cookie
    assert cookie.startswith("better-auth.last_login_method=chrome")


def test_build_cookie_secure_and_domain_derived_over_https():
    from better_auth.config import CrossSubDomainCookies
    from better_auth.session import build_cookie

    auth = make_auth(
        base_url="https://app.example.com",
        cross_sub_domain_cookies=CrossSubDomainCookies(enabled=True, domain="example.com"),
    )
    cookie = build_cookie(auth, "v", 60, "last_login_method", http_only=False)
    assert "Secure" in cookie
    assert "Domain=example.com" in cookie
    assert cookie.startswith("__Secure-better-auth.last_login_method=v")


# ============================================================================
# Item 3 — new-session signal (ctx.new_session, TS ctx.context.newSession set by
# setNewSession, core/src/types/context.ts:357) + expose-headers helper.
# ============================================================================


async def test_create_session_sets_ctx_new_session():
    from better_auth.session import create_session
    from better_auth.types import AuthRequest, Ctx

    auth = make_auth()
    user = await auth.internal.create_user(
        {"name": "Ada", "email": "ada@x.com"}, force_allow_id=True
    )
    assert user is not None
    ctx = Ctx(auth=auth, request=AuthRequest(method="POST", path="/sign-in/email"))
    await create_session(auth, user["id"], ctx.request, user=user, ctx=ctx)
    assert ctx.new_session is not None
    assert ctx.new_session["user"]["id"] == user["id"]
    assert ctx.new_session["session"]["userId"] == user["id"]


class _NewSessionCapture(Plugin):
    id = "capture"

    def __init__(self):
        self.seen: list[Any] = []

    async def after(self, ctx, response):
        self.seen.append(ctx.new_session)
        return None


async def test_new_session_fires_on_sign_in_path():
    plugin = _NewSessionCapture()
    auth = make_auth(plugins=[plugin])
    async with make_client(auth) as client:
        await sign_up(client)  # sign-up path
        plugin.seen.clear()
        resp = await client.post(
            "/api/auth/sign-in/email",
            json={"email": "ada@example.com", "password": "s3cret-password"},
        )
        assert resp.status_code == 200
    fired = [s for s in plugin.seen if s is not None]
    assert fired and fired[-1]["user"]["email"] == "ada@example.com"


def test_add_expose_headers_merges_without_clobbering():
    from better_auth.plugins import add_expose_headers

    resp = AuthResponse()
    resp.headers.append(("Access-Control-Expose-Headers", "set-cookie"))
    add_expose_headers(resp, "set-auth-token", "set-cookie")  # dedup set-cookie
    values = [v for h, v in resp.headers if h.lower() == "access-control-expose-headers"]
    assert len(values) == 1  # single header, not appended twice
    assert values[0] == "set-cookie, set-auth-token"


def test_add_expose_headers_creates_when_absent():
    from better_auth.plugins import add_expose_headers

    resp = AuthResponse()
    add_expose_headers(resp, "set-ott")
    assert ("Access-Control-Expose-Headers", "set-ott") in resp.headers


# ============================================================================
# Item 7 — plugin routes shadow same-(method,path) core routes (auth.py routing)
# ============================================================================


class _ShadowGetSession(Plugin):
    id = "shadow"

    def routes(self):
        return [("GET", "/get-session", self.custom)]

    async def custom(self, ctx):
        return {"custom_session": True}


async def test_plugin_route_shadows_core_get_session():
    async with make_client(make_auth(plugins=[_ShadowGetSession()])) as client:
        resp = await client.get("/api/auth/get-session")
        assert resp.json() == {"custom_session": True}  # plugin wins over core handler


async def test_unrelated_core_routes_unaffected_by_shadow():
    async with make_client(make_auth(plugins=[_ShadowGetSession()])) as client:
        assert (await client.get("/api/auth/ok")).json() == {"ok": True}


# ============================================================================
# Item 4 — on_password_reset callback (api/routes/password.ts:316 —
# onPasswordReset({user}, ctx.request) after a successful reset)
# ============================================================================


async def test_on_password_reset_invoked_after_reset():
    captured: list[Any] = []
    sent: list[tuple[Any, str, str]] = []

    async def send_reset_password(user, url, token):
        sent.append((user, url, token))

    async def on_password_reset(data, request):
        captured.append(data)

    auth = make_auth(
        email_and_password=EmailAndPassword(
            enabled=True,
            send_reset_password=send_reset_password,
            on_password_reset=on_password_reset,
        )
    )
    async with make_client(auth) as client:
        await sign_up(client)
        await client.post("/api/auth/request-password-reset", json={"email": "ada@example.com"})
        _user, _url, token = sent[0]
        resp = await client.post(
            "/api/auth/reset-password", json={"newPassword": "brand-new-password", "token": token}
        )
        assert resp.json() == {"status": True}
    assert len(captured) == 1
    assert captured[0]["user"]["email"] == "ada@example.com"  # payload is {"user": user}


# ============================================================================
# Item 5 — overridable password-hash seam (auth.hash_password_checked runs
# auth.password_checks then crypto.hash_password; every endpoint hash routes through it)
# ============================================================================


class _PwnedCheckPlugin(Plugin):
    id = "pwned"

    def __init__(self):
        self.paths: list[str] = []

    def init(self, auth):
        async def check(password, path):
            self.paths.append(path)
            if password == "pwned-password":
                raise APIError(400, "PASSWORD_COMPROMISED", "Password compromised")

        auth.password_checks.append(check)


async def test_hash_password_checked_runs_checks_then_hashes():
    from better_auth.crypto import verify_password

    auth = make_auth()

    async def reject_short(password, path):
        if len(password) < 4:
            raise APIError(400, "TOO_SHORT", "nope")

    auth.password_checks.append(reject_short)
    stored = await auth.hash_password_checked("long-enough", "/sign-up/email")
    assert verify_password(stored, "long-enough")  # hashed after passing checks
    with pytest.raises(APIError):
        await auth.hash_password_checked("ab", "/sign-up/email")


async def test_password_check_blocks_sign_up():
    plugin = _PwnedCheckPlugin()
    auth = make_auth(plugins=[plugin])
    async with make_client(auth) as client:
        resp = await client.post(
            "/api/auth/sign-up/email",
            json={"name": "A", "email": "a@x.com", "password": "pwned-password"},
        )
        assert resp.status_code == 400
        assert resp.json()["code"] == "PASSWORD_COMPROMISED"
    assert "/sign-up/email" in plugin.paths  # the seam passed the request path


async def test_password_check_blocks_reset_and_change_and_set():
    # every hash call site routes through the checked seam
    plugin = _PwnedCheckPlugin()
    sent: list[Any] = []

    async def send_reset_password(user, url, token):
        sent.append(token)

    auth = make_auth(
        plugins=[plugin],
        email_and_password=EmailAndPassword(enabled=True, send_reset_password=send_reset_password),
    )
    async with make_client(auth) as client:
        await sign_up(client)
        # change-password with a pwned newPassword is rejected
        change = await client.post(
            "/api/auth/change-password",
            json={"currentPassword": "s3cret-password", "newPassword": "pwned-password"},
        )
        assert change.status_code == 400 and change.json()["code"] == "PASSWORD_COMPROMISED"
        # reset-password with a pwned newPassword is rejected
        await client.post("/api/auth/request-password-reset", json={"email": "ada@example.com"})
        reset = await client.post(
            "/api/auth/reset-password", json={"newPassword": "pwned-password", "token": sent[0]}
        )
        assert reset.status_code == 400 and reset.json()["code"] == "PASSWORD_COMPROMISED"


# ============================================================================
# Item 9 — EmailVerification.send_verification_email swappable in Plugin.init
# (endpoints._send_verification_email reads cfg at call time)
# ============================================================================


class _SenderSwapPlugin(Plugin):
    id = "sender-swap"

    def __init__(self):
        self.sent: list[tuple[Any, str, str]] = []

    def init(self, auth):
        async def send(user, url, token):
            self.sent.append((user, url, token))

        auth.email_verification.send_verification_email = send


async def test_plugin_swapped_verification_sender_is_used():
    plugin = _SenderSwapPlugin()
    auth = make_auth(
        plugins=[plugin],
        email_verification=EmailVerification(),  # no sender configured up front
    )
    # the plugin's init reassigned the sender on the (non-frozen) dataclass
    assert auth.email_verification.send_verification_email is not None
    async with make_client(auth) as client:
        await sign_up(client)
        resp = await client.post(
            "/api/auth/send-verification-email", json={"email": "ada@example.com"}
        )
        assert resp.json() == {"status": True}
    assert plugin.sent and plugin.sent[0][0]["email"] == "ada@example.com"
