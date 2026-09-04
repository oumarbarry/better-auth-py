"""Tests for the two-factor plugin (parity with better-auth's two-factor/*.test.ts).

Covers the spec's endpoints, crypto, cookies, hooks and edge cases: enable →
sign-in-redirect → verify-totp/otp/backup → session; trust-device skip + rotation;
backup-code single-use under asyncio.gather concurrency; per-challenge attempt budget +
account lockout; disable clears + revokes trust; a TS-layout row (XChaCha20 secret +
encrypted backup-codes JSON) decrypting under the Python port; otpauth URI format; exact
error strings.

The tests drive the plugin through ``auth.handle`` with a tiny browser-like ``Session``
(cookie jar + origin header) rather than the FastAPI client, for precise cookie control
under concurrency.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

from better_auth import SessionOptions, Where
from better_auth.config import CookieCache
from better_auth.crypto import generate_totp, symmetric_decrypt, symmetric_encrypt
from better_auth.plugins_ext.two_factor import ERROR_CODES, TwoFactorPlugin
from better_auth.types import AuthRequest, dump_json
from conftest import SECRET, make_auth

PW = "password123"


# --- harness -------------------------------------------------------------------------


def build(*, session: SessionOptions | None = None, otp: bool = True, **plugin_kwargs: Any):
    """Build an auth with the two-factor plugin; return ``(auth, box, plugin)``.

    ``box`` captures the last emitted 2FA OTP. ``otp=True`` wires a ``send_otp`` so the
    sign-in gate advertises the "otp" method.
    """
    box: dict[str, Any] = {"otp": None, "calls": []}

    def send(data: dict[str, Any], ctx: Any = None) -> None:
        box["otp"] = data["otp"]
        box["calls"].append(data)

    otp_options = plugin_kwargs.pop("otp_options", None) or {}
    if otp and "send_otp" not in otp_options:
        otp_options = {**otp_options, "send_otp": send}
    plugin = TwoFactorPlugin(otp_options=otp_options, **plugin_kwargs)
    overrides: dict[str, Any] = {"plugins": [plugin]}
    if session is not None:
        overrides["session"] = session
    return make_auth(**overrides), box, plugin


class Session:
    """A minimal cookie-jar client over ``auth.handle`` (path without the base_path)."""

    def __init__(self, auth: Any) -> None:
        self.auth = auth
        self.cookies: dict[str, str] = {}

    async def request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
        *,
        keep_cookies: bool = True,
        extra_cookies: dict[str, str] | None = None,
    ) -> Any:
        headers = {"origin": "http://testserver"}
        cookies = {**self.cookies, **(extra_cookies or {})}
        if cookies:
            headers["cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())
        if body is not None:
            headers["content-type"] = "application/json"
        req = AuthRequest(
            method=method,
            path=path,
            headers=headers,
            body=dump_json(body) if body is not None else b"",
        )
        resp = await self.auth.handle(req)
        if keep_cookies:
            self._apply(resp)
        return resp

    def _apply(self, resp: Any) -> None:
        for key, value in resp.headers:
            if key.lower() != "set-cookie":
                continue
            name, _, rest = value.partition("=")
            cookie_value = rest.split(";")[0]
            if cookie_value == "" or "max-age=0" in value.lower():
                self.cookies.pop(name, None)
            else:
                self.cookies[name] = cookie_value

    async def post(self, path: str, body: dict[str, Any] | None = None, **kw: Any) -> Any:
        return await self.request("POST", path, body, **kw)

    async def get(self, path: str, **kw: Any) -> Any:
        return await self.request("GET", path, **kw)


def set_cookies(resp: Any) -> dict[str, tuple[str, dict[str, str]]]:
    """Parse a response's Set-Cookie headers → ``{name: (value, attrs)}``."""
    out: dict[str, tuple[str, dict[str, str]]] = {}
    for key, value in resp.headers:
        if key.lower() != "set-cookie":
            continue
        first, *rest = value.split(";")
        name, _, cookie_value = first.strip().partition("=")
        attrs: dict[str, str] = {}
        for part in rest:
            attr_key, _, attr_value = part.strip().partition("=")
            attrs[attr_key.lower()] = attr_value
        out[name] = (cookie_value, attrs)
    return out


async def sign_up(s: Session, email: str = "user@example.com", password: str = PW) -> str:
    resp = await s.post("/sign-up/email", {"email": email, "password": password, "name": "U"})
    assert resp.status == 200, resp.body
    return resp.body["user"]["id"]


async def row(auth: Any, user_id: str, table: str = "twoFactor") -> dict[str, Any] | None:
    return await auth.adapter.find_one(table, [Where("userId", user_id)])


async def require_row(auth: Any, user_id: str, table: str = "twoFactor") -> dict[str, Any]:
    r = await row(auth, user_id, table)
    assert r is not None
    return r


async def totp_for(auth: Any, user_id: str, table: str = "twoFactor") -> str:
    r = await require_row(auth, user_id, table)
    return generate_totp(symmetric_decrypt(SECRET, r["secret"]))


async def enroll(
    auth: Any, email: str = "user@example.com", password: str = PW
) -> tuple[Session, str]:
    """Sign up + enable + verify-totp → a fully-enrolled 2FA user (session active)."""
    s = Session(auth)
    uid = await sign_up(s, email, password)
    enable_res = await s.post("/two-factor/enable", {"password": password})
    assert enable_res.status == 200, enable_res.body
    verify = await s.post("/two-factor/verify-totp", {"code": await totp_for(auth, uid)})
    assert verify.status == 200, verify.body
    return s, uid


# --- enable / enrollment -------------------------------------------------------------


async def test_enable_returns_uri_and_codes_without_enabling() -> None:
    auth, _box, _plugin = build()
    s = Session(auth)
    uid = await sign_up(s)
    res = await s.post("/two-factor/enable", {"password": PW})
    assert res.status == 200
    assert len(res.body["backupCodes"]) == 10
    assert res.body["totpURI"].startswith("otpauth://totp/")

    user = await auth.adapter.find_one("user", [Where("id", uid)])
    assert user["twoFactorEnabled"] is False
    r = await require_row(auth, uid)
    assert r["secret"] and r["backupCodes"]
    assert r["verified"] is False


async def test_enable_requires_valid_password() -> None:
    auth, _box, _plugin = build()
    s = Session(auth)
    await sign_up(s)
    res = await s.post("/two-factor/enable", {"password": "wrong-password"})
    assert res.status == 400
    assert res.body["code"] == "INVALID_PASSWORD"


async def test_default_issuer_is_app_name() -> None:
    auth, _box, _plugin = build()
    s = Session(auth)
    await sign_up(s)
    res = await s.post("/two-factor/enable", {"password": PW})
    uri = res.body["totpURI"]
    assert uri.startswith("otpauth://totp/Better%20Auth:")
    assert "&issuer=Better+Auth&" in uri
    assert "secret=" in uri and "digits=6" in uri and "period=30" in uri


async def test_custom_issuer_from_request() -> None:
    auth, _box, _plugin = build()
    s = Session(auth)
    await sign_up(s)
    res = await s.post("/two-factor/enable", {"password": PW, "issuer": "Custom App Name"})
    uri = res.body["totpURI"]
    assert uri.startswith("otpauth://totp/Custom%20App%20Name:")
    assert "&issuer=Custom+App+Name&" in uri


async def test_option_issuer_used_when_no_request_issuer() -> None:
    auth, _box, _plugin = build(issuer="MyOrg")
    s = Session(auth)
    await sign_up(s)
    res = await s.post("/two-factor/enable", {"password": PW})
    assert "&issuer=MyOrg&" in res.body["totpURI"]


async def test_enable_stores_decryptable_secret_and_codes() -> None:
    auth, _box, _plugin = build()
    s = Session(auth)
    uid = await sign_up(s)
    res = await s.post("/two-factor/enable", {"password": PW})
    r = await require_row(auth, uid)
    # secret round-trips through symmetric_decrypt (XChaCha20 hex)
    secret = symmetric_decrypt(SECRET, r["secret"])
    assert 20 <= len(secret) <= 40
    codes = json.loads(symmetric_decrypt(SECRET, r["backupCodes"]))
    assert codes == res.body["backupCodes"]
    assert all("-" in c and len(c) == 11 for c in codes)


async def test_verify_totp_completes_enrollment() -> None:
    auth, _box, _plugin = build()
    s = Session(auth)
    uid = await sign_up(s)
    await s.post("/two-factor/enable", {"password": PW})
    res = await s.post("/two-factor/verify-totp", {"code": await totp_for(auth, uid)})
    assert res.status == 200
    assert res.body["token"]

    user = await auth.adapter.find_one("user", [Where("id", uid)])
    assert user["twoFactorEnabled"] is True
    assert (await require_row(auth, uid))["verified"] is True


async def test_verify_totp_wrong_code_during_enrollment() -> None:
    auth, _box, _plugin = build()
    s = Session(auth)
    uid = await sign_up(s)
    await s.post("/two-factor/enable", {"password": PW})
    res = await s.post("/two-factor/verify-totp", {"code": "000000"})
    assert res.status == 401
    assert res.body["message"] == ERROR_CODES["INVALID_CODE"]
    # re-verify (authenticated) is NOT attempt-capped: enrollment still pending
    user = await auth.adapter.find_one("user", [Where("id", uid)])
    assert user["twoFactorEnabled"] is False


async def test_skip_verification_on_enable() -> None:
    auth, _box, _plugin = build(skip_verification_on_enable=True)
    s = Session(auth)
    uid = await sign_up(s)
    res = await s.post("/two-factor/enable", {"password": PW})
    assert res.status == 200
    user = await auth.adapter.find_one("user", [Where("id", uid)])
    assert user["twoFactorEnabled"] is True
    assert (await require_row(auth, uid))["verified"] is True


async def test_get_totp_uri() -> None:
    auth, _box, _plugin = build()
    s, _uid = await enroll(auth)
    res = await s.post("/two-factor/get-totp-uri", {"password": PW})
    assert res.status == 200
    assert res.body["totpURI"].startswith("otpauth://totp/")


# --- sign-in gate --------------------------------------------------------------------


async def test_sign_in_gate_returns_redirect_and_methods() -> None:
    auth, _box, _plugin = build()
    await enroll(auth)

    fresh = Session(auth)
    res = await fresh.post("/sign-in/email", {"email": "user@example.com", "password": PW})
    assert res.status == 200
    assert res.body["twoFactorRedirect"] is True
    assert res.body["twoFactorMethods"] == ["totp", "otp"]

    cookies = set_cookies(res)
    assert cookies["better-auth.session_token"][0] == ""
    assert "better-auth.two_factor" in cookies
    assert cookies["better-auth.two_factor"][0] != ""


async def test_sign_in_gate_scrubs_session_cookies_with_cache() -> None:
    auth, _box, _plugin = build(session=SessionOptions(cookie_cache=CookieCache(enabled=True)))
    await enroll(auth)

    fresh = Session(auth)
    res = await fresh.post("/sign-in/email", {"email": "user@example.com", "password": PW})
    cookies = set_cookies(res)
    # no valid session_token or session_data may leak on a 2FA-required sign-in
    assert cookies["better-auth.session_token"][0] == ""
    assert cookies.get("better-auth.session_data", ("",))[0] == ""
    # the scrubbed cookies cannot authenticate
    session = await fresh.get("/get-session")
    assert session.body is None


async def test_sign_in_gate_default_max_age_600() -> None:
    auth, _box, _plugin = build()
    await enroll(auth)
    fresh = Session(auth)
    res = await fresh.post("/sign-in/email", {"email": "user@example.com", "password": PW})
    assert set_cookies(res)["better-auth.two_factor"][1].get("max-age") == "600"


async def test_sign_in_gate_custom_cookie_max_age() -> None:
    auth, _box, _plugin = build(two_factor_cookie_max_age=900)
    await enroll(auth)
    fresh = Session(auth)
    res = await fresh.post("/sign-in/email", {"email": "user@example.com", "password": PW})
    assert set_cookies(res)["better-auth.two_factor"][1].get("max-age") == "900"


async def test_no_gate_when_two_factor_disabled() -> None:
    auth, _box, _plugin = build()
    s = Session(auth)
    await sign_up(s)  # user without 2FA
    fresh = Session(auth)
    res = await fresh.post("/sign-in/email", {"email": "user@example.com", "password": PW})
    assert res.status == 200
    assert res.body.get("twoFactorRedirect") is None
    assert res.body["user"]["email"] == "user@example.com"


async def test_methods_totp_only_without_send_otp() -> None:
    auth, _box, _plugin = build(otp=False)
    await enroll(auth)
    fresh = Session(auth)
    res = await fresh.post("/sign-in/email", {"email": "user@example.com", "password": PW})
    assert res.body["twoFactorMethods"] == ["totp"]


# --- full flows: verify-otp / verify-totp on sign-in ---------------------------------


async def test_full_flow_send_otp_verify_otp_mints_session() -> None:
    auth, box, _plugin = build()
    await enroll(auth)

    fresh = Session(auth)
    await fresh.post("/sign-in/email", {"email": "user@example.com", "password": PW})
    send = await fresh.post("/two-factor/send-otp", {})
    assert send.status == 200
    assert len(box["otp"]) == 6

    verify = await fresh.post("/two-factor/verify-otp", {"code": box["otp"]})
    assert verify.status == 200
    assert verify.body["token"]

    session = await fresh.get("/get-session")
    assert session.body is not None
    assert session.body["user"]["email"] == "user@example.com"


async def test_sign_in_verify_totp_mints_session() -> None:
    auth, _box, _plugin = build()
    _s, uid = await enroll(auth)

    fresh = Session(auth)
    await fresh.post("/sign-in/email", {"email": "user@example.com", "password": PW})
    verify = await fresh.post("/two-factor/verify-totp", {"code": await totp_for(auth, uid)})
    assert verify.status == 200
    assert verify.body["token"]
    assert (await fresh.get("/get-session")).body is not None


async def test_missing_two_factor_cookie_is_rejected() -> None:
    auth, box, _plugin = build()
    _s, _uid = await enroll(auth)
    fresh = Session(auth)
    await fresh.post("/sign-in/email", {"email": "user@example.com", "password": PW})
    # send otp so a row exists, then drop the two_factor cookie before verifying
    await fresh.post("/two-factor/send-otp", {})
    fresh.cookies.pop("better-auth.two_factor", None)
    res = await fresh.post("/two-factor/verify-otp", {"code": box["otp"]})
    assert res.status == 401
    assert res.body["message"] == ERROR_CODES["INVALID_TWO_FACTOR_COOKIE"]


async def test_wrong_totp_on_sign_in_returns_invalid_code() -> None:
    auth, _box, _plugin = build()
    await enroll(auth)
    fresh = Session(auth)
    await fresh.post("/sign-in/email", {"email": "user@example.com", "password": PW})
    res = await fresh.post("/two-factor/verify-totp", {"code": "000000"})
    assert res.status == 401
    assert res.body["message"] == ERROR_CODES["INVALID_CODE"]


# --- attempt budget + lockout --------------------------------------------------------


async def test_totp_attempt_budget_then_cancels_challenge() -> None:
    auth, _box, _plugin = build()
    _s, uid = await enroll(auth)
    fresh = Session(auth)
    await fresh.post("/sign-in/email", {"email": "user@example.com", "password": PW})

    for _ in range(5):
        res = await fresh.post("/two-factor/verify-totp", {"code": "000000"})
        assert res.status == 401
        assert res.body["message"] == ERROR_CODES["INVALID_CODE"]

    # budget spent: even a correct code is rejected as too-many-attempts
    locked = await fresh.post("/two-factor/verify-totp", {"code": await totp_for(auth, uid)})
    assert locked.status == 400
    assert locked.body["message"] == ERROR_CODES["TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE"]

    # the lockout cancelled the challenge itself → next call is a dead cookie
    after = await fresh.post("/two-factor/verify-totp", {"code": "000000"})
    assert after.status == 401
    assert after.body["message"] == ERROR_CODES["INVALID_TWO_FACTOR_COOKIE"]


async def test_otp_attempt_budget() -> None:
    auth, box, _plugin = build(otp_options={"allowed_attempts": 2})
    await enroll(auth)
    fresh = Session(auth)
    await fresh.post("/sign-in/email", {"email": "user@example.com", "password": PW})
    await fresh.post("/two-factor/send-otp", {})

    for _ in range(2):
        res = await fresh.post("/two-factor/verify-otp", {"code": "000000"})
        assert res.status == 401
        assert res.body["message"] == ERROR_CODES["INVALID_CODE"]

    locked = await fresh.post("/two-factor/verify-otp", {"code": box["otp"]})
    assert locked.status == 400
    assert locked.body["message"] == ERROR_CODES["TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE"]


async def test_account_lockout_across_challenge() -> None:
    auth, _box, _plugin = build(account_lockout={"max_failed_attempts": 2, "duration_seconds": 900})
    _s, uid = await enroll(auth)
    fresh = Session(auth)
    await fresh.post("/sign-in/email", {"email": "user@example.com", "password": PW})

    for _ in range(2):
        res = await fresh.post("/two-factor/verify-totp", {"code": "000000"})
        assert res.status == 401

    locked = await fresh.post("/two-factor/verify-totp", {"code": await totp_for(auth, uid)})
    assert locked.status == 429
    assert locked.body["message"] == ERROR_CODES["ACCOUNT_TEMPORARILY_LOCKED"]
    # the lock is recorded on the twoFactor row
    assert (await require_row(auth, uid))["lockedUntil"] is not None


# --- backup codes --------------------------------------------------------------------


async def test_backup_code_sign_in_removes_code() -> None:
    auth, _box, _plugin = build()
    _s, uid = await enroll(auth)
    codes = json.loads(symmetric_decrypt(SECRET, (await require_row(auth, uid))["backupCodes"]))

    fresh = Session(auth)
    await fresh.post("/sign-in/email", {"email": "user@example.com", "password": PW})
    res = await fresh.post("/two-factor/verify-backup-code", {"code": codes[0]})
    assert res.status == 200
    assert (await fresh.get("/get-session")).body is not None

    remaining = json.loads(symmetric_decrypt(SECRET, (await require_row(auth, uid))["backupCodes"]))
    assert codes[0] not in remaining
    assert len(remaining) == 9


async def test_wrong_backup_code_returns_invalid_backup_code() -> None:
    auth, _box, _plugin = build()
    await enroll(auth)
    fresh = Session(auth)
    await fresh.post("/sign-in/email", {"email": "user@example.com", "password": PW})
    res = await fresh.post("/two-factor/verify-backup-code", {"code": "invalid-code"})
    assert res.status == 401
    assert res.body["message"] == ERROR_CODES["INVALID_BACKUP_CODE"]


async def test_backup_code_single_use_under_concurrency() -> None:
    """The same backup code submitted concurrently must succeed exactly once."""
    auth, _box, _plugin = build()
    s, uid = await enroll(auth)  # authenticated re-verify path (no per-challenge counter)
    codes = json.loads(symmetric_decrypt(SECRET, (await require_row(auth, uid))["backupCodes"]))
    token = s.cookies["better-auth.session_token"]

    async def attempt() -> int:
        client = Session(auth)
        resp = await client.post(
            "/two-factor/verify-backup-code",
            {"code": codes[0], "disableSession": True},
            extra_cookies={"better-auth.session_token": token},
        )
        return resp.status

    results = await asyncio.gather(*(attempt() for _ in range(8)))
    # exactly one success; every loser is rejected (409 lost-CAS or 401 already-consumed)
    assert results.count(200) == 1
    assert all(status in (200, 401, 409) for status in results)

    remaining = json.loads(symmetric_decrypt(SECRET, (await require_row(auth, uid))["backupCodes"]))
    assert codes[0] not in remaining
    assert len(remaining) == 9


async def test_backup_code_optimistic_concurrency_guard() -> None:
    """The load-bearing CAS: a backup-codes rewrite guarded on the old value loses when the
    row was changed under it (the 409-CONFLICT path that makes a code single-use under real
    DB parallelism, where the in-memory adapter's synchronous ops don't interleave)."""
    auth, _box, plugin = build()
    _s, uid = await enroll(auth)
    tf = await require_row(auth, uid)
    old = tf["backupCodes"]

    first = await auth.adapter.increment_one(
        plugin.table,
        [Where("id", tf["id"]), Where("backupCodes", old)],
        increment={},
        set={"backupCodes": await plugin._encode_backup_codes(["first-first"])},
    )
    assert first is not None  # first writer wins
    second = await auth.adapter.increment_one(
        plugin.table,
        [Where("id", tf["id"]), Where("backupCodes", old)],  # guard on the now-stale value
        increment={},
        set={"backupCodes": await plugin._encode_backup_codes(["secnd-secnd"])},
    )
    assert second is None  # stale write loses → endpoint maps this to 409 CONFLICT


async def test_generate_backup_codes_replaces_set() -> None:
    auth, _box, _plugin = build()
    s, uid = await enroll(auth)
    before = json.loads(symmetric_decrypt(SECRET, (await require_row(auth, uid))["backupCodes"]))
    res = await s.post("/two-factor/generate-backup-codes", {"password": PW})
    assert res.status == 200
    assert len(res.body["backupCodes"]) == 10
    after = json.loads(symmetric_decrypt(SECRET, (await require_row(auth, uid))["backupCodes"]))
    assert after == res.body["backupCodes"]
    assert after != before


async def test_view_backup_codes_server_only() -> None:
    auth, _box, plugin = build()
    s, uid = await enroll(auth)
    # not exposed over HTTP
    http = await s.post("/two-factor/view-backup-codes", {"userId": uid})
    assert http.status == 404
    # available as a server method, returns a parsed array
    result = await plugin.view_backup_codes(uid)
    assert result["status"] is True
    assert isinstance(result["backupCodes"], list)
    assert len(result["backupCodes"]) == 10


# --- trust device --------------------------------------------------------------------


async def test_trust_device_skips_2fa_and_rotates() -> None:
    auth, box, _plugin = build()
    await enroll(auth)

    fresh = Session(auth)
    await fresh.post("/sign-in/email", {"email": "user@example.com", "password": PW})
    await fresh.post("/two-factor/send-otp", {})
    verify = await fresh.post("/two-factor/verify-otp", {"code": box["otp"], "trustDevice": True})
    assert verify.status == 200
    trust_value = set_cookies(verify)["better-auth.trust_device"][0]
    assert trust_value != ""

    # a later sign-in with the trust cookie skips 2FA and rotates the cookie
    trusted = Session(auth)
    trusted.cookies["better-auth.trust_device"] = trust_value
    signin = await trusted.post("/sign-in/email", {"email": "user@example.com", "password": PW})
    assert signin.status == 200
    assert signin.body.get("twoFactorRedirect") is None
    assert signin.body["user"]["email"] == "user@example.com"
    rotated = set_cookies(signin)["better-auth.trust_device"][0]
    assert rotated != ""

    # the OLD (pre-rotation) trust cookie no longer skips 2FA
    stale = Session(auth)
    stale.cookies["better-auth.trust_device"] = trust_value
    again = await stale.post("/sign-in/email", {"email": "user@example.com", "password": PW})
    assert again.body.get("twoFactorRedirect") is True

    # the rotated cookie still works
    ok = Session(auth)
    ok.cookies["better-auth.trust_device"] = rotated
    ok_res = await ok.post("/sign-in/email", {"email": "user@example.com", "password": PW})
    assert ok_res.body.get("twoFactorRedirect") is None


async def test_trust_device_custom_max_age() -> None:
    auth, box, _plugin = build(trust_device_max_age=7 * 24 * 60 * 60)
    await enroll(auth)
    fresh = Session(auth)
    await fresh.post("/sign-in/email", {"email": "user@example.com", "password": PW})
    await fresh.post("/two-factor/send-otp", {})
    verify = await fresh.post("/two-factor/verify-otp", {"code": box["otp"], "trustDevice": True})
    trust = set_cookies(verify)["better-auth.trust_device"]
    assert trust[1].get("max-age") == str(7 * 24 * 60 * 60)


async def test_trust_device_expired_record_forces_2fa() -> None:
    auth, box, _plugin = build()
    _s, uid = await enroll(auth)
    fresh = Session(auth)
    await fresh.post("/sign-in/email", {"email": "user@example.com", "password": PW})
    await fresh.post("/two-factor/send-otp", {})
    verify = await fresh.post("/two-factor/verify-otp", {"code": box["otp"], "trustDevice": True})
    trust_value = set_cookies(verify)["better-auth.trust_device"][0]

    # expire the server-side trust record
    records = await auth.adapter.find_many("verification", [Where("value", uid)])
    trust_rows = [r for r in records if r["identifier"].startswith("trust-device-")]
    assert trust_rows
    from datetime import timedelta

    from better_auth.session import utcnow

    for r in trust_rows:
        await auth.adapter.update(
            "verification", [Where("id", r["id"])], {"expiresAt": utcnow() - timedelta(seconds=60)}
        )

    trusted = Session(auth)
    trusted.cookies["better-auth.trust_device"] = trust_value
    res = await trusted.post("/sign-in/email", {"email": "user@example.com", "password": PW})
    assert res.body.get("twoFactorRedirect") is True
    # the expired cookie is cleared
    assert set_cookies(res)["better-auth.trust_device"][0] == ""


# --- disable -------------------------------------------------------------------------


async def test_disable_clears_two_factor_and_revokes_trust() -> None:
    auth, box, _plugin = build()
    _s, uid = await enroll(auth)

    # trust this device first
    fresh = Session(auth)
    await fresh.post("/sign-in/email", {"email": "user@example.com", "password": PW})
    await fresh.post("/two-factor/send-otp", {})
    await fresh.post("/two-factor/verify-otp", {"code": box["otp"], "trustDevice": True})
    trust_id = None
    records = await auth.adapter.find_many("verification", [Where("value", uid)])
    for r in records:
        if r["identifier"].startswith("trust-device-"):
            trust_id = r["identifier"]

    # disable via the trusted (freshly authenticated) session
    disable = await fresh.post("/two-factor/disable", {"password": PW})
    assert disable.status == 200
    assert disable.body["status"] is True
    assert set_cookies(disable)["better-auth.trust_device"][0] == ""

    user = await auth.adapter.find_one("user", [Where("id", uid)])
    assert user["twoFactorEnabled"] is False
    assert await row(auth, uid) is None
    if trust_id is not None:
        assert await auth.internal.find_verification_value(trust_id) is None

    # a subsequent sign-in no longer requires 2FA
    plain = Session(auth)
    res = await plain.post("/sign-in/email", {"email": "user@example.com", "password": PW})
    assert res.body.get("twoFactorRedirect") is None
    assert res.body["user"]["email"] == "user@example.com"


async def test_disable_requires_valid_password() -> None:
    auth, _box, _plugin = build()
    s, _uid = await enroll(auth)
    res = await s.post("/two-factor/disable", {"password": "wrong"})
    assert res.status == 400
    assert res.body["code"] == "INVALID_PASSWORD"


# --- cross-runtime fidelity ----------------------------------------------------------


async def test_ts_layout_row_decrypts() -> None:
    """A twoFactor row written the TS way (XChaCha20 secret + encrypted JSON codes)
    must verify and decode under the Python port."""
    auth, _box, plugin = build()
    s = Session(auth)
    uid = await sign_up(s)

    secret_plain = "JBSWY3DPEHPK3PXPABCDEFGH"  # a TOTP secret string
    codes = ["aaaaa-bbbbb", "ccccc-ddddd", "eeeee-fffff"]
    await auth.adapter.create(
        "twoFactor",
        {
            "userId": uid,
            "secret": symmetric_encrypt(SECRET, secret_plain),
            "backupCodes": symmetric_encrypt(SECRET, json.dumps(codes)),
            "verified": True,
        },
    )
    await auth.internal.update_user(uid, {"twoFactorEnabled": True})

    # re-verify TOTP with a code derived from the plaintext secret
    verify = await s.post("/two-factor/verify-totp", {"code": generate_totp(secret_plain)})
    assert verify.status == 200

    # backup codes decode to the exact JSON array TS wrote
    view = await plugin.view_backup_codes(uid)
    assert view["backupCodes"] == codes

    # and a hand-built backup code is accepted on a sign-in challenge
    fresh = Session(auth)
    await fresh.post("/sign-in/email", {"email": "user@example.com", "password": PW})
    used = await fresh.post("/two-factor/verify-backup-code", {"code": "aaaaa-bbbbb"})
    assert used.status == 200


async def test_otp_storage_encrypted_round_trip() -> None:
    auth, box, _plugin = build(otp_options={"store_otp": "encrypted"})
    await enroll(auth)
    fresh = Session(auth)
    await fresh.post("/sign-in/email", {"email": "user@example.com", "password": PW})
    await fresh.post("/two-factor/send-otp", {})
    res = await fresh.post("/two-factor/verify-otp", {"code": box["otp"]})
    assert res.status == 200


async def test_otp_storage_hashed_round_trip() -> None:
    auth, box, _plugin = build(otp_options={"store_otp": "hashed"})
    await enroll(auth)
    fresh = Session(auth)
    await fresh.post("/sign-in/email", {"email": "user@example.com", "password": PW})
    await fresh.post("/two-factor/send-otp", {})
    ok = await fresh.post("/two-factor/verify-otp", {"code": box["otp"]})
    assert ok.status == 200


# --- configuration -------------------------------------------------------------------


async def test_custom_table_name() -> None:
    auth, _box, _plugin = build(
        two_factor_table="custom_two_factor", skip_verification_on_enable=True
    )
    s = Session(auth)
    uid = await sign_up(s)
    res = await s.post("/two-factor/enable", {"password": PW})
    assert res.status == 200
    record = await auth.adapter.find_one("custom_two_factor", [Where("userId", uid)])
    assert record is not None and record["secret"]


async def test_error_code_strings_exact() -> None:
    assert ERROR_CODES["OTP_NOT_ENABLED"] == "OTP not enabled"
    assert ERROR_CODES["OTP_HAS_EXPIRED"] == "OTP has expired"
    assert ERROR_CODES["TOTP_NOT_ENABLED"] == "TOTP not enabled"
    assert ERROR_CODES["TWO_FACTOR_NOT_ENABLED"] == "Two factor isn't enabled"
    assert ERROR_CODES["BACKUP_CODES_NOT_ENABLED"] == "Backup codes aren't enabled"
    assert ERROR_CODES["INVALID_BACKUP_CODE"] == "Invalid backup code"
    assert ERROR_CODES["INVALID_CODE"] == "Invalid code"
    assert (
        ERROR_CODES["TOO_MANY_ATTEMPTS_REQUEST_NEW_CODE"]
        == "Too many attempts. Please request a new code."
    )
    assert ERROR_CODES["ACCOUNT_TEMPORARILY_LOCKED"] == (
        "Too many failed verification attempts. Your account is temporarily locked. "
        "Please try again later."
    )
    assert ERROR_CODES["INVALID_TWO_FACTOR_COOKIE"] == "Invalid two factor cookie"


async def test_rate_limit_rule() -> None:
    _auth, _box, plugin = build()
    rules = plugin.rate_limit()
    assert len(rules) == 1
    assert rules[0].window == 10
    assert rules[0].max == 3
    assert rules[0].path_matcher("/two-factor/verify-totp") is True
    assert rules[0].path_matcher("/sign-in/email") is False
