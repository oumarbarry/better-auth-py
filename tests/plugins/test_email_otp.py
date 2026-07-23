"""Tests for the email-otp plugin (parity with better-auth's email-otp.test.ts).

Covers every "Behaviors/edge cases" bullet of the spec: emails lowercased, atomic
consume (one winner under concurrency), non-consuming check + attempt budget, expiry,
storeOTP variants, resendStrategy, overrideDefaultEmailVerification, additionalFields,
verify-email cookie-cache isolation, change-email flows, enumeration prevention, and the
nine rate-limit rules.
"""

from __future__ import annotations

import asyncio
from datetime import timedelta
from typing import Any

from better_auth import EmailAndPassword, EmailVerification, Field, SessionOptions, Where
from better_auth.config import CookieCache, UserOptions
from better_auth.plugins_ext.email_otp import ERROR_CODES, EmailOTPPlugin
from better_auth.session import utcnow

# tests/plugins/ has no conftest of its own; pytest imports tests/conftest.py first
# (putting tests/ on sys.path), so the top-level helpers import cleanly.
from conftest import make_auth, make_client

API = "/api/auth"


def otp_auth(
    *,
    email_and_password: EmailAndPassword | None = None,
    email_verification: EmailVerification | None = None,
    session: SessionOptions | None = None,
    user: UserOptions | None = None,
    **plugin_kwargs: Any,
):
    """Build an auth with the email-otp plugin; return ``(auth, box, plugin)``.

    ``box`` captures the last-sent OTP and every send call so tests can read the code.
    """
    box: dict[str, Any] = {"otp": None, "calls": []}

    async def send(data: dict[str, Any], ctx: Any = None) -> None:
        box["otp"] = data["otp"]
        box["calls"].append(data)

    plugin = EmailOTPPlugin(send_verification_otp=send, **plugin_kwargs)
    overrides: dict[str, Any] = {"plugins": [plugin]}
    if email_and_password is not None:
        overrides["email_and_password"] = email_and_password
    if email_verification is not None:
        overrides["email_verification"] = email_verification
    if session is not None:
        overrides["session"] = session
    if user is not None:
        overrides["user"] = user
    return make_auth(**overrides), box, plugin


# --- request helpers (keep call sites short) ------------------------------------------


async def post(client: Any, path: str, body: dict[str, Any]) -> Any:
    return await client.post(f"{API}{path}", json=body)


async def signup(client: Any, email: str, password: str = "password123") -> Any:
    return await post(client, "/sign-up/email", {"email": email, "password": password, "name": "U"})


async def signin_pw(client: Any, email: str, password: str) -> Any:
    return await post(client, "/sign-in/email", {"email": email, "password": password})


async def send_otp(client: Any, email: str, otp_type: str) -> Any:
    body = {"email": email, "type": otp_type}
    return await post(client, "/email-otp/send-verification-otp", body)


async def verify_email(client: Any, email: str, otp: str) -> Any:
    return await post(client, "/email-otp/verify-email", {"email": email, "otp": otp})


async def signin_otp(client: Any, email: str, otp: str, **extra: Any) -> Any:
    return await post(client, "/sign-in/email-otp", {"email": email, "otp": otp, **extra})


async def check_otp(client: Any, email: str, otp_type: str, otp: str) -> Any:
    body = {"email": email, "type": otp_type, "otp": otp}
    return await post(client, "/email-otp/check-verification-otp", body)


async def reset_pw(client: Any, email: str, otp: str, password: str) -> Any:
    body = {"email": email, "otp": otp, "password": password}
    return await post(client, "/email-otp/reset-password", body)


async def request_change(client: Any, new_email: str, otp: str | None = None) -> Any:
    body: dict[str, Any] = {"newEmail": new_email}
    if otp is not None:
        body["otp"] = otp
    return await post(client, "/email-otp/request-email-change", body)


async def change_email(client: Any, new_email: str, otp: str) -> Any:
    return await post(client, "/email-otp/change-email", {"newEmail": new_email, "otp": otp})


async def get_session(client: Any) -> Any:
    return await client.get(f"{API}/get-session")


async def user_by_email(auth: Any, email: str) -> Any:
    return await auth.adapter.find_one("user", [Where("email", email)])


async def find_rows(auth: Any, identifier: str) -> list[dict[str, Any]]:
    return await auth.adapter.find_many("verification", [Where("identifier", identifier)])


async def expire(auth: Any, identifier: str) -> None:
    for row in await find_rows(auth, identifier):
        await auth.adapter.update(
            "verification", [Where("id", row["id"])], {"expiresAt": utcnow() - timedelta(seconds=5)}
        )


# --------------------------------------------------------------------------- basics


async def test_error_codes_exact_strings():
    assert ERROR_CODES == {
        "OTP_EXPIRED": "OTP expired",
        "INVALID_OTP": "Invalid OTP",
        "TOO_MANY_ATTEMPTS": "Too many attempts",
    }


async def test_verify_email_with_otp():
    auth, box, _ = otp_auth()
    async with make_client(auth) as client:
        await signup(client, "ada@example.com")
        res = await send_otp(client, "ada@example.com", "email-verification")
        assert res.status_code == 200
        assert res.json() == {"success": True}
        assert len(box["otp"]) == 6
        verified = await verify_email(client, "ada@example.com", box["otp"])
        assert verified.status_code == 200, verified.text
        assert verified.json()["status"] is True
        assert (await user_by_email(auth, "ada@example.com"))["emailVerified"] is True


async def test_sign_in_with_otp_existing_user():
    auth, box, _ = otp_auth()
    async with make_client(auth) as client:
        await signup(client, "ada@example.com")
        await send_otp(client, "ada@example.com", "sign-in")
        res = await signin_otp(client, "ada@example.com", box["otp"])
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["token"]
        assert body["user"]["email"] == "ada@example.com"
        assert "set-cookie" in res.headers  # session cookie issued


async def test_sign_in_creates_user_when_absent():
    auth, box, _ = otp_auth()
    async with make_client(auth) as client:
        await send_otp(client, "new-user@domain.com", "sign-in")
        res = await signin_otp(client, "new-user@domain.com", box["otp"])
        assert res.status_code == 200, res.text
        assert res.json()["token"]
        user = await user_by_email(auth, "new-user@domain.com")
        assert user is not None
        assert user["emailVerified"] is True


async def test_sign_in_sets_name_and_image():
    auth, box, _ = otp_auth()
    async with make_client(auth) as client:
        await send_otp(client, "named@domain.com", "sign-in")
        res = await signin_otp(
            client, "named@domain.com", box["otp"], name="Test User", image="https://x/a.png"
        )
        body = res.json()
        assert body["user"]["name"] == "Test User"
        assert body["user"]["image"] == "https://x/a.png"


async def test_uppercase_email_lowercased():
    auth, box, _ = otp_auth()
    async with make_client(auth) as client:
        await send_otp(client, "TEST-EMAIL@DOMAIN.COM", "sign-in")
        assert await find_rows(auth, "sign-in-otp-test-email@domain.com")  # stored lowercased
        res = await signin_otp(client, "TEST-EMAIL@DOMAIN.COM", box["otp"])
        assert res.status_code == 200, res.text
        assert res.json()["token"]


async def test_invalid_email_on_send():
    auth, _, _ = otp_auth()
    async with make_client(auth) as client:
        res = await send_otp(client, "invalid-email", "email-verification")
        assert res.status_code == 400
        assert res.json()["code"] == "INVALID_EMAIL"


async def test_reject_change_email_type_on_send():
    auth, _, _ = otp_auth()
    async with make_client(auth) as client:
        await signup(client, "ada@example.com")
        res = await send_otp(client, "ada@example.com", "change-email")
        assert res.status_code == 400
        assert res.json()["message"] == "Invalid OTP type"


async def test_sign_in_clears_unverified_account_password():
    """An unverified account's password is revoked once a sign-in OTP proves the mailbox."""
    auth, box, _ = otp_auth(
        email_and_password=EmailAndPassword(enabled=True, require_email_verification=True),
    )
    async with make_client(auth) as client:
        await signup(client, "unverified@e.com", "existing-password-123")
        user = await user_by_email(auth, "unverified@e.com")
        assert user["emailVerified"] is False
        blocked = await signin_pw(client, "unverified@e.com", "existing-password-123")
        assert blocked.status_code == 403  # verification gate
        await send_otp(client, "unverified@e.com", "sign-in")
        signed_in = await signin_otp(client, "unverified@e.com", box["otp"])
        assert signed_in.status_code == 200, signed_in.text
        assert (await user_by_email(auth, "unverified@e.com"))["emailVerified"] is True
        account = await auth.adapter.find_one(
            "account", [Where("userId", user["id"]), Where("providerId", "credential")]
        )
        assert account is None  # credential revoked


# --------------------------------------------------------------------- password reset


async def test_reset_password_flow():
    auth, box, _ = otp_auth()
    async with make_client(auth) as client:
        await signup(client, "ada@example.com", "orig-password")
        await send_otp(client, "ada@example.com", "forget-password")
        res = await reset_pw(client, "ada@example.com", box["otp"], "changed-password")
        assert res.status_code == 200, res.text
        assert res.json() == {"success": True}
        assert (await signin_pw(client, "ada@example.com", "changed-password")).status_code == 200


async def test_deprecated_forget_password_alias():
    auth, box, _ = otp_auth()
    async with make_client(auth) as client:
        await signup(client, "ada@example.com", "orig-password")
        res = await post(client, "/forget-password/email-otp", {"email": "ada@example.com"})
        assert res.status_code == 200
        assert res.json() == {"success": True}
        reset = await reset_pw(client, "ada@example.com", box["otp"], "changed-2")
        assert reset.status_code == 200, reset.text
        assert (await signin_pw(client, "ada@example.com", "changed-2")).status_code == 200


async def test_on_password_reset_callback():
    calls: list[Any] = []

    async def on_reset(data: dict[str, Any], request: Any) -> None:
        calls.append(data)

    eap = EmailAndPassword(enabled=True, on_password_reset=on_reset)
    auth, box, _ = otp_auth(email_and_password=eap)
    async with make_client(auth) as client:
        await signup(client, "ada@example.com", "orig-password")
        await send_otp(client, "ada@example.com", "forget-password")
        await reset_pw(client, "ada@example.com", box["otp"], "new-password")
        assert len(calls) == 1
        assert calls[0]["user"]["email"] == "ada@example.com"


async def test_reset_password_creates_credential_account():
    """A user that signed up via OTP (no password) gets a credential account on reset."""
    auth, box, _ = otp_auth()
    async with make_client(auth) as client:
        await send_otp(client, "otp-user@domain.com", "sign-in")
        await signin_otp(client, "otp-user@domain.com", box["otp"])
        user = await user_by_email(auth, "otp-user@domain.com")
        cred = await auth.adapter.find_one(
            "account", [Where("userId", user["id"]), Where("providerId", "credential")]
        )
        assert cred is None
        await send_otp(client, "otp-user@domain.com", "forget-password")
        await reset_pw(client, "otp-user@domain.com", box["otp"], "password")
        assert (await signin_pw(client, "otp-user@domain.com", "password")).status_code == 200


# -------------------------------------------------- check-verification-otp (non-consuming)


async def test_check_verification_otp_success():
    auth, box, _ = otp_auth()
    async with make_client(auth) as client:
        await signup(client, "ada@example.com")
        await send_otp(client, "ada@example.com", "email-verification")
        res = await check_otp(client, "ada@example.com", "email-verification", box["otp"])
        assert res.status_code == 200
        assert res.json() == {"success": True}
        assert await find_rows(auth, "email-verification-otp-ada@example.com")  # non-consuming


async def test_check_wrong_increments_attempts_without_burning():
    auth, box, _ = otp_auth()
    async with make_client(auth) as client:
        await signup(client, "ada@example.com")
        await send_otp(client, "ada@example.com", "email-verification")
        valid = box["otp"]
        res = await check_otp(client, "ada@example.com", "email-verification", "000000")
        assert res.status_code == 400
        assert res.json()["code"] == "INVALID_OTP"
        rows = await find_rows(auth, "email-verification-otp-ada@example.com")
        assert rows[0]["value"].endswith(":1")  # attempts bumped, OTP intact
        ok = await check_otp(client, "ada@example.com", "email-verification", valid)
        assert ok.status_code == 200  # valid OTP still works


async def test_check_user_not_found():
    auth, _, _ = otp_auth()
    async with make_client(auth) as client:
        res = await check_otp(client, "nobody@domain.com", "email-verification", "000000")
        assert res.status_code == 400
        assert res.json()["code"] == "USER_NOT_FOUND"


async def test_check_too_many_attempts():
    auth, _, _ = otp_auth()
    async with make_client(auth) as client:
        await signup(client, "ada@example.com")
        await send_otp(client, "ada@example.com", "email-verification")
        for _ in range(3):
            res = await check_otp(client, "ada@example.com", "email-verification", "000000")
            assert res.status_code == 400
            assert res.json()["message"] == "Invalid OTP"
        blocked = await check_otp(client, "ada@example.com", "email-verification", "000000")
        assert blocked.status_code == 403
        assert blocked.json()["message"] == "Too many attempts"


async def test_check_expired_otp():
    auth, box, _ = otp_auth()
    async with make_client(auth) as client:
        await signup(client, "ada@example.com")
        await send_otp(client, "ada@example.com", "email-verification")
        await expire(auth, "email-verification-otp-ada@example.com")
        res = await check_otp(client, "ada@example.com", "email-verification", box["otp"])
        assert res.status_code == 400
        assert res.json()["code"] == "OTP_EXPIRED"
        assert not await find_rows(auth, "email-verification-otp-ada@example.com")


# ---------------------------------------------------------------- expiry & attempt budget


async def test_verify_email_expired_otp_removes_row():
    auth, box, _ = otp_auth()
    async with make_client(auth) as client:
        await signup(client, "ada@example.com")
        await send_otp(client, "ada@example.com", "email-verification")
        await expire(auth, "email-verification-otp-ada@example.com")
        res = await verify_email(client, "ada@example.com", box["otp"])
        assert res.status_code == 400
        assert res.json()["code"] == "OTP_EXPIRED"
        assert not await find_rows(auth, "email-verification-otp-ada@example.com")


async def test_block_after_exceeding_attempts_verify_email():
    auth, _, _ = otp_auth()
    async with make_client(auth) as client:
        await signup(client, "ada@example.com")
        await send_otp(client, "ada@example.com", "email-verification")
        for _ in range(3):
            res = await verify_email(client, "ada@example.com", "wrong-otp")
            assert res.status_code == 400
            assert res.json()["message"] == "Invalid OTP"
        blocked = await verify_email(client, "ada@example.com", "000000")
        assert blocked.status_code == 403
        assert blocked.json()["message"] == "Too many attempts"


async def test_block_reset_password_after_attempts():
    auth, _, _ = otp_auth()
    async with make_client(auth) as client:
        await signup(client, "ada@example.com", "orig-password")
        await send_otp(client, "ada@example.com", "forget-password")
        for _ in range(3):
            res = await reset_pw(client, "ada@example.com", "wrong-otp", "new-password")
            assert res.status_code == 400
            assert res.json()["message"] == "Invalid OTP"
        blocked = await reset_pw(client, "ada@example.com", "000000", "new-password")
        assert blocked.status_code == 403
        assert blocked.json()["message"] == "Too many attempts"


# -------------------------------------------------------------- atomic consume & races


async def test_consumed_otp_cannot_replay_sign_in():
    auth, box, _ = otp_auth()
    async with make_client(auth) as client:
        await send_otp(client, "race@domain.com", "sign-in")
        first = await signin_otp(client, "race@domain.com", box["otp"])
        assert first.status_code == 200
        assert not await find_rows(auth, "sign-in-otp-race@domain.com")
        replay = await signin_otp(client, "race@domain.com", box["otp"])
        assert replay.status_code == 400
        assert replay.json()["code"] == "INVALID_OTP"


async def test_concurrent_sign_in_exactly_one_success():
    auth, box, _ = otp_auth()
    async with make_client(auth) as client:
        await send_otp(client, "concurrent@domain.com", "sign-in")
        otp = box["otp"]
        r1, r2 = await asyncio.gather(
            signin_otp(client, "concurrent@domain.com", otp),
            signin_otp(client, "concurrent@domain.com", otp),
        )
        assert sorted([r1.status_code, r2.status_code]) == [200, 400]
        failure = r1 if r1.status_code == 400 else r2
        assert failure.json()["code"] == "INVALID_OTP"
        assert not await find_rows(auth, "sign-in-otp-concurrent@domain.com")


async def test_concurrent_verify_email_exactly_one_success():
    auth, box, _ = otp_auth()
    async with make_client(auth) as client:
        await signup(client, "cverify@domain.com")
        await send_otp(client, "cverify@domain.com", "email-verification")
        otp = box["otp"]
        r1, r2 = await asyncio.gather(
            verify_email(client, "cverify@domain.com", otp),
            verify_email(client, "cverify@domain.com", otp),
        )
        assert sorted([r1.status_code, r2.status_code]) == [200, 400]


async def test_wrong_then_valid_then_replay():
    auth, box, _ = otp_auth()
    async with make_client(auth) as client:
        await send_otp(client, "wtvr@domain.com", "sign-in")
        valid = box["otp"]
        wrong = "111111" if valid == "000000" else "000000"
        bad = await signin_otp(client, "wtvr@domain.com", wrong)
        assert bad.json()["code"] == "INVALID_OTP"
        rows = await find_rows(auth, "sign-in-otp-wtvr@domain.com")
        assert rows[0]["value"].endswith(":1")
        assert (await signin_otp(client, "wtvr@domain.com", valid)).status_code == 200
        replay = await signin_otp(client, "wtvr@domain.com", valid)
        assert replay.json()["code"] == "INVALID_OTP"


async def test_lockout_not_recreated_then_fresh_works():
    auth, box, _ = otp_auth()
    async with make_client(auth) as client:
        await send_otp(client, "lock@domain.com", "sign-in")
        valid = box["otp"]
        wrong = "111111" if valid == "000000" else "000000"
        for _ in range(3):
            await signin_otp(client, "lock@domain.com", wrong)
        locked = await signin_otp(client, "lock@domain.com", wrong)
        assert locked.json()["code"] == "TOO_MANY_ATTEMPTS"
        assert not await find_rows(auth, "sign-in-otp-lock@domain.com")  # not recreated
        after = await signin_otp(client, "lock@domain.com", valid)
        assert after.json()["code"] == "INVALID_OTP"
        await send_otp(client, "lock@domain.com", "sign-in")  # a fresh send works
        assert (await signin_otp(client, "lock@domain.com", box["otp"])).status_code == 200


# ---------------------------------------------------------- disableSignUp enumeration


async def test_disable_sign_up_sign_in_invalid_otp():
    auth, box, _ = otp_auth(disable_sign_up=True)
    async with make_client(auth) as client:
        await send_otp(client, "ghost@domain.com", "sign-in")
        res = await signin_otp(client, "ghost@domain.com", box["otp"] or "000000")
        assert res.status_code == 400
        assert res.json()["code"] == "INVALID_OTP"


async def test_disable_sign_up_send_no_leak():
    auth, box, _ = otp_auth(disable_sign_up=True)
    async with make_client(auth) as client:
        box["calls"].clear()
        res = await send_otp(client, "ghost@domain.com", "sign-in")
        assert res.json() == {"success": True}
        assert box["calls"] == []  # never sent for a non-existent user
        await signup(client, "real@domain.com")
        res2 = await send_otp(client, "real@domain.com", "sign-in")
        assert res2.json() == {"success": True}
        assert len(box["calls"]) == 1  # existing user does get it


# ------------------------------------------------------- server-only + storeOTP variants


async def test_create_and_get_verification_otp_server():
    _auth, _box, plugin = otp_auth()
    otp = await plugin.create_verification_otp("srv@email.com", "sign-in")
    assert len(otp) == 6
    assert await plugin.get_verification_otp("srv@email.com", "sign-in") == otp


async def test_server_only_endpoints_not_http_dispatchable():
    auth, _, _ = otp_auth()
    async with make_client(auth) as client:
        create_body = {"email": "x@e.com", "type": "sign-in"}
        r1 = await post(client, "/email-otp/create-verification-otp", create_body)
        r2 = await client.get(f"{API}/email-otp/get-verification-otp?email=x@e.com&type=sign-in")
        assert r1.status_code == 404
        assert r2.status_code == 404


async def _expect_hashed_get_blocked(plugin: Any, email: str) -> None:
    try:
        await plugin.get_verification_otp(email, "sign-in")
        raise AssertionError("expected APIError")
    except Exception as exc:
        assert getattr(exc, "message", "") == "OTP is hashed, cannot return the plain text OTP"


async def test_store_otp_hashed():
    auth, box, plugin = otp_auth(store_otp="hashed")
    async with make_client(auth) as client:
        await send_otp(client, "hash@email.com", "sign-in")
        stored = (await find_rows(auth, "sign-in-otp-hash@email.com"))[0]["value"]
        assert stored.endswith(":0")
        assert stored.rsplit(":", 1)[0] != box["otp"]  # hashed, not plain
        await _expect_hashed_get_blocked(plugin, "hash@email.com")
        assert (await signin_otp(client, "hash@email.com", box["otp"])).status_code == 200


async def test_store_otp_encrypted():
    auth, box, plugin = otp_auth(store_otp="encrypted")
    async with make_client(auth) as client:
        await send_otp(client, "enc@email.com", "sign-in")
        stored = (await find_rows(auth, "sign-in-otp-enc@email.com"))[0]["value"]
        assert stored.endswith(":0")
        assert stored.rsplit(":", 1)[0] != box["otp"]
        assert await plugin.get_verification_otp("enc@email.com", "sign-in") == box["otp"]
        assert (await signin_otp(client, "enc@email.com", box["otp"])).status_code == 200


async def test_store_otp_custom_hash():
    async def custom_hash(otp: str) -> str:
        return f"hashed-{otp}"

    auth, box, plugin = otp_auth(store_otp={"hash": custom_hash})
    async with make_client(auth) as client:
        await send_otp(client, "chash@email.com", "sign-in")
        stored = (await find_rows(auth, "sign-in-otp-chash@email.com"))[0]["value"]
        assert stored == f"hashed-{box['otp']}:0"
        await _expect_hashed_get_blocked(plugin, "chash@email.com")
        assert (await signin_otp(client, "chash@email.com", box["otp"])).status_code == 200


async def test_store_otp_custom_encrypt():
    async def enc(otp: str) -> str:
        return otp + "encrypted"

    async def dec(value: str) -> str:
        return value.replace("encrypted", "")

    auth, box, plugin = otp_auth(store_otp={"encrypt": enc, "decrypt": dec})
    async with make_client(auth) as client:
        await send_otp(client, "cenc@email.com", "sign-in")
        stored = (await find_rows(auth, "sign-in-otp-cenc@email.com"))[0]["value"]
        assert stored == f"{box['otp']}encrypted:0"
        assert await plugin.get_verification_otp("cenc@email.com", "sign-in") == box["otp"]
        assert (await signin_otp(client, "cenc@email.com", box["otp"])).status_code == 200


# --------------------------------------------------------------------- resendStrategy


async def test_resend_reuse_returns_same_otp():
    auth, box, _ = otp_auth(resend_strategy="reuse")
    async with make_client(auth) as client:
        await signup(client, "ada@example.com")
        await send_otp(client, "ada@example.com", "email-verification")
        first = box["otp"]
        await send_otp(client, "ada@example.com", "email-verification")
        assert box["otp"] == first  # reused
        assert box["calls"][-1]["otp"] == first


async def test_resend_reuse_new_after_expiry():
    auth, box, _ = otp_auth(resend_strategy="reuse")
    async with make_client(auth) as client:
        await signup(client, "ada@example.com")
        await send_otp(client, "ada@example.com", "sign-in")
        first = box["otp"]
        await expire(auth, "sign-in-otp-ada@example.com")
        await send_otp(client, "ada@example.com", "sign-in")
        assert box["otp"] != first


async def test_resend_reuse_rotates_for_hashed():
    auth, box, _ = otp_auth(resend_strategy="reuse", store_otp="hashed")
    async with make_client(auth) as client:
        await signup(client, "ada@example.com")
        await send_otp(client, "ada@example.com", "email-verification")
        first = box["otp"]
        await send_otp(client, "ada@example.com", "email-verification")
        assert box["otp"] != first  # cannot recover a hash -> rotates


async def test_resend_reuse_rotates_for_custom_hash():
    async def custom_hash(otp: str) -> str:
        return f"hashed-{otp}"

    auth, box, _ = otp_auth(resend_strategy="reuse", store_otp={"hash": custom_hash})
    async with make_client(auth) as client:
        await signup(client, "ada@example.com")
        await send_otp(client, "ada@example.com", "email-verification")
        first = box["otp"]
        await send_otp(client, "ada@example.com", "email-verification")
        assert box["otp"] != first


async def test_resend_reuse_fresh_after_exhaustion():
    auth, box, _ = otp_auth(resend_strategy="reuse", allowed_attempts=2)
    async with make_client(auth) as client:
        await signup(client, "ada@example.com")
        await send_otp(client, "ada@example.com", "email-verification")
        first = box["otp"]
        await verify_email(client, "ada@example.com", "wrong1")
        await verify_email(client, "ada@example.com", "wrong2")
        await send_otp(client, "ada@example.com", "email-verification")
        assert box["otp"] != first  # attempts exhausted -> fresh OTP


# -------------------------------------------------------- overrideDefaultEmailVerification


async def test_override_sends_otp_once_on_sign_up_and_verifies():
    auth, box, _ = otp_auth(
        override_default_email_verification=True,
        send_verification_on_sign_up=True,  # must be ignored when overriding
        email_and_password=EmailAndPassword(enabled=True),
        email_verification=EmailVerification(send_on_sign_up=True),
    )
    async with make_client(auth) as client:
        await signup(client, "override@email.com", "password")
        assert len(box["calls"]) == 1  # exactly once
        assert box["calls"][0]["type"] == "email-verification"
        assert len(box["otp"]) == 6
        res = await verify_email(client, "override@email.com", box["otp"])
        assert res.status_code == 200, res.text
        assert res.json()["user"]["emailVerified"] is True


async def test_override_fires_after_verification_hook():
    after_calls: list[Any] = []

    async def after_hook(user: dict[str, Any], request: Any) -> None:
        after_calls.append(user)

    ev = EmailVerification(send_on_sign_up=True)
    # before/after email-verification hooks aren't fields on the Python config yet
    # (config.py is owned elsewhere); the plugin reads them via getattr, so set them
    # dynamically here to exercise the seam.
    setattr(ev, "after_email_verification", after_hook)  # noqa: B010
    auth, box, _ = otp_auth(
        override_default_email_verification=True,
        email_and_password=EmailAndPassword(enabled=True),
        email_verification=ev,
    )
    async with make_client(auth) as client:
        await signup(client, "hook@email.com", "password")
        res = await verify_email(client, "hook@email.com", box["otp"])
        assert res.status_code == 200, res.text
        assert len(after_calls) == 1
        assert after_calls[0]["email"] == "hook@email.com"
        assert after_calls[0]["emailVerified"] is True


async def test_default_does_not_override_email_verification():
    sent: list[Any] = []

    async def send_link(user: dict[str, Any], url: str, token: str) -> None:
        sent.append(user)

    ev = EmailVerification(send_on_sign_up=True, send_verification_email=send_link)
    auth, _, _ = otp_auth(
        email_and_password=EmailAndPassword(enabled=True),
        email_verification=ev,
    )  # override_default_email_verification defaults False
    async with make_client(auth) as client:
        await signup(client, "nolink@email.com", "password")
        assert len(sent) == 1  # the link sender fired, not the OTP override


# ---------------------------------------------------------- sign-up additional fields


def _af_user_options() -> UserOptions:
    return UserOptions(
        additional_fields={
            "lang": Field("string", required=False, input=True),
            "isAdmin": Field("boolean", default=False, input=False),
        }
    )


async def test_sign_up_with_additional_fields():
    auth, box, _ = otp_auth(user=_af_user_options())
    async with make_client(auth) as client:
        await send_otp(client, "af@domain.com", "sign-in")
        res = await signin_otp(client, "af@domain.com", box["otp"], name="AF User", lang="ko")
        assert res.status_code == 200, res.text
        assert res.json()["user"]["name"] == "AF User"
        user = await user_by_email(auth, "af@domain.com")
        assert user["lang"] == "ko"
        assert user["isAdmin"] is False


async def test_sign_up_ignores_input_false_fields():
    auth, box, _ = otp_auth(user=_af_user_options())
    async with make_client(auth) as client:
        await send_otp(client, "iff@domain.com", "sign-in")
        res = await signin_otp(client, "iff@domain.com", box["otp"], isAdmin=True)
        assert res.status_code == 200, res.text
        user = await user_by_email(auth, "iff@domain.com")
        assert user["isAdmin"] is False  # input:false ignored, default applied


# -------------------------------------------------------- verify-email cookie-cache isolation


async def test_verify_email_cookie_cache_isolation():
    auth, box, _ = otp_auth(session=SessionOptions(cookie_cache=CookieCache(enabled=True)))
    async with make_client(auth) as client:
        # user B signed in on this client (their own unverified account)
        await signup(client, "user-b@test.com", "user-b-password")
        # a separate account whose email the OTP is for
        async with make_client(auth) as other_client:
            await signup(other_client, "other@test.com", "other-password")
        await send_otp(client, "other@test.com", "email-verification")
        # verify other's email while authenticated as user B
        verified = await verify_email(client, "other@test.com", box["otp"])
        assert verified.status_code == 200, verified.text
        assert verified.json()["user"]["email"] == "other@test.com"
        assert verified.json()["user"]["emailVerified"] is True
        # user B's session must still read as unverified (cache not stamped)
        data = (await get_session(client)).json()
        assert data["user"]["email"] == "user-b@test.com"
        assert data["user"]["emailVerified"] is False


async def test_verify_email_auto_sign_in_returns_token():
    ev = EmailVerification(auto_sign_in_after_verification=True)
    auth, box, _ = otp_auth(email_verification=ev)
    async with make_client(auth) as client:
        await signup(client, "auto@example.com")
        await send_otp(client, "auto@example.com", "email-verification")
        res = await verify_email(client, "auto@example.com", box["otp"])
        assert res.status_code == 200, res.text
        assert res.json()["token"]


# ------------------------------------------------------------------------- change email


def _change_auth(**kw: Any):
    return otp_auth(change_email={"enabled": True}, **kw)


async def test_request_email_change_success():
    auth, box, _ = _change_auth()
    async with make_client(auth) as client:
        await signup(client, "owner@test.com")
        box["calls"].clear()
        res = await request_change(client, "new-email@test.com")
        assert res.status_code == 200, res.text
        assert res.json() == {"success": True}
        assert box["calls"][-1]["email"] == "new-email@test.com"
        assert box["calls"][-1]["type"] == "change-email"


async def test_request_email_change_unauthorized():
    auth, _, _ = _change_auth()
    async with make_client(auth) as client:
        res = await request_change(client, "new-email@test.com")
        assert res.status_code == 401
        assert res.json()["code"] == "UNAUTHORIZED"


async def test_request_email_change_disabled():
    auth, _, _ = otp_auth(change_email={"enabled": False})
    async with make_client(auth) as client:
        await signup(client, "owner@test.com")
        res = await request_change(client, "new@test.com")
        assert res.status_code == 400
        assert res.json()["message"] == "Change email with OTP is disabled"


async def test_request_email_change_same_email():
    auth, _, _ = _change_auth()
    async with make_client(auth) as client:
        await signup(client, "owner@test.com")
        res = await request_change(client, "owner@test.com")
        assert res.status_code == 400
        assert "Email is the same" in res.json()["message"]


async def test_request_email_change_taken_no_enumeration():
    auth, box, _ = _change_auth()
    async with make_client(auth) as client:
        async with make_client(auth) as other:
            await signup(other, "taken@test.com")
        await signup(client, "owner@test.com")
        box["calls"].clear()
        res = await request_change(client, "taken@test.com")
        assert res.status_code == 200
        assert res.json() == {"success": True}
        # no OTP sent to a taken address
        assert all(c["email"] != "taken@test.com" for c in box["calls"])


async def test_request_email_change_verify_current_email():
    auth, box, _ = otp_auth(change_email={"enabled": True, "verify_current_email": True})
    async with make_client(auth) as client:
        await signup(client, "owner@test.com")
        missing = await request_change(client, "new@test.com")
        assert missing.status_code == 400
        assert missing.json()["message"] == "OTP is required to verify current email"
        invalid = await request_change(client, "new@test.com", otp="123456")
        assert invalid.status_code == 400
        assert invalid.json()["code"] == "INVALID_OTP"  # no current-email OTP requested
        await send_otp(client, "owner@test.com", "email-verification")
        current_otp = box["otp"]
        box["calls"].clear()
        ok = await request_change(client, "verified-change@test.com", otp=current_otp)
        assert ok.status_code == 200, ok.text
        assert box["calls"][-1]["email"] == "verified-change@test.com"
        assert box["calls"][-1]["type"] == "change-email"


async def test_request_email_change_verify_current_expired():
    auth, box, _ = otp_auth(change_email={"enabled": True, "verify_current_email": True})
    async with make_client(auth) as client:
        await signup(client, "owner@test.com")
        await send_otp(client, "owner@test.com", "email-verification")
        await expire(auth, "email-verification-otp-owner@test.com")
        res = await request_change(client, "new@test.com", otp=box["otp"])
        assert res.status_code == 400
        assert res.json()["code"] == "OTP_EXPIRED"


async def test_change_email_success():
    auth, box, _ = _change_auth()
    async with make_client(auth) as client:
        await signup(client, "owner@test.com")
        await request_change(client, "changed@test.com")
        res = await change_email(client, "changed@test.com", box["otp"])
        assert res.status_code == 200, res.text
        assert res.json() == {"success": True}
        data = (await get_session(client)).json()
        assert data["user"]["email"] == "changed@test.com"
        assert data["user"]["emailVerified"] is True


async def test_change_email_unauthorized():
    auth, _, _ = _change_auth()
    async with make_client(auth) as client:
        res = await change_email(client, "x@test.com", "123456")
        assert res.status_code == 401
        assert res.json()["code"] == "UNAUTHORIZED"


async def test_change_email_different_session_email_invalid_otp():
    auth, box, _ = _change_auth()
    async with make_client(auth) as client:
        await signup(client, "owner@test.com")
        await request_change(client, "target@test.com")
        otp = box["otp"]
    async with make_client(auth) as other:  # a different user tries owner's OTP
        await signup(other, "other-acct@test.com")
        res = await change_email(other, "target@test.com", otp)
        assert res.status_code == 400
        assert res.json()["code"] == "INVALID_OTP"


async def test_change_email_wrong_new_email_invalid_otp():
    auth, box, _ = _change_auth()
    async with make_client(auth) as client:
        await signup(client, "owner@test.com")
        await request_change(client, "requested@test.com")
        res = await change_email(client, "wrong@test.com", box["otp"])
        assert res.status_code == 400
        assert res.json()["code"] == "INVALID_OTP"


async def test_change_email_expired_otp():
    auth, box, _ = _change_auth()
    async with make_client(auth) as client:
        await signup(client, "owner@test.com")
        await request_change(client, "exp@test.com")
        await expire(auth, "change-email-otp-owner@test.com-exp@test.com")
        res = await change_email(client, "exp@test.com", box["otp"])
        assert res.status_code == 400
        assert res.json()["code"] == "OTP_EXPIRED"


async def test_change_email_before_after_hooks():
    before_calls: list[Any] = []
    after_calls: list[Any] = []

    async def before_hook(user: dict[str, Any], request: Any) -> None:
        before_calls.append(user)

    async def after_hook(user: dict[str, Any], request: Any) -> None:
        after_calls.append(user)

    ev = EmailVerification()
    setattr(ev, "before_email_verification", before_hook)  # noqa: B010
    setattr(ev, "after_email_verification", after_hook)  # noqa: B010
    auth, box, _ = otp_auth(change_email={"enabled": True}, email_verification=ev)
    async with make_client(auth) as client:
        await signup(client, "owner@test.com")
        await request_change(client, "hooked@test.com")
        res = await change_email(client, "hooked@test.com", box["otp"])
        assert res.status_code == 200, res.text
        assert len(before_calls) == 1 and before_calls[0]["email"] == "owner@test.com"
        assert len(after_calls) == 1 and after_calls[0]["email"] == "hooked@test.com"
        assert after_calls[0]["emailVerified"] is True


# ---------------------------------------------------------------------------- rate limit


async def test_rate_limit_rules_default_and_custom():
    _auth, _box, plugin = otp_auth()
    rules = plugin.rate_limit()
    paths = [
        "/email-otp/send-verification-otp",
        "/email-otp/check-verification-otp",
        "/email-otp/verify-email",
        "/sign-in/email-otp",
        "/email-otp/request-password-reset",
        "/email-otp/reset-password",
        "/forget-password/email-otp",
        "/email-otp/request-email-change",
        "/email-otp/change-email",
    ]
    assert len(rules) == 9
    assert all(r.window == 60 and r.max == 3 for r in rules)
    matched = [p for p in paths if any(r.path_matcher(p) for r in rules)]
    assert sorted(matched) == sorted(paths)

    _a, _b, custom = otp_auth(rate_limit={"window": 120, "max": 7})
    assert all(r.window == 120 and r.max == 7 for r in custom.rate_limit())


async def test_rate_limit_integration_blocks_after_max():
    from better_auth.config import RateLimit

    auth, _, _ = otp_auth()
    auth.rate_limit = RateLimit(enabled=True)
    async with make_client(auth) as client:
        statuses = []
        for _ in range(5):
            statuses.append((await send_otp(client, "rl@email.com", "sign-in")).status_code)
        assert 429 in statuses  # folded plugin rule enforces window/max
