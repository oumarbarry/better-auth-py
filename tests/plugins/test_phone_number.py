"""Tests for the phone-number plugin (SMS-OTP sign-in, verification, password reset).

Mirrors the behaviours in better-auth's phone-number/phone-number.test.ts and the
gap spec (docs/plans/gap/04-plugins-simple.md, "phone-number"). Wire/storage fidelity
is the point: exact verification-value formats ("<code>:<attempts>"), reset identifier
"<phone>-request-password-reset", error strings/codes, and the atomic single-use gate.
"""

from __future__ import annotations

import asyncio
from datetime import timedelta
from typing import Any

from better_auth import Field
from better_auth.adapters.base import Where
from better_auth.config import EmailAndPassword, UserOptions
from better_auth.plugins_ext.phone_number import ERROR_CODES, PhoneNumberPlugin
from better_auth.session import utcnow
from conftest import make_auth, make_client

BASE = "/api/auth"


def phone_plugin(otp: dict[str, Any], **overrides: Any) -> PhoneNumberPlugin:
    """A plugin whose sendOTP records the last code into ``otp['code']``."""

    async def send_otp(data: dict[str, Any], ctx: Any = None) -> None:
        otp["code"] = data["code"]

    opts: dict[str, Any] = {
        "send_otp": send_otp,
        "sign_up_on_verification": {"get_temp_email": lambda p: f"temp-{p}@example.com"},
    }
    opts.update(overrides)
    return PhoneNumberPlugin(**opts)


async def send_otp(client: Any, phone: str, headers: dict[str, str] | None = None) -> Any:
    return await client.post(
        f"{BASE}/phone-number/send-otp", json={"phoneNumber": phone}, headers=headers or {}
    )


async def request_reset(client: Any, phone: str) -> Any:
    return await client.post(
        f"{BASE}/phone-number/request-password-reset", json={"phoneNumber": phone}
    )


async def register(client: Any, otp: dict[str, Any], phone: str) -> Any:
    """send-otp + verify → creates the user (signUpOnVerification) and a session cookie."""
    await send_otp(client, phone)
    res = await client.post(
        f"{BASE}/phone-number/verify", json={"phoneNumber": phone, "code": otp["code"]}
    )
    assert res.status_code == 200, res.text
    return res


# --- send-otp -------------------------------------------------------------------------


async def test_send_otp_stores_code_and_returns_message():
    otp: dict[str, Any] = {}
    auth = make_auth(plugins=[phone_plugin(otp)])
    phone = "+251911121314"
    async with make_client(auth) as client:
        res = await send_otp(client, phone)
        assert res.status_code == 200
        assert res.json() == {"message": "code sent"}
        assert len(otp["code"]) == 6 and otp["code"].isdigit()
        row = await auth.adapter.find_one("verification", [Where("identifier", phone)])
        assert row is not None
        assert row["value"] == f"{otp['code']}:0"  # "<code>:<attempts>" format


async def test_send_otp_not_implemented_returns_501():
    auth = make_auth(plugins=[PhoneNumberPlugin()])  # no send_otp configured
    async with make_client(auth) as client:
        res = await send_otp(client, "+251911121314")
        assert res.status_code == 501
        assert res.json()["message"] == ERROR_CODES["SEND_OTP_NOT_IMPLEMENTED"]


async def test_send_otp_invalid_phone_number():
    otp: dict[str, Any] = {}
    auth = make_auth(
        plugins=[phone_plugin(otp, phone_number_validator=lambda p: p.startswith("+"))]
    )
    async with make_client(auth) as client:
        res = await send_otp(client, "0000")
        assert res.status_code == 400
        assert res.json()["message"] == ERROR_CODES["INVALID_PHONE_NUMBER"]


async def test_send_otp_failure_does_not_fail_request():
    async def failing(data: dict[str, Any], ctx: Any = None) -> None:
        raise RuntimeError("SMS provider down")

    auth = make_auth(plugins=[PhoneNumberPlugin(send_otp=failing)])
    phone = "+251922334455"
    async with make_client(auth) as client:
        res = await send_otp(client, phone)
        assert res.status_code == 200
        assert res.json() == {"message": "code sent"}
        # the OTP row is written before sendOTP runs, so it survives the failure
        assert await auth.adapter.find_one("verification", [Where("identifier", phone)]) is not None


# --- verify (signUp / session) --------------------------------------------------------


async def test_verify_creates_user_and_session():
    otp: dict[str, Any] = {}
    auth = make_auth(plugins=[phone_plugin(otp)])
    phone = "+251911121314"
    async with make_client(auth) as client:
        await send_otp(client, phone)
        res = await client.post(
            f"{BASE}/phone-number/verify", json={"phoneNumber": phone, "code": otp["code"]}
        )
        assert res.status_code == 200
        body = res.json()
        assert body["status"] is True
        assert body["token"]
        assert body["user"]["phoneNumber"] == phone
        assert body["user"]["phoneNumberVerified"] is True
        assert body["user"]["email"] == f"temp-{phone}@example.com"
        # cookie set → the session is live
        session = await client.get(f"{BASE}/get-session")
        assert session.json()["user"]["phoneNumber"] == phone


async def test_verify_signup_copies_additional_fields():
    otp: dict[str, Any] = {}
    auth = make_auth(
        plugins=[phone_plugin(otp)],
        user=UserOptions(additional_fields={"lastName": Field("string", required=True)}),
    )
    phone = "+1234567890"
    async with make_client(auth) as client:
        await send_otp(client, phone)
        res = await client.post(
            f"{BASE}/phone-number/verify",
            json={"phoneNumber": phone, "code": otp["code"], "lastName": "Doe"},
        )
        assert res.status_code == 200, res.text
        assert res.json()["user"]["lastName"] == "Doe"


async def test_verify_disable_session_skips_session():
    otp: dict[str, Any] = {}
    auth = make_auth(plugins=[phone_plugin(otp)])
    phone = "+251911121314"
    async with make_client(auth) as client:
        await send_otp(client, phone)
        res = await client.post(
            f"{BASE}/phone-number/verify",
            json={"phoneNumber": phone, "code": otp["code"], "disableSession": True},
        )
        assert res.status_code == 200
        assert res.json()["token"] is None
        # no session cookie → not authenticated
        session = await client.get(f"{BASE}/get-session")
        assert session.json() is None


# --- verify (attempt accounting / atomic consume) -------------------------------------


async def test_verify_wrong_code_increments_attempts():
    otp: dict[str, Any] = {}
    auth = make_auth(plugins=[phone_plugin(otp, allowed_attempts=3)])
    phone = "+251900000002"
    async with make_client(auth) as client:
        await send_otp(client, phone)
        correct = otp["code"]
        for expected in (1, 2):
            res = await client.post(
                f"{BASE}/phone-number/verify", json={"phoneNumber": phone, "code": "000000"}
            )
            assert res.status_code == 400
            assert res.json()["message"] == ERROR_CODES["INVALID_OTP"]
            row = await auth.adapter.find_one("verification", [Where("identifier", phone)])
            assert row is not None
            value, attempts = row["value"].split(":")
            assert value == correct  # original code survives each wrong attempt
            assert attempts == str(expected)  # counter advances by exactly one
        # the surviving original code still verifies
        res = await client.post(
            f"{BASE}/phone-number/verify", json={"phoneNumber": phone, "code": correct}
        )
        assert res.status_code == 200
        assert await auth.adapter.find_one("verification", [Where("identifier", phone)]) is None


async def test_verify_too_many_attempts_locks_out():
    otp: dict[str, Any] = {}
    auth = make_auth(plugins=[phone_plugin(otp, allowed_attempts=3)])
    phone = "+251911121314"
    async with make_client(auth) as client:
        await send_otp(client, phone)
        for _ in range(3):
            res = await client.post(
                f"{BASE}/phone-number/verify", json={"phoneNumber": phone, "code": "000000"}
            )
            assert res.status_code == 400
            assert res.json()["message"] == ERROR_CODES["INVALID_OTP"]
        # past the budget → 403 and the row is NOT recreated (locked out)
        res = await client.post(
            f"{BASE}/phone-number/verify", json={"phoneNumber": phone, "code": "000000"}
        )
        assert res.status_code == 403
        assert res.json()["message"] == ERROR_CODES["TOO_MANY_ATTEMPTS"]
        assert await auth.adapter.find_one("verification", [Where("identifier", phone)]) is None


async def test_verify_cannot_reuse_after_success():
    otp: dict[str, Any] = {}
    auth = make_auth(plugins=[phone_plugin(otp)])
    phone = "+251911121314"
    async with make_client(auth) as client:
        await send_otp(client, phone)
        code = otp["code"]
        first = await client.post(
            f"{BASE}/phone-number/verify", json={"phoneNumber": phone, "code": code}
        )
        assert first.status_code == 200
        again = await client.post(
            f"{BASE}/phone-number/verify", json={"phoneNumber": phone, "code": code}
        )
        assert again.status_code == 400  # consumed


async def test_verify_expired_code_deletes_row():
    otp: dict[str, Any] = {}
    auth = make_auth(plugins=[phone_plugin(otp)])
    phone = "+25120201212"
    async with make_client(auth) as client:
        await send_otp(client, phone)
        # force the stored OTP past its expiry
        await auth.adapter.update_many(
            "verification",
            [Where("identifier", phone)],
            {"expiresAt": utcnow() - timedelta(seconds=1)},
        )
        res = await client.post(
            f"{BASE}/phone-number/verify", json={"phoneNumber": phone, "code": otp["code"]}
        )
        assert res.status_code == 400
        assert res.json()["message"] == ERROR_CODES["OTP_EXPIRED"]
        assert await auth.adapter.find_one("verification", [Where("identifier", phone)]) is None


async def test_verify_otp_not_found():
    otp: dict[str, Any] = {}
    auth = make_auth(plugins=[phone_plugin(otp)])
    async with make_client(auth) as client:
        res = await client.post(
            f"{BASE}/phone-number/verify", json={"phoneNumber": "+000", "code": "123456"}
        )
        assert res.status_code == 400
        assert res.json()["message"] == ERROR_CODES["OTP_NOT_FOUND"]


async def test_concurrent_verify_allows_exactly_one_success():
    otp: dict[str, Any] = {}
    auth = make_auth(plugins=[phone_plugin(otp, allowed_attempts=3)])
    phone = "+251900000001"
    async with make_client(auth) as client:
        await send_otp(client, phone)
        code = otp["code"]

        # Barrier: force both requests to read the live OTP row before either consumes
        # it, so the atomic consume gate — not luck — decides the single winner.
        original_find = auth.internal.find_verification_value
        state = {"entered": 0}
        barrier = asyncio.Event()

        async def patched(identifier: str) -> Any:
            result = await original_find(identifier)
            if identifier == phone:
                state["entered"] += 1
                if state["entered"] >= 2:
                    barrier.set()
                await barrier.wait()
            return result

        auth.internal.find_verification_value = patched  # ty: ignore[invalid-assignment]
        try:
            results = await asyncio.gather(
                client.post(
                    f"{BASE}/phone-number/verify", json={"phoneNumber": phone, "code": code}
                ),
                client.post(
                    f"{BASE}/phone-number/verify", json={"phoneNumber": phone, "code": code}
                ),
            )
        finally:
            auth.internal.find_verification_value = original_find  # ty: ignore[invalid-assignment]

        successes = [r for r in results if r.status_code == 200 and r.json().get("status") is True]
        failures = [r for r in results if r.status_code != 200]
        assert len(successes) == 1
        assert len(failures) == 1
        assert failures[0].status_code == 400
        assert failures[0].json()["message"] == ERROR_CODES["INVALID_OTP"]
        # the code was consumed exactly once
        assert await auth.internal.find_verification_value(phone) is None


# --- verify (updatePhoneNumber) -------------------------------------------------------


async def test_verify_update_phone_number_requires_session():
    otp: dict[str, Any] = {}
    auth = make_auth(plugins=[phone_plugin(otp)])
    phone = "+251911121314"
    async with make_client(auth) as client:
        await send_otp(client, phone)
        res = await client.post(
            f"{BASE}/phone-number/verify",
            json={"phoneNumber": phone, "code": otp["code"], "updatePhoneNumber": True},
        )
        assert res.status_code == 401
        assert res.json()["code"] == "USER_NOT_FOUND"


async def test_verify_update_phone_number_rejects_existing():
    otp: dict[str, Any] = {}
    auth = make_auth(plugins=[phone_plugin(otp)])
    taken = "+251911121314"
    async with make_client(auth) as owner:
        await register(owner, otp, taken)  # owner now holds `taken`
    async with make_client(auth) as client:
        await register(client, otp, "+9990001112")  # client has a session on another number
        await send_otp(client, taken)
        res = await client.post(
            f"{BASE}/phone-number/verify",
            json={"phoneNumber": taken, "code": otp["code"], "updatePhoneNumber": True},
        )
        assert res.status_code == 400
        assert res.json()["message"] == ERROR_CODES["PHONE_NUMBER_EXIST"]


async def test_verify_update_phone_number_fires_callback():
    otp: dict[str, Any] = {}
    calls: list[dict[str, Any]] = []

    async def callback(data: dict[str, Any], ctx: Any = None) -> None:
        calls.append(data)

    auth = make_auth(plugins=[phone_plugin(otp, callback_on_verification=callback)])
    async with make_client(auth) as client:
        await register(client, otp, "+251911121314")  # initial number + session
        calls.clear()
        updated = "+0123456789"
        await send_otp(client, updated)
        res = await client.post(
            f"{BASE}/phone-number/verify",
            json={"phoneNumber": updated, "code": otp["code"], "updatePhoneNumber": True},
        )
        assert res.status_code == 200
        assert res.json()["user"]["phoneNumber"] == updated
        assert len(calls) == 1
        assert calls[0]["phoneNumber"] == updated
        assert calls[0]["user"]["phoneNumberVerified"] is True
        session = await client.get(f"{BASE}/get-session")
        assert session.json()["user"]["phoneNumber"] == updated


# --- custom verifyOTP -----------------------------------------------------------------


async def test_custom_verify_otp_used_and_cleans_up_row():
    otp: dict[str, Any] = {}
    valid = {"ok": True}

    async def verify_otp(data: dict[str, Any], ctx: Any = None) -> bool:
        return valid["ok"]

    auth = make_auth(plugins=[phone_plugin(otp, verify_otp=verify_otp)])
    phone = "+1234567890"
    async with make_client(auth) as client:
        await send_otp(client, phone)  # writes an internal row the custom path must clean up
        res = await client.post(
            f"{BASE}/phone-number/verify", json={"phoneNumber": phone, "code": "any-code"}
        )
        assert res.status_code == 200
        assert res.json()["status"] is True
        # custom verify still removes the stored verification row
        assert await auth.adapter.find_one("verification", [Where("identifier", phone)]) is None


async def test_custom_verify_otp_returns_false():
    otp: dict[str, Any] = {}

    async def verify_otp(data: dict[str, Any], ctx: Any = None) -> bool:
        return False

    auth = make_auth(plugins=[phone_plugin(otp, verify_otp=verify_otp)])
    async with make_client(auth) as client:
        await send_otp(client, "+9876543210")
        res = await client.post(
            f"{BASE}/phone-number/verify", json={"phoneNumber": "+9876543210", "code": "nope"}
        )
        assert res.status_code == 400
        assert res.json()["message"] == ERROR_CODES["INVALID_OTP"]


async def test_custom_verify_otp_without_internal_store():
    otp: dict[str, Any] = {}

    async def verify_otp(data: dict[str, Any], ctx: Any = None) -> bool:
        return True

    auth = make_auth(plugins=[phone_plugin(otp, verify_otp=verify_otp)])
    async with make_client(auth) as client:
        # no send-otp: external SMS provider owns the code, internal store is empty
        res = await client.post(
            f"{BASE}/phone-number/verify", json={"phoneNumber": "+5555555555", "code": "external"}
        )
        assert res.status_code == 200
        assert res.json()["status"] is True


# --- sign-in --------------------------------------------------------------------------


async def test_sign_in_phone_number_success():
    otp: dict[str, Any] = {}
    auth = make_auth(plugins=[phone_plugin(otp)])
    phone = "+251911121314"
    async with make_client(auth) as client:
        await register(client, otp, phone)  # creates user (no password yet) + session
        set_pw = await client.post(f"{BASE}/set-password", json={"newPassword": "password123"})
        assert set_pw.status_code == 200, set_pw.text
    async with make_client(auth) as fresh:
        res = await fresh.post(
            f"{BASE}/sign-in/phone-number",
            json={"phoneNumber": phone, "password": "password123"},
        )
        assert res.status_code == 200, res.text
        assert res.json()["token"]
        assert res.json()["user"]["phoneNumber"] == phone


async def test_sign_in_unknown_phone_number():
    otp: dict[str, Any] = {}
    auth = make_auth(plugins=[phone_plugin(otp)])
    async with make_client(auth) as client:
        res = await client.post(
            f"{BASE}/sign-in/phone-number", json={"phoneNumber": "+000", "password": "x"}
        )
        assert res.status_code == 401
        assert res.json()["message"] == ERROR_CODES["INVALID_PHONE_NUMBER_OR_PASSWORD"]


async def test_sign_in_invalid_phone_number_validator():
    otp: dict[str, Any] = {}
    auth = make_auth(
        plugins=[phone_plugin(otp, phone_number_validator=lambda p: p.startswith("+"))]
    )
    async with make_client(auth) as client:
        res = await client.post(
            f"{BASE}/sign-in/phone-number", json={"phoneNumber": "0000", "password": "x"}
        )
        assert res.status_code == 400
        assert res.json()["message"] == ERROR_CODES["INVALID_PHONE_NUMBER"]


async def test_sign_in_require_verification_sends_otp():
    otp: dict[str, Any] = {}
    auth = make_auth(plugins=[phone_plugin(otp, require_verification=True)])
    phone = "+251911121314"
    # seed an unverified phone user directly (core /sign-up/email doesn't persist plugin fields)
    await auth.internal.create_user(
        {"name": "t", "email": "t@test.com", "phoneNumber": phone, "phoneNumberVerified": False}
    )
    async with make_client(auth) as client:
        res = await client.post(
            f"{BASE}/sign-in/phone-number", json={"phoneNumber": phone, "password": "whatever"}
        )
        assert res.status_code == 401
        assert res.json()["code"] == "PHONE_NUMBER_NOT_VERIFIED"
        # a fresh OTP was sent, stored under the raw phone identifier (no ":0" suffix)
        assert len(otp["code"]) == 6
        row = await auth.adapter.find_one("verification", [Where("identifier", phone)])
        assert row is not None
        assert row["value"] == otp["code"]


# --- request / reset password ---------------------------------------------------------


async def test_request_password_reset_is_constant_and_no_enumeration():
    otp: dict[str, Any] = {}
    reset: dict[str, Any] = {}
    auth = make_auth(
        plugins=[phone_plugin(otp, send_password_reset_otp=_recorder(reset))]
    )
    phone = "+251911999888"
    async with make_client(auth) as client:
        # unknown phone → still {status: true}, OTP row written, but nothing sent
        res = await client.post(
            f"{BASE}/phone-number/request-password-reset", json={"phoneNumber": phone}
        )
        assert res.status_code == 200
        assert res.json() == {"status": True}
        assert "code" not in reset  # no enumeration: no send for a non-existent user
        identifier = f"{phone}-request-password-reset"
        row = await auth.adapter.find_one("verification", [Where("identifier", identifier)])
        assert row is not None
        assert row["value"].endswith(":0")


async def test_reset_password_success_and_credential_upsert():
    otp: dict[str, Any] = {}
    reset: dict[str, Any] = {}
    auth = make_auth(plugins=[phone_plugin(otp, send_password_reset_otp=_recorder(reset))])
    phone = "+251911121314"
    async with make_client(auth) as client:
        await register(client, otp, phone)  # user created with no credential account
        await request_reset(client, phone)
        res = await client.post(
            f"{BASE}/phone-number/reset-password",
            json={"phoneNumber": phone, "otp": reset["code"], "newPassword": "new-secure-pass"},
        )
        assert res.status_code == 200
        assert res.json() == {"status": True}
    # the credential account was created → email sign-in with temp email works
    async with make_client(auth) as fresh:
        signin = await fresh.post(
            f"{BASE}/sign-in/email",
            json={"email": f"temp-{phone}@example.com", "password": "new-secure-pass"},
        )
        assert signin.status_code == 200, signin.text
        assert signin.json()["token"]


async def test_reset_password_rejects_reused_otp():
    otp: dict[str, Any] = {}
    reset: dict[str, Any] = {}
    auth = make_auth(plugins=[phone_plugin(otp, send_password_reset_otp=_recorder(reset))])
    phone = "+251911121314"
    async with make_client(auth) as client:
        await register(client, otp, phone)
        await request_reset(client, phone)
        code = reset["code"]
        first = await client.post(
            f"{BASE}/phone-number/reset-password",
            json={"phoneNumber": phone, "otp": code, "newPassword": "new-secure-pass"},
        )
        assert first.status_code == 200
        second = await client.post(
            f"{BASE}/phone-number/reset-password",
            json={"phoneNumber": phone, "otp": code, "newPassword": "another-pass"},
        )
        assert second.status_code == 400  # OTP consumed


async def test_reset_password_too_short():
    otp: dict[str, Any] = {}
    reset: dict[str, Any] = {}
    auth = make_auth(plugins=[phone_plugin(otp, send_password_reset_otp=_recorder(reset))])
    phone = "+251911121314"
    async with make_client(auth) as client:
        await register(client, otp, phone)
        await request_reset(client, phone)
        res = await client.post(
            f"{BASE}/phone-number/reset-password",
            json={"phoneNumber": phone, "otp": reset["code"], "newPassword": "short"},
        )
        assert res.status_code == 400
        assert res.json()["code"] == "PASSWORD_TOO_SHORT"


async def test_reset_password_blocks_after_allowed_attempts():
    otp: dict[str, Any] = {}
    reset: dict[str, Any] = {}
    auth = make_auth(
        plugins=[phone_plugin(otp, send_password_reset_otp=_recorder(reset), allowed_attempts=3)]
    )
    phone = "+251911121314"
    async with make_client(auth) as client:
        await register(client, otp, phone)
        await request_reset(client, phone)
        for _ in range(3):
            res = await client.post(
                f"{BASE}/phone-number/reset-password",
                json={"phoneNumber": phone, "otp": "000000", "newPassword": "new-secure-pass"},
            )
            assert res.status_code == 400
            assert res.json()["message"] == ERROR_CODES["INVALID_OTP"]
        res = await client.post(
            f"{BASE}/phone-number/reset-password",
            json={"phoneNumber": phone, "otp": "000000", "newPassword": "new-secure-pass"},
        )
        assert res.status_code == 403
        assert res.json()["message"] == ERROR_CODES["TOO_MANY_ATTEMPTS"]


async def test_reset_password_revokes_sessions():
    otp: dict[str, Any] = {}
    reset: dict[str, Any] = {}
    auth = make_auth(
        plugins=[phone_plugin(otp, send_password_reset_otp=_recorder(reset))],
        email_and_password=EmailAndPassword(enabled=True, revoke_sessions_on_password_reset=True),
    )
    phone = "+251911000000"
    async with make_client(auth) as client:
        await register(client, otp, phone)  # active session on this client
        assert (await client.get(f"{BASE}/get-session")).json() is not None
        await request_reset(client, phone)
        res = await client.post(
            f"{BASE}/phone-number/reset-password",
            json={"phoneNumber": phone, "otp": reset["code"], "newPassword": "new-secure-pass"},
        )
        assert res.status_code == 200
        # every session was revoked → the client's session is gone
        assert (await client.get(f"{BASE}/get-session")).json() is None


async def test_reset_password_fires_on_password_reset_callback():
    otp: dict[str, Any] = {}
    reset: dict[str, Any] = {}
    calls: list[dict[str, Any]] = []

    async def on_password_reset(data: dict[str, Any], request: Any) -> None:
        calls.append(data)

    auth = make_auth(
        plugins=[phone_plugin(otp, send_password_reset_otp=_recorder(reset))],
        email_and_password=EmailAndPassword(enabled=True, on_password_reset=on_password_reset),
    )
    phone = "+251911999888"
    async with make_client(auth) as client:
        await register(client, otp, phone)
        await request_reset(client, phone)
        res = await client.post(
            f"{BASE}/phone-number/reset-password",
            json={"phoneNumber": phone, "otp": reset["code"], "newPassword": "new-password-123"},
        )
        assert res.status_code == 200
        assert len(calls) == 1
        assert calls[0]["user"]["phoneNumber"] == phone


# --- update-user hooks ----------------------------------------------------------------


async def test_update_user_phone_number_change_blocked():
    otp: dict[str, Any] = {}
    auth = make_auth(plugins=[phone_plugin(otp)])
    async with make_client(auth) as client:
        await register(client, otp, "+251911121314")
        res = await client.post(f"{BASE}/update-user", json={"phoneNumber": "+9876543210"})
        assert res.status_code == 400
        assert res.json()["message"] == ERROR_CODES["PHONE_NUMBER_CANNOT_BE_UPDATED"]
        # unchanged
        session = await client.get(f"{BASE}/get-session")
        assert session.json()["user"]["phoneNumber"] == "+251911121314"
        assert session.json()["user"]["phoneNumberVerified"] is True


async def test_update_user_disassociation_and_reclaim():
    otp: dict[str, Any] = {}
    auth = make_auth(plugins=[phone_plugin(otp)])
    shared = "+251911121314"
    async with make_client(auth) as original:
        await register(original, otp, shared)
        # disassociate: null the number → verified flag resets to false atomically
        dis = await original.post(f"{BASE}/update-user", json={"phoneNumber": None})
        assert dis.status_code == 200, dis.text
        after = await original.get(f"{BASE}/get-session")
        assert after.json()["user"]["phoneNumber"] is None
        assert after.json()["user"]["phoneNumberVerified"] is False

        # another user claims the released number via verify(updatePhoneNumber)
        async with make_client(auth) as reclaimer:
            signup = await reclaimer.post(
                f"{BASE}/sign-up/email",
                json={"name": "r", "email": "r@test.com", "password": "password123"},
            )
            assert signup.status_code == 200, signup.text
            await send_otp(reclaimer, shared)
            res = await reclaimer.post(
                f"{BASE}/phone-number/verify",
                json={"phoneNumber": shared, "code": otp["code"], "updatePhoneNumber": True},
            )
            assert res.status_code == 200, res.text
            reclaimer_session = await reclaimer.get(f"{BASE}/get-session")
            assert reclaimer_session.json()["user"]["phoneNumber"] == shared
            assert reclaimer_session.json()["user"]["phoneNumberVerified"] is True

        # the original user still has no number
        original_session = await original.get(f"{BASE}/get-session")
        assert original_session.json()["user"]["phoneNumber"] is None


# --- rate limit + error codes ---------------------------------------------------------


def test_rate_limit_rule():
    plugin = phone_plugin({})
    rules = plugin.rate_limit()
    assert len(rules) == 1
    rule = rules[0]
    assert rule.window == 60
    assert rule.max == 10
    assert rule.path_matcher("/phone-number/send-otp") is True
    assert rule.path_matcher("/sign-in/phone-number") is False


def test_error_codes_match_ts():
    assert ERROR_CODES == {
        "INVALID_PHONE_NUMBER": "Invalid phone number",
        "PHONE_NUMBER_EXIST": "Phone number already exists",
        "PHONE_NUMBER_NOT_EXIST": "phone number isn't registered",
        "INVALID_PHONE_NUMBER_OR_PASSWORD": "Invalid phone number or password",
        "UNEXPECTED_ERROR": "Unexpected error",
        "OTP_NOT_FOUND": "OTP not found",
        "OTP_EXPIRED": "OTP expired",
        "INVALID_OTP": "Invalid OTP",
        "PHONE_NUMBER_NOT_VERIFIED": "Phone number not verified",
        "PHONE_NUMBER_CANNOT_BE_UPDATED": "Phone number cannot be updated",
        "SEND_OTP_NOT_IMPLEMENTED": "sendOTP not implemented",
        "TOO_MANY_ATTEMPTS": "Too many attempts",
    }


def _recorder(holder: dict[str, Any]):
    async def record(data: dict[str, Any], ctx: Any = None) -> None:
        holder["code"] = data["code"]

    return record
