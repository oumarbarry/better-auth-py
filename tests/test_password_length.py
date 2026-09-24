"""maxPasswordLength is enforced before hashing on every endpoint that verifies a password.

TS 88534192c (#11324): utils/password.ts:14 ``assertPasswordNotTooLong`` runs before any
scrypt work on sign-in (email sign-in.ts:527, username index.ts:459, phone-number
routes.ts:109), verify-password (password.ts:377 via validatePassword), change-password
``currentPassword`` (update-user.ts:260), delete-user (update-user.ts:459), the two-factor
password gate (utils/password.ts:31/48) and admin create-user (admin/routes.ts:434).
The spy on ``crypto._scrypt`` proves no hash or verify ran.
"""

from typing import Any

import pytest

from better_auth import Where, crypto
from better_auth.config import DeleteUserOptions, UserOptions
from better_auth.plugins_ext.admin import AdminPlugin
from better_auth.plugins_ext.anonymous import AnonymousPlugin
from better_auth.plugins_ext.phone_number import PhoneNumberPlugin
from better_auth.plugins_ext.two_factor import TwoFactorPlugin
from better_auth.plugins_ext.username import UsernamePlugin
from conftest import SIGNUP, make_auth, make_client, sign_up

LONG = "x" * 129  # default max_password_length is 128


@pytest.fixture
def scrypt_calls(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []
    real = crypto._scrypt

    def spy(password: str, salt_hex: str) -> bytes:
        calls.append(password)
        return real(password, salt_hex)

    monkeypatch.setattr(crypto, "_scrypt", spy)
    return calls


def assert_too_long(response: Any) -> None:
    assert response.status_code == 400, response.text
    # core/src/error/codes.ts:36
    assert response.json() == {"code": "PASSWORD_TOO_LONG", "message": "Password too long"}


@pytest.mark.parametrize("email", [SIGNUP["email"], "unknown-long-password@example.com"])
async def test_sign_in_email_rejects_long_password_before_hashing(email, scrypt_calls):
    async with make_client(make_auth()) as client:
        await sign_up(client)
        scrypt_calls.clear()
        response = await client.post(
            "/api/auth/sign-in/email", json={"email": email, "password": LONG}
        )
        assert_too_long(response)
        assert scrypt_calls == []


async def test_sign_in_username_rejects_long_password_before_hashing(scrypt_calls):
    async with make_client(make_auth(plugins=[UsernamePlugin()])) as client:
        response = await client.post(
            "/api/auth/sign-in/username", json={"username": "nobody", "password": LONG}
        )
        assert_too_long(response)
        assert scrypt_calls == []


async def test_sign_in_phone_number_rejects_long_password_before_hashing(scrypt_calls):
    async with make_client(make_auth(plugins=[PhoneNumberPlugin()])) as client:
        response = await client.post(
            "/api/auth/sign-in/phone-number", json={"phoneNumber": "+15550000000", "password": LONG}
        )
        assert_too_long(response)
        assert scrypt_calls == []


async def test_verify_password_rejects_long_password_before_hashing(scrypt_calls):
    async with make_client(make_auth()) as client:
        await sign_up(client)
        scrypt_calls.clear()
        assert_too_long(await client.post("/api/auth/verify-password", json={"password": LONG}))
        assert scrypt_calls == []


async def test_change_password_rejects_long_current_password_before_hashing(scrypt_calls):
    async with make_client(make_auth()) as client:
        await sign_up(client)
        scrypt_calls.clear()
        response = await client.post(
            "/api/auth/change-password",
            json={"currentPassword": LONG, "newPassword": "another-password"},
        )
        assert_too_long(response)
        assert scrypt_calls == []


async def test_delete_user_rejects_long_password_before_hashing(scrypt_calls):
    auth = make_auth(user=UserOptions(delete_user=DeleteUserOptions(enabled=True)))
    async with make_client(auth) as client:
        await sign_up(client)
        scrypt_calls.clear()
        assert_too_long(await client.post("/api/auth/delete-user", json={"password": LONG}))
        assert scrypt_calls == []


@pytest.mark.parametrize("path", ["/two-factor/enable", "/two-factor/get-totp-uri"])
async def test_two_factor_rejects_long_password_before_hashing(path, scrypt_calls):
    async with make_client(make_auth(plugins=[TwoFactorPlugin()])) as client:
        await sign_up(client)
        if path == "/two-factor/get-totp-uri":  # needs 2FA enabled first, as in the TS test
            enabled = await client.post(
                "/api/auth/two-factor/enable", json={"password": SIGNUP["password"]}
            )
            assert enabled.status_code == 200, enabled.text
        scrypt_calls.clear()
        assert_too_long(await client.post(f"/api/auth{path}", json={"password": LONG}))
        assert scrypt_calls == []


async def test_two_factor_ignores_long_password_for_passwordless_user():
    # two-factor.test.ts: allowPasswordless + no credential account → the optional
    # password is never checked, so an overlong one does not fail the request.
    auth = make_auth(plugins=[AnonymousPlugin(), TwoFactorPlugin(allow_passwordless=True)])
    async with make_client(auth) as client:
        assert (await client.post("/api/auth/sign-in/anonymous")).status_code == 200
        response = await client.post("/api/auth/two-factor/enable", json={"password": LONG})
        assert response.status_code == 200, response.text


async def test_admin_create_user_rejects_long_password_before_hashing(scrypt_calls):
    auth = make_auth(plugins=[AdminPlugin()])
    async with make_client(auth) as client:
        await sign_up(client)
        admin = await auth.adapter.find_one("user", [Where("email", SIGNUP["email"])])
        assert admin is not None
        await auth.adapter.update("user", [Where("id", admin["id"])], {"role": "admin"})
        scrypt_calls.clear()
        response = await client.post(
            "/api/auth/admin/create-user",
            json={"email": "bob@example.com", "name": "Bob", "password": LONG},
        )
        assert_too_long(response)
        assert scrypt_calls == []
        assert await auth.adapter.find_one("user", [Where("email", "bob@example.com")]) is None


async def test_sign_up_too_short_message_matches_ts():
    # core/src/error/codes.ts:35
    async with make_client(make_auth()) as client:
        response = await client.post("/api/auth/sign-up/email", json={**SIGNUP, "password": "x"})
        assert response.status_code == 400
        assert response.json() == {"code": "PASSWORD_TOO_SHORT", "message": "Password too short"}
