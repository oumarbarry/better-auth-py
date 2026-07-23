"""username plugin — parity with better-auth's plugins/username.

Behaviours mirror packages/better-auth/src/plugins/username/username.test.ts:
uniqueness (case-insensitive via normalisation), display-vs-username rules,
per-path validation status codes (422 on sign-in/is-available, 400 on the
sign-up/update http hooks), timing-safe credential sign-in, and the
"no info leak" email-verification gate.
"""

from __future__ import annotations

import re
from typing import Any

import pytest

from better_auth import EmailAndPassword
from better_auth.config import EmailVerification
from better_auth.plugins_ext.username import ERROR_CODES, UsernamePlugin
from conftest import make_auth, make_client

SIGNUP = {"email": "u@example.com", "password": "s3cret-password", "name": "U"}
_DISPLAY_RE = re.compile(r"^[a-zA-Z0-9_-]+$")


def _display_ok(d: str) -> bool:
    return _DISPLAY_RE.match(d) is not None


def _auth(**plugin_kwargs: Any) -> Any:
    return make_auth(plugins=[UsernamePlugin(**plugin_kwargs)])


async def _signup(client: Any, **body: Any) -> Any:
    return await client.post("/api/auth/sign-up/email", json={**SIGNUP, **body})


async def _session(client: Any, token: str) -> dict[str, Any]:
    r = await client.get(
        "/api/auth/get-session", headers={"authorization": f"Bearer {token}"}
    )
    return r.json()


# --- sign-up + persistence --------------------------------------------------------------


async def test_sign_up_persists_normalized_username():
    async with make_client(_auth(min_username_length=4)) as client:
        r = await _signup(client, email="a@b.com", username="New_Username")
        assert r.status_code == 200, r.text
        s = await _session(client, r.json()["token"])
        assert s["user"]["username"] == "new_username"
        # displayUsername defaults to the raw (un-normalized) username
        assert s["user"]["displayUsername"] == "New_Username"


async def test_display_username_not_normalized_by_default():
    async with make_client(_auth()) as client:
        r = await _signup(
            client, email="d@b.com", username="the_user", **{"displayUsername": "Test_Username"}
        )
        s = await _session(client, r.json()["token"])
        assert s["user"]["username"] == "the_user"
        assert s["user"]["displayUsername"] == "Test_Username"


async def test_preserve_both_username_and_display_on_signup():
    async with make_client(_auth()) as client:
        r = await _signup(
            client, email="both@b.com", username="custom_user",
            **{"displayUsername": "Fancy Display Name"},
        )
        s = await _session(client, r.json()["token"])
        assert s["user"]["username"] == "custom_user"
        assert s["user"]["displayUsername"] == "Fancy Display Name"


async def test_invalid_display_only_value_not_stored_as_username():
    async with make_client(_auth()) as client:
        r = await _signup(client, email="inv@b.com", **{"displayUsername": "Invalid Username"})
        assert r.status_code == 200, r.text
        s = await _session(client, r.json()["token"])
        assert s["user"].get("username") is None
        assert s["user"]["displayUsername"] == "Invalid Username"


async def test_explicit_empty_username_not_replaced_by_display():
    async with make_client(_auth()) as client:
        r = await _signup(
            client, email="empty@b.com", username="", **{"displayUsername": "valid_username"}
        )
        assert r.status_code == 400
        assert r.json()["code"] == "USERNAME_TOO_SHORT"


# --- validation status codes (sign-up http hooks -> 400) --------------------------------


async def test_invalid_username_signup_400():
    async with make_client(_auth()) as client:
        r = await _signup(client, email="x@b.com", username="new username")
        assert r.status_code == 400
        assert r.json()["code"] == "INVALID_USERNAME"


async def test_too_short_username_signup_400():
    async with make_client(_auth(min_username_length=4)) as client:
        r = await _signup(client, email="x@b.com", username="new")
        assert r.status_code == 400
        assert r.json()["code"] == "USERNAME_TOO_SHORT"


async def test_empty_username_signup_400():
    async with make_client(_auth()) as client:
        r = await _signup(client, email="x@b.com", username="")
        assert r.status_code == 400


# --- uniqueness -------------------------------------------------------------------------


async def test_duplicate_username_signup_fails():
    async with make_client(_auth()) as client:
        await _signup(client, email="a@b.com", username="taken_user")
        r = await _signup(client, email="c@b.com", username="Taken_User")  # case-insensitive
        assert r.status_code == 400
        assert r.json()["code"] == "USERNAME_IS_ALREADY_TAKEN"


async def test_update_username():
    async with make_client(_auth()) as client:
        r = await _signup(client, email="a@b.com", username="first_user")
        token = r.json()["token"]
        upd = await client.post(
            "/api/auth/update-user",
            json={"username": "Second_User"},
            headers={"authorization": f"Bearer {token}"},
        )
        assert upd.status_code == 200, upd.text
        s = await _session(client, token)
        assert s["user"]["username"] == "second_user"


async def test_duplicate_username_update_different_user_fails():
    async with make_client(_auth()) as client:
        await _signup(client, email="owner@b.com", username="owned_name")
        other = await _signup(client, email="other@b.com", username="other_name")
        token = other.json()["token"]
        r = await client.post(
            "/api/auth/update-user",
            json={"username": "Owned_Name"},  # different casing, different user
            headers={"authorization": f"Bearer {token}"},
        )
        assert r.status_code == 400
        assert r.json()["code"] == "USERNAME_IS_ALREADY_TAKEN"


async def test_duplicate_username_update_same_user_succeeds():
    async with make_client(_auth()) as client:
        r = await _signup(client, email="me@b.com", username="my_name")
        token = r.json()["token"]
        upd = await client.post(
            "/api/auth/update-user",
            json={"username": "My_Name"},  # same row, different casing
            headers={"authorization": f"Bearer {token}"},
        )
        assert upd.status_code == 200, upd.text
        s = await _session(client, token)
        assert s["user"]["username"] == "my_name"


async def test_preserve_both_on_update():
    async with make_client(_auth()) as client:
        r = await _signup(client, email="me@b.com", username="my_name")
        token = r.json()["token"]
        await client.post(
            "/api/auth/update-user",
            json={"username": "priority_user", "displayUsername": "Priority Display Name"},
            headers={"authorization": f"Bearer {token}"},
        )
        s = await _session(client, token)
        assert s["user"]["username"] == "priority_user"
        assert s["user"]["displayUsername"] == "Priority Display Name"


# --- is-username-available (422 on validation) ------------------------------------------


async def test_is_available_true():
    async with make_client(_auth(min_username_length=4)) as client:
        r = await client.post("/api/auth/is-username-available", json={"username": "free_name"})
        assert r.status_code == 200
        assert r.json() == {"available": True}


async def test_is_available_false_case_insensitive():
    async with make_client(_auth()) as client:
        await _signup(client, email="a@b.com", username="priority_user")
        r = await client.post("/api/auth/is-username-available", json={"username": "PRIORITY_USER"})
        assert r.json() == {"available": False}


async def test_is_available_invalid_format_422():
    async with make_client(_auth()) as client:
        r = await client.post("/api/auth/is-username-available", json={"username": "invalid name!"})
        assert r.status_code == 422
        assert r.json()["code"] == "INVALID_USERNAME"


async def test_is_available_too_short_422():
    async with make_client(_auth(min_username_length=4)) as client:
        r = await client.post("/api/auth/is-username-available", json={"username": "abc"})
        assert r.status_code == 422
        assert r.json()["code"] == "USERNAME_TOO_SHORT"


async def test_is_available_too_long_422():
    async with make_client(_auth()) as client:
        r = await client.post(
            "/api/auth/is-username-available", json={"username": "a" * 31}
        )
        assert r.status_code == 422
        assert r.json()["code"] == "USERNAME_TOO_LONG"


# --- sign-in ----------------------------------------------------------------------------


async def test_sign_in_with_username():
    async with make_client(_auth(min_username_length=4)) as client:
        await _signup(client, email="a@b.com", username="login_user", password="new-password")
        r = await client.post(
            "/api/auth/sign-in/username",
            json={"username": "login_user", "password": "new-password"},
        )
        assert r.status_code == 200, r.text
        assert r.json()["token"]
        assert r.json()["redirect"] is False
        assert r.json()["url"] is None


async def test_sign_in_normalizes_username_before_lookup():
    async with make_client(_auth()) as client:
        await _signup(client, email="a@b.com", username="Custom_User", password="test-password")
        r = await client.post(
            "/api/auth/sign-in/username",
            json={"username": "Custom_User", "password": "test-password"},
        )
        assert r.status_code == 200, r.text
        assert r.json()["user"]["username"] == "custom_user"
        assert r.json()["user"]["displayUsername"] == "Custom_User"


async def test_sign_in_callback_url_sets_redirect_and_location():
    async with make_client(_auth()) as client:
        await _signup(client, email="a@b.com", username="cb_user", password="test-password")
        r = await client.post(
            "/api/auth/sign-in/username",
            json={"username": "cb_user", "password": "test-password", "callbackURL": "/dashboard"},
        )
        assert r.status_code == 200, r.text
        assert r.json()["redirect"] is True
        assert r.json()["url"] == "/dashboard"
        assert r.headers["location"] == "/dashboard"


async def test_sign_in_missing_fields_401():
    async with make_client(_auth()) as client:
        r = await client.post("/api/auth/sign-in/username", json={"username": "x"})
        assert r.status_code == 401
        assert r.json()["code"] == "INVALID_USERNAME_OR_PASSWORD"


async def test_sign_in_user_not_found_401():
    async with make_client(_auth()) as client:
        r = await client.post(
            "/api/auth/sign-in/username",
            json={"username": "ghost_user", "password": "whatever-1234"},
        )
        assert r.status_code == 401
        assert r.json()["code"] == "INVALID_USERNAME_OR_PASSWORD"


async def test_sign_in_bad_password_401():
    async with make_client(_auth()) as client:
        await _signup(client, email="a@b.com", username="pw_user", password="correct-password")
        r = await client.post(
            "/api/auth/sign-in/username",
            json={"username": "pw_user", "password": "wrong-password"},
        )
        assert r.status_code == 401
        assert r.json()["code"] == "INVALID_USERNAME_OR_PASSWORD"


async def test_sign_in_no_credential_account_401():
    # A user with a username but no credential account (created directly) -> 401, never 500.
    auth = _auth()
    async with make_client(auth) as client:
        await auth.internal.create_user(
            {"email": "oauth@b.com", "name": "O", "username": "oauth_user"}
        )
        r = await client.post(
            "/api/auth/sign-in/username",
            json={"username": "oauth_user", "password": "whatever-1234"},
        )
        assert r.status_code == 401
        assert r.json()["code"] == "INVALID_USERNAME_OR_PASSWORD"


# --- custom validators / normalisers ----------------------------------------------------


async def test_custom_normalization_and_duplicate_detection():
    plugin = UsernamePlugin(
        min_username_length=4,
        username_normalization=lambda u: u.replace("0", "o").replace("4", "a").lower(),
    )
    async with make_client(make_auth(plugins=[plugin])) as client:
        first = await _signup(client, email="a@b.com", username="H4XX0R", password="new-password")
        assert first.status_code == 200, first.text
        s = await _session(client, first.json()["token"])
        assert s["user"]["username"] == "haxxor"
        dup = await _signup(client, email="c@b.com", username="haxxor", password="new-password")
        assert dup.status_code == 400


async def test_custom_display_normalization():
    plugin = UsernamePlugin(display_username_normalization=lambda d: d.lower())
    async with make_client(make_auth(plugins=[plugin])) as client:
        r = await _signup(
            client, email="a@b.com", username="test_username",
            **{"displayUsername": "Test Username"},
        )
        s = await _session(client, r.json()["token"])
        assert s["user"]["username"] == "test_username"
        assert s["user"]["displayUsername"] == "test username"


async def test_custom_username_validator_rejects_on_available_and_signup():
    plugin = UsernamePlugin(username_validator=lambda u: u.startswith("user_"))
    async with make_client(make_auth(plugins=[plugin])) as client:
        avail = "/api/auth/is-username-available"
        ok = await client.post(avail, json={"username": "user_valid123"})
        assert ok.json() == {"available": True}
        bad = await client.post(avail, json={"username": "invalid_user"})
        assert bad.status_code == 422
        assert bad.json()["code"] == "INVALID_USERNAME"
        su = await _signup(client, email="a@b.com", username="invalid_user")
        assert su.status_code == 400
        assert su.json()["code"] == "INVALID_USERNAME"


# --- displayUsername validation ---------------------------------------------------------


async def test_display_validator_accepts_and_rejects():
    plugin = UsernamePlugin(display_username_validator=_display_ok)
    async with make_client(make_auth(plugins=[plugin])) as client:
        ok = await _signup(client, email="a@b.com", **{"displayUsername": "Valid_Display-123"})
        assert ok.status_code == 200, ok.text
        s = await _session(client, ok.json()["token"])
        assert s["user"].get("username") is None
        assert s["user"]["displayUsername"] == "Valid_Display-123"

        bad = await _signup(
            client, email="c@b.com", username="invalid_display",
            **{"displayUsername": "Invalid Display!"},
        )
        assert bad.status_code == 400
        assert bad.json()["code"] == "INVALID_DISPLAY_USERNAME"


async def test_inferred_display_not_validated_during_signup():
    plugin = UsernamePlugin(display_username_validator=_display_ok)
    async with make_client(make_auth(plugins=[plugin])) as client:
        # username has a "." (valid username) but would fail the display validator;
        # the inferred displayUsername must NOT be validated.
        r = await _signup(client, email="a@b.com", username="valid.username")
        assert r.status_code == 200, r.text
        s = await _session(client, r.json()["token"])
        assert s["user"]["username"] == "valid.username"
        assert s["user"]["displayUsername"] == "valid.username"


# --- validationOrder post-normalization -------------------------------------------------


async def test_post_normalization_validates_normalized_value():
    plugin = UsernamePlugin(
        validation_order={
            "username": "post-normalization",
            "displayUsername": "post-normalization",
        },
        username_normalization=lambda u: u.replace(" ", "_").lower(),
    )
    async with make_client(make_auth(plugins=[plugin])) as client:
        # "Test Username" contains a space (fails the default validator on the RAW value),
        # but post-normalization validates the normalized "test_username" -> passes.
        r = await _signup(client, email="a@b.com", username="Test Username")
        assert r.status_code == 200, r.text
        s = await _session(client, r.json()["token"])
        assert s["user"]["username"] == "test_username"
        assert s["user"]["displayUsername"] == "Test Username"


# --- email-verification gate (no info leak) ---------------------------------------------


def _verify_auth(**ev: Any) -> Any:
    return make_auth(
        email_and_password=EmailAndPassword(enabled=True, require_email_verification=True),
        email_verification=EmailVerification(**ev),
        plugins=[UsernamePlugin()],
    )


async def test_wrong_password_never_leaks_email_not_verified():
    async with make_client(_verify_auth()) as client:
        await _signup(
            client,
            email="unverified@b.com",
            username="unverified_user",
            password="correct-password",
        )
        r = await client.post(
            "/api/auth/sign-in/username",
            json={"username": "unverified_user", "password": "wrong-password"},
        )
        assert r.status_code == 401
        assert r.json()["code"] == "INVALID_USERNAME_OR_PASSWORD"


async def test_email_not_verified_only_after_correct_password():
    async with make_client(_verify_auth()) as client:
        await _signup(
            client,
            email="unverified@b.com",
            username="unverified_user",
            password="correct-password",
        )
        r = await client.post(
            "/api/auth/sign-in/username",
            json={"username": "unverified_user", "password": "correct-password"},
        )
        assert r.status_code == 403
        assert r.json()["code"] == "EMAIL_NOT_VERIFIED"


async def test_sign_in_verify_email_encodes_callback_url():
    """Regression (better-auth#6086): the verify-email link keeps a callbackURL that
    itself contains `&`/`?`, rather than truncating at the first ampersand."""
    captured: dict[str, str] = {}

    async def send_verification_email(user: dict[str, Any], url: str, token: str) -> None:
        captured["url"] = url

    auth = _verify_auth(send_verification_email=send_verification_email)
    auth.email_verification.send_on_sign_in = True  # config field absent from the port dataclass
    async with make_client(auth) as client:
        await _signup(
            client,
            email="encode@b.com",
            username="encode_user",
            password="correct-password",
        )
        cb = "/welcome?ref=username&plan=pro"
        r = await client.post(
            "/api/auth/sign-in/username",
            json={"username": "encode_user", "password": "correct-password", "callbackURL": cb},
        )
        assert r.status_code == 403
        assert "url" in captured
        from urllib.parse import parse_qs, urlsplit

        got = parse_qs(urlsplit(captured["url"]).query)["callbackURL"][0]
        assert got == cb


# --- error-code surface -----------------------------------------------------------------


async def test_error_codes_surface_on_instance():
    auth = _auth()
    assert auth.error_codes["INVALID_USERNAME_OR_PASSWORD"] == "Invalid username or password"
    assert (
        auth.error_codes["USERNAME_IS_ALREADY_TAKEN"]
        == "Username is already taken. Please try another."
    )
    assert ERROR_CODES["EMAIL_NOT_VERIFIED"] == "Email not verified"


@pytest.mark.parametrize(
    "key,message",
    [
        ("INVALID_USERNAME_OR_PASSWORD", "Invalid username or password"),
        ("EMAIL_NOT_VERIFIED", "Email not verified"),
        ("UNEXPECTED_ERROR", "Unexpected error"),
        ("USERNAME_IS_ALREADY_TAKEN", "Username is already taken. Please try another."),
        ("USERNAME_TOO_SHORT", "Username is too short"),
        ("USERNAME_TOO_LONG", "Username is too long"),
        ("INVALID_USERNAME", "Username is invalid"),
        ("INVALID_DISPLAY_USERNAME", "Display username is invalid"),
    ],
)
def test_error_code_strings_exact(key: str, message: str):
    assert ERROR_CODES[key] == message
