"""Tests for the haveibeenpwned plugin (reject breached passwords via k-anonymity range
query, before they're hashed).

Mirrors better-auth's plugins/haveibeenpwned/haveibeenpwned.test.ts and the gap spec
(docs/plans/gap/04-plugins-simple.md, "haveibeenpwned"). TS source verified against:
  packages/better-auth/src/plugins/haveibeenpwned/index.ts

The plugin registers a check into ``auth.password_checks`` (the W3-A foundation seam);
most cases call that check callable directly with ``(password, path)`` — it's the whole
contract, and doing so lets us exercise every default `paths` entry (including ones for
plugins not yet ported, e.g. admin/phone-number) without needing those routes to exist.
Two tests go through a real sign-up/change-password HTTP round trip via
``conftest.make_client`` to prove end-to-end wiring.
"""

from __future__ import annotations

import hashlib

import httpx
import pytest

from better_auth import APIError
from better_auth.plugins_ext.haveibeenpwned import DEFAULT_PATHS, ERROR_CODES, HaveIBeenPwnedPlugin
from conftest import make_auth, make_client


def hibp_transport(
    target_password: str, *, breached: bool, capture: list[httpx.Request] | None = None
) -> httpx.AsyncClient:
    """A range-API stub reporting ``target_password`` as breached (or not)."""
    suffix = hashlib.sha1(target_password.encode()).hexdigest().upper()[5:]

    def handler(request: httpx.Request) -> httpx.Response:
        if capture is not None:
            capture.append(request)
        body = f"{suffix}:42\r\n" if breached else ""
        body += "0000000000000000000000000000000AAAA:1\r\n"
        return httpx.Response(200, text=body)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def failing_transport(*, status: int | None = None) -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        if status is None:
            raise httpx.ConnectError("boom", request=request)
        return httpx.Response(status, text="unavailable")

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


# --- constants / config defaults ---------------------------------------------------------


def test_error_codes_exact_message():
    assert ERROR_CODES == {
        "PASSWORD_COMPROMISED": (
            "The password you entered has been compromised. Please choose a different password."
        )
    }


def test_plugin_id_matches_ts():
    assert HaveIBeenPwnedPlugin().id == "have-i-been-pwned"


def test_default_paths_and_enabled_default():
    plugin = HaveIBeenPwnedPlugin()
    assert plugin.paths == [
        "/sign-up/email",
        "/change-password",
        "/reset-password",
        "/email-otp/reset-password",
        "/phone-number/reset-password",
        "/admin/create-user",
        "/admin/set-user-password",
    ]
    assert plugin.paths == DEFAULT_PATHS
    assert plugin.enabled is True
    assert plugin.custom_password_compromised_message is None


def test_error_codes_surface_on_auth_instance():
    auth = make_auth(plugins=[HaveIBeenPwnedPlugin()])
    assert auth.error_codes["PASSWORD_COMPROMISED"] == ERROR_CODES["PASSWORD_COMPROMISED"]


def test_init_registers_exactly_one_password_check():
    auth = make_auth(plugins=[HaveIBeenPwnedPlugin()])
    assert len(auth.password_checks) == 1


# --- check callable: path gating (direct — covers paths with no route yet) --------------


@pytest.mark.parametrize(
    "path",
    [
        "/sign-up/email",
        "/change-password",
        "/reset-password",
        "/email-otp/reset-password",
        "/phone-number/reset-password",
        "/admin/create-user",
        "/admin/set-user-password",
    ],
)
async def test_enforced_on_every_default_path(path):
    compromised = "leaked-default-path-pw"
    auth = make_auth(
        plugins=[HaveIBeenPwnedPlugin()], http_client=hibp_transport(compromised, breached=True)
    )
    check = auth.password_checks[0]

    with pytest.raises(APIError) as exc_info:
        await check(compromised, path)
    assert exc_info.value.status == 400
    assert exc_info.value.code == "PASSWORD_COMPROMISED"


async def test_not_enforced_on_unconfigured_path():
    compromised = "leaked-unrelated-path-pw"
    auth = make_auth(
        plugins=[HaveIBeenPwnedPlugin()], http_client=hibp_transport(compromised, breached=True)
    )
    check = auth.password_checks[0]

    await check(compromised, "/some/unrelated/path")  # must not raise


async def test_custom_paths_restrict_enforcement():
    compromised = "leaked-custom-paths-pw"
    plugin = HaveIBeenPwnedPlugin(paths=["/only-this-path"])
    auth = make_auth(plugins=[plugin], http_client=hibp_transport(compromised, breached=True))
    check = auth.password_checks[0]

    await check(compromised, "/sign-up/email")  # default path, no longer configured -> no-op
    with pytest.raises(APIError):
        await check(compromised, "/only-this-path")


async def test_enabled_false_skips_check_entirely():
    compromised = "leaked-disabled-pw"
    plugin = HaveIBeenPwnedPlugin(enabled=False)
    auth = make_auth(plugins=[plugin], http_client=hibp_transport(compromised, breached=True))
    check = auth.password_checks[0]

    await check(compromised, "/sign-up/email")  # must not raise despite being "breached"


async def test_empty_password_is_a_no_op():
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("HIBP must not be called for an empty password")

    auth = make_auth(
        plugins=[HaveIBeenPwnedPlugin()],
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    check = auth.password_checks[0]

    await check("", "/sign-up/email")


# --- check callable: wire format + failure semantics --------------------------------------


async def test_sends_sha1_prefix_and_required_headers():
    compromised = "123456789"
    capture: list[httpx.Request] = []
    auth = make_auth(
        plugins=[HaveIBeenPwnedPlugin()],
        http_client=hibp_transport(compromised, breached=True, capture=capture),
    )
    check = auth.password_checks[0]

    with pytest.raises(APIError):
        await check(compromised, "/sign-up/email")

    prefix = hashlib.sha1(compromised.encode()).hexdigest().upper()[:5]
    assert len(capture) == 1
    request = capture[0]
    assert request.method == "GET"
    assert request.url.host == "api.pwnedpasswords.com"
    assert request.url.path == f"/range/{prefix}"
    assert request.headers["add-padding"] == "true"
    assert request.headers["user-agent"] == "BetterAuth Password Checker"


async def test_strong_password_passes_check():
    auth = make_auth(
        plugins=[HaveIBeenPwnedPlugin()],
        http_client=hibp_transport("some-other-breached-pw", breached=False),
    )
    check = auth.password_checks[0]

    await check("Str0ng!Uncompromised-Pw", "/sign-up/email")  # must not raise


async def test_custom_compromised_message_overrides_default():
    compromised = "leaked-custom-message-pw"
    plugin = HaveIBeenPwnedPlugin(custom_password_compromised_message="Nope, try again.")
    auth = make_auth(plugins=[plugin], http_client=hibp_transport(compromised, breached=True))
    check = auth.password_checks[0]

    with pytest.raises(APIError) as exc_info:
        await check(compromised, "/sign-up/email")
    assert exc_info.value.message == "Nope, try again."
    assert exc_info.value.code == "PASSWORD_COMPROMISED"


async def test_transport_failure_raises_500_with_exact_message():
    auth = make_auth(plugins=[HaveIBeenPwnedPlugin()], http_client=failing_transport())
    check = auth.password_checks[0]

    with pytest.raises(APIError) as exc_info:
        await check("whatever-password", "/sign-up/email")
    assert exc_info.value.status == 500
    assert exc_info.value.message == "Failed to check password. Please try again later."


async def test_non_2xx_response_raises_500_with_exact_message():
    auth = make_auth(plugins=[HaveIBeenPwnedPlugin()], http_client=failing_transport(status=503))
    check = auth.password_checks[0]

    with pytest.raises(APIError) as exc_info:
        await check("whatever-password", "/sign-up/email")
    assert exc_info.value.status == 500
    assert exc_info.value.message == "Failed to check password. Please try again later."


# --- end-to-end: real sign-up / change-password round trips (integration) -----------------


async def test_blocks_compromised_password_on_sign_up_e2e():
    compromised = "123456789"
    auth = make_auth(
        plugins=[HaveIBeenPwnedPlugin()], http_client=hibp_transport(compromised, breached=True)
    )
    async with make_client(auth) as client:
        res = await client.post(
            "/api/auth/sign-up/email",
            json={"email": "compromised@example.com", "password": compromised, "name": "Test User"},
        )

    assert res.status_code == 400
    body = res.json()
    assert body["code"] == "PASSWORD_COMPROMISED"
    assert body["message"] == ERROR_CODES["PASSWORD_COMPROMISED"]


async def test_allows_strong_password_on_sign_up_e2e():
    strong = "Str0ng!Uncompromised-Pw-42"
    auth = make_auth(
        plugins=[HaveIBeenPwnedPlugin()],
        http_client=hibp_transport("a-totally-different-pw", breached=False),
    )
    async with make_client(auth) as client:
        res = await client.post(
            "/api/auth/sign-up/email",
            json={"email": "strong@example.com", "password": strong, "name": "Test User"},
        )

    assert res.status_code == 200
    assert res.json()["user"]["email"] == "strong@example.com"


async def test_blocks_compromised_password_on_change_password_e2e():
    strong = "Str0ng!InitialPassw0rd-99"
    compromised = "leaked-via-change-password"
    auth = make_auth(
        plugins=[HaveIBeenPwnedPlugin()], http_client=hibp_transport(compromised, breached=True)
    )
    async with make_client(auth) as client:
        signup = await client.post(
            "/api/auth/sign-up/email",
            json={"email": "change-pw@example.com", "password": strong, "name": "Test User"},
        )
        assert signup.status_code == 200, signup.text
        token = signup.json()["token"]

        result = await client.post(
            "/api/auth/change-password",
            json={"currentPassword": strong, "newPassword": compromised},
            headers={"authorization": f"Bearer {token}"},
        )

    assert result.status_code == 400
    assert result.json()["code"] == "PASSWORD_COMPROMISED"


async def test_enabled_false_allows_compromised_password_e2e():
    compromised = "123456789"
    auth = make_auth(
        plugins=[HaveIBeenPwnedPlugin(enabled=False)],
        http_client=hibp_transport(compromised, breached=True),
    )
    async with make_client(auth) as client:
        res = await client.post(
            "/api/auth/sign-up/email",
            json={
                "email": "disabled-check@example.com",
                "password": compromised,
                "name": "Test User",
            },
        )

    assert res.status_code == 200
    assert res.json()["user"] is not None
