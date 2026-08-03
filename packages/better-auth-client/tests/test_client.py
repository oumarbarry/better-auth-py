"""End-to-end: both client shells against the in-process server (see conftest).

Each test body is written once; the ``client``/``res`` fixtures run it against the
sync (Flask/WSGI) and async (FastAPI/ASGI) mounts.
"""

from __future__ import annotations

from typing import Any

import pytest
from better_auth_client import CATALOG, APIError

from better_auth.adapters.base import Where

BASE_URL = "http://testserver"
SIGNUP = {"name": "Ada Lovelace", "email": "ada@example.com", "password": "s3cret-password"}
GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"


async def sign_up(res: Any, client: Any, **overrides: Any) -> dict[str, Any]:
    return await res(client.sign_up.email(**{**SIGNUP, **overrides}))


# --- surface ---------------------------------------------------------------------------


async def test_catalog_surface_is_generated(client: Any) -> None:
    for name, _method, _path in CATALOG:
        target = client
        for part in name.split("."):
            target = getattr(target, part)
        assert callable(target), name
    assert callable(client.device.flow)


# --- core ------------------------------------------------------------------------------


async def test_sign_up_sign_in_session_roundtrip(client: Any, res: Any) -> None:
    result = await sign_up(res, client)
    assert result["user"]["email"] == SIGNUP["email"]

    session = await res(client.get_session())
    assert session["user"]["email"] == SIGNUP["email"]
    assert len(await res(client.list_sessions())) >= 1

    await res(client.sign_out())
    assert await res(client.get_session()) is None

    signed_in = await res(client.sign_in.email(email=SIGNUP["email"], password=SIGNUP["password"]))
    assert signed_in["user"]["email"] == SIGNUP["email"]


async def test_get_session_returns_none_unauthenticated(client: Any, res: Any) -> None:
    assert await res(client.get_session()) is None


async def test_api_error_carries_wire_code(client: Any, res: Any) -> None:
    await sign_up(res, client)
    with pytest.raises(APIError) as exc:
        await res(client.sign_in.email(email=SIGNUP["email"], password="wrong-password"))
    assert exc.value.status == 401
    assert exc.value.code == "INVALID_EMAIL_OR_PASSWORD"
    assert exc.value.body["code"] == "INVALID_EMAIL_OR_PASSWORD"


async def test_origin_defaults_to_base_url(client: Any, res: Any) -> None:
    assert client._http.headers["origin"] == BASE_URL
    await sign_up(res, client)
    # cookie-carrying POST: passes only because the client sends Origin by default
    await res(client.update_user(name="Ada King"))
    del client._http.headers["origin"]
    with pytest.raises(APIError) as exc:
        await res(client.update_user(name="Nope"))
    assert exc.value.code == "MISSING_OR_NULL_ORIGIN"


# --- bearer ----------------------------------------------------------------------------


async def test_bearer_capture_and_set_bearer(client: Any, client_factory: Any, res: Any) -> None:
    await sign_up(res, client)
    assert client._bearer  # captured from the set-auth-token response header

    other = client_factory()
    assert await res(other.get_session()) is None
    other.set_bearer(client._bearer)
    session = await res(other.get_session())
    assert session["user"]["email"] == SIGNUP["email"]


# --- two-factor ------------------------------------------------------------------------


async def test_two_factor_enable(client: Any, res: Any) -> None:
    await sign_up(res, client)
    result = await res(client.two_factor.enable(password=SIGNUP["password"]))
    assert result["totpURI"].startswith("otpauth://totp/")
    assert len(result["backupCodes"]) == 10


# --- organization ----------------------------------------------------------------------


async def test_organization_create_and_list(client: Any, res: Any) -> None:
    await sign_up(res, client)
    created = await res(client.organization.create(name="Acme", slug="acme"))
    assert created["slug"] == "acme"
    organizations = await res(client.organization.list())
    assert [org["slug"] for org in organizations] == ["acme"]


# --- admin -----------------------------------------------------------------------------


async def test_admin_list_users(client: Any, res: Any, auth: Any) -> None:
    await sign_up(res, client)
    user = await auth.adapter.find_one("user", [Where("email", SIGNUP["email"])])
    await auth.adapter.update("user", [Where("id", user["id"])], {"role": "admin"})
    result = await res(client.admin.list_users())
    assert result["total"] == 1
    assert result["users"][0]["email"] == SIGNUP["email"]


# --- api-key ---------------------------------------------------------------------------


async def test_api_key_create_and_list(client: Any, res: Any) -> None:
    await sign_up(res, client)
    created = await res(client.api_key.create(name="ci"))
    assert created["key"]
    keys = await res(client.api_key.list())
    assert [key["name"] for key in keys["apiKeys"]] == ["ci"]


# --- magic-link (also: 302 returned, never followed) -------------------------------------


async def test_magic_link_verify_returns_302_not_followed(
    client: Any, res: Any, outbox: dict[str, Any]
) -> None:
    await res(client.sign_in.magic_link(email="link@example.com", callbackURL="/welcome"))
    token = outbox["magic_link"]["token"]

    response = await res(client.magic_link.verify(token=token, callbackURL="/welcome"))
    assert response.status_code == 302
    assert response.headers["location"] == f"{BASE_URL}/welcome"
    # the redirect itself carried the session cookie; the jar picked it up
    session = await res(client.get_session())
    assert session["user"]["email"] == "link@example.com"


# --- email-otp ---------------------------------------------------------------------------


async def test_email_otp_sign_in(client: Any, res: Any, outbox: dict[str, Any]) -> None:
    await res(client.email_otp.send_verification_otp(email="otp@example.com", type="sign-in"))
    result = await res(client.sign_in.email_otp(email="otp@example.com", otp=outbox["otp"]["otp"]))
    assert result["user"]["email"] == "otp@example.com"
    assert (await res(client.get_session()))["user"]["email"] == "otp@example.com"


# --- device flow -------------------------------------------------------------------------


async def _claim(res: Any, approver: Any, user_code: str) -> None:
    """Second screen: the signed-in approver looks up (and thereby claims) the code."""
    claim = await res(approver.device(user_code=user_code))
    assert claim["status"] == "pending"


async def test_device_flow_approve(client: Any, client_factory: Any, res: Any) -> None:
    flow = await res(client.device.flow("test-cli", scope="profile"))
    assert flow.user_code and flow.device_code
    # urljoin("/device") against base_url+base_path resolves at the host root
    assert flow.verification_uri == f"{BASE_URL}/device"
    assert flow.user_code in flow.verification_uri_complete

    # poll before approval: authorization_pending rides APIError.code
    with pytest.raises(APIError) as exc:
        await res(
            client.device.token(
                grant_type=GRANT_TYPE, device_code=flow.device_code, client_id="test-cli"
            )
        )
    assert exc.value.code == "authorization_pending"

    approver = client_factory()
    await sign_up(res, approver, email="approver@example.com")
    await _claim(res, approver, flow.user_code)
    approved = await res(approver.device.approve(userCode=flow.user_code))
    assert approved["success"] is True

    token = await res(flow.poll())
    assert token["token_type"] == "Bearer"
    assert token["scope"] == "profile"

    client.set_bearer(token["access_token"])
    session = await res(client.get_session())
    assert session["user"]["email"] == "approver@example.com"


async def test_device_flow_deny(client: Any, client_factory: Any, res: Any) -> None:
    flow = await res(client.device.flow("test-cli"))

    approver = client_factory()
    await sign_up(res, approver, email="denier@example.com")
    await _claim(res, approver, flow.user_code)
    denied = await res(approver.device.deny(userCode=flow.user_code))
    assert denied["success"] is True

    with pytest.raises(APIError) as exc:
        await res(flow.poll())
    assert exc.value.code == "access_denied"
