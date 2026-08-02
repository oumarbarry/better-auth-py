"""device-authorization plugin — OAuth 2.0 Device Authorization Grant (RFC 8628).

Verified against TS `packages/better-auth/src/plugins/device-authorization/`
(`index.ts`, `routes.ts`, `schema.ts`, `error-codes.ts`) and
`device-authorization.test.ts` at v1.6.23.
"""

from __future__ import annotations

import asyncio
import re

import pytest

from better_auth.adapters.base import Where
from better_auth.adapters.memory import MemoryAdapter
from better_auth.plugins_ext.device_authorization import (
    ERROR_CODES,
    DeviceAuthorizationPlugin,
)
from conftest import make_auth, make_client, sign_up

GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"


def device_auth(**kwargs):
    return make_auth(plugins=[DeviceAuthorizationPlugin(**kwargs)])


async def _request_code(client, **body):
    response = await client.post("/api/auth/device/code", json={"client_id": "test-client", **body})
    assert response.status_code == 200, response.text
    return response.json()


async def _poll_token(client, device_code, client_id="test-client"):
    return await client.post(
        "/api/auth/device/token",
        json={"grant_type": GRANT_TYPE, "device_code": device_code, "client_id": client_id},
    )


# --- config validation ---------------------------------------------------------------


def test_default_construction_does_not_raise():
    DeviceAuthorizationPlugin()


def test_invalid_expires_in_format_raises():
    with pytest.raises(ValueError):
        DeviceAuthorizationPlugin(expires_in="not-a-duration")


def test_invalid_interval_format_raises():
    with pytest.raises(ValueError):
        DeviceAuthorizationPlugin(interval="also-not-a-duration")


def test_invalid_verification_uri_type_raises():
    with pytest.raises(ValueError):
        DeviceAuthorizationPlugin(verification_uri=123)  # ty: ignore[invalid-argument-type]


def test_error_codes_surface_on_auth_instance():
    auth = device_auth()
    assert auth.error_codes["AUTHORIZATION_PENDING"] == "Authorization pending"
    assert auth.error_codes["DEVICE_CODE_NOT_CLAIMED"] == ERROR_CODES["DEVICE_CODE_NOT_CLAIMED"]


def test_schema_registers_device_code_table():
    auth = device_auth()
    fields = auth.schema["deviceCode"]
    assert fields["deviceCode"].required is True
    assert fields["userCode"].required is True
    assert fields["userId"].required is False
    assert fields["status"].required is True
    assert fields["expiresAt"].type == "datetime"
    assert fields["lastPolledAt"].type == "datetime"
    assert fields["pollingInterval"].type == "number"
    assert fields["clientId"].required is False
    assert fields["scope"].required is False


# --- client validation (validateClient hook) ------------------------------------------


async def test_rejects_invalid_client_in_device_code_request():
    valid_clients = {"valid-client-1", "valid-client-2"}
    auth = device_auth(validate_client=lambda cid: cid in valid_clients)
    async with make_client(auth) as client:
        response = await client.post("/api/auth/device/code", json={"client_id": "invalid-client"})
        assert response.status_code == 400
        assert response.json() == {
            "error": "invalid_client",
            "error_description": "Invalid client ID",
        }


async def test_accepts_valid_client_in_device_code_request():
    auth = device_auth(validate_client=lambda cid: cid == "valid-client-1")
    async with make_client(auth) as client:
        response = await client.post("/api/auth/device/code", json={"client_id": "valid-client-1"})
        assert response.status_code == 200
        assert response.json()["device_code"]


async def test_rejects_invalid_client_in_token_request():
    auth = device_auth(validate_client=lambda cid: cid == "valid-client-1")
    async with make_client(auth) as client:
        code = await _request_code(client, client_id="valid-client-1")
        response = await client.post(
            "/api/auth/device/token",
            json={
                "grant_type": GRANT_TYPE,
                "device_code": code["device_code"],
                "client_id": "invalid-client",
            },
        )
        assert response.status_code == 400
        assert response.json() == {
            "error": "invalid_grant",
            "error_description": "Invalid client ID",
        }


async def test_rejects_mismatched_client_id_in_token_request():
    async with make_client(device_auth()) as client:
        code = await _request_code(client)
        response = await client.post(
            "/api/auth/device/token",
            json={
                "grant_type": GRANT_TYPE,
                "device_code": code["device_code"],
                "client_id": "someone-else",
            },
        )
        assert response.status_code == 400
        assert response.json() == {
            "error": "invalid_grant",
            "error_description": "Client ID mismatch",
        }


# --- POST /device/code -----------------------------------------------------------------


async def test_generates_device_and_user_codes():
    auth = device_auth(expires_in="5min", interval="2s")
    async with make_client(auth) as client:
        body = await _request_code(client)
        assert body["device_code"]
        assert body["user_code"]
        assert "/device" in body["verification_uri"]
        assert "/device" in body["verification_uri_complete"]
        assert f"user_code={body['user_code']}" in body["verification_uri_complete"]
        assert body["expires_in"] == 300
        assert body["interval"] == 2


async def test_device_code_response_sets_no_store_header():
    async with make_client(device_auth()) as client:
        response = await client.post("/api/auth/device/code", json={"client_id": "test-client"})
        assert response.headers["cache-control"] == "no-store"


async def test_default_user_code_format():
    async with make_client(device_auth()) as client:
        body = await _request_code(client)
        assert re.fullmatch(r"[A-Z0-9]{8}", body["user_code"])
        # Crockford-ish charset: no ambiguous I, O, 0, 1
        assert set(body["user_code"]) <= set("ABCDEFGHJKLMNPQRSTUVWXYZ23456789")


async def test_default_device_code_format():
    async with make_client(device_auth()) as client:
        body = await _request_code(client)
        assert re.fullmatch(r"[a-zA-Z0-9]{40}", body["device_code"])


async def test_supports_custom_client_id_and_scope():
    async with make_client(device_auth()) as client:
        body = await _request_code(client, scope="read write")
        assert body["device_code"]
        assert body["user_code"]


async def test_interval_stored_as_milliseconds_in_database():
    auth = device_auth(interval="5s")
    async with make_client(auth) as client:
        body = await _request_code(client)
    record = await auth.adapter.find_one("deviceCode", [Where("deviceCode", body["device_code"])])
    assert record is not None
    assert record["pollingInterval"] == 5000
    assert isinstance(record["pollingInterval"], int)


async def test_custom_code_generators():
    auth = device_auth(
        generate_device_code=lambda: "custom-device-code-12345",
        generate_user_code=lambda: "CUSTOM12",
    )
    async with make_client(auth) as client:
        body = await _request_code(client)
        assert body["device_code"] == "custom-device-code-12345"
        assert body["user_code"] == "CUSTOM12"


async def test_custom_expiration_time():
    async with make_client(device_auth(expires_in="1min")) as client:
        body = await _request_code(client)
        assert body["expires_in"] == 60


async def test_verification_uri_defaults_to_device():
    async with make_client(device_auth()) as client:
        body = await _request_code(client)
        assert "/device" in body["verification_uri"]
        assert "/device" in body["verification_uri_complete"]
        assert f"user_code={body['user_code']}" in body["verification_uri_complete"]


async def test_custom_relative_verification_uri():
    auth = device_auth(verification_uri="/auth/device-verify")
    async with make_client(auth) as client:
        body = await _request_code(client)
        assert "/auth/device-verify" in body["verification_uri"]
        assert "/auth/device-verify" in body["verification_uri_complete"]
        assert f"user_code={body['user_code']}" in body["verification_uri_complete"]


async def test_absolute_verification_uri():
    custom_url = "https://myapp.com/device"
    auth = device_auth(verification_uri=custom_url)
    async with make_client(auth) as client:
        body = await _request_code(client)
        assert body["verification_uri"] == custom_url
        assert body["verification_uri_complete"] == f"{custom_url}?user_code={body['user_code']}"


async def test_verification_uri_complete_preserves_dash_in_custom_user_code():
    auth = device_auth(verification_uri="/device", generate_user_code=lambda: "ABC-123")
    async with make_client(auth) as client:
        body = await _request_code(client)
        assert "user_code=ABC-123" in body["verification_uri_complete"]


async def test_verification_uri_with_existing_query_parameters():
    auth = device_auth(verification_uri="/device?lang=en")
    async with make_client(auth) as client:
        body = await _request_code(client)
        assert "lang=en" in body["verification_uri"]
        assert "lang=en" in body["verification_uri_complete"]
        assert f"user_code={body['user_code']}" in body["verification_uri_complete"]


# --- POST /device/token polling ---------------------------------------------------------


async def test_authorization_pending_when_not_approved():
    async with make_client(device_auth()) as client:
        code = await _request_code(client)
        response = await _poll_token(client, code["device_code"])
        assert response.status_code == 400
        assert response.json() == {
            "error": "authorization_pending",
            "error_description": "Authorization pending",
        }


async def test_invalid_device_code_returns_invalid_grant():
    async with make_client(device_auth()) as client:
        response = await client.post(
            "/api/auth/device/token",
            json={
                "grant_type": GRANT_TYPE,
                "device_code": "unknown-code",
                "client_id": "test-client",
            },
        )
        assert response.status_code == 400
        assert response.json() == {
            "error": "invalid_grant",
            "error_description": "Invalid device code",
        }


async def test_expired_device_code_is_burned():
    auth = device_auth()
    async with make_client(auth) as client:
        code = await _request_code(client)
        await auth.adapter.update(
            "deviceCode",
            [Where("deviceCode", code["device_code"])],
            {"expiresAt": _past()},
        )
        response = await _poll_token(client, code["device_code"])
        assert response.status_code == 400
        assert response.json() == {
            "error": "expired_token",
            "error_description": "Device code has expired",
        }
    record = await auth.adapter.find_one("deviceCode", [Where("deviceCode", code["device_code"])])
    assert record is None


def _past():
    from datetime import timedelta

    from better_auth.session import utcnow

    return utcnow() - timedelta(seconds=1)


async def test_slow_down_on_immediate_repoll_and_last_polled_at_updates():
    auth = device_auth(interval="2s")
    async with make_client(auth) as client:
        code = await _request_code(client)

        first = await _poll_token(client, code["device_code"])
        assert first.status_code == 400
        assert first.json()["error"] == "authorization_pending"

        record = await auth.adapter.find_one(
            "deviceCode", [Where("deviceCode", code["device_code"])]
        )
        assert record is not None
        assert record["lastPolledAt"] is not None

        second = await _poll_token(client, code["device_code"])
        assert second.status_code == 400
        assert second.json() == {
            "error": "slow_down",
            "error_description": "Polling too frequently",
        }


# --- GET /device (verify) ---------------------------------------------------------------


async def test_verify_valid_user_code_returns_pending():
    async with make_client(device_auth()) as client:
        code = await _request_code(client)
        response = await client.get("/api/auth/device", params={"user_code": code["user_code"]})
        assert response.status_code == 200
        assert response.json() == {"user_code": code["user_code"], "status": "pending"}


async def test_verify_invalid_user_code():
    async with make_client(device_auth()) as client:
        response = await client.get("/api/auth/device", params={"user_code": "NOPE0000"})
        assert response.status_code == 400
        assert response.json() == {
            "error": "invalid_request",
            "error_description": "Invalid user code",
        }


async def test_verify_expired_user_code():
    auth = device_auth()
    async with make_client(auth) as client:
        code = await _request_code(client)
        await auth.adapter.update(
            "deviceCode", [Where("deviceCode", code["device_code"])], {"expiresAt": _past()}
        )
        response = await client.get("/api/auth/device", params={"user_code": code["user_code"]})
        assert response.status_code == 400
        assert response.json() == {
            "error": "expired_token",
            "error_description": "User code has expired",
        }


async def test_verify_strips_dashes_from_user_code():
    async with make_client(device_auth()) as client:
        code = await _request_code(client)
        clean = code["user_code"].replace("-", "")
        response = await client.get("/api/auth/device", params={"user_code": clean})
        assert response.status_code == 200
        assert response.json()["status"] == "pending"


# --- device approval flow ----------------------------------------------------------------


async def test_full_happy_path_code_to_session():
    auth = device_auth(expires_in="5min", interval="2s")
    async with make_client(auth) as user_client:
        await sign_up(user_client)

        async with make_client(auth) as device_client:
            code = await _request_code(device_client)

            # user claims + approves via their own authenticated browser
            verify = await user_client.get(
                "/api/auth/device", params={"user_code": code["user_code"]}
            )
            assert verify.status_code == 200
            assert verify.json()["status"] == "pending"

            approve = await user_client.post(
                "/api/auth/device/approve", json={"userCode": code["user_code"]}
            )
            assert approve.status_code == 200
            assert approve.json() == {"success": True}

            token_response = await _poll_token(device_client, code["device_code"])
            assert token_response.status_code == 200
            payload = token_response.json()
            assert payload["access_token"]
            assert payload["token_type"] == "Bearer"
            assert payload["expires_in"] > 0
            assert payload["scope"] == ""

            # the minted access_token is a genuine bearer-usable session
            session_check = await device_client.get(
                "/api/auth/get-session",
                headers={"Authorization": f"Bearer {payload['access_token']}"},
            )
            assert session_check.status_code == 200
            assert session_check.json()["user"]["email"] == "ada@example.com"


async def test_deny_flow_returns_access_denied_on_token_poll():
    auth = device_auth()
    async with make_client(auth) as user_client:
        await sign_up(user_client)
        code = await _request_code(user_client)

        await user_client.get("/api/auth/device", params={"user_code": code["user_code"]})
        deny = await user_client.post("/api/auth/device/deny", json={"userCode": code["user_code"]})
        assert deny.status_code == 200
        assert deny.json() == {"success": True}

        response = await _poll_token(user_client, code["device_code"])
        assert response.status_code == 400
        assert response.json() == {
            "error": "access_denied",
            "error_description": "Access denied",
        }


async def test_approve_requires_authentication():
    async with make_client(device_auth()) as client:
        code = await _request_code(client)
        response = await client.post(
            "/api/auth/device/approve", json={"userCode": code["user_code"]}
        )
        assert response.status_code == 401
        assert response.json() == {
            "error": "unauthorized",
            "error_description": "Authentication required",
        }


async def test_deny_requires_authentication():
    async with make_client(device_auth()) as client:
        code = await _request_code(client)
        response = await client.post("/api/auth/device/deny", json={"userCode": code["user_code"]})
        assert response.status_code == 401
        assert response.json() == {
            "error": "unauthorized",
            "error_description": "Authentication required",
        }


async def test_cannot_approve_already_processed_device_code():
    auth = device_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        code = await _request_code(client)
        await client.get("/api/auth/device", params={"user_code": code["user_code"]})
        first = await client.post("/api/auth/device/approve", json={"userCode": code["user_code"]})
        assert first.status_code == 200

        second = await client.post("/api/auth/device/approve", json={"userCode": code["user_code"]})
        assert second.status_code == 400
        assert second.json() == {
            "error": "invalid_request",
            "error_description": "Device code already processed",
        }


async def test_scope_stored_and_returned_through_token():
    auth = device_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        code = await _request_code(client, scope="read write profile")
        await client.get("/api/auth/device", params={"user_code": code["user_code"]})
        await client.post("/api/auth/device/approve", json={"userCode": code["user_code"]})

        response = await _poll_token(client, code["device_code"])
        assert response.status_code == 200
        assert response.json()["scope"] == "read write profile"


# --- ownership gate (security: GHSA-cq3f-vc6p-68fh) ---------------------------------------


async def test_approve_rejects_session_that_never_claimed_the_code():
    auth = device_auth()
    async with make_client(auth) as device_client:
        code = await _request_code(device_client)

    async with make_client(auth) as attacker:
        await sign_up(attacker, email="attacker@example.test")
        response = await attacker.post(
            "/api/auth/device/approve", json={"userCode": code["user_code"]}
        )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_request"

    record = await auth.adapter.find_one("deviceCode", [Where("userCode", code["user_code"])])
    assert record is not None
    assert record["status"] == "pending"
    assert not record.get("userId")


async def test_deny_rejects_session_that_never_claimed_the_code():
    auth = device_auth()
    async with make_client(auth) as device_client:
        code = await _request_code(device_client)

    async with make_client(auth) as attacker:
        await sign_up(attacker, email="attacker@example.test")
        response = await attacker.post(
            "/api/auth/device/deny", json={"userCode": code["user_code"]}
        )
        assert response.status_code == 400
        assert response.json()["error"] == "invalid_request"

    record = await auth.adapter.find_one("deviceCode", [Where("userCode", code["user_code"])])
    assert record is not None
    assert record["status"] == "pending"


async def test_approve_succeeds_when_same_session_verified_first():
    auth = device_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        code = await _request_code(client)
        await client.get("/api/auth/device", params={"user_code": code["user_code"]})
        response = await client.post(
            "/api/auth/device/approve", json={"userCode": code["user_code"]}
        )
        assert response.status_code == 200
        assert response.json() == {"success": True}


async def test_approve_rejects_different_user_after_another_claimed():
    auth = device_auth()
    async with make_client(auth) as claimer:
        await sign_up(claimer, email="claimer@example.test")
        code = await _request_code(claimer)
        await claimer.get("/api/auth/device", params={"user_code": code["user_code"]})

        async with make_client(auth) as attacker:
            await sign_up(attacker, email="attacker@example.test")
            approve = await attacker.post(
                "/api/auth/device/approve", json={"userCode": code["user_code"]}
            )
            assert approve.status_code == 403
            assert approve.json() == {
                "error": "access_denied",
                "error_description": "You are not authorized to approve this device authorization",
            }

            deny = await attacker.post(
                "/api/auth/device/deny", json={"userCode": code["user_code"]}
            )
            assert deny.status_code == 403
            assert deny.json() == {
                "error": "access_denied",
                "error_description": "You are not authorized to deny this device authorization",
            }


async def test_approve_rejects_wrong_user_when_prebound_via_user_id():
    auth = device_auth()
    async with make_client(auth) as owner_client:
        owner = await sign_up(owner_client, email="owner@example.test")

    async with make_client(auth) as bystander:
        code = await _request_code(bystander, user_id=owner["user"]["id"])

    async with make_client(auth) as attacker:
        await sign_up(attacker, email="attacker@example.test")
        response = await attacker.post(
            "/api/auth/device/approve", json={"userCode": code["user_code"]}
        )
        assert response.status_code == 403
        assert response.json()["error"] == "access_denied"


async def test_approve_allows_when_prebound_user_matches_current_user():
    auth = device_auth()
    async with make_client(auth) as client:
        user = await sign_up(client)
        code = await _request_code(client, user_id=user["user"]["id"])
        response = await client.post(
            "/api/auth/device/approve", json={"userCode": code["user_code"]}
        )
        assert response.status_code == 200
        assert response.json() == {"success": True}


async def test_deny_allows_when_prebound_user_matches_current_user():
    auth = device_auth()
    async with make_client(auth) as client:
        user = await sign_up(client)
        code = await _request_code(client, user_id=user["user"]["id"])
        response = await client.post("/api/auth/device/deny", json={"userCode": code["user_code"]})
        assert response.status_code == 200
        assert response.json() == {"success": True}


async def test_empty_user_id_is_treated_as_omitted():
    """RFC 8628 section 3.1: an empty user_id is the same as omitting it."""
    auth = device_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        code = await _request_code(client, user_id="")
        await client.get("/api/auth/device", params={"user_code": code["user_code"]})
        response = await client.post(
            "/api/auth/device/approve", json={"userCode": code["user_code"]}
        )
        assert response.status_code == 200
        assert response.json() == {"success": True}


async def test_verify_claim_does_not_overwrite_a_concurrent_claim():
    """Guarded `increment_one` (status=pending AND userId IS NULL) must not let a
    stale read clobber a claim that already landed between read and write."""

    owner_id_holder: list[str] = []

    class RacingAdapter(MemoryAdapter):
        armed = False

        async def increment_one(self, model, where, increment=None, set=None):
            if (
                self.armed
                and model == "deviceCode"
                and set
                and set.get("userId")
                and owner_id_holder
            ):
                self.armed = False
                device_id = next((w.value for w in where if w.field == "id"), None)
                if device_id is not None:
                    await MemoryAdapter.update(
                        self,
                        "deviceCode",
                        [Where("id", device_id)],
                        {"userId": owner_id_holder[0]},
                    )
            return await super().increment_one(model, where, increment, set)

    auth = make_auth(adapter=RacingAdapter(), plugins=[DeviceAuthorizationPlugin()])

    async with make_client(auth) as owner_client:
        owner = await sign_up(owner_client, email="owner@example.test")
        owner_id_holder.append(owner["user"]["id"])

    async with make_client(auth) as racer_client:
        await sign_up(racer_client, email="racer@example.test")
        racer_session = (await racer_client.get("/api/auth/get-session")).json()

        code = await _request_code(racer_client)

        adapter = auth.adapter
        assert isinstance(adapter, RacingAdapter)
        adapter.armed = True
        await racer_client.get("/api/auth/device", params={"user_code": code["user_code"]})

        record = await auth.adapter.find_one("deviceCode", [Where("userCode", code["user_code"])])
        assert record is not None
        assert record["userId"] == owner["user"]["id"]
        assert record["userId"] != racer_session["user"]["id"]
        assert record["status"] == "pending"


# --- concurrent redemption (single-winner claim) -------------------------------------------


async def test_concurrent_token_claims_exactly_one_wins():
    auth = device_auth()
    async with make_client(auth) as user_client:
        await sign_up(user_client)
        code = await _request_code(user_client)
        await user_client.get("/api/auth/device", params={"user_code": code["user_code"]})
        await user_client.post("/api/auth/device/approve", json={"userCode": code["user_code"]})

        async def poll():
            return await _poll_token(user_client, code["device_code"])

        results = await asyncio.gather(poll(), poll())

    successes = [r for r in results if r.status_code == 200 and "access_token" in r.json()]
    assert len(successes) == 1

    record = await auth.adapter.find_one("deviceCode", [Where("deviceCode", code["device_code"])])
    assert record is None

    async with make_client(auth) as client:
        third = await _poll_token(client, code["device_code"])
        assert third.status_code == 400
        assert third.json()["error"] == "invalid_grant"


async def test_burns_expired_approved_device_code_instead_of_issuing_token():
    auth = device_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        code = await _request_code(client)
        await client.get("/api/auth/device", params={"user_code": code["user_code"]})
        await client.post("/api/auth/device/approve", json={"userCode": code["user_code"]})

        await auth.adapter.update(
            "deviceCode", [Where("deviceCode", code["device_code"])], {"expiresAt": _past()}
        )

        response = await _poll_token(client, code["device_code"])
        assert response.status_code == 400
        assert response.json()["error"] == "expired_token"

    record = await auth.adapter.find_one("deviceCode", [Where("deviceCode", code["device_code"])])
    assert record is None
