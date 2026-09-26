"""OAuth provider device authorization grant (RFC 8628).

Anchored to TS ``packages/oauth-provider/src/device-code.ts`` and ``device-code.test.ts`` at
v1.7.6 (f68044dcf, 6782647d7, 3ca2c08dc).
"""

from __future__ import annotations

import base64
import json

import jwt as pyjwt
import pytest

from better_auth.adapters.base import Where
from better_auth.plugins_ext.device_authorization import DeviceAuthorizationPlugin
from better_auth.plugins_ext.jwt import JWTPlugin
from better_auth.plugins_ext.oauth_provider import OAuthProviderPlugin
from better_auth.plugins_ext.oauth_provider.device_code import (
    DEVICE_CODE_GRANT_TYPE,
    OAuthDeviceAuthorizationPlugin,
)
from better_auth.types import AuthRequest, Ctx
from conftest import make_auth, make_client, sign_up

RESOURCE = "https://api.example.com"
OTHER_RESOURCE = "https://files.example.com"
FORM = {"content-type": "application/x-www-form-urlencoded"}


def device_auth(**device_options):
    return make_auth(
        plugins=[
            JWTPlugin(),
            OAuthProviderPlugin(
                resources=[RESOURCE, OTHER_RESOURCE],
                enforce_per_client_resources=False,
                scopes=["openid", "profile", "email", "offline_access"],
            ),
            OAuthDeviceAuthorizationPlugin(expires_in="5min", interval="2s", **device_options),
        ]
    )


def plugin_of(auth) -> OAuthProviderPlugin:
    return next(p for p in auth.plugins if isinstance(p, OAuthProviderPlugin))


async def admin_create(auth, client, body):
    cookie = "; ".join(f"{k}={v}" for k, v in client.cookies.items())
    request = AuthRequest(
        method="POST",
        path="/admin/oauth2/create-client",
        headers={"cookie": cookie, "origin": "http://testserver"},
        body=json.dumps(body).encode(),
    )
    response = await plugin_of(auth).admin_create_client(Ctx(auth=auth, request=request))
    assert response.status == 201, response.body
    return response.body


async def public_device_client(auth, client, grant_types=(DEVICE_CODE_GRANT_TYPE,)):
    created = await admin_create(
        auth,
        client,
        {
            "token_endpoint_auth_method": "none",
            "grant_types": list(grant_types),
            "scope": "openid profile email",
            "application_type": "native",
        },
    )
    return created["client_id"]


async def approved_code(client, client_id, scope="openid profile email", resource=None):
    body = {"client_id": client_id, "scope": scope}
    if resource is not None:
        body["resource"] = resource
    res = await client.post("/api/auth/device/code", json=body)
    assert res.status_code == 200, res.text
    code = res.json()
    verify = await client.get("/api/auth/device", params={"user_code": code["user_code"]})
    if resource is not None:
        assert verify.json()["resource"] == resource
    await client.post("/api/auth/device/approve", json={"userCode": code["user_code"]})
    return code["device_code"]


async def poll(client, headers=None, **body):
    return await client.post(
        "/api/auth/oauth2/token",
        data={"grant_type": DEVICE_CODE_GRANT_TYPE, **body},
        headers={**FORM, **(headers or {})},
    )


def basic(client_id, secret):
    return {"authorization": "Basic " + base64.b64encode(f"{client_id}:{secret}".encode()).decode()}


# --- composition (device-code.test.ts:24) -----------------------------------------------


def test_oauth_fields_join_the_device_code_model_only_when_composed():
    assert "oauthClientId" not in DeviceAuthorizationPlugin().schema["deviceCode"]
    fields = OAuthDeviceAuthorizationPlugin().schema["deviceCode"]
    assert fields["oauthClientId"].type == "string"
    assert fields["resources"].type == "string[]"
    assert fields["oauthClientId"].required is False


def test_composition_requires_the_provider_and_a_single_device_plugin():
    with pytest.raises(ValueError, match="requires oauthProvider"):
        make_auth(plugins=[OAuthDeviceAuthorizationPlugin()])
    with pytest.raises(ValueError, match="cannot be combined"):
        make_auth(
            plugins=[
                JWTPlugin(),
                DeviceAuthorizationPlugin(),
                OAuthProviderPlugin(),
                OAuthDeviceAuthorizationPlugin(),
            ]
        )


async def test_discovery_advertises_the_device_endpoint_and_grant():
    auth = make_auth(plugins=[JWTPlugin(), OAuthDeviceAuthorizationPlugin(), OAuthProviderPlugin()])
    provider = plugin_of(auth)
    server = await provider.get_oauth_server_config()
    assert server["device_authorization_endpoint"] == "http://testserver/api/auth/device/code"
    assert DEVICE_CODE_GRANT_TYPE in server["grant_types_supported"]
    openid = await provider.get_openid_config()
    assert openid["device_authorization_endpoint"] == server["device_authorization_endpoint"]


# --- issuance (device-code.test.ts:970) -------------------------------------------------


async def test_approved_device_code_issues_an_oauth_token_set():
    auth = device_auth()
    async with make_client(auth) as client:
        user = await sign_up(client)
        client_id = await public_device_client(auth, client)
        device_code = await approved_code(client, client_id, resource=RESOURCE)
        res = await poll(client, device_code=device_code, client_id=client_id, resource=RESOURCE)
        assert res.status_code == 200, res.text
        assert res.headers["cache-control"] == "no-store"
        body = res.json()
        assert body["token_type"] == "Bearer"
        assert body["scope"] == "openid profile email"
        access = pyjwt.decode(body["access_token"], options={"verify_signature": False})
        assert access["client_id"] == client_id
        assert RESOURCE in access["aud"]
        id_token = pyjwt.decode(body["id_token"], options={"verify_signature": False})
        assert id_token["aud"] == client_id
        assert id_token["sub"] == access["sub"] == user["user"]["id"]

        replay = await poll(client, device_code=device_code, client_id=client_id)
        assert replay.json()["error"] == "invalid_grant"


async def test_confidential_clients_authenticate_at_both_endpoints():
    auth = device_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        created = await admin_create(
            auth,
            client,
            {
                "token_endpoint_auth_method": "client_secret_basic",
                "grant_types": [DEVICE_CODE_GRANT_TYPE],
                "scope": "openid",
                "redirect_uris": ["https://confidential.example.com/cb"],
            },
        )
        auth_header = basic(created["client_id"], created["client_secret"])
        res = await client.post(
            "/api/auth/device/code", content="scope=openid", headers={**FORM, **auth_header}
        )
        assert res.status_code == 200, res.text
        code = res.json()
        await client.get("/api/auth/device", params={"user_code": code["user_code"]})
        await client.post("/api/auth/device/approve", json={"userCode": code["user_code"]})
        unauthenticated = await poll(client, device_code=code["device_code"])
        assert unauthenticated.json()["error"] == "invalid_request"
        issued = await poll(client, auth_header, device_code=code["device_code"])
        assert issued.status_code == 200, issued.text


async def test_device_code_request_errors():
    auth = device_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        unknown = await client.post(
            "/api/auth/device/code", content="client_id=unknown&scope=openid", headers=FORM
        )
        assert unknown.json() == {
            "error": "invalid_client",
            "error_description": "Invalid client ID",
        }
        missing = await client.post("/api/auth/device/code", content="scope=openid", headers=FORM)
        assert missing.json() == {
            "error": "invalid_request",
            "error_description": "client_id is required",
        }
        client_id = await public_device_client(auth, client)
        bad_resource = await client.post(
            "/api/auth/device/code", json={"client_id": client_id, "resource": "not-a-uri"}
        )
        assert bad_resource.json() == {
            "error": "invalid_target",
            "error_description": "Invalid resource indicator",
        }
        outside = await client.post(
            "/api/auth/device/code",
            json={"client_id": client_id, "resource": "https://unknown.example.com"},
        )
        assert outside.json()["error"] == "invalid_target"
        scope = await client.post(
            "/api/auth/device/code", json={"client_id": client_id, "scope": "offline_access"}
        )
        assert scope.json() == {
            "error": "invalid_scope",
            "error_description": "client does not allow scope offline_access",
        }


async def test_failed_basic_authentication_is_a_basic_challenge():
    auth = device_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        client_id = await public_device_client(auth, client)
        res = await client.post(
            "/api/auth/device/code",
            content="scope=openid",
            headers={**FORM, **basic(client_id, "wrong")},
        )
        assert res.status_code == 401
        assert res.headers["www-authenticate"] == "Basic"
        assert res.json()["error"] == "invalid_client"


async def test_mismatched_basic_and_body_client_is_invalid_client():
    auth = device_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        created = await admin_create(
            auth,
            client,
            {
                "token_endpoint_auth_method": "client_secret_basic",
                "grant_types": [DEVICE_CODE_GRANT_TYPE],
                "scope": "openid",
                "redirect_uris": ["https://confidential.example.com/cb"],
            },
        )
        body_client = await public_device_client(auth, client)
        res = await client.post(
            "/api/auth/device/code",
            content=f"client_id={body_client}&scope=openid",
            headers={**FORM, **basic(created["client_id"], created["client_secret"])},
        )
        assert res.json() == {"error": "invalid_client", "error_description": "Client ID mismatch"}


async def test_repeated_form_resources_are_bound_and_narrowable():
    auth = device_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        client_id = await public_device_client(auth, client)
        res = await client.post(
            "/api/auth/device/code",
            content=f"client_id={client_id}&scope=openid&resource={RESOURCE}&resource={OTHER_RESOURCE}",
            headers=FORM,
        )
        assert res.status_code == 200, res.text
        record = await auth.adapter.find_one(
            "deviceCode", [Where("deviceCode", res.json()["device_code"])]
        )
        assert record["resources"] == [RESOURCE, OTHER_RESOURCE]
        assert record["oauthClientId"] == client_id


async def test_unapproved_resource_keeps_the_code():
    auth = device_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        client_id = await public_device_client(auth, client)
        device_code = await approved_code(client, client_id, resource=RESOURCE)
        res = await poll(
            client, device_code=device_code, client_id=client_id, resource=OTHER_RESOURCE
        )
        assert res.json() == {
            "error": "invalid_target",
            "error_description": "Requested resource was not authorized by the user",
        }
        assert await auth.adapter.find_one("deviceCode", [Where("deviceCode", device_code)])


async def test_polling_states_follow_rfc_8628():
    auth = device_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        client_id = await public_device_client(auth, client)
        res = await client.post(
            "/api/auth/device/code", json={"client_id": client_id, "scope": "openid"}
        )
        device_code = res.json()["device_code"]
        pending = await poll(client, device_code=device_code, client_id=client_id)
        assert pending.json()["error"] == "authorization_pending"
        fast = await poll(client, device_code=device_code, client_id=client_id)
        assert fast.json()["error"] == "slow_down"
        unknown = await poll(client, device_code="nope", client_id=client_id)
        assert unknown.json()["error"] == "invalid_grant"


async def test_another_client_cannot_redeem_the_code():
    auth = device_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        client_id = await public_device_client(auth, client)
        other = await public_device_client(auth, client)
        device_code = await approved_code(client, client_id)
        res = await poll(client, device_code=device_code, client_id=other)
        assert res.json() == {"error": "invalid_grant", "error_description": "Client ID mismatch"}


async def test_oauth_codes_are_refused_at_the_session_token_endpoint():
    auth = device_auth(validate_client=lambda _client_id: True)
    async with make_client(auth) as client:
        await sign_up(client)
        client_id = await public_device_client(auth, client)
        device_code = await approved_code(client, client_id)
        res = await client.post(
            "/api/auth/device/token",
            json={
                "grant_type": DEVICE_CODE_GRANT_TYPE,
                "device_code": device_code,
                "client_id": client_id,
            },
        )
        assert res.json() == {
            "error": "invalid_grant",
            "error_description": (
                "This device code must be exchanged at the OAuth token endpoint (/oauth2/token)."
            ),
        }
        # A non-OAuth client id stays in the first-party session flow.
        standalone = await approved_code(client, "first-party-cli", scope="")
        session = await client.post(
            "/api/auth/device/token",
            json={
                "grant_type": DEVICE_CODE_GRANT_TYPE,
                "device_code": standalone,
                "client_id": "first-party-cli",
            },
        )
        assert session.status_code == 200, session.text
        assert session.json()["token_type"] == "Bearer"


async def test_standalone_codes_are_not_redeemable_at_the_oauth_endpoint():
    auth = device_auth(validate_client=lambda _client_id: True)
    async with make_client(auth) as client:
        await sign_up(client)
        device_code = await approved_code(client, "first-party-cli", scope="")
        res = await poll(client, device_code=device_code, client_id="first-party-cli")
        assert res.json()["error"] in ("invalid_grant", "invalid_client")
