"""End-to-end: both client shells against the in-process server (see conftest).

Each test body is written once; the ``client``/``res`` fixtures run it against the
sync (Flask/WSGI) and async (FastAPI/ASGI) mounts.
"""

from __future__ import annotations

import base64
import hashlib
import json
import struct
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from better_auth_client import CATALOG, APIError
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

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


# --- username ----------------------------------------------------------------------------


async def test_username_sign_in_and_availability(client: Any, res: Any) -> None:
    assert (await res(client.is_username_available(username="ada"))) == {"available": True}
    await sign_up(res, client, username="ada")
    await res(client.sign_out())

    signed_in = await res(client.sign_in.username(username="ada", password=SIGNUP["password"]))
    assert signed_in["user"]["email"] == SIGNUP["email"]
    assert (await res(client.is_username_available(username="ada"))) == {"available": False}


# --- phone-number ------------------------------------------------------------------------


async def test_phone_number_full_flow(client: Any, res: Any, outbox: dict[str, Any]) -> None:
    phone = "+15551230001"
    assert (await res(client.phone_number.send_otp(phoneNumber=phone))) == {"message": "code sent"}
    verified = await res(client.phone_number.verify(phoneNumber=phone, code=outbox["sms"]["code"]))
    assert verified["status"] is True
    session = await res(client.get_session())
    assert session["user"]["phoneNumber"] == phone

    await res(client.phone_number.request_password_reset(phoneNumber=phone))
    await res(
        client.phone_number.reset_password(
            phoneNumber=phone, otp=outbox["sms"]["code"], newPassword="new-secure-pass"
        )
    )
    await res(client.sign_out())
    signed_in = await res(
        client.sign_in.phone_number(phoneNumber=phone, password="new-secure-pass")
    )
    assert signed_in["user"]["phoneNumber"] == phone


# --- passkey (real WebAuthn ceremonies via a software ES256 authenticator) ---------------


def _b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


class SoftKey:
    """Minimal ES256 software authenticator (trimmed from tests/plugins/test_passkey.py)."""

    RP_ID = "testserver"

    def __init__(self) -> None:
        self.cred_id = bytes(range(1, 17))
        self._priv = ec.generate_private_key(ec.SECP256R1())
        self.sign_count = 0

    def _cose(self) -> bytes:
        from webauthn.helpers import encode_cbor

        nums = self._priv.public_key().public_numbers()
        return encode_cbor(
            {1: 2, 3: -7, -1: 1, -2: nums.x.to_bytes(32, "big"), -3: nums.y.to_bytes(32, "big")}
        )

    def _auth_data(self, flags: int, sign_count: int, attested: bytes = b"") -> bytes:
        return (
            hashlib.sha256(self.RP_ID.encode()).digest()
            + bytes([flags])
            + struct.pack(">I", sign_count)
            + attested
        )

    def register(self, challenge_b64url: str) -> dict[str, Any]:
        from webauthn.helpers import encode_cbor

        cdj = json.dumps(
            {
                "type": "webauthn.create",
                "challenge": challenge_b64url,
                "origin": BASE_URL,
                "crossOrigin": False,
            }
        ).encode()
        attested = bytes(16) + struct.pack(">H", len(self.cred_id)) + self.cred_id + self._cose()
        ad = self._auth_data(0x01 | 0x04 | 0x40, 0, attested)  # UP | UV | AT
        att_obj = encode_cbor({"fmt": "none", "attStmt": {}, "authData": ad})
        return {
            "id": _b64url(self.cred_id),
            "rawId": _b64url(self.cred_id),
            "response": {
                "clientDataJSON": _b64url(cdj),
                "attestationObject": _b64url(att_obj),
                "transports": ["internal"],
            },
            "type": "public-key",
            "clientExtensionResults": {},
            "authenticatorAttachment": "platform",
        }

    def authenticate(self, challenge_b64url: str) -> dict[str, Any]:
        self.sign_count += 1
        cdj = json.dumps(
            {
                "type": "webauthn.get",
                "challenge": challenge_b64url,
                "origin": BASE_URL,
                "crossOrigin": False,
            }
        ).encode()
        ad = self._auth_data(0x01 | 0x04, self.sign_count)  # UP | UV
        sig = self._priv.sign(ad + hashlib.sha256(cdj).digest(), ec.ECDSA(hashes.SHA256()))
        return {
            "id": _b64url(self.cred_id),
            "rawId": _b64url(self.cred_id),
            "response": {
                "clientDataJSON": _b64url(cdj),
                "authenticatorData": _b64url(ad),
                "signature": _b64url(sig),
            },
            "type": "public-key",
            "clientExtensionResults": {},
        }


async def test_passkey_register_authenticate_manage(client: Any, res: Any) -> None:
    await sign_up(res, client)
    key = SoftKey()

    options = await res(client.passkey.generate_register_options())
    registered = await res(
        client.passkey.verify_registration(response=key.register(options["challenge"]), name="ci")
    )
    passkey_id = registered["id"]

    listed = await res(client.passkey.list_user_passkeys())
    assert [p["id"] for p in listed] == [passkey_id]
    updated = await res(client.passkey.update_passkey(id=passkey_id, name="laptop"))
    assert updated["passkey"]["name"] == "laptop"

    await res(client.sign_out())
    options = await res(client.passkey.generate_authenticate_options())
    authed = await res(
        client.passkey.verify_authentication(response=key.authenticate(options["challenge"]))
    )
    assert authed["user"]["email"] == SIGNUP["email"]
    assert (await res(client.get_session()))["user"]["email"] == SIGNUP["email"]

    deleted = await res(client.passkey.delete_passkey(id=passkey_id))
    assert deleted == {"status": True}
    assert await res(client.passkey.list_user_passkeys()) == []


# --- anonymous ---------------------------------------------------------------------------


async def test_anonymous_sign_in_and_delete(client: Any, res: Any) -> None:
    anon = await res(client.sign_in.anonymous())
    assert anon["user"]["isAnonymous"] is True
    assert (await res(client.get_session()))["user"]["id"] == anon["user"]["id"]

    deleted = await res(client.delete_anonymous_user())
    assert deleted == {"success": True}
    assert await res(client.get_session()) is None


# --- siwe --------------------------------------------------------------------------------

SIWE_WALLET = "0x000000000000000000000000000000000000dEaD"  # matches conftest
SIWE_NONCE = "A1b2C3d4E5f6G7h8J"

SIWE_MESSAGE = (
    "example.com wants you to sign in with your Ethereum account:\n"
    f"{SIWE_WALLET}\n\n"
    "Sign in.\n\n"
    "URI: https://example.com\n"
    "Version: 1\n"
    "Chain ID: 1\n"
    f"Nonce: {SIWE_NONCE}\n"
    "Issued At: 2024-01-01T00:00:00.000Z"
)


async def test_siwe_nonce_verify_roundtrip(client: Any, res: Any) -> None:
    nonce = await res(client.siwe.nonce(walletAddress=SIWE_WALLET, chainId=1))
    assert nonce == {"nonce": SIWE_NONCE}
    # the mounted /siwe/get-nonce alias answers identically
    assert (await res(client.siwe.get_nonce(walletAddress=SIWE_WALLET, chainId=1))) == nonce

    verified = await res(
        client.siwe.verify(
            message=SIWE_MESSAGE,
            signature="valid_signature",
            walletAddress=SIWE_WALLET,
            chainId=1,
        )
    )
    assert verified["success"] is True
    assert await res(client.get_session()) is not None


# --- one-tap -----------------------------------------------------------------------------


async def test_one_tap_callback(client: Any, res: Any, google_token: Any) -> None:
    result = await res(client.one_tap.callback(idToken=google_token()))
    assert result["user"]["email"] == "one-tap@example.com"
    assert (await res(client.get_session()))["user"]["email"] == "one-tap@example.com"


# --- jwt (root-mounted /token and /jwks) -------------------------------------------------


async def test_jwt_token_and_jwks(client: Any, res: Any) -> None:
    await sign_up(res, client)
    token = (await res(client.token()))["token"]
    assert token.count(".") == 2

    jwks = await res(client.jwks())
    assert jwks["keys"] and jwks["keys"][0]["kty"]


# --- one-time-token ----------------------------------------------------------------------


async def test_one_time_token_generate_verify(client: Any, client_factory: Any, res: Any) -> None:
    await sign_up(res, client)
    token = (await res(client.one_time_token.generate()))["token"]

    other = client_factory()
    verified = await res(other.one_time_token.verify(token=token))
    assert verified["user"]["email"] == SIGNUP["email"]
    assert (await res(other.get_session()))["user"]["email"] == SIGNUP["email"]


# --- multi-session -----------------------------------------------------------------------


async def test_multi_session_list_switch_revoke(client: Any, res: Any) -> None:
    first = await sign_up(res, client)
    second = await sign_up(res, client, email="second@example.com")

    listed = await res(client.multi_session.list_device_sessions())
    assert {item["user"]["email"] for item in listed} == {SIGNUP["email"], "second@example.com"}

    switched = await res(client.multi_session.set_active(sessionToken=first["token"]))
    assert switched["user"]["email"] == SIGNUP["email"]
    assert (await res(client.get_session()))["user"]["email"] == SIGNUP["email"]

    await res(client.multi_session.revoke(sessionToken=second["token"]))
    listed = await res(client.multi_session.list_device_sessions())
    assert [item["user"]["email"] for item in listed] == [SIGNUP["email"]]


# --- oauth-popup (302 to the provider, returned unfollowed) ------------------------------


async def test_oauth_popup_start_redirects_to_provider(client: Any, res: Any) -> None:
    response = await res(
        client.oauth_popup.start(
            provider="acme", popupOrigin=BASE_URL, popupNonce="n1", callbackURL="/dash"
        )
    )
    assert response.status_code == 302
    assert response.headers["location"].startswith("https://idp.example.com/authorize?")


# --- generic-oauth -----------------------------------------------------------------------


async def test_generic_oauth_sign_in_and_link(client: Any, res: Any) -> None:
    started = await res(client.sign_in.oauth2(providerId="acme", callbackURL="/dash"))
    assert started["redirect"] is True
    query = parse_qs(urlsplit(started["url"]).query)
    assert started["url"].startswith("https://idp.example.com/authorize?")
    assert query["client_id"] == ["acme-client"]

    await sign_up(res, client)
    linked = await res(client.oauth2.link(providerId="acme", callbackURL="/settings"))
    assert linked["redirect"] is True
    assert linked["url"].startswith("https://idp.example.com/authorize?")


# --- sso ---------------------------------------------------------------------------------


def _sso_register_body(**overrides: Any) -> dict[str, Any]:
    body: dict[str, Any] = {
        "providerId": "acme-sso",
        "issuer": "https://idp.example.com",
        "domain": "example.com",
        "oidcConfig": {
            "clientId": "sso-client",
            "clientSecret": "s3cr3t",
            "authorizationEndpoint": "https://idp.example.com/authorize",
            "tokenEndpoint": "https://idp.example.com/token",
            "jwksEndpoint": "https://idp.example.com/jwks",
            "skipDiscovery": True,
            "scopes": ["openid", "email"],
        },
    }
    body.update(overrides)
    return body


async def test_sso_provider_management_and_sign_in(client: Any, res: Any) -> None:
    await sign_up(res, client)
    registered = await res(client.sso.register(**_sso_register_body()))
    assert registered["issuer"] == "https://idp.example.com"

    providers = (await res(client.sso.providers()))["providers"]
    assert [p["providerId"] for p in providers] == ["acme-sso"]
    provider = await res(client.sso.get_provider(providerId="acme-sso"))
    assert provider["domain"] == "example.com"
    await res(client.sso.update_provider(providerId="acme-sso", domain="acme.dev"))
    provider = await res(client.sso.get_provider(providerId="acme-sso"))
    assert provider["domain"] == "acme.dev"

    deleted = await res(client.sso.delete_provider(providerId="acme-sso"))
    assert deleted == {"success": True}
    assert (await res(client.sso.providers()))["providers"] == []


async def test_sso_domain_verification(client: Any, res: Any, outbox: dict[str, Any]) -> None:
    await sign_up(res, client)
    await res(client.sso.register(**_sso_register_body()))

    requested = await res(client.sso.request_domain_verification(providerId="acme-sso"))
    token = requested["domainVerificationToken"]
    # publish the expected TXT record on the stub resolver, then verify (204, no body)
    outbox["dns_txt"]["_better-auth-token-acme-sso.example.com"] = [token]
    assert await res(client.sso.verify_domain(providerId="acme-sso")) is None

    provider = await res(client.sso.get_provider(providerId="acme-sso"))
    assert provider["domainVerified"] is True

    # sign-in is gated on the verified domain (domain_verification is enabled here)
    started = await res(client.sign_in.sso(providerId="acme-sso", callbackURL="/dash"))
    assert started["redirect"] is True
    assert started["url"].startswith("https://idp.example.com/authorize?")


# --- oauth-provider ----------------------------------------------------------------------

CB = "https://app.example.com/cb"


async def test_oauth_provider_dcr_consent_token_userinfo(
    client: Any, client_factory: Any, res: Any
) -> None:
    await sign_up(res, client)
    registered = await res(
        client.oauth2.register(
            redirect_uris=[CB], client_name="ci", token_endpoint_auth_method="client_secret_post"
        )
    )
    client_id, client_secret = registered["client_id"], registered["client_secret"]

    # DCR clients require PKCE (S256)
    verifier = "verifier-" + "a" * 40
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )

    # authorize: 302 to the app-hosted consent page carrying the signed query
    response = await res(
        client.oauth2.authorize(
            client_id=client_id,
            response_type="code",
            redirect_uri=CB,
            scope="openid",
            code_challenge=challenge,
            code_challenge_method="S256",
        )
    )
    assert response.status_code == 302
    location = response.headers["location"]
    assert location.startswith("https://app.example.com/consent?")

    # accept consent -> the redirect URL now carries the authorization code
    accepted = await res(client.oauth2.consent(accept=True, oauth_query=urlsplit(location).query))
    code = parse_qs(urlsplit(accepted["url"]).query)["code"][0]

    tokens = await res(
        client.oauth2.token(
            grant_type="authorization_code",
            code=code,
            redirect_uri=CB,
            client_id=client_id,
            client_secret=client_secret,
            code_verifier=verifier,
        )
    )
    assert tokens["token_type"] == "Bearer"

    # userinfo over the freshly minted bearer access token (separate, cookie-less client)
    resource = client_factory()
    resource.set_bearer(tokens["access_token"])
    userinfo = await res(resource.oauth2.userinfo())
    assert userinfo["sub"]

    active = await res(
        client.oauth2.introspect(
            token=tokens["access_token"], client_id=client_id, client_secret=client_secret
        )
    )
    assert active["active"] is True

    await res(
        client.oauth2.revoke(
            token=tokens["access_token"], client_id=client_id, client_secret=client_secret
        )
    )
    revoked = await res(
        client.oauth2.introspect(
            token=tokens["access_token"], client_id=client_id, client_secret=client_secret
        )
    )
    assert revoked["active"] is False


async def test_oauth_provider_client_crud_and_rotate(client: Any, res: Any) -> None:
    await sign_up(res, client)
    created = await res(client.oauth2.create_client(redirect_uris=[CB], client_name="app"))
    client_id = created["client_id"]

    fetched = await res(client.oauth2.get_client(client_id=client_id))
    assert fetched["client_id"] == client_id
    assert "client_secret" not in fetched
    assert [c["client_id"] for c in await res(client.oauth2.get_clients())] == [client_id]

    updated = await res(
        client.oauth2.update_client(client_id=client_id, update={"client_name": "renamed"})
    )
    assert updated["client_name"] == "renamed"

    # the one three-level namespace: oauth2.client.rotate_secret
    rotated = await res(client.oauth2.client.rotate_secret(client_id=client_id))
    assert rotated["client_secret"] != created["client_secret"]

    deleted = await res(client.oauth2.delete_client(client_id=client_id))
    assert deleted == {"success": True}
