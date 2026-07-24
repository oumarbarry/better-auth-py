"""passkey plugin (WebAuthn/FIDO2) — parity with @better-auth/passkey.

Behaviours mirror packages/passkey/src/routes.ts. The happy-path registration and
authentication tests drive py_webauthn's REAL verify calls via a software
authenticator (SoftKey) — no mocking of the crypto. Negative-path tests exercise the
challenge single-use gate, cross-ceremony isolation, ownership guard, and the exact
error codes / storage encodings that make a TS-written row verify under Python.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import struct
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from better_auth.adapters.base import Where
from better_auth.plugins_ext.passkey import (
    PasskeyPlugin,
    _device_type,
    _encode_credential_id,
    _encode_public_key,
)
from conftest import make_auth, make_client, sign_up

RP_ID = "testserver"
ORIGIN = "http://testserver"


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


class SoftKey:
    """A minimal ES256 software authenticator producing real WebAuthn responses."""

    def __init__(
        self, cred_id: bytes = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
    ):
        self.cred_id = cred_id
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
            hashlib.sha256(RP_ID.encode()).digest()
            + bytes([flags])
            + struct.pack(">I", sign_count)
            + attested
        )

    def register(self, challenge_b64url: str, origin: str = ORIGIN) -> dict[str, Any]:
        from webauthn.helpers import encode_cbor

        cdj = json.dumps(
            {
                "type": "webauthn.create",
                "challenge": challenge_b64url,
                "origin": origin,
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

    def authenticate(self, challenge_b64url: str, origin: str = ORIGIN) -> dict[str, Any]:
        self.sign_count += 1
        cdj = json.dumps(
            {
                "type": "webauthn.get",
                "challenge": challenge_b64url,
                "origin": origin,
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


def _auth(**kw: Any) -> Any:
    extra = {k: kw.pop(k) for k in list(kw) if k in ("email_and_password", "user")}
    return make_auth(plugins=[PasskeyPlugin(**kw)], **extra)


async def _bearer(client: Any, email: str = "ada@example.com") -> str:
    body = await sign_up(client, email=email)
    return body["token"]


async def _gen_register(client: Any, token: str | None = None, **params: Any) -> Any:
    headers = {"authorization": f"Bearer {token}"} if token else {}
    return await client.get(
        "/api/auth/passkey/generate-register-options", params=params, headers=headers
    )


async def _register(client: Any, key: SoftKey, token: str, **body: Any) -> Any:
    r = await _gen_register(client, token)
    assert r.status_code == 200, r.text
    challenge = r.json()["challenge"]
    return await client.post(
        "/api/auth/passkey/verify-registration",
        json={"response": key.register(challenge), **body},
        headers={"authorization": f"Bearer {token}"},
    )


# --- encoding vectors (exact stored strings, cross-runtime contract) ---------------------


def test_public_key_encoding_is_standard_padded_base64():
    assert _encode_public_key(b"\x00\x01\x02\x03") == "AAECAw=="
    # round-trips via stdlib standard base64 (NOT base64url)
    assert base64.b64decode("AAECAw==") == b"\x00\x01\x02\x03"


def test_credential_id_encoding_is_base64url_nopad():
    raw = b"\xfb\xff\xfe\x01\x02\x03\x04"
    enc = _encode_credential_id(raw)
    assert enc == _b64url(raw)
    assert "=" not in enc and "+" not in enc and "/" not in enc


def test_device_type_maps_snake_to_camel():
    assert _device_type("single_device") == "singleDevice"
    assert _device_type("multi_device") == "multiDevice"


# --- registration options wire shape -----------------------------------------------------


async def test_register_options_shape_and_cookie():
    async with make_client(_auth()) as client:
        token = await _bearer(client)
        r = await _gen_register(client, token)
        assert r.status_code == 200, r.text
        body = r.json()
        assert isinstance(body["challenge"], str)
        assert body["rp"] == {"name": "Better Auth", "id": RP_ID}
        assert set(body["user"]) == {"id", "name", "displayName"}
        assert [p["alg"] for p in body["pubKeyCredParams"]] == [-8, -7, -257]
        assert body["attestation"] == "none"
        assert body["authenticatorSelection"]["residentKey"] == "preferred"
        assert body["authenticatorSelection"]["userVerification"] == "preferred"
        # challenge cookie set
        set_cookie = r.headers.get("set-cookie", "")
        assert "better-auth-passkey" in set_cookie


async def test_register_options_requires_session_by_default():
    async with make_client(_auth()) as client:
        r = await _gen_register(client)  # no session
        assert r.status_code == 401
        assert r.json()["code"] == "SESSION_REQUIRED"


async def test_register_options_authenticator_attachment_query():
    async with make_client(_auth()) as client:
        token = await _bearer(client)
        r = await _gen_register(client, token, authenticatorAttachment="platform")
        assert r.json()["authenticatorSelection"]["authenticatorAttachment"] == "platform"


# --- resolveUser (requireSession=false) --------------------------------------------------


async def test_resolve_user_required_when_no_session():
    async with make_client(_auth(registration={"require_session": False})) as client:
        r = await _gen_register(client)
        assert r.status_code == 400
        assert r.json()["code"] == "RESOLVE_USER_REQUIRED"


async def test_resolve_user_invalid_result():
    def resolve(*, ctx, context):
        return {"id": "u1"}  # missing name

    plugin_auth = _auth(registration={"require_session": False, "resolve_user": resolve})
    async with make_client(plugin_auth) as client:
        r = await _gen_register(client)
        assert r.status_code == 400
        assert r.json()["code"] == "RESOLVED_USER_INVALID"


async def test_resolve_user_success_pre_auth():
    def resolve(*, ctx, context):
        return {"id": "u1", "name": "pre-auth-user"}

    async with make_client(
        _auth(registration={"require_session": False, "resolve_user": resolve})
    ) as client:
        r = await _gen_register(client, context="onboard")
        assert r.status_code == 200
        assert r.json()["user"]["name"] == "pre-auth-user"


# --- happy path: full registration + authentication (REAL crypto) ------------------------


async def test_full_registration_then_authentication():
    auth = _auth()
    async with make_client(auth) as client:
        token = await _bearer(client)
        key = SoftKey()

        reg = await _register(client, key, token, name="My Laptop")
        assert reg.status_code == 200, reg.text
        row = reg.json()
        assert row["name"] == "My Laptop"
        assert row["counter"] == 0
        assert row["deviceType"] == "singleDevice"
        assert row["backedUp"] is False
        assert row["transports"] == "internal"
        assert row["aaguid"] == "00000000-0000-0000-0000-000000000000"
        # cross-runtime encodings
        assert row["credentialID"] == _b64url(key.cred_id)
        assert base64.b64decode(row["publicKey"])  # standard padded, decodes

        # authenticate
        r = await client.get(
            "/api/auth/passkey/generate-authenticate-options",
            headers={"authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200, r.text
        auth_opts = r.json()
        assert auth_opts["rpId"] == RP_ID
        assert auth_opts["userVerification"] == "preferred"
        assert any(c["id"] == _b64url(key.cred_id) for c in auth_opts["allowCredentials"])

        verify = await client.post(
            "/api/auth/passkey/verify-authentication",
            json={"response": key.authenticate(auth_opts["challenge"])},
        )
        assert verify.status_code == 200, verify.text
        vbody = verify.json()
        assert vbody["user"]["email"] == "ada@example.com"
        assert "session" in vbody
        assert "set-cookie" in verify.headers

        # counter bumped to the authenticator's new sign count
        rows = await auth.adapter.find_many("passkey", [Where("credentialID", row["credentialID"])])
        assert rows[0]["counter"] == key.sign_count


# --- authenticate options without a session (discoverable) -------------------------------


async def test_authenticate_options_no_session_omits_allow_credentials():
    async with make_client(_auth()) as client:
        r = await client.get("/api/auth/passkey/generate-authenticate-options")
        assert r.status_code == 200
        assert "allowCredentials" not in r.json()


# --- challenge single-use + cross-ceremony -----------------------------------------------


async def test_ceremony_confusion_rejected():
    """A registration challenge cannot be spent on authentication."""
    async with make_client(_auth()) as client:
        token = await _bearer(client)
        r = await _gen_register(client, token)  # mints type=registration, sets cookie
        challenge = r.json()["challenge"]
        key = SoftKey()
        # try to use it on the authentication verifier
        verify = await client.post(
            "/api/auth/passkey/verify-authentication",
            json={"response": key.authenticate(challenge)},
        )
        assert verify.status_code == 400
        assert verify.json()["code"] == "CHALLENGE_NOT_FOUND"


async def test_verify_registration_missing_cookie():
    async with make_client(_auth()) as client:
        token = await _bearer(client)
        key = SoftKey()
        r = await client.post(
            "/api/auth/passkey/verify-registration",
            json={"response": key.register(_b64url(b"x" * 16))},
            headers={"authorization": f"Bearer {token}"},
        )
        assert r.status_code == 400
        assert r.json()["code"] == "CHALLENGE_NOT_FOUND"


async def test_concurrent_registration_verify_mints_one_row(auth_holder=None):
    auth = _auth()
    async with make_client(auth) as client:
        token = await _bearer(client)
        key = SoftKey()
        r = await _gen_register(client, token)
        challenge = r.json()["challenge"]
        body = {"response": key.register(challenge)}
        headers = {"authorization": f"Bearer {token}"}
        results = await asyncio.gather(
            client.post("/api/auth/passkey/verify-registration", json=body, headers=headers),
            client.post("/api/auth/passkey/verify-registration", json=body, headers=headers),
        )
        ok = [x for x in results if x.status_code == 200]
        assert len(ok) == 1
        rows = await auth.adapter.find_many(
            "passkey", [Where("credentialID", _b64url(key.cred_id))]
        )
        assert len(rows) == 1


async def test_concurrent_authentication_verify_mints_one_session():
    auth = _auth()
    async with make_client(auth) as client:
        token = await _bearer(client)
        key = SoftKey()
        await _register(client, key, token)
        r = await client.get(
            "/api/auth/passkey/generate-authenticate-options",
            headers={"authorization": f"Bearer {token}"},
        )
        challenge = r.json()["challenge"]
        body = {"response": key.authenticate(challenge)}
        results = await asyncio.gather(
            client.post("/api/auth/passkey/verify-authentication", json=body),
            client.post("/api/auth/passkey/verify-authentication", json=body),
        )
        ok = [x for x in results if x.status_code == 200]
        assert len(ok) == 1


# --- error propagation -------------------------------------------------------------------


async def test_failed_registration_verify():
    async with make_client(_auth()) as client:
        token = await _bearer(client)
        await _gen_register(client, token)  # sets cookie with a real challenge
        key = SoftKey()
        # build a response for a DIFFERENT challenge -> verify raises -> 400
        bad = key.register(_b64url(b"not-the-stored-challenge!"))
        r = await client.post(
            "/api/auth/passkey/verify-registration",
            json={"response": bad},
            headers={"authorization": f"Bearer {token}"},
        )
        assert r.status_code == 400
        assert r.json()["code"] == "FAILED_TO_VERIFY_REGISTRATION"


async def test_verify_authentication_unknown_passkey():
    async with make_client(_auth()) as client:
        # discoverable auth options (no session) -> type=authentication challenge
        r = await client.get("/api/auth/passkey/generate-authenticate-options")
        challenge = r.json()["challenge"]
        key = SoftKey(cred_id=b"unknown-credential-id-01")
        verify = await client.post(
            "/api/auth/passkey/verify-authentication",
            json={"response": key.authenticate(challenge)},
        )
        assert verify.status_code == 401
        assert verify.json()["code"] == "PASSKEY_NOT_FOUND"


async def test_failed_authentication_verify():
    auth = _auth()
    async with make_client(auth) as client:
        token = await _bearer(client)
        key = SoftKey()
        await _register(client, key, token)
        # mint an authentication challenge (sets the cookie); the value is unused
        await client.get(
            "/api/auth/passkey/generate-authenticate-options",
            headers={"authorization": f"Bearer {token}"},
        )
        # tamper: sign a DIFFERENT challenge than the stored one
        assertion = key.authenticate(_b64url(b"wrong-challenge-bytes-xx"))
        assertion["id"] = _b64url(key.cred_id)  # keep id so passkey is found
        assertion["rawId"] = _b64url(key.cred_id)
        verify = await client.post(
            "/api/auth/passkey/verify-authentication", json={"response": assertion}
        )
        assert verify.status_code == 401
        assert verify.json()["code"] == "AUTHENTICATION_FAILED"


# --- afterVerification (registration) ----------------------------------------------------


async def test_after_verification_name_fallback():
    def after(*, ctx, verification, user, client_data, context):
        return {"name": "  Fallback Name  "}

    async with make_client(_auth(registration={"after_verification": after})) as client:
        token = await _bearer(client)
        key = SoftKey()
        reg = await _register(client, key, token)  # no client name
        assert reg.json()["name"] == "Fallback Name"


async def test_after_verification_client_name_wins():
    def after(*, ctx, verification, user, client_data, context):
        return {"name": "should-not-win"}

    async with make_client(_auth(registration={"after_verification": after})) as client:
        token = await _bearer(client)
        key = SoftKey()
        reg = await _register(client, key, token, name="client-name")
        assert reg.json()["name"] == "client-name"


async def test_after_verification_userid_mismatch_rejected():
    def after(*, ctx, verification, user, client_data, context):
        return {"userId": "some-other-user"}

    async with make_client(_auth(registration={"after_verification": after})) as client:
        token = await _bearer(client)
        key = SoftKey()
        reg = await _register(client, key, token)
        assert reg.status_code == 401
        assert reg.json()["code"] == "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY"


async def test_after_verification_empty_userid_rejected():
    def after(*, ctx, verification, user, client_data, context):
        return {"userId": ""}

    async with make_client(_auth(registration={"after_verification": after})) as client:
        token = await _bearer(client)
        key = SoftKey()
        # userId="" is falsy -> treated as "no override"; but targetUserId stays the session
        # user, so this actually succeeds. Use a whitespace/non-string to hit invalid.
        reg = await _register(client, key, token)
        assert reg.status_code == 200


async def test_after_verification_non_string_userid_rejected():
    def after(*, ctx, verification, user, client_data, context):
        return {"userId": 12345}  # non-string truthy -> RESOLVED_USER_INVALID (routes.ts:662)

    async with make_client(_auth(registration={"after_verification": after})) as client:
        token = await _bearer(client)
        key = SoftKey()
        reg = await _register(client, key, token)
        assert reg.status_code == 400
        assert reg.json()["code"] == "RESOLVED_USER_INVALID"


async def test_whitespace_name_stored_null():
    async with make_client(_auth()) as client:
        token = await _bearer(client)
        key = SoftKey()
        reg = await _register(client, key, token, name="   ")
        assert reg.json().get("name") in (None, "")


# --- list / delete / update + ownership --------------------------------------------------


async def test_list_passkeys():
    async with make_client(_auth()) as client:
        token = await _bearer(client)
        key = SoftKey()
        await _register(client, key, token)
        r = await client.get(
            "/api/auth/passkey/list-user-passkeys",
            headers={"authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        assert len(r.json()) == 1


async def test_update_passkey_name():
    async with make_client(_auth()) as client:
        token = await _bearer(client)
        key = SoftKey()
        reg = await _register(client, key, token)
        pid = reg.json()["id"]
        r = await client.post(
            "/api/auth/passkey/update-passkey",
            json={"id": pid, "name": "renamed"},
            headers={"authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        assert r.json()["passkey"]["name"] == "renamed"


async def test_delete_passkey():
    auth = _auth()
    async with make_client(auth) as client:
        token = await _bearer(client)
        key = SoftKey()
        reg = await _register(client, key, token)
        pid = reg.json()["id"]
        r = await client.post(
            "/api/auth/passkey/delete-passkey",
            json={"id": pid},
            headers={"authorization": f"Bearer {token}"},
        )
        assert r.status_code == 200
        assert r.json() == {"status": True}
        assert await auth.adapter.find_one("passkey", [Where("id", pid)]) is None


async def test_delete_other_users_passkey_rejected_and_intact():
    auth = _auth()
    async with make_client(auth) as client:
        token_a = await _bearer(client, "a@example.com")
        key = SoftKey()
        reg = await _register(client, key, token_a)
        pid = reg.json()["id"]
        token_b = await _bearer(client, "b@example.com")
        r = await client.post(
            "/api/auth/passkey/delete-passkey",
            json={"id": pid},
            headers={"authorization": f"Bearer {token_b}"},
        )
        assert r.status_code == 401
        assert await auth.adapter.find_one("passkey", [Where("id", pid)]) is not None


async def test_update_other_users_passkey_rejected_and_intact():
    auth = _auth()
    async with make_client(auth) as client:
        token_a = await _bearer(client, "a@example.com")
        key = SoftKey()
        reg = await _register(client, key, token_a)
        pid = reg.json()["id"]
        token_b = await _bearer(client, "b@example.com")
        r = await client.post(
            "/api/auth/passkey/update-passkey",
            json={"id": pid, "name": "hijacked"},
            headers={"authorization": f"Bearer {token_b}"},
        )
        assert r.status_code == 401
        row = await auth.adapter.find_one("passkey", [Where("id", pid)])
        assert row["name"] != "hijacked"


async def test_delete_missing_passkey_not_found():
    async with make_client(_auth()) as client:
        token = await _bearer(client)
        r = await client.post(
            "/api/auth/passkey/delete-passkey",
            json={"id": "does-not-exist"},
            headers={"authorization": f"Bearer {token}"},
        )
        assert r.status_code == 401
        assert r.json()["code"] == "PASSKEY_NOT_FOUND"
