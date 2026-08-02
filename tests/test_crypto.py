import base64
import hashlib
import hmac
import json
import re
import time
from urllib.parse import unquote

import jwt as pyjwt
import pytest

from better_auth.crypto import (
    decode_email_verification_token,
    generate_id,
    generate_random_string,
    hash_password,
    sign_email_verification_token,
    sign_value,
    unsign_value,
    verify_password,
)


def test_hash_matches_better_auth_format():
    hashed = hash_password("hello-world")
    assert re.fullmatch(r"[0-9a-f]{32}:[0-9a-f]{128}", hashed)


def test_verify_password():
    hashed = hash_password("correct horse battery staple")
    assert verify_password(hashed, "correct horse battery staple")
    assert not verify_password(hashed, "wrong password")
    assert not verify_password("garbage", "whatever")


def test_verify_nfkc_normalization():
    # "ﬁ" (U+FB01) normalizes to "fi" under NFKC, like better-auth
    hashed = hash_password("ﬁsh-and-chips")
    assert verify_password(hashed, "fish-and-chips")


def test_sign_round_trip():
    secret = "s" * 32
    signed = sign_value(secret, "my-token")
    assert unsign_value(secret, signed) == "my-token"


def test_signed_value_shape():
    signed = unquote(sign_value("s" * 32, "tok"))
    value, _, signature = signed.rpartition(".")
    assert value == "tok"
    assert len(signature) == 44 and signature.endswith("=")


def test_unsign_rejects_tampering():
    secret = "s" * 32
    signed = sign_value(secret, "my-token")
    assert unsign_value(secret, signed.replace("my-token", "other-token")) is None
    assert unsign_value("x" * 32, signed) is None
    assert unsign_value(secret, "no-dot-here") is None
    assert unsign_value(secret, "value.badsig") is None


def test_generate_id_alphabet():
    token = generate_id()
    assert len(token) == 32
    assert re.fullmatch(r"[a-zA-Z0-9]{32}", token)


def test_generate_random_string_alphabet():
    value = generate_random_string(128)
    assert len(value) == 128
    assert re.fullmatch(r"[a-zA-Z0-9_\-]{128}", value)


# --- email-verification JWT: cross-runtime (jose/TS) interop -----------------------------


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(segment: str) -> bytes:
    return base64.urlsafe_b64decode(segment + "=" * (-len(segment) % 4))


def _build_jose_style_jwt(secret: str, payload: dict) -> str:
    """Hand-build an HS256 JWT exactly the way better-auth's TS `signJWT`
    (`crypto/jwt.ts`, built on `jose`'s `SignJWT`) does: header is the bare
    `{"alg":"HS256"}` object jose was given — jose does not inject a `typ`
    claim — compact (no-whitespace) JSON claims, base64url-without-padding
    segments, HMAC-SHA256 over `header.payload`. Built independently of PyJWT
    to prove `decode_email_verification_token` interoperates with a real
    cross-runtime token rather than merely round-tripping its own encoder.
    """
    header = _b64url(json.dumps({"alg": "HS256"}, separators=(",", ":")).encode())
    body = _b64url(json.dumps(payload, separators=(",", ":")).encode())
    signature = _b64url(
        hmac.new(secret.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest()
    )
    return f"{header}.{body}.{signature}"


def test_decode_accepts_a_jose_built_token():
    """A token that was never touched by PyJWT — built by hand the way TS's
    `signJWT` builds it — decodes with the exact claims, proving wire format
    interop with a real better-auth (TypeScript) deployment sharing the secret.
    """
    secret = "cross-runtime-interop-secret-0123456789ab"
    now = int(time.time())
    payload = {"email": "ada@example.com", "iat": now, "exp": now + 3600}
    token = _build_jose_style_jwt(secret, payload)

    decoded = decode_email_verification_token(secret, token)

    assert decoded == payload


def test_decode_rejects_a_jose_built_token_with_wrong_secret():
    secret = "cross-runtime-interop-secret-0123456789ab"
    now = int(time.time())
    token = _build_jose_style_jwt(
        secret, {"email": "ada@example.com", "iat": now, "exp": now + 3600}
    )

    with pytest.raises(pyjwt.InvalidTokenError):
        decode_email_verification_token("a-completely-different-secret-value", token)


def test_decode_rejects_an_expired_jose_built_token():
    secret = "cross-runtime-interop-secret-0123456789ab"
    now = int(time.time())
    token = _build_jose_style_jwt(
        secret, {"email": "ada@example.com", "iat": now - 7200, "exp": now - 3600}
    )

    with pytest.raises(pyjwt.ExpiredSignatureError):
        decode_email_verification_token(secret, token)


def test_sign_produces_a_standard_hs256_jwt_with_ts_payload_keys():
    """Independently re-derive the HMAC (not via PyJWT) over the token our own
    `sign_email_verification_token` produces, to prove it is a genuine,
    standard-format HS256 JWT — not just something our own decoder happens to
    accept — with exactly the payload keys TS's `createEmailVerificationToken`
    uses: `email`, `updateTo` (when given), `iat`, `exp`.
    """
    secret = "cross-runtime-interop-secret-0123456789ab"
    token = sign_email_verification_token(secret, "Ada@Example.COM", expires_in=1800)
    header_b64, payload_b64, signature_b64 = token.split(".")

    header = json.loads(_b64url_decode(header_b64))
    payload = json.loads(_b64url_decode(payload_b64))

    assert header["alg"] == "HS256"
    assert set(payload) == {"email", "iat", "exp"}
    assert payload["email"] == "ada@example.com"  # lowercased, like TS
    assert payload["exp"] == payload["iat"] + 1800

    expected_signature = _b64url(
        hmac.new(secret.encode(), f"{header_b64}.{payload_b64}".encode(), hashlib.sha256).digest()
    )
    assert signature_b64 == expected_signature


def test_sign_includes_update_to_and_extra_payload_when_given():
    secret = "cross-runtime-interop-secret-0123456789ab"
    token = sign_email_verification_token(
        secret,
        "ada@example.com",
        update_to="grace@example.com",
        extra_payload={"requestType": "change-email-verification"},
    )
    payload = decode_email_verification_token(secret, token)
    assert payload["email"] == "ada@example.com"
    assert payload["updateTo"] == "grace@example.com"
    assert payload["requestType"] == "change-email-verification"
