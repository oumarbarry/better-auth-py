"""Hashing, tokens and cookie signing — exact better-auth formats.

Password hashes, IDs, tokens and signed cookie values match better-auth's TypeScript
implementation byte-for-byte, so a Python app can share a database (and existing
credentials/sessions) with a TypeScript better-auth app.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import time
import unicodedata
from typing import Any
from urllib.parse import quote, unquote

import jwt

# better-auth scrypt config (@better-auth/utils/password)
_SCRYPT_N = 16384
_SCRYPT_R = 16
_SCRYPT_P = 1
_SCRYPT_DKLEN = 64
_SCRYPT_MAXMEM = 128 * _SCRYPT_N * _SCRYPT_R * 2  # 64 MiB

# better-auth alphabets: generateId (DB ids, session tokens) vs generateRandomString
# (OAuth state, PKCE code verifier, verification tokens)
_ID_ALPHABET = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_RANDOM_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ-_"


def generate_id(size: int = 32) -> str:
    return "".join(secrets.choice(_ID_ALPHABET) for _ in range(size))


def generate_random_string(size: int = 32) -> str:
    return "".join(secrets.choice(_RANDOM_ALPHABET) for _ in range(size))


def _scrypt(password: str, salt_hex: str) -> bytes:
    # better-auth passes the hex STRING as salt (its utf-8 bytes), not the raw bytes
    return hashlib.scrypt(
        unicodedata.normalize("NFKC", password).encode(),
        salt=salt_hex.encode(),
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
        maxmem=_SCRYPT_MAXMEM,
    )


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    return f"{salt}:{_scrypt(password, salt).hex()}"


def verify_password(stored: str, password: str) -> bool:
    salt, _, key_hex = stored.partition(":")
    if not salt or not key_hex:
        return False
    return hmac.compare_digest(_scrypt(password, salt).hex(), key_hex)


_DUMMY_HASH: str | None = None


def dummy_verify(password: str) -> None:
    """Burn the same scrypt cost as a real verification (timing equalization)."""
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password("better-auth-timing-equalization")
    verify_password(_DUMMY_HASH, password)


def _signature(secret: str, value: str) -> str:
    digest = hmac.new(secret.encode(), value.encode(), hashlib.sha256).digest()
    return base64.b64encode(digest).decode()  # standard base64 WITH padding (44 chars)


def sign_hmac_b64url(secret: str, value: str) -> str:
    """HMAC-SHA256 as base64url WITHOUT padding — better-auth's ``base64urlnopad``
    signature scheme used by the compact ``session_data`` cookie cache."""
    digest = hmac.new(secret.encode(), value.encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def b64url_encode_nopad(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode_nopad(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def sign_value(secret: str, value: str) -> str:
    """better-auth signed-cookie format: encodeURIComponent(`${value}.${base64(hmac)}`)."""
    return quote(f"{value}.{_signature(secret, value)}", safe="")


def unsign_value(secret: str, signed: str) -> str | None:
    decoded = unquote(signed)
    value, _, signature = decoded.rpartition(".")
    if not value or len(signature) != 44 or not signature.endswith("="):
        return None
    if not hmac.compare_digest(signature, _signature(secret, value)):
        return None
    return value


def sign_email_verification_token(
    secret: str,
    email: str,
    update_to: str | None = None,
    expires_in: int = 3600,
    extra_payload: dict[str, Any] | None = None,
) -> str:
    """HS256 JWT matching better-auth's ``signJWT``/``createEmailVerificationToken``
    (``crypto/jwt.ts``, ``api/routes/email-verification.ts:15``): payload
    ``{email, updateTo?, ...extraPayload}`` plus ``iat``/``exp`` claims, signed with
    the auth secret. No ``aud``/``iss`` — TS's ``signJWT`` doesn't set them either.
    """
    payload: dict[str, Any] = {"email": email.lower()}
    if update_to:
        payload["updateTo"] = update_to.lower()
    if extra_payload:
        payload.update(extra_payload)
    now = int(time.time())
    payload["iat"] = now
    payload["exp"] = now + expires_in
    return jwt.encode(payload, secret, algorithm="HS256")


def decode_email_verification_token(secret: str, token: str) -> dict[str, Any]:
    """Verify + decode an email-verification JWT (HS256 only, matching TS's
    ``jwtVerify(token, secret, {algorithms:["HS256"]})``). Raises
    ``jwt.ExpiredSignatureError`` / ``jwt.InvalidTokenError`` on failure — callers
    map those to ``TOKEN_EXPIRED`` / ``INVALID_TOKEN``.
    """
    return jwt.decode(token, secret, algorithms=["HS256"])
