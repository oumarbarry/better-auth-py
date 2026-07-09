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
import unicodedata
from urllib.parse import quote, unquote

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
