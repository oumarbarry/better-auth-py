"""Hashing, tokens and cookie signing — exact better-auth formats.

Password hashes, IDs, tokens and signed cookie values match better-auth's TypeScript
implementation byte-for-byte, so a Python app can share a database (and existing
credentials/sessions) with a TypeScript better-auth app.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import re
import secrets
import time
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import quote, unquote, urlencode

import jwt
from nacl import bindings as sodium

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


def generate_random_string(size: int = 32, alphabet: str | None = None) -> str:
    """Secure random string. Default alphabet matches TS ``generateRandomString``
    (``createRandomStringGenerator("a-z","0-9","A-Z","-_")``); pass ``alphabet`` for
    a custom charset (e.g. ``"0123456789"`` for digit-only OTPs)."""
    return "".join(secrets.choice(alphabet or _RANDOM_ALPHABET) for _ in range(size))


def generate_otp(length: int) -> str:
    """Digit-only OTP (TS ``generateOTP`` = ``generateRandomString(size, "0-9")``,
    phone-number/routes.ts:902)."""
    return generate_random_string(length, "0123456789")


def default_key_hasher(token: str) -> str:
    """base64url-no-pad of SHA-256(utf-8 token) — byte-for-byte with TS
    ``defaultKeyHasher`` (magic-link/utils.ts, one-time-token/utils.ts), used when a
    plugin stores tokens with ``storeToken: "hashed"``."""
    return b64url_encode_nopad(hashlib.sha256(token.encode()).digest())


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


ENVELOPE_PREFIX = "$ba$"  # TS crypto/index.ts formatEnvelope; key-rotation envelope "$ba$<v>$<hex>"
_HEX_RE = re.compile(r"[0-9a-f]+")

#: TS ``utils/constants.ts`` — the built-in fallback secret; never adopted as a legacy key.
DEFAULT_SECRET = "better-auth-secret-12345678901234567890"


@dataclass(frozen=True)
class SecretConfig:
    """Versioned secret material for key rotation — TS ``core/types/secret.ts`` ``SecretConfig``.

    ``keys`` maps a version number to its secret; ``current_version`` is minted into new
    ``$ba$<v>$<hex>`` envelopes; ``legacy_secret`` decrypts pre-rotation bare-hex payloads
    (``BETTER_AUTH_SECRET`` unless it is the built-in ``DEFAULT_SECRET``)."""

    keys: dict[int, str] = field(default_factory=dict)
    current_version: int = 0
    legacy_secret: str | None = None


# A resolved secret is either a plain string (bare-hex path) or a versioned SecretConfig.
SecretLike = str | SecretConfig


def _symmetric_key(secret: str) -> bytes:
    return hashlib.sha256(secret.encode()).digest()


def _raw_encrypt(secret: str, data: str) -> str:
    """XChaCha20-Poly1305 encrypt with ``SHA-256(secret)`` → bare lowercase hex of
    ``nonce(24) || ciphertext || tag(16)`` (TS ``rawEncrypt``; libsodium combined == noble
    sealed output, 24-byte random ``managedNonce`` prepended)."""
    key = _symmetric_key(secret)
    nonce = secrets.token_bytes(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)  # 24
    combined = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(data.encode(), b"", nonce, key)
    return (nonce + combined).hex()


def symmetric_encrypt(secret: SecretLike, data: str) -> str:
    """Encrypt ``data`` — byte-parity with TS ``symmetricEncrypt`` (``crypto/index.ts``).

    A plain ``str`` key produces bare hex (unchanged, byte-identical to prior vectors). A
    :class:`SecretConfig` encrypts with ``keys[current_version]`` and wraps the result in a
    ``$ba$<current_version>$<hex>`` envelope."""
    if isinstance(secret, SecretConfig):
        key = secret.keys.get(secret.current_version)
        if key is None:
            raise ValueError(f"Secret version {secret.current_version} not found in keys")
        return format_envelope(secret.current_version, _raw_encrypt(key, data))
    return _raw_encrypt(secret, data)


def symmetric_decrypt(
    secret: SecretLike, payload: str, *, keys: dict[int, str] | None = None
) -> str:
    """Decrypt an XChaCha20 payload — TS ``symmetricDecrypt`` (``crypto/index.ts``).

    With a :class:`SecretConfig`: a ``$ba$<v>$<hex>`` envelope resolves to ``keys[v]`` (missing
    version → ``ValueError``, the key was retired); a bare-hex payload falls back to
    ``legacy_secret`` (absent → ``ValueError``). With a plain ``str``: bare hex decrypts
    directly; the ``keys`` kwarg still resolves an envelope for callers without a SecretConfig.
    Tamper / wrong key raises ``nacl.exceptions.CryptoError``."""
    if isinstance(secret, SecretConfig):
        envelope = parse_envelope(payload)
        if envelope is not None:
            version, ciphertext = envelope
            key = secret.keys.get(version)
            if key is None:
                raise ValueError(
                    f"Secret version {version} not found in keys (key may have been retired)"
                )
            return _raw_decrypt(key, ciphertext)
        if secret.legacy_secret:
            return _raw_decrypt(secret.legacy_secret, payload)
        raise ValueError(
            "Cannot decrypt legacy bare-hex payload: no legacy secret available. "
            "Set BETTER_AUTH_SECRET for backwards compatibility."
        )
    envelope = parse_envelope(payload)
    if envelope is not None:
        version, ciphertext = envelope
        if not keys or version not in keys:
            raise ValueError(f"Cannot decrypt envelope: secret version {version} not in keys")
        return _raw_decrypt(keys[version], ciphertext)
    return _raw_decrypt(secret, payload)


def _normalize_secret_entry(entry: Any) -> tuple[int, str]:
    if isinstance(entry, Mapping):
        return int(entry["version"]), entry["value"]
    version, value = entry
    return int(version), value


def parse_secrets_env(env_value: str | None) -> list[tuple[int, str]] | None:
    """Parse ``BETTER_AUTH_SECRETS`` (``"<version>:<secret>,<version>:<secret>"``) into
    ``[(version, value), …]`` — TS ``context/secret-utils.ts`` ``parseSecretsEnv``. Returns
    ``None`` when unset/empty; raises ``ValueError`` on a malformed entry."""
    if not env_value:
        return None
    out: list[tuple[int, str]] = []
    for raw in env_value.split(","):
        item = raw.strip()
        colon = item.find(":")
        if colon == -1:
            raise ValueError(
                f'Invalid BETTER_AUTH_SECRETS entry: "{item}". '
                'Expected format: "<version>:<secret>"'
            )
        version_str = item[:colon]
        try:
            version = int(version_str)
        except ValueError:
            version = -1
        if version < 0 or str(version) != version_str.strip():
            raise ValueError(
                f'Invalid version in BETTER_AUTH_SECRETS: "{version_str}". '
                "Version must be a non-negative integer."
            )
        value = item[colon + 1 :].strip()
        if not value:
            raise ValueError(f"Empty secret value for version {version} in BETTER_AUTH_SECRETS.")
        out.append((version, value))
    return out


def resolve_secret_config(
    secret: str,
    secrets: Sequence[tuple[int, str] | Mapping[str, Any]] | None = None,
) -> SecretLike:
    """Resolve the effective secret — TS ``context/create-context.ts`` + ``buildSecretConfig``.

    No ``secrets`` → the plain ``secret`` string (bare-hex path). With ``secrets`` (each
    ``(version, value)`` or ``{"version", "value"}``): a :class:`SecretConfig` whose
    ``current_version`` is the FIRST entry, and whose ``legacy_secret`` is ``secret`` unless it
    is the built-in :data:`DEFAULT_SECRET`. Raises ``ValueError`` on an empty array, a
    negative/non-integer/duplicate version, or an empty value (TS ``validateSecretsArray``).

    # ponytail: entropy/length WARNINGS from validateSecretsArray are logging-only, dropped —
    # add if a warn channel is wired for the SDK.
    """
    if secrets is None:
        return secret
    entries = [_normalize_secret_entry(e) for e in secrets]
    if not entries:
        raise ValueError("`secrets` array must contain at least one entry.")
    seen: set[int] = set()
    for version, value in entries:
        if version < 0:
            raise ValueError(
                f"Invalid version {version} in `secrets`. Version must be a non-negative integer."
            )
        if not value:
            raise ValueError(f"Empty secret value for version {version} in `secrets`.")
        if version in seen:
            raise ValueError(
                f"Duplicate version {version} in `secrets`. Each version must be unique."
            )
        seen.add(version)
    legacy = secret if secret and secret != DEFAULT_SECRET else None
    return SecretConfig(
        keys={v: val for v, val in entries},
        current_version=entries[0][0],
        legacy_secret=legacy,
    )


def _raw_decrypt(secret: str, hex_ct: str) -> str:
    raw = bytes.fromhex(hex_ct)
    nonce, combined = raw[:24], raw[24:]
    return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
        combined, b"", nonce, _symmetric_key(secret)
    ).decode()


def parse_envelope(data: str) -> tuple[int, str] | None:
    """``"$ba$<version>$<ciphertext>"`` → ``(version, ciphertext)``; ``None`` if not an envelope
    (TS ``parseEnvelope``)."""
    if not data.startswith(ENVELOPE_PREFIX):
        return None
    version_str, sep, ciphertext = data[len(ENVELOPE_PREFIX) :].partition("$")
    if not sep:
        return None
    try:
        version = int(version_str)
    except ValueError:
        return None
    return (version, ciphertext) if version >= 0 else None


def format_envelope(version: int, ciphertext: str) -> str:
    return f"{ENVELOPE_PREFIX}{version}${ciphertext}"


def is_likely_encrypted(token: str) -> bool:
    """Does ``token`` look like a ``symmetric_encrypt`` output — a ``$ba$…`` envelope or bare
    lowercase hex of at least a nonce+tag (40 bytes)? Lets ``encrypt_oauth_tokens`` be flipped on
    without mangling plaintext rows written before the flag.

    # ponytail: hex+length heuristic — a plaintext token that is itself 80+ hex chars is a false
    # positive. A per-column "encrypted" flag would be exact; add it if that ever bites.
    """
    if parse_envelope(token) is not None:
        return True
    return len(token) >= 80 and len(token) % 2 == 0 and bool(_HEX_RE.fullmatch(token))


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


# --- TOTP / HOTP (@better-auth/utils createOTP; RFC 4226 / 6238) ---------------------------


def generate_hotp(secret: str, counter: int, digits: int = 6, hash: str = "SHA-1") -> str:
    """RFC-4226 HOTP, byte-parity with ``@better-auth/utils`` ``createOTP().hotp``. The HMAC key is
    the UTF-8 bytes of the ``secret`` STRING (no base32 decode); ``counter`` is 8-byte big-endian;
    default hash SHA-1. ``digits`` is 1-8 (default 6)."""
    if digits < 1 or digits > 8:
        raise ValueError("Digits must be between 1 and 8")
    algo = hash.replace("-", "").lower()
    mac = hmac.new(secret.encode(), counter.to_bytes(8, "big"), algo).digest()
    offset = mac[-1] & 0x0F
    truncated = (
        (mac[offset] & 0x7F) << 24
        | (mac[offset + 1] & 0xFF) << 16
        | (mac[offset + 2] & 0xFF) << 8
        | (mac[offset + 3] & 0xFF)
    )
    return str(truncated % 10**digits).zfill(digits)


def generate_totp(
    secret: str, *, digits: int = 6, period: int = 30, now: float | None = None
) -> str:
    """RFC-6238 TOTP. ``now`` is UNIX seconds (injectable); counter = ``floor(now/period)``,
    matching TS ``createOTP().totp`` (``floor(Date.now()/(period*1000))``)."""
    seconds = time.time() if now is None else now
    return generate_hotp(secret, math.floor(seconds / period), digits=digits)


def verify_totp(
    otp: str,
    *,
    secret: str,
    digits: int = 6,
    period: int = 30,
    window: int = 1,
    now: float | None = None,
) -> bool:
    """Check ``otp`` against counters ``floor(now/period) ± window`` with a constant-time compare
    (TS ``verifyTOTP``, default window 1). The full window is always evaluated — no early exit."""
    seconds = time.time() if now is None else now
    counter = math.floor(seconds / period)
    matched = False
    for i in range(-window, window + 1):
        candidate = generate_hotp(secret, counter + i, digits=digits)
        matched = _constant_time_equal(otp, candidate) or matched
    return matched


def _constant_time_equal(a: str, b: str) -> bool:
    """Length-then-content xor accumulate (TS ``constantTimeEqualOTP``): no early return, so timing
    is independent of the mismatch position. Tolerates any input length/charset (unlike
    ``hmac.compare_digest``, which rejects a length mismatch or non-ASCII up front)."""
    difference = len(a) ^ len(b)
    for i in range(len(b)):
        difference |= (ord(a[i]) if i < len(a) else 0) ^ ord(b[i])
    return difference == 0


def otpauth_url(secret: str, issuer: str, account: str, digits: int = 6, period: int = 30) -> str:
    """``otpauth://totp/…`` provisioning URI, byte-parity with TS ``createOTP().url``. The secret is
    exposed as base32 (RFC 4648, no padding) of its UTF-8 bytes; query params are ordered secret,
    issuer, digits, period (TS ``URLSearchParams``)."""
    label = f"{quote(issuer, safe='')}:{quote(account, safe='')}"
    b32 = base64.b32encode(secret.encode()).rstrip(b"=").decode()
    params = urlencode(
        [("secret", b32), ("issuer", issuer), ("digits", str(digits)), ("period", str(period))]
    )
    return f"otpauth://totp/{label}?{params}"


# --- Ed25519 / JWKS key material (jose exportJWK parity; jwt plugin storage) ---------------


def generate_ed25519_jwk_pair() -> tuple[dict[str, str], dict[str, str]]:
    """Fresh Ed25519 keypair as ``(public_jwk, private_jwk)``, field-parity with jose ``exportJWK``:
    ``kty`` OKP, ``crv`` Ed25519, ``x`` = b64url-nopad public key; the private JWK adds ``d`` =
    b64url-nopad 32-byte seed. (The jwt plugin stores ``alg``/``kid`` as separate jwks-row columns,
    not inside the JWK — ``plugins/jwt/utils.ts`` / ``adapter.ts``.)"""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    private = Ed25519PrivateKey.generate()
    raw_public = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    raw_private = private.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    public_jwk = {"kty": "OKP", "crv": "Ed25519", "x": b64url_encode_nopad(raw_public)}
    private_jwk = {**public_jwk, "d": b64url_encode_nopad(raw_private)}
    return public_jwk, private_jwk


def encode_jwk_private_key(secret: str, private_jwk: dict[str, str]) -> str:
    """The jwks table ``privateKey`` column (TS ``plugins/jwt/utils.ts:63-81``):
    ``JSON.stringify(symmetricEncrypt(JSON.stringify(privateJWK)))`` — a JSON-quoted string wrapping
    the XChaCha20 ciphertext. Uses the plain-string-secret path (bare hex); the port has no
    ``SecretConfig`` yet."""
    return json.dumps(symmetric_encrypt(secret, json.dumps(private_jwk)))


def decode_jwk_private_key(secret: str, stored: str) -> dict[str, str]:
    """Inverse of :func:`encode_jwk_private_key` (TS on read: ``JSON.parse`` → ``symmetricDecrypt``
    → ``JSON.parse``)."""
    return json.loads(symmetric_decrypt(secret, json.loads(stored)))
