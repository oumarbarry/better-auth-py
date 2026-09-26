"""RFC 9449 DPoP primitives (TS v1.7.6 core ``oauth2/dpop.ts``, oauth-provider ``dpop.ts``
and the DPoP challenge half of oauth-provider ``resource-challenge.ts``).

Pure helpers: proof verification, JWK thumbprints (RFC 7638), ``ath`` hashing, replay stores,
the resource-request binding check and the ``WWW-Authenticate: DPoP`` challenge string.
Endpoint wiring lives in the token, userinfo and introspection modules.
"""

from __future__ import annotations

import binascii
import hashlib
import json
import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Literal, Protocol
from urllib.parse import urlsplit

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import rsa

from ...crypto import b64url_decode_nopad, b64url_encode_nopad
from ...session import utcnow
from ...types import Ctx

DPOP_AUTHORIZATION_SCHEME = "DPoP"
BEARER_AUTHORIZATION_SCHEME = "Bearer"
DPOP_PROOF_TYPE = "dpop+jwt"
#: TS ``DPOP_SIGNING_ALGORITHMS`` (dpop.ts:14).
DPOP_SIGNING_ALGORITHMS: tuple[str, ...] = ("EdDSA", "ES256", "ES512", "PS256", "RS256")

DEFAULT_DPOP_PROOF_MAX_AGE_SECONDS = 300
MAX_DPOP_JTI_LENGTH = 512
_JWK_PRIVATE_FIELDS = ("d", "p", "q", "dp", "dq", "qi", "oth", "k")

AccessTokenAuthorizationScheme = Literal["Bearer", "DPoP", "Unknown"]
DpopBindingErrorCode = Literal["invalid_token", "invalid_dpop_proof"]


@dataclass(frozen=True)
class AccessTokenAuthorization:
    scheme: AccessTokenAuthorizationScheme
    token: str


@dataclass(frozen=True)
class VerifiedDpopProof:
    jwk: dict[str, Any]
    jkt: str
    jti: str
    htm: str
    htu: str
    iat: float
    ath: str | None
    replay_key: str
    expires_at: datetime


class DpopBindingError(Exception):
    """TS ``DpopBindingError`` (dpop.ts:470): ``code`` is ``invalid_token`` or
    ``invalid_dpop_proof``; the message is the wire ``error_description``."""

    def __init__(self, code: DpopBindingErrorCode, message: str) -> None:
        super().__init__(message)
        self.code: DpopBindingErrorCode = code


class DpopProofError(DpopBindingError):
    """TS ``DpopProofError`` (dpop.ts:48), always ``invalid_dpop_proof``. It subclasses
    :class:`DpopBindingError` because TS ``isDpopBindingError`` accepts it too."""

    def __init__(self, message: str) -> None:
        super().__init__("invalid_dpop_proof", message)


def is_dpop_proof_error(error: object) -> bool:
    return isinstance(error, DpopBindingError) and error.code == "invalid_dpop_proof"


def is_dpop_binding_error(error: object) -> bool:
    return isinstance(error, DpopBindingError)


# --- replay stores (TS dpop.ts:57-110) -----------------------------------------------


class DpopReplayStore(Protocol):
    async def reserve(self, *, key: str, expires_at: datetime, now: datetime) -> bool: ...


class InMemoryDpopReplayStore:
    """TS ``createInMemoryDpopReplayStore``: process-local, single-instance only."""

    def __init__(self) -> None:
        self._reservations: dict[str, datetime] = {}

    async def reserve(self, *, key: str, expires_at: datetime, now: datetime) -> bool:
        for stored_key, stored_expires in list(self._reservations.items()):
            if stored_expires <= now:
                del self._reservations[stored_key]
        if key in self._reservations:
            return False
        self._reservations[key] = expires_at
        return True


def create_in_memory_dpop_replay_store() -> InMemoryDpopReplayStore:
    return InMemoryDpopReplayStore()


class DpopReplayReservations(Protocol):
    """The internal adapter's ``reserve_verification_value`` (TS dpop.ts:84)."""

    async def reserve_verification_value(
        self, identifier: str, value: str, expires_at: datetime
    ) -> bool: ...


class _DatabaseDpopReplayStore:
    def __init__(self, reservations: DpopReplayReservations) -> None:
        self._reservations = reservations

    async def reserve(self, *, key: str, expires_at: datetime, now: datetime) -> bool:
        return await self._reservations.reserve_verification_value(
            identifier=f"dpop-proof:{key}", value=key, expires_at=expires_at
        )


def create_dpop_replay_store(reservations: DpopReplayReservations) -> DpopReplayStore:
    """TS ``createDpopReplayStore`` (dpop.ts:103): cross-instance replay protection on the
    verification table, row identifier ``dpop-proof:<key>``, value ``<key>``. A
    secondary-storage-only deployment raises (fails closed)."""
    return _DatabaseDpopReplayStore(reservations)


# --- parsing and hashing (TS dpop.ts:153-229) ----------------------------------------

_AUTHORIZATION = re.compile(r"^([A-Za-z][A-Za-z0-9!#$%&'*+.^_`|~-]*)\s+(.+)$")


def parse_access_token_authorization(
    authorization: str | None,
) -> AccessTokenAuthorization | None:
    if not authorization:
        return None
    value = authorization.strip()
    if not value:
        return None
    match = _AUTHORIZATION.match(value)
    if not match:
        return AccessTokenAuthorization("Unknown", value)
    scheme = match.group(1).lower()
    token = match.group(2).strip()
    if scheme == "bearer":
        return AccessTokenAuthorization("Bearer", token)
    if scheme == "dpop":
        return AccessTokenAuthorization("DPoP", token)
    return AccessTokenAuthorization("Unknown", value)


def strip_access_token_authorization_scheme(token: str) -> str:
    parsed = parse_access_token_authorization(token)
    return parsed.token if parsed else token


_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443, "ftp": 21}


def normalize_dpop_htu(url: str) -> str:
    """WHATWG ``origin + pathname`` (TS dpop.ts:179). Raises ``ValueError``.

    ponytail: lowercases scheme and host, drops the default port and userinfo, maps an
    empty path to ``/``; no dot-segment or percent-encoding normalization. Both sides of
    the comparison go through this, so the ceiling is only exotic URLs failing to match.
    """
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        raise ValueError("Invalid URL") from None
    scheme = parts.scheme.lower()
    if not scheme or not re.fullmatch(r"[a-z][a-z0-9+.-]*", scheme):
        raise ValueError("Invalid URL")
    host = parts.hostname or ""
    if scheme in _DEFAULT_PORTS and not host:
        raise ValueError("Invalid URL")
    # RFC 9449 section 4.2: reject a fragment rather than silently strip it
    if parts.fragment:
        raise ValueError("DPoP proof htu must not contain a fragment")
    if scheme not in _DEFAULT_PORTS:
        return f"null{parts.path}"
    if ":" in host:
        host = f"[{host}]"
    origin = f"{scheme}://{host}"
    if port is not None and port != _DEFAULT_PORTS[scheme]:
        origin += f":{port}"
    return origin + (parts.path or "/")


async def derive_dpop_ath(access_token: str) -> str:
    return b64url_encode_nopad(hashlib.sha256(access_token.encode()).digest())


#: RFC 7638 section 3.2 required members per ``kty``.
_THUMBPRINT_MEMBERS = {
    "EC": ("crv", "kty", "x", "y"),
    "OKP": ("crv", "kty", "x"),
    "RSA": ("e", "kty", "n"),
    "oct": ("k", "kty"),
}


async def derive_dpop_jkt(jwk: Mapping[str, Any]) -> str:
    """RFC 7638 SHA-256 thumbprint: required members only, sorted, no whitespace."""
    members = _THUMBPRINT_MEMBERS.get(jwk.get("kty"))  # type: ignore[arg-type]
    if members is None:
        raise ValueError('unsupported "kty" (Key Type) Parameter value')
    if not all(isinstance(jwk.get(name), str) for name in members):
        raise ValueError("JWK is missing a required thumbprint member")
    canonical = json.dumps({name: jwk[name] for name in members}, separators=(",", ":"))
    return b64url_encode_nopad(hashlib.sha256(canonical.encode()).digest())


def get_confirmation_jkt(confirmation: object) -> str | None:
    """``cnf.jkt`` from an untrusted RFC 7800 confirmation; any other shape is None."""
    if not isinstance(confirmation, Mapping):
        return None
    jkt = confirmation.get("jkt")
    return jkt if isinstance(jkt, str) and jkt else None


def get_dpop_jkt_from_payload(payload: Mapping[str, Any]) -> str | None:
    return get_confirmation_jkt(payload.get("cnf"))


# --- proof verification (TS dpop.ts:232-460) -----------------------------------------


def _string_claim(payload: Mapping[str, Any], claim: str) -> str | None:
    value = payload.get(claim)
    return value if isinstance(value, str) and value else None


def _is_number(value: object) -> bool:
    return isinstance(value, int | float) and not isinstance(value, bool) and math.isfinite(value)


def _assert_supported_algorithm(alg: object, signing_algorithms: Sequence[str]) -> str:
    if not isinstance(alg, str) or not alg or alg == "none" or alg.startswith("HS"):
        raise DpopProofError("DPoP proof must use an asymmetric JWS algorithm")
    if alg not in signing_algorithms:
        raise DpopProofError("DPoP proof uses an unsupported JWS algorithm")
    return alg


def _assert_public_jwk(jwk: Any) -> dict[str, Any]:
    if not isinstance(jwk, dict):
        raise DpopProofError("DPoP proof header must include a public jwk")
    if jwk.get("kty") == "oct":
        raise DpopProofError("DPoP proof jwk must be asymmetric")
    if any(field in jwk for field in _JWK_PRIVATE_FIELDS):
        raise DpopProofError("DPoP proof jwk must not contain private key material")
    return jwk


def _decode_protected_header(proof_jwt: str) -> dict[str, Any]:
    """jose ``decodeProtectedHeader`` with its error message."""
    try:
        header = json.loads(b64url_decode_nopad(proof_jwt.split(".")[0]))
    except (ValueError, binascii.Error):
        header = None
    if not isinstance(header, dict):
        raise DpopProofError("Invalid Token or Protected Header formatting")
    return header


def _verify_signature(proof_jwt: str, jwk: dict[str, Any], alg: str) -> dict[str, Any]:
    """TS ``importJWK`` + ``jwtVerify`` (dpop.ts:375). Raises with jose's messages."""
    # PyJWT rejects a kty or curve that does not fit ``alg``, like WebCrypto does in TS
    key = pyjwt.PyJWK(jwk, algorithm=alg).key
    if isinstance(key, rsa.RSAPublicKey) and key.key_size < 2048:
        raise ValueError(f"{alg} requires key modulusLength to be 2048 bits or larger")
    try:
        decoded = pyjwt.PyJWS().decode_complete(proof_jwt, key=key, algorithms=[alg])
    except pyjwt.InvalidSignatureError:
        raise ValueError("signature verification failed") from None
    try:
        payload = json.loads(decoded["payload"])
    except ValueError:
        payload = None
    if not isinstance(payload, dict):
        raise ValueError("JWT Claims Set must be a top-level JSON object")
    # jose ``validateClaimsSet`` with no options: types, then exp/nbf on the wall clock
    now = int(utcnow().timestamp())
    for claim in ("iat", "nbf", "exp"):
        if claim in payload and not _is_number(payload[claim]):
            raise ValueError(f'"{claim}" claim must be a number')
    if "nbf" in payload and payload["nbf"] > now:
        raise ValueError('"nbf" claim timestamp check failed')
    if "exp" in payload and payload["exp"] <= now:
        raise ValueError('"exp" claim timestamp check failed')
    return payload


async def verify_dpop_proof(
    *,
    proof_jwt: str,
    method: str,
    url: str,
    access_token: str | None = None,
    expected_jkt: str | None = None,
    require_ath: bool = False,
    now_seconds: float | None = None,
    proof_max_age_seconds: float | None = None,
    signing_algorithms: Sequence[str] | None = None,
    replay_store: DpopReplayStore | None = None,
) -> VerifiedDpopProof:
    """TS ``verifyDpopProof`` (dpop.ts:334). Raises :class:`DpopProofError`."""
    if now_seconds is None:
        now_seconds = math.floor(utcnow().timestamp())
    if proof_max_age_seconds is None:
        proof_max_age_seconds = DEFAULT_DPOP_PROOF_MAX_AGE_SECONDS
    if signing_algorithms is None:
        signing_algorithms = DPOP_SIGNING_ALGORITHMS

    if not proof_jwt or len(proof_jwt.split(".")) != 3:
        raise DpopProofError("DPoP proof must be a compact JWT")
    header = _decode_protected_header(proof_jwt)
    if header.get("typ") != DPOP_PROOF_TYPE:
        raise DpopProofError('DPoP proof typ must be "dpop+jwt"')
    alg = _assert_supported_algorithm(header.get("alg"), signing_algorithms)
    jwk = _assert_public_jwk(header.get("jwk"))

    try:
        # the key import sits inside the try: a well-shaped jwk that fails to import
        # is bad client input, not a server error (TS dpop.ts:372)
        payload = _verify_signature(proof_jwt, jwk, alg)
    except Exception as error:
        raise DpopProofError(str(error) or "DPoP proof signature is invalid") from None

    htm = _string_claim(payload, "htm")
    htu = _string_claim(payload, "htu")
    jti = _string_claim(payload, "jti")
    iat = payload.get("iat")
    if not htm or not htu or not jti or not _is_number(iat):
        raise DpopProofError("DPoP proof must include htm, htu, jti, and iat claims")
    assert isinstance(iat, int | float)
    if len(jti) > MAX_DPOP_JTI_LENGTH:
        raise DpopProofError("DPoP proof jti is too large")
    if htm.upper() != method.upper():
        raise DpopProofError("DPoP proof htm does not match the request method")
    try:
        normalized_htu = normalize_dpop_htu(url)
        proof_htu = normalize_dpop_htu(htu)
    except ValueError as error:
        raise DpopProofError(str(error)) from None
    if proof_htu != normalized_htu:
        raise DpopProofError("DPoP proof htu does not match the request URL")
    if iat > now_seconds + 5 or now_seconds - iat > proof_max_age_seconds:
        raise DpopProofError("DPoP proof iat is outside the accepted window")

    ath = _string_claim(payload, "ath")
    if require_ath and not ath:
        raise DpopProofError("DPoP proof must include an ath claim")
    if access_token is not None and ath != await derive_dpop_ath(access_token):
        raise DpopProofError("DPoP proof ath does not match the access token")

    jkt = await derive_dpop_jkt(jwk)
    if expected_jkt is not None and jkt != expected_jkt:
        raise DpopProofError("DPoP proof key does not match the bound token")

    # key the replay record on the compared method and normalized URL, not the raw
    # claims, so casing or query changes cannot reuse a jti (TS dpop.ts:446)
    replay_key = b64url_encode_nopad(
        hashlib.sha256(f"{jkt}\n{htm.upper()}\n{normalized_htu}\n{jti}".encode()).digest()
    )
    expires_at = datetime.fromtimestamp(iat + proof_max_age_seconds, tz=timezone.utc)
    if replay_store is not None and not await replay_store.reserve(
        key=replay_key,
        expires_at=expires_at,
        now=datetime.fromtimestamp(now_seconds, tz=timezone.utc),
    ):
        raise DpopProofError("DPoP proof jti has already been used")

    return VerifiedDpopProof(
        jwk=jwk,
        jkt=jkt,
        jti=jti,
        htm=htm,
        htu=normalized_htu,
        iat=iat,
        ath=ath,
        replay_key=replay_key,
        expires_at=expires_at,
    )


async def enforce_dpop_binding(
    *,
    payload: Mapping[str, Any],
    authorization: AccessTokenAuthorization,
    proof_jwt: str | None,
    method: str,
    url: str,
    replay_store: DpopReplayStore | None = None,
    proof_max_age_seconds: float | None = None,
    signing_algorithms: Sequence[str] | None = None,
) -> None:
    """RFC 9449 section 7.1 sender-constraint check for an already-validated access token
    (TS ``enforceDpopBinding``, dpop.ts:512). Raises :class:`DpopBindingError`; returns
    for a plain bearer token. A :class:`DpopProofError` is already a binding error with
    code ``invalid_dpop_proof``, so the TS re-wrap is not needed."""
    dpop_jkt = get_dpop_jkt_from_payload(payload)
    if not dpop_jkt:
        if authorization.scheme == "DPoP":
            raise DpopBindingError(
                "invalid_token", "DPoP authorization requires a DPoP-bound access token"
            )
        return
    if authorization.scheme != "DPoP":
        raise DpopBindingError(
            "invalid_token", "DPoP-bound access token requires the DPoP authorization scheme"
        )
    if not proof_jwt:
        raise DpopBindingError("invalid_dpop_proof", "DPoP proof header is required")
    await verify_dpop_proof(
        proof_jwt=proof_jwt,
        method=method,
        url=url,
        access_token=authorization.token,
        expected_jkt=dpop_jkt,
        require_ath=True,
        proof_max_age_seconds=proof_max_age_seconds,
        signing_algorithms=signing_algorithms,
        replay_store=replay_store,
    )


# --- oauth-provider dpop.ts ----------------------------------------------------------


def get_dpop_proof_jwt(ctx: Ctx) -> str | None:
    return ctx.request.headers.get("dpop")


def get_endpoint_url(ctx: Ctx, path: str) -> str:
    """The request URL, else ``baseURL + path`` (TS oauth-provider dpop.ts:9)."""
    return ctx.request.url or f"{ctx.auth.base_url}{ctx.auth.base_path}{path}"


# --- resource-challenge.ts DPoP challenge --------------------------------------------

_DPOP_CHALLENGE_ERRORS = frozenset({"invalid_dpop_proof"})
_ERROR_DESCRIPTION = re.compile(r"[\x20-\x21\x23-\x5b\x5d-\x7e]+")


def quote_auth_param(value: str) -> str:
    if re.search(r"[\x00-\x1f\x7f]", value):
        raise ValueError("invalid WWW-Authenticate parameter")
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _validate_error_description(description: object) -> str:
    if not isinstance(description, str) or not _ERROR_DESCRIPTION.fullmatch(description):
        raise ValueError("invalid error_description")
    return description


def is_dpop_challenge_error(*, error_code: str | None, description: str) -> bool:
    """TS ``isDpopChallengeError`` (resource-challenge.ts:56). Pass the 401's ``error``
    and ``error_description``."""
    return bool(error_code) and (
        error_code in _DPOP_CHALLENGE_ERRORS
        or (error_code == "invalid_token" and "DPoP" in description)
    )


def build_dpop_challenge(
    *,
    error_code: str | None,
    description: str,
    dpop_signing_algorithms: Sequence[str] | None = None,
) -> str:
    """``WWW-Authenticate`` value for a DPoP 401 (TS resource-challenge.ts:65)."""
    algorithms = dpop_signing_algorithms or DPOP_SIGNING_ALGORITHMS
    return ", ".join(
        (
            f'DPoP error="{quote_auth_param(error_code or "invalid_dpop_proof")}"',
            f'error_description="{_validate_error_description(description)}"',
            f'algs="{quote_auth_param(" ".join(algorithms))}"',
        )
    )
