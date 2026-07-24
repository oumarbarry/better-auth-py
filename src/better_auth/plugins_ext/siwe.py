"""siwe plugin — Sign-In with Ethereum (ERC-4361) wallet authentication.

A faithful port of TS ``packages/better-auth/src/plugins/siwe/`` (``index.ts``,
``parse-message.ts``, ``schema.ts``, ``types.ts``) at v1.6.23.

The plugin owns a self-contained ERC-4361 parser (``parse_siwe_message`` /
``normalize_siwe_domain``, ported verbatim from ``parse-message.ts``): it does NOT
trust the caller's ``verify_message`` for message-body validation. Signature
recovery (secp256k1) is caller-supplied config, exactly as in TS — the documented
viem ``verifyMessage`` only recovers the signature and never inspects the message.

The single dependency this plugin adds is ``pycryptodome`` for keccak256, needed by
the EIP-55 checksum (``to_checksum_address``). hashlib's ``sha3_256`` is FIPS-202
SHA3 (0x06 padding), NOT Ethereum's original Keccak (0x01 padding), so it cannot be
used here.
"""

from __future__ import annotations

import inspect
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar

from Crypto.Hash import keccak

from ..adapters.base import Where
from ..endpoints import validate_email
from ..origin import _get_origin
from ..plugins import Plugin, Route
from ..schema import Field, Reference, Schema
from ..session import create_session, utcnow
from ..types import APIError, AuthResponse, Ctx

# --- ERC-4361 message parser (parse-message.ts, verbatim) ------------------------

_HEADER_RE = re.compile(
    r"^(?:([a-zA-Z][a-zA-Z0-9+.-]*)://)?(\S+) "
    r"wants you to sign in with your Ethereum account:$"
)
_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")
_FIELD_RE = re.compile(r"^([A-Za-z ]+): (.*)$")

# Wallet-address body input (TS ``walletAddressInputSchema``): 0x + 40 hex, len 42.
_WALLET_RE = re.compile(r"^0[xX][a-fA-F0-9]{40}$")


@dataclass
class ParsedSiweMessage:
    """Fields ``parse_siwe_message`` extracts from a signed ERC-4361 message
    (TS ``ParsedSiweMessage``). Every field is optional; parsing never raises."""

    scheme: str | None = None
    domain: str | None = None
    address: str | None = None
    uri: str | None = None
    version: str | None = None
    chain_id: int | None = None
    nonce: str | None = None
    issued_at: str | None = None
    expiration_time: str | None = None
    not_before: str | None = None
    request_id: str | None = None


def _js_number_to_int(value: str) -> int | None:
    """JS ``Number(value)`` gated by ``Number.isInteger``: the integer when ``value``
    coerces to a finite integer, else ``None``. Mirrors JS coercion (trims whitespace,
    ``""`` -> 0, accepts ``0x``/``0o``/``0b`` and exponent forms) so the ``Chain ID``
    field accepts/rejects exactly what ``parse-message.ts`` does.

    ponytail: real SIWE chain ids are plain decimals; the exotic bases exist only to
    match JS ``Number`` byte-for-byte on adversarial input.
    """
    s = value.strip()
    if s == "":
        return 0
    if re.fullmatch(r"[+-]?(0[xX][0-9a-fA-F]+|0[oO][0-7]+|0[bB][01]+)", s):
        return int(s, 0)
    try:
        parsed = float(s)
    except ValueError:
        return None
    if parsed != parsed or parsed in (float("inf"), float("-inf")):  # NaN / Infinity
        return None
    return int(parsed) if parsed.is_integer() else None


def parse_siwe_message(message: str) -> ParsedSiweMessage:
    """Minimal, tolerant ERC-4361 parser (``parse-message.ts``).

    Extracts the labeled fields the plugin validates (nonce, domain, address, chain
    id, time bounds); leaves presence/equality checks to the caller. Splits tolerant
    of CRLF. The labeled fields are parsed line-by-line so an optional statement (which
    may itself contain ``": "``) does not break parsing; suffix fields win because they
    come after the statement (the loop walks top-to-bottom and later lines overwrite).
    """
    result = ParsedSiweMessage()
    lines = re.split(r"\r?\n", message)

    header_match = _HEADER_RE.match(lines[0]) if lines else None
    if header_match:
        if header_match.group(1):
            result.scheme = header_match.group(1)
        result.domain = header_match.group(2)

    address_line = lines[1].strip() if len(lines) > 1 else None
    if address_line and _ADDRESS_RE.match(address_line):
        result.address = address_line

    for line in lines:
        match = _FIELD_RE.match(line)
        if not match:
            continue
        key, value = match.group(1), match.group(2)
        if key == "URI":
            result.uri = value
        elif key == "Version":
            result.version = value
        elif key == "Chain ID":
            parsed = _js_number_to_int(value)
            if parsed is not None:
                result.chain_id = parsed
        elif key == "Nonce":
            result.nonce = value
        elif key == "Issued At":
            result.issued_at = value
        elif key == "Expiration Time":
            result.expiration_time = value
        elif key == "Not Before":
            result.not_before = value
        elif key == "Request ID":
            result.request_id = value

    return result


def normalize_siwe_domain(domain: str) -> str:
    """Normalize a SIWE ``domain`` (RFC 3986 authority) for comparison: strip any
    scheme and path, lowercase, leaving ``host[:port]`` (``parse-message.ts``)."""
    without_scheme = re.sub(r"^[a-z][a-z0-9+.-]*://", "", domain.strip().lower())
    path_start = without_scheme.find("/")
    return without_scheme if path_start == -1 else without_scheme[:path_start]


# --- EIP-55 checksum (utils/hashing.ts, keccak256) -------------------------------


def to_checksum_address(address: str) -> str:
    """ERC-55 ("mixed-case checksum address encoding") via keccak256, a verbatim port
    of TS ``toChecksumAddress`` (``utils/hashing.ts``)."""
    address = address.lower().replace("0x", "", 1)
    digest = keccak.new(digest_bits=256)
    digest.update(address.encode())
    hash_hex = digest.hexdigest()
    ret = "0x"
    for i in range(40):
        ret += address[i].upper() if int(hash_hex[i], 16) >= 8 else address[i]
    return ret


# --- plugin ----------------------------------------------------------------------

#: TS ``schema.ts`` — the ``walletAddress`` model (exact camelCase columns).
_SCHEMA: Schema = {
    "walletAddress": {
        "userId": Field("string", required=True, references=Reference("user", "id"), index=True),
        "address": Field("string", required=True),
        "chainId": Field("number", required=True),
        "isPrimary": Field("boolean", default=False),
        "createdAt": Field("datetime", required=True),
    },
}


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


def _positive_int(value: Any, default: int = 1) -> int:
    """TS ``z.number().int().positive().optional().default(1)`` for ``chainId``.
    Accepts an integer or an integral float (JS has no int/float split); rejects
    anything else or a non-positive value with a 400."""
    if value is None:
        return default
    if isinstance(value, bool):
        raise APIError(400, "INVALID_BODY", "chainId must be a positive integer")
    if isinstance(value, int):
        number = value
    elif isinstance(value, float) and value.is_integer():
        number = int(value)
    else:
        raise APIError(400, "INVALID_BODY", "chainId must be a positive integer")
    if number <= 0:
        raise APIError(400, "INVALID_BODY", "chainId must be a positive integer")
    return number


def _validate_wallet_address(raw: Any) -> str:
    """TS ``walletAddressInputSchema`` — 0x + 40 hex, length 42 (400 otherwise)."""
    if not isinstance(raw, str) or not _WALLET_RE.match(raw):
        raise APIError(400, "INVALID_BODY", "Invalid wallet address")
    return raw


def _parse_iso(value: str) -> datetime | None:
    """JS ``Date.parse`` of an ISO-8601/RFC-3339 timestamp -> aware ``datetime``, or
    ``None`` when unparseable (matching TS's ``Number.isNaN`` gate, which skips the
    time-bound check on an unparseable value). A naive value is treated as UTC."""
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


class SiwePlugin(Plugin):
    """TS ``siwe()`` — see module docstring for the source files."""

    id = "siwe"
    schema: ClassVar[Schema] = _SCHEMA

    def __init__(
        self,
        *,
        domain: str,
        get_nonce: Callable[[], Awaitable[str] | str],
        verify_message: Callable[[dict[str, Any]], Awaitable[bool] | bool],
        email_domain_name: str | None = None,
        anonymous: bool = True,
        ens_lookup: Callable[[dict[str, Any]], Awaitable[dict[str, Any]] | dict[str, Any]]
        | None = None,
    ) -> None:
        # ponytail: TS also accepts a per-instance `schema` override (field-name
        # remapping only). `Plugin.schema` is a ClassVar on the shared base, so an
        # instance override isn't wired here — same call the ported `anonymous`
        # plugin makes. The fixed `walletAddress` shape below is what every path uses.
        self.domain = domain
        self.get_nonce = get_nonce
        self.verify_message = verify_message
        self.email_domain_name = email_domain_name
        self.anonymous = anonymous
        self.ens_lookup = ens_lookup

    def routes(self) -> list[Route]:
        # ``/siwe/nonce`` and its ``/siwe/get-nonce`` alias share one handler
        # (TS ``createSiweNonceEndpoint``).
        return [
            ("POST", "/siwe/nonce", self.get_nonce_route),
            ("POST", "/siwe/get-nonce", self.get_nonce_route),
            ("POST", "/siwe/verify", self.verify),
        ]

    # --- /siwe/nonce (+ /siwe/get-nonce alias) -----------------------------------

    async def get_nonce_route(self, ctx: Ctx) -> dict[str, str]:
        body = ctx.body()
        raw = body.get("walletAddress") or body.get("address")
        if not raw:
            raise APIError(400, "INVALID_BODY", "walletAddress or address is required")
        raw = _validate_wallet_address(raw)
        chain_id = _positive_int(body.get("chainId"))
        wallet_address = to_checksum_address(raw)
        nonce = await _maybe_await(self.get_nonce())

        # Store the nonce keyed by (checksummed address, chain id); expires in 15 min.
        await ctx.internal.create_verification_value(
            {
                "identifier": f"siwe:{wallet_address}:{chain_id}",
                "value": nonce,
                "expiresAt": utcnow() + timedelta(minutes=15),
            }
        )
        return {"nonce": nonce}

    # --- /siwe/verify ------------------------------------------------------------

    async def verify(self, ctx: Ctx) -> AuthResponse:
        body = ctx.body()
        message = body.get("message")
        signature = body.get("signature")
        if not isinstance(message, str) or not message:
            raise APIError(400, "INVALID_BODY", "message is required")
        if not isinstance(signature, str) or not signature:
            raise APIError(400, "INVALID_BODY", "signature is required")
        wallet_address = to_checksum_address(_validate_wallet_address(body.get("walletAddress")))
        chain_id = _positive_int(body.get("chainId"))

        # ``email`` is optional but, when present (even ``""``), must be a valid address
        # (TS ``z.email().optional()``); it is required when ``anonymous`` is disabled.
        email = body.get("email")
        if email is not None:
            email = validate_email(email)  # 400 INVALID_EMAIL on bad format; lowercases
        is_anon = self.anonymous
        if not is_anon and not email:
            raise APIError(400, "INVALID_BODY", "Email is required when anonymous is disabled.")

        try:
            # Atomically consume the single-use nonce before any signature work or
            # state mutation: the first concurrent request wins, every racer gets
            # None, so the same nonce can never replay a login. Consuming here also
            # burns the record on a failed attempt and applies the expiry gate.
            verification = await ctx.internal.consume_verification_value(
                f"siwe:{wallet_address}:{chain_id}"
            )
            if verification is None:
                raise APIError(
                    401,
                    "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE",
                    "Unauthorized: Invalid or expired nonce",
                )
            nonce = verification["value"]

            # Bind the *signed* message to server state before accepting the signature.
            # Signature recovery alone (the documented viem verify_message) does NOT
            # inspect the message body, so a previously produced signature (stale, for
            # another domain, or over an arbitrary string) could otherwise be presented
            # with a freshly minted nonce. Parse the ERC-4361 message ourselves and
            # require nonce, address, chain id and domain to match, plus honor the
            # signed time bounds.
            parsed = parse_siwe_message(message)
            nonce_matches = parsed.nonce == nonce
            address_matches = bool(parsed.address) and (
                parsed.address.lower() == wallet_address.lower()
            )
            chain_matches = parsed.chain_id == chain_id
            domain_matches = bool(parsed.domain) and (
                normalize_siwe_domain(parsed.domain) == normalize_siwe_domain(self.domain)
            )
            if not (nonce_matches and address_matches and chain_matches and domain_matches):
                raise APIError(
                    401,
                    "UNAUTHORIZED_SIWE_MESSAGE_MISMATCH",
                    "Unauthorized: SIWE message does not match the expected nonce, "
                    "domain, address, or chain ID",
                )

            now = utcnow()
            if parsed.expiration_time:
                expires_at = _parse_iso(parsed.expiration_time)
                if expires_at is not None and now >= expires_at:
                    raise APIError(
                        401,
                        "UNAUTHORIZED_SIWE_MESSAGE_EXPIRED",
                        "Unauthorized: SIWE message has expired",
                    )
            if parsed.not_before:
                not_before = _parse_iso(parsed.not_before)
                if not_before is not None and now < not_before:
                    raise APIError(
                        401,
                        "UNAUTHORIZED_SIWE_MESSAGE_NOT_YET_VALID",
                        "Unauthorized: SIWE message is not yet valid",
                    )

            verified = await _maybe_await(
                self.verify_message(
                    {
                        "message": message,
                        "signature": signature,
                        "address": wallet_address,
                        "chainId": chain_id,
                        "cacao": {
                            "h": {"t": "caip122"},
                            "p": {
                                "domain": self.domain,
                                "aud": self.domain,
                                "nonce": nonce,
                                "iss": self.domain,
                                "version": "1",
                            },
                            "s": {"t": "eip191", "s": signature},
                        },
                    }
                )
            )
            if not verified:
                raise APIError(401, "UNAUTHORIZED", "Unauthorized: Invalid SIWE signature")

            user = await self._resolve_user(ctx, wallet_address, chain_id, is_anon, email)

            session, cookies = await create_session(
                ctx.auth, user["id"], ctx.request, user=user, ctx=ctx
            )
            if not session:
                raise APIError(500, "INTERNAL_SERVER_ERROR", "Internal Server Error")

            response = AuthResponse(
                body={
                    "token": session["token"],
                    "success": True,
                    "user": {
                        "id": user["id"],
                        "walletAddress": wallet_address,
                        "chainId": chain_id,
                    },
                }
            )
            for cookie in cookies:
                response.set_cookie(cookie)
            return response
        except APIError:
            raise
        except Exception as error:  # TS wraps any failure (incl. verify_message) as a 401
            raise APIError(
                401, "UNAUTHORIZED", "Something went wrong. Please try again later."
            ) from error

    async def _resolve_user(
        self, ctx: Ctx, wallet_address: str, chain_id: int, is_anon: bool, email: str | None
    ) -> dict[str, Any]:
        """Find the user owning this wallet (exact address+chain, else the address on
        any chain), else create one — mirroring TS ``verifySiweMessage`` user resolution.
        Adds the ``walletAddress`` row and ``siwe`` account for a first-seen combo."""
        user: dict[str, Any] | None = None

        existing_wallet = await ctx.adapter.find_one(
            "walletAddress",
            [Where("address", wallet_address), Where("chainId", chain_id)],
        )
        if existing_wallet:
            user = await ctx.adapter.find_one("user", [Where("id", existing_wallet["userId"])])
        else:
            any_wallet = await ctx.adapter.find_one(
                "walletAddress", [Where("address", wallet_address)]
            )
            if any_wallet:
                user = await ctx.adapter.find_one("user", [Where("id", any_wallet["userId"])])

        if user is None:
            domain = self.email_domain_name or _get_origin(ctx.auth.base_url)
            # SIWE proves wallet control, not email ownership: bind the caller email
            # only when it is unclaimed, else keep the wallet-derived address. The
            # silent fallback (no distinct error) avoids an enumeration oracle.
            user_email = f"{wallet_address}@{domain}"
            if not is_anon and email:
                existing_user = await ctx.adapter.find_one("user", [Where("email", email)])
                if not existing_user:
                    user_email = email
            ens = (
                (await _maybe_await(self.ens_lookup({"walletAddress": wallet_address})) or {})
                if self.ens_lookup
                else {}
            )
            user = await ctx.internal.create_user(
                {
                    "name": ens.get("name") or wallet_address,
                    "email": user_email,
                    "image": ens.get("avatar") or "",
                }
            )
            await self._add_wallet(ctx, user["id"], wallet_address, chain_id, is_primary=True)
        elif not existing_wallet:
            # Existing user, new chain for this address: additional addresses are not
            # primary by default.
            await self._add_wallet(ctx, user["id"], wallet_address, chain_id, is_primary=False)

        return user

    async def _add_wallet(
        self, ctx: Ctx, user_id: str, wallet_address: str, chain_id: int, *, is_primary: bool
    ) -> None:
        await ctx.adapter.create(
            "walletAddress",
            {
                "userId": user_id,
                "address": wallet_address,
                "chainId": chain_id,
                "isPrimary": is_primary,
                "createdAt": utcnow(),
            },
        )
        await ctx.internal.create_account(
            {
                "userId": user_id,
                "providerId": "siwe",
                "accountId": f"{wallet_address}:{chain_id}",
            }
        )
