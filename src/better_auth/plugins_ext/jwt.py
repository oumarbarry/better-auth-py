"""jwt — issue EdDSA-signed JWTs for the session and publish a JWKS for verification.

Port of TS ``packages/better-auth/src/plugins/jwt/`` (index.ts + utils.ts + adapter.ts
+ sign.ts + verify.ts + schema.ts). Verified at v1.6.23.

Storage fidelity is the prime directive: a ``jwks`` row written here must be readable
by a TS app sharing the DB and vice-versa. The columns are exactly TS ``schema.ts``
(``publicKey``, ``privateKey``, ``createdAt``, ``expiresAt`` + the ``id`` PK); the
``privateKey`` codec is ``crypto.encode/decode_jwk_private_key`` (already TS-verified).
``alg``/``crv`` are NOT persisted (TS ``schema.ts`` declares no such columns) — they are
reconstructed on read from ``key_pair_config`` and the public JWK, exactly like TS
``getJwks`` (``keySet.alg ?? config.alg ?? "EdDSA"`` and the ``...publicKey`` spread).

ponytail: the port signs only the DEFAULT EdDSA/Ed25519 (jose supports ES256/ES512/
PS256/RS256 too). A non-EdDSA ``key_pair_config`` constructs fine but raises
NotImplementedError at local key generation — broaden with cryptography EC/RSA JWK
codecs if a caller needs another alg.
"""

from __future__ import annotations

import inspect
import json
import math
import re
import time
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Any, ClassVar

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ..crypto import (
    b64url_decode_nopad,
    decode_jwk_private_key,
    encode_jwk_private_key,
    generate_ed25519_jwk_pair,
)
from ..plugins import HookSet, Plugin, PluginHook, add_expose_headers
from ..schema import Field, Schema
from ..session import utcnow
from ..types import APIError, AuthResponse, Ctx, dump_json

if TYPE_CHECKING:
    from ..auth import BetterAuth

_DEFAULT_KEY_PAIR_CONFIG = {"alg": "EdDSA", "crv": "Ed25519"}
_DEFAULT_GRACE_PERIOD = 60 * 60 * 24 * 30  # 30 days (TS DEFAULT_GRACE_PERIOD)

#: TS ``schema.ts`` — the jwks table (``date`` -> port ``datetime``). ``alg``/``crv`` are
#: intentionally absent (TS declares no such columns); they are reconstructed on read.
_SCHEMA: Schema = {
    "jwks": {
        "id": Field("string", required=True, unique=True),
        "publicKey": Field("string", required=True),
        "privateKey": Field("string", required=True),
        "createdAt": Field("datetime", required=True),
        "expiresAt": Field("datetime", required=False),
    },
}

# TS utils/time `sec` unit table (jose-style time spans).
_TIME_UNITS = {
    "s": 1, "sec": 1, "secs": 1, "second": 1, "seconds": 1,
    "m": 60, "min": 60, "mins": 60, "minute": 60, "minutes": 60,
    "h": 3600, "hr": 3600, "hrs": 3600, "hour": 3600, "hours": 3600,
    "d": 86400, "day": 86400, "days": 86400,
    "w": 604800, "week": 604800, "weeks": 604800,
    "y": 31557600, "yr": 31557600, "yrs": 31557600, "year": 31557600, "years": 31557600,
}  # fmt: skip
_TIME_RE = re.compile(
    r"^(?P<sign>[+-])? ?(?P<num>\d+(?:\.\d+)?) ?(?P<unit>[a-z]+)(?: (?P<suffix>ago|from now))?$",
    re.IGNORECASE,
)

_DECRYPT_ERROR = (
    "Failed to decrypt private key. Make sure the secret currently in use is the same as "
    "the one used to encrypt the private key. If you are using a different secret, either "
    "clean up your JWKS or disable private key encryption."
)


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


def _sec(span: str) -> int:
    """Parse a jose/vercel-``ms`` time span (``"15m"``, ``"1 hour"``, ``"-1h"``,
    ``"1h ago"``) to seconds. ponytail: minimal parser covering TS ``sec``'s unit set;
    months are unsupported there too."""
    match = _TIME_RE.match(span.strip())
    if match is None:
        raise TypeError(f"Invalid time period format: {span!r}")
    unit = match.group("unit").lower()
    if unit not in _TIME_UNITS:
        raise TypeError(f"Invalid time period unit: {unit!r}")
    value = float(match.group("num")) * _TIME_UNITS[unit]
    if match.group("sign") == "-" or match.group("suffix") == "ago":
        value = -value
    return round(value)


def to_exp_jwt(expiration_time: int | float | datetime | str, iat: int) -> int | float:
    """TS ``toExpJWT`` — resolve ``options.jwt.expirationTime`` to a JWT ``exp`` (seconds):
    a number passes through, a ``datetime`` floors to epoch seconds, a time-span string is
    added to ``iat``."""
    if isinstance(expiration_time, bool):  # bool is an int subclass; reject explicitly
        raise TypeError("expirationTime must be a number, datetime, or time-span string")
    if isinstance(expiration_time, (int, float)):
        return expiration_time
    if isinstance(expiration_time, datetime):
        return math.floor(expiration_time.timestamp())
    return iat + _sec(expiration_time)


def generate_exported_key_pair(
    key_pair_config: dict[str, Any] | None = None,
) -> tuple[dict[str, str], dict[str, str], str]:
    """TS ``generateExportedKeyPair`` — a fresh key pair as ``(public_jwk, private_jwk,
    alg)``. Only the default EdDSA/Ed25519 is implemented (see module docstring)."""
    cfg = key_pair_config or _DEFAULT_KEY_PAIR_CONFIG
    alg = cfg.get("alg", "EdDSA")
    if alg != "EdDSA":
        raise NotImplementedError(
            f"jwt plugin: the Python port signs only EdDSA/Ed25519 keys (got alg={alg!r}). "
            "Broaden with cryptography EC/RSA JWK codecs if another alg is needed."
        )
    public_jwk, private_jwk = generate_ed25519_jwk_pair()
    return public_jwk, private_jwk, alg


class JWTPlugin(Plugin):
    """Port of TS ``jwt(options)``. Flat snake_case kwargs mirror the TS ``jwks``/``jwt``
    option groups with identical defaults."""

    id = "jwt"
    schema: ClassVar[Schema] = _SCHEMA

    def __init__(
        self,
        *,
        # jwks group
        remote_url: str | None = None,
        key_pair_config: dict[str, Any] | None = None,
        disable_private_key_encryption: bool = False,
        rotation_interval: int | None = None,
        grace_period: int = _DEFAULT_GRACE_PERIOD,
        jwks_path: str = "/jwks",
        # jwt group
        issuer: str | None = None,
        audience: str | list[str] | None = None,
        expiration_time: int | float | datetime | str = "15m",
        define_payload: Any = None,
        get_subject: Any = None,
        sign: Any = None,
        # top-level
        disable_setting_jwt_header: bool = False,
    ) -> None:
        # TS init guards (index.ts:42-67).
        if sign is not None and remote_url is None:
            raise ValueError("options.jwks.remoteUrl must be set when using options.jwt.sign")
        if remote_url is not None and not (key_pair_config and key_pair_config.get("alg")):
            raise ValueError(
                "options.jwks.keyPairConfig.alg must be specified when using the oidc plugin "
                "with options.jwks.remoteUrl"
            )
        if (
            not isinstance(jwks_path, str)
            or len(jwks_path) == 0
            or not jwks_path.startswith("/")
            or ".." in jwks_path
        ):
            raise ValueError(
                "options.jwks.jwksPath must be a non-empty string starting with '/' and not "
                "contain '..'"
            )

        self.remote_url = remote_url
        self.key_pair_config = key_pair_config  # None -> EdDSA default applied at key gen
        self.disable_private_key_encryption = disable_private_key_encryption
        self.rotation_interval = rotation_interval
        self.grace_period = grace_period
        self.jwks_path = jwks_path
        self.issuer = issuer
        self.audience = audience
        self.expiration_time = expiration_time
        self.define_payload = define_payload
        self.get_subject = get_subject
        self.sign = sign
        self.disable_setting_jwt_header = disable_setting_jwt_header
        self._auth: BetterAuth | None = None

    @property
    def auth(self) -> BetterAuth:
        assert self._auth is not None, "plugin.init() has not run yet"
        return self._auth

    # --- lifecycle --------------------------------------------------------------------

    def init(self, auth: BetterAuth) -> None:
        self._auth = auth

    def routes(self) -> list[tuple[str, str, Any]]:
        return [
            ("GET", self.jwks_path, self._route_jwks),
            ("GET", "/token", self._route_token),
        ]

    def hooks(self) -> HookSet:
        return HookSet(
            after=[PluginHook(matcher=self._is_get_session, handler=self._after_get_session)]
        )

    # --- key config helpers -----------------------------------------------------------

    def _alg(self) -> str:
        cfg = self.key_pair_config or {}
        return cfg.get("alg") or "EdDSA"

    def _crv_default(self) -> str | None:
        cfg = self.key_pair_config
        return cfg.get("crv") if cfg and "crv" in cfg else None

    # --- jwks adapter (default DB-backed; TS adapter.ts) ------------------------------

    async def _get_all_keys(self) -> list[dict[str, Any]]:
        return await self.auth.adapter.find_many("jwks")

    async def _get_latest_or_new_key(self) -> dict[str, Any]:
        """TS ``getLatestKey`` + the ``sign.ts`` rotation guard: newest key by
        ``createdAt``; create a fresh one when there is none or it has expired."""
        keys = await self._get_all_keys()
        latest = max(keys, key=lambda k: k["createdAt"], default=None)
        if latest is None or (latest.get("expiresAt") and latest["expiresAt"] < utcnow()):
            latest = await self._create_jwk()
        return latest

    async def _create_jwk(self) -> dict[str, Any]:
        """TS ``createJwk`` — persist a new key. Writes only the TS ``schema.ts`` columns."""
        public_jwk, private_jwk, _alg = generate_exported_key_pair(self.key_pair_config)
        data: dict[str, Any] = {
            "publicKey": json.dumps(public_jwk),
            "privateKey": self._encode_private(private_jwk),
            "createdAt": utcnow(),
        }
        if self.rotation_interval is not None:
            data["expiresAt"] = utcnow() + timedelta(seconds=self.rotation_interval)
        return await self.auth.adapter.create("jwks", data)

    def _encode_private(self, private_jwk: dict[str, str]) -> str:
        if self.disable_private_key_encryption:
            return json.dumps(private_jwk)
        return encode_jwk_private_key(self.auth.secret, private_jwk)

    def _decode_private(self, key: dict[str, Any]) -> dict[str, str]:
        stored = key["privateKey"]
        if self.disable_private_key_encryption:
            return json.loads(stored)
        try:
            return decode_jwk_private_key(self.auth.secret, stored)
        except Exception as exc:  # nacl CryptoError / ValueError -> TS BetterAuthError message
            raise ValueError(_DECRYPT_ERROR) from exc

    # --- signing (TS sign.ts) ---------------------------------------------------------

    async def _sign(
        self,
        payload: dict[str, Any],
        *,
        issuer: str | list[str] | None,
        audience: str | list[str] | None,
        expiration_time: Any,
        sign_fn: Any,
    ) -> str:
        now_seconds = math.floor(time.time())
        iat = payload.get("iat")
        exp = payload.get("exp")
        if exp is None:
            exp = to_exp_jwt(
                expiration_time if expiration_time is not None else "15m",
                iat if iat is not None else now_seconds,
            )
        base_origin = self.auth.base_url
        iss = payload.get("iss")
        iss = iss if iss is not None else (issuer if issuer is not None else base_origin)
        aud = payload.get("aud")
        aud = aud if aud is not None else (audience if audience is not None else base_origin)

        # Custom/remote signing: the user function owns all headers (TS jwt.sign).
        if sign_fn is not None:
            full = {**payload, "iat": iat, "exp": exp, "iss": iss, "aud": aud}
            if payload.get("nbf") is not None:
                full["nbf"] = payload["nbf"]
            return await _maybe_await(sign_fn(full))

        key = await self._get_latest_or_new_key()
        private_jwk = self._decode_private(key)
        priv = Ed25519PrivateKey.from_private_bytes(b64url_decode_nopad(private_jwk["d"]))

        # jose sets exp/iss/aud unconditionally; iat/sub/nbf/jti stay as provided in payload.
        claims = dict(payload)
        claims["exp"] = exp
        claims["iss"] = iss
        claims["aud"] = aud
        claims = json.loads(dump_json(claims))  # JSON-safe (dates -> ISO, like TS JSON.stringify)
        return pyjwt.encode(claims, priv, algorithm=self._alg(), headers={"kid": key["id"]})

    async def _get_jwt_token(self, session: dict[str, Any]) -> str:
        """TS ``getJwtToken`` — payload from ``definePayload`` (default ``session.user``),
        ``sub`` from ``getSubject`` (default ``session.user.id``), signed with the newest key."""
        if self.define_payload is not None:
            base = await _maybe_await(self.define_payload(session))
        else:
            base = session["user"]
        sub = None
        if self.get_subject is not None:
            sub = await _maybe_await(self.get_subject(session))
        if sub is None:
            sub = session["user"]["id"]
        payload = {"iat": math.floor(time.time()), **base, "sub": sub}
        return await self._sign(
            payload,
            issuer=self.issuer,
            audience=self.audience,
            expiration_time=self.expiration_time,
            sign_fn=self.sign,
        )

    # --- JWKS response (TS getJwks) ---------------------------------------------------

    async def _jwks_body(self) -> dict[str, list[dict[str, Any]]]:
        keys = await self._get_all_keys()
        if not keys:
            await self._create_jwk()
            keys = await self._get_all_keys()

        now = utcnow()
        grace = timedelta(seconds=self.grace_period)
        alg_default = self._alg()
        crv_default = self._crv_default()

        out: list[dict[str, Any]] = []
        for key in keys:
            expires_at = key.get("expiresAt")
            if expires_at is not None and expires_at + grace <= now:
                continue  # past grace window (TS: keep while expiresAt + grace > now)
            public_jwk = json.loads(key["publicKey"])
            # TS merges {alg, crv, ...publicKey, kid}: the publicKey spread supplies the real
            # crv/kty/x and leaves alg (public JWK has none). Order: alg, crv, kty, x, kid.
            entry = {"alg": alg_default, "crv": crv_default, **public_jwk, "kid": key["id"]}
            if entry.get("crv") is None:
                del entry["crv"]
            out.append(entry)
        return {"keys": out}

    # --- endpoints --------------------------------------------------------------------

    async def _route_jwks(self, ctx: Ctx) -> AuthResponse:
        if self.remote_url:  # remote-url strategy disables the local endpoint (TS: 404)
            raise APIError(404, "NOT_FOUND", "Not Found")
        return AuthResponse(body=await self._jwks_body())

    async def _route_token(self, ctx: Ctx) -> AuthResponse:
        session = await ctx.require_session()  # TS sessionMiddleware -> 401 when unauthenticated
        return AuthResponse(body={"token": await self._get_jwt_token(session)})

    # --- set-auth-jwt after-hook (TS hooks.after on /get-session) ---------------------

    def _is_get_session(self, ctx: Ctx) -> bool:
        return ctx.request.path == "/get-session"

    async def _after_get_session(self, ctx: Ctx) -> None:
        if self.disable_setting_jwt_header:
            return None
        response = ctx.response
        if not isinstance(response, AuthResponse):
            return None
        # /get-session body IS the resolved {session, user} (TS ctx.context.session), or None.
        session = response.body
        if not (isinstance(session, dict) and session.get("session")):
            return None
        token = await self._get_jwt_token(session)
        response.headers.append(("set-auth-jwt", token))
        add_expose_headers(response, "set-auth-jwt")
        return None

    # --- server-only helpers (W3 convention: not HTTP-mounted, callable directly) -----

    async def sign_jwt(
        self, *, payload: dict[str, Any], override_options: dict[str, Any] | None = None
    ) -> str:
        """TS server-only ``signJWT`` — sign ``payload`` with the newest key. ``override_options``
        may override ``issuer``/``audience``/``expiration_time``/``sign`` for this call."""
        o = override_options or {}
        return await self._sign(
            dict(payload),
            issuer=o.get("issuer", self.issuer),
            audience=o.get("audience", self.audience),
            expiration_time=o.get("expiration_time", self.expiration_time),
            sign_fn=o.get("sign", self.sign),
        )

    async def verify_jwt(self, token: str, issuer: str | None = None) -> dict[str, Any] | None:
        """TS server-only ``verifyJWT`` — verify against the JWKS public keys by ``kid``.
        Returns the payload (requires ``sub``/``aud``) or ``None`` on any failure."""
        try:
            kid = pyjwt.get_unverified_header(token).get("kid")
        except Exception:
            return None
        if not kid:
            return None
        key = next((k for k in await self._get_all_keys() if k["id"] == kid), None)
        if key is None:
            return None
        public_jwk = json.loads(key["publicKey"])
        pub = Ed25519PublicKey.from_public_bytes(b64url_decode_nopad(public_jwk["x"]))
        base_origin = self.auth.base_url
        want_iss = issuer if issuer is not None else (self.issuer or base_origin)
        want_aud = self.audience if self.audience is not None else base_origin
        try:
            payload = pyjwt.decode(
                token, pub, algorithms=[self._alg()], issuer=want_iss, audience=want_aud
            )
        except Exception:
            return None
        if not payload.get("sub") or not payload.get("aud"):
            return None
        return payload
