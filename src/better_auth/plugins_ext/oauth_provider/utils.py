"""Enabling helpers for the oauth-provider plugin.

Ports the small shared pieces the provider needs on top of existing port seams
(``packages/oauth-provider/src/utils/index.ts``, ``signed-query.ts``, ``authorize.ts``
formatErrorURL/handleRedirect, and ``@better-auth/core/utils/redirect-uri`` SafeUrlSchema)
at v1.6.23. Everything crypto-shaped delegates to :mod:`better_auth.crypto`.
"""

from __future__ import annotations

import inspect
import ipaddress
import json
import weakref
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any
from urllib.parse import quote_plus, urlencode, urlsplit

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ...crypto import (
    _constant_time_equal,
    _signature,
    b64url_decode_nopad,
    default_key_hasher,
    generate_random_string,
)
from ...session import utcnow
from ...types import AuthResponse, Ctx
from .signed_query import (
    POST_LOGIN_CLEARED_PARAM,
    SIGNED_QUERY_ISSUED_AT_PARAM,
    Pairs,
    canonicalize_oauth_query_params,
    parse_query,
    set_signed_oauth_query_parameter_names,
)

if TYPE_CHECKING:
    from ...auth import BetterAuth

#: Valid OAuth prompt values (TS ``parsePrompt``).
_PROMPTS = ("login", "consent", "create", "select_account", "none")

# --- OAuth error envelope + redirect helpers (item 1) --------------------------------


class OAuthError(Exception):
    """An OAuth-shaped error (RFC 6749 ``{error, error_description}``). Raised deep in the
    call tree and converted to an :class:`AuthResponse` at the endpoint boundary — the core
    dispatcher only renders ``APIError`` as ``{code, message}``, which is the wrong shape."""

    def __init__(
        self,
        status: int,
        error: str,
        description: str,
        *,
        error_uri: str | None = None,
        headers: list[tuple[str, str]] | None = None,
    ) -> None:
        super().__init__(description)
        self.status = status
        self.error = error
        self.description = description
        self.error_uri = error_uri
        self.headers = headers

    def to_response(self) -> AuthResponse:
        return _oauth_error(
            self.status,
            self.error,
            self.description,
            error_uri=self.error_uri,
            headers=self.headers,
        )


def _oauth_error(
    status: int,
    error: str,
    description: str,
    *,
    error_uri: str | None = None,
    headers: list[tuple[str, str]] | None = None,
) -> AuthResponse:
    """OAuth-shaped error body (device-authorization precedent), optionally with ``error_uri``
    and extra headers (e.g. ``WWW-Authenticate`` on a 401)."""
    body: dict[str, Any] = {"error": error, "error_description": description}
    if error_uri is not None:
        body["error_uri"] = error_uri
    return AuthResponse(status=status, body=body, headers=list(headers or []))


def format_error_url(
    url: str,
    error: str,
    description: str,
    state: str | None = None,
    iss: str | None = None,
) -> str:
    """Build ``redirect_uri?error&error_description[&state][&iss]`` — TS ``formatErrorURL``."""
    params: Pairs = [("error", error), ("error_description", description)]
    if state:
        params.append(("state", state))
    if iss:
        params.append(("iss", iss))
    sep = "&" if "?" in url else "?"
    return f"{url}{sep}{urlencode(params, quote_via=quote_plus)}"


def handle_redirect(ctx: Ctx, uri: str) -> AuthResponse:
    """Fetch/JSON callers get ``{redirect: true, url}``; browsers get a real redirect — TS
    ``handleRedirect`` (``sec-fetch-mode: cors`` or ``Accept: application/json``)."""
    headers = ctx.request.headers
    from_fetch = headers.get("sec-fetch-mode") == "cors"
    accept_json = "application/json" in (headers.get("accept") or "")
    if from_fetch or accept_json:
        return AuthResponse(body={"redirect": True, "url": uri})
    return AuthResponse(status=302, redirect_to=uri)


# --- signatures + constant time (items 3, 6) -----------------------------------------


def make_signature(value: str, secret: str) -> str:
    """Public wrapper over the port's padded-base64 HMAC-SHA256 (``crypto._signature``, arg
    order flipped) — byte-identical to TS ``makeSignature(value, secret)`` (``btoa(hmac)``)."""
    return _signature(secret, value)


def constant_time_equal(a: str, b: str) -> bool:
    """Length-independent constant-time compare — TS ``constantTimeEqual``. For the ASCII
    base64 signatures/hashes this plugin compares, code-point iteration equals UTF-8 bytes.

    ponytail: reuses crypto's ``_constant_time_equal`` (OTP variant); swap for a byte-level
    compare if a non-ASCII value ever flows through here (none do today)."""
    return _constant_time_equal(a, b)


def sign_oauth_query(
    pairs: Pairs,
    secret: str,
    *,
    exp: int,
    issued_at_ms: int,
    post_login_cleared_for_session: str | None = None,
) -> str:
    """Sign an authorization query — TS ``signParams`` (``authorize.ts``). Appends ``exp`` and
    ``ba_iat``, an optional session-bound ``ba_pl`` marker, declares the signed param names,
    signs the canonical form, and appends ``sig``. Reserved markers are stripped first so a
    client can never smuggle ``sig``/``ba_pl``."""
    reserved = {"sig", "exp", SIGNED_QUERY_ISSUED_AT_PARAM, POST_LOGIN_CLEARED_PARAM}
    params: Pairs = [(k, v) for k, v in pairs if k not in reserved]
    params.append(("exp", str(exp)))
    params.append((SIGNED_QUERY_ISSUED_AT_PARAM, str(issued_at_ms)))
    if post_login_cleared_for_session:
        params.append((POST_LOGIN_CLEARED_PARAM, post_login_cleared_for_session))
    params = set_signed_oauth_query_parameter_names(params)
    signature = make_signature(canonicalize_oauth_query_params(params), secret)
    params.append(("sig", signature))
    return urlencode(params, quote_via=quote_plus)


def verify_oauth_query_params(oauth_query: str, secret: str) -> bool:
    """Verify a signed query — TS ``verifyOAuthQueryParams``: exactly one ``sig``, constant-time
    match over the canonicalized remainder, and ``exp`` not in the past."""
    pairs = parse_query(oauth_query)
    sigs = [v for k, v in pairs if k == "sig"]
    exp_raw = next((v for k, v in pairs if k == "exp"), None)
    try:
        exp_ms = (float(exp_raw) if exp_raw not in (None, "") else 0.0) * 1000
    except ValueError:
        exp_ms = float("nan")  # JS Number("abc") -> NaN -> comparison is false
    remaining = [(k, v) for k, v in pairs if k != "sig"]
    verify_sig = make_signature(canonicalize_oauth_query_params(remaining), secret)
    now_ms = utcnow().timestamp() * 1000
    return (
        len(sigs) == 1
        and bool(sigs[0])
        and constant_time_equal(sigs[0], verify_sig)
        and exp_ms >= now_ms
    )


# --- HTTP Basic client credentials (item 6) ------------------------------------------


def basic_to_client_credentials(authorization: str) -> dict[str, str] | None:
    """Decode an HTTP Basic ``id:secret`` header — TS ``basicToClientCredentials``
    (``utils/index.ts:391``). Returns ``None`` when the header is not Basic; raises
    :class:`OAuthError` on a malformed pair."""
    if not authorization.startswith("Basic "):
        return None
    import base64

    encoded = authorization[len("Basic ") :]
    try:
        decoded = base64.b64decode(encoded).decode()
    except Exception:
        raise OAuthError(400, "invalid_client", "invalid authorization header format") from None
    sep = decoded.find(":")
    if sep == -1:
        raise OAuthError(400, "invalid_client", "invalid authorization header format")
    client_id, client_secret = decoded[:sep], decoded[sep + 1 :]
    if not client_id or not client_secret:
        raise OAuthError(400, "invalid_client", "invalid authorization header format")
    return {"client_id": client_id, "client_secret": client_secret}


# --- SafeUrl scheme policy (item 4) --------------------------------------------------

#: TS ``@better-auth/core/utils/url`` DANGEROUS_URL_SCHEMES.
DANGEROUS_URL_SCHEMES = ("javascript:", "data:", "vbscript:")


def _host_only(netloc: str) -> str:
    if netloc.startswith("["):  # [::1]:port
        return netloc[1 : netloc.index("]")] if "]" in netloc else netloc[1:]
    return netloc.rsplit(":", 1)[0] if ":" in netloc else netloc


def is_loopback_host(netloc: str) -> bool:
    """Loopback per RFC 6761/8252 — ``127.0.0.0/8``, ``[::1]``, ``localhost``/``*.localhost``.
    DNS ``localhost`` counts here (SafeUrl HTTP allowance), unlike the authorize loopback-IP
    redirect match which is IP-literal only."""
    host = _host_only(netloc).lower()
    if host == "localhost" or host.endswith(".localhost"):
        return True
    if host == "::1":
        return True
    return host == "127.0.0.1" or host.startswith("127.")


def is_safe_url(value: str) -> bool:
    """Port of ``SafeUrlSchema`` — rejects ``javascript:``/``data:``/``vbscript:``, rejects a
    fragment component, and requires HTTPS except for loopback hosts. Custom app schemes
    (``myapp://cb``) pass."""
    if not isinstance(value, str):
        return False
    parts = urlsplit(value)
    if not parts.scheme:
        return False  # z.url() rejects relative URLs
    scheme = parts.scheme.lower() + ":"
    if scheme in DANGEROUS_URL_SCHEMES:
        return False
    if "#" in value:
        return False
    return not (scheme == "http:" and not is_loopback_host(parts.netloc))


# --- jwt plugin lookup (item 2) ------------------------------------------------------


def get_jwt_plugin(auth: BetterAuth) -> Any:
    """Return the installed ``jwt`` plugin instance, or raise if absent — TS ``getJwtPlugin``
    (``jwt_config`` error). The provider is JWT-first; ``disableJwtPlugin`` is unsupported in
    this port (rejected at plugin init), so the jwt plugin must be present."""
    plugin = next((p for p in auth.plugins if getattr(p, "id", None) == "jwt"), None)
    if plugin is None:
        raise ValueError(
            "oauth-provider requires the jwt plugin to be installed (disableJwtPlugin is "
            "unsupported in this port)"
        )
    return plugin


# --- client secret storage (item 8) --------------------------------------------------


async def _maybe_await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


def _client_secret_prefix(opts: Any) -> str | None:
    prefix = getattr(opts, "prefix", None) or {}
    return prefix.get("clientSecret") if isinstance(prefix, dict) else None


async def store_client_secret(opts: Any, client_secret: str) -> str:
    """Store a client secret per ``store_client_secret`` — default ``"hashed"`` via
    ``default_key_hasher`` (base64url-nopad SHA-256), or a custom ``{"hash": fn}`` object.
    ``"encrypted"`` is blocked in this port (see BINDING DECISIONS)."""
    method = getattr(opts, "store_client_secret", None) or "hashed"
    if method == "hashed":
        return default_key_hasher(client_secret)
    if isinstance(method, dict) and "hash" in method:
        return await _maybe_await(method["hash"](client_secret))
    if method == "encrypted" or (isinstance(method, dict) and "encrypt" in method):
        raise ValueError(
            "store_client_secret 'encrypted' is not supported in this port "
            "(blocked on secrets-rotation backlog); use 'hashed' or a custom {hash, verify}"
        )
    raise ValueError(f"unsupported store_client_secret: {method!r}")


async def verify_client_secret(opts: Any, stored: str, provided: str | None) -> bool:
    """Constant-time verify a presented secret against the stored value — TS
    ``verifyStoredClientSecret``. Strips ``prefix.clientSecret`` first (never stored); a
    present-but-mismatched prefix is a hard reject."""
    method = getattr(opts, "store_client_secret", None) or "hashed"
    prefix = _client_secret_prefix(opts)
    if provided and prefix:
        if provided.startswith(prefix):
            provided = provided[len(prefix) :]
        else:
            raise OAuthError(401, "invalid_client", "invalid client_secret")

    if method == "hashed":
        if not provided:
            return False
        return constant_time_equal(default_key_hasher(provided), stored)
    if isinstance(method, dict) and "hash" in method:
        verify = method.get("verify")
        if verify is not None:
            return bool(provided) and await _maybe_await(verify(provided, stored))
        if not provided:
            return False
        return constant_time_equal(await _maybe_await(method["hash"](provided)), stored)
    raise ValueError(f"unsupported store_client_secret: {method!r}")


# --- client id/secret generation (item 8) --------------------------------------------

#: TS ``generateRandomString(32, "a-z", "A-Z")`` charset.
CLIENT_ID_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"


def generate_client_id(opts: Any) -> str:
    gen = getattr(opts, "generate_client_id", None)
    if gen is not None:
        return gen()
    return generate_random_string(32, CLIENT_ID_ALPHABET)


def generate_client_secret(opts: Any) -> str:
    gen = getattr(opts, "generate_client_secret", None)
    if gen is not None:
        return gen()
    return generate_random_string(32, CLIENT_ID_ALPHABET)


def apply_client_secret_prefix(opts: Any, client_secret: str) -> str:
    """Prepend ``prefix.clientSecret`` to the returned (never stored) secret."""
    return (_client_secret_prefix(opts) or "") + client_secret


def is_loopback_ip(host: str) -> bool:
    """RFC 8252 §7.3 loopback IP literal — ``127.0.0.0/8`` or ``::1`` ONLY. DNS names
    (``localhost``) are excluded (§8.3) — TS ``isLoopbackIP``. Used by the authorize
    redirect_uri port-agnostic match, distinct from :func:`is_loopback_host` (SafeUrl)."""
    stripped = host[1:-1] if host.startswith("[") and host.endswith("]") else host
    try:
        ip = ipaddress.ip_address(stripped)
    except ValueError:
        return False
    if ip == ipaddress.IPv6Address("::1"):
        return True
    return ip.version == 4 and ip in ipaddress.ip_network("127.0.0.0/8")


def parse_prompt(prompt: str) -> set[str]:
    """Parse a space-separated ``prompt`` into the set of valid values — TS ``parsePrompt``."""
    return {p.strip() for p in prompt.split(" ") if p.strip() in _PROMPTS}


def remove_prompt_from_query(pairs: Pairs, prompt: str) -> Pairs:
    """Return ``pairs`` with ``prompt`` removed from the space-separated ``prompt`` value
    (dropping the key entirely if it becomes empty) — TS ``removePromptFromQuery``."""
    result: Pairs = []
    for key, value in pairs:
        if key != "prompt":
            result.append((key, value))
            continue
        remaining = [p for p in value.split(" ") if p and p != prompt]
        if remaining:
            result.append(("prompt", " ".join(remaining)))
    return result


def normalize_timestamp_value(value: Any) -> datetime | None:
    """Coerce an adapter timestamp (datetime / epoch-ms number / ISO or numeric string)
    into an aware datetime — TS ``normalizeTimestampValue``. Returns ``None`` when unusable."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(value / 1000, tz=timezone.utc)
        except (ValueError, OverflowError, OSError):
            return None
    if isinstance(value, str):
        trimmed = value.strip()
        if not trimmed:
            return None
        try:
            return datetime.fromtimestamp(float(trimmed) / 1000, tz=timezone.utc)
        except (ValueError, OverflowError, OSError):
            pass
        try:
            return datetime.fromisoformat(trimmed.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def search_params_to_query(pairs: Pairs) -> dict[str, Any]:
    """Collapse ordered pairs into a query dict, keeping multi-valued keys as lists — TS
    ``searchParamsToQuery``."""
    grouped: dict[str, list[str]] = {}
    for key, value in pairs:
        grouped.setdefault(key, []).append(value)
    return {k: (v[0] if len(v) == 1 else v) for k, v in grouped.items()}


def client_allows_grant(client: dict[str, Any], grant_type: str) -> bool:
    """Whether a client may use ``grant_type`` — TS ``clientAllowsGrant``. Unset ``grantTypes``
    defaults to ``["authorization_code"]``; a client allowing ``authorization_code`` implicitly
    allows ``refresh_token`` (refresh is only ever issued through the auth-code flow)."""
    allowed = client.get("grantTypes") or ["authorization_code"]
    if grant_type == "refresh_token" and "authorization_code" in allowed:
        return True
    return grant_type in allowed


#: TS ``PKCERequirementErrors`` messages (surfaced as the ``invalid_request`` reason).
PKCE_PUBLIC_CLIENT = "pkce is required for public clients"
PKCE_OFFLINE_ACCESS = "pkce is required when requesting offline_access scope"
PKCE_CLIENT_REQUIRE = "pkce is required for this client"


def is_pkce_required(client: dict[str, Any], requested_scopes: list[str] | None) -> str | None:
    """Return the reason PKCE is required, or ``None`` if not — TS ``isPKCERequired``.
    Public clients, ``offline_access`` scope, and ``requirePKCE ?? True`` each force it."""
    is_public = (
        client.get("tokenEndpointAuthMethod") == "none"
        or client.get("type") in ("native", "user-agent-based")
        or client.get("public") is True
    )
    if is_public:
        return PKCE_PUBLIC_CLIENT
    if requested_scopes and "offline_access" in requested_scopes:
        return PKCE_OFFLINE_ACCESS
    require = client.get("requirePKCE")
    if require is None or require is True:
        return PKCE_CLIENT_REQUIRE
    return None


async def store_token(store_tokens: Any, token: str, token_type: str) -> str:
    """Hash a token for at-rest storage — TS ``storeToken``. Default ``"hashed"`` uses
    ``default_key_hasher`` (base64url-nopad SHA-256); a custom ``{"hash": fn}`` receives
    ``(token, type)``."""
    method = store_tokens or "hashed"
    if method == "hashed":
        return default_key_hasher(token)
    if isinstance(method, dict) and "hash" in method:
        return await _maybe_await(method["hash"](token, token_type))
    raise ValueError(f"storeToken: unsupported storageMethod type {method!r}")


def parse_client_metadata(metadata: str | dict | None) -> dict | None:
    """Tolerant parse of the ``metadata`` JSON column — TS ``parseClientMetadata`` (handles
    adapters that auto-parse JSON)."""
    if not metadata:
        return None
    if isinstance(metadata, str):
        try:
            return json.loads(metadata)
        except ValueError:
            return None
    return metadata


# --- pairwise subject identifier (utils/index.ts:564-609) ----------------------------


def resolve_subject_identifier(client: dict[str, Any], opts: Any, user_id: str) -> str:
    """Return the subject identifier for a user+client pair — TS ``resolveSubjectIdentifier``.
    Pairwise (``sub = makeSignature(f"{sectorHost}.{userId}", pairwiseSecret)``, sector = host of
    the first redirect_uri) only when the client opts in AND the server has ``pairwise_secret``;
    otherwise the real ``user.id``."""
    secret = getattr(opts, "pairwise_secret", None)
    if client.get("subjectType") == "pairwise" and secret:
        uris = client.get("redirectUris") or []
        if not uris:
            raise ValueError("Client has no redirect URIs for sector identifier")
        sector = urlsplit(uris[0]).netloc
        return make_signature(f"{sector}.{user_id}", secret)
    return user_id


# --- server-side JWT-access-token verify (item 5) ------------------------------------


class JwsAccessTokenInvalid(Exception):
    """The token is not a verifiable JWS (bad structure / signature / unknown key). The caller
    falls through to opaque-token handling — TS ``JWSInvalid``/``TypeError`` path."""


class JwsAccessTokenExpired(Exception):
    """A cryptographically valid but expired access token — introspection reports it inactive
    rather than erroring (OAuth semantics; TS ``JWTExpired``)."""


class JwsAccessTokenClaimInvalid(Exception):
    """Signature verified but issuer/audience mismatch — inactive (TS ``JWTInvalid``)."""


#: Instance-keyed cache of verify keys ({kid: Ed25519PublicKey}) so repeated introspections
#: read the signing keys once per jwt-plugin instance (TS ``jwksCacheKey: jwtPlugin``).
_verify_key_cache: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()


async def _load_verify_keys(jwt_plugin: Any, *, refresh: bool = False) -> dict[str, Any]:
    cache = None if refresh else _verify_key_cache.get(jwt_plugin)
    if cache is None:
        cache = {}
        for key in await jwt_plugin._get_all_keys():
            public_jwk = json.loads(key["publicKey"])
            cache[key["id"]] = Ed25519PublicKey.from_public_bytes(
                b64url_decode_nopad(public_jwk["x"])
            )
        _verify_key_cache[jwt_plugin] = cache
    return cache


async def verify_jws_access_token(
    jwt_plugin: Any,
    token: str,
    *,
    audience: str | list[str],
    issuer: str,
) -> dict[str, Any]:
    """Verify an OAuth JWT access token against the jwt plugin's local signing keys with OAuth
    semantics — TS ``verifyJwsAccessToken``. Raises :class:`JwsAccessTokenInvalid` (structural /
    signature failure -> try opaque), :class:`JwsAccessTokenExpired`, or
    :class:`JwsAccessTokenClaimInvalid` (iss/aud mismatch). The ``azp`` client-binding gate is
    enforced by the caller, not here."""
    try:
        header = pyjwt.get_unverified_header(token)
    except Exception as exc:  # not a JWT at all
        raise JwsAccessTokenInvalid(str(exc)) from exc
    kid = header.get("kid")
    if not kid:
        raise JwsAccessTokenInvalid("missing kid")

    keys = await _load_verify_keys(jwt_plugin)
    public_key = keys.get(kid)
    if public_key is None:  # key rotated in since last cache -> refetch once
        keys = await _load_verify_keys(jwt_plugin, refresh=True)
        public_key = keys.get(kid)
    if public_key is None:
        raise JwsAccessTokenInvalid("unknown kid")

    auds = list(audience) if isinstance(audience, (list, tuple)) else [audience]
    try:
        return pyjwt.decode(token, public_key, algorithms=["EdDSA"], audience=auds, issuer=issuer)
    except pyjwt.ExpiredSignatureError as exc:
        raise JwsAccessTokenExpired() from exc
    except (pyjwt.InvalidAudienceError, pyjwt.InvalidIssuerError) as exc:
        raise JwsAccessTokenClaimInvalid() from exc
    except Exception as exc:  # bad signature / malformed -> likely an opaque token
        raise JwsAccessTokenInvalid(str(exc)) from exc
