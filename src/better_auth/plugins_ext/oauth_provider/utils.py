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
import re
import weakref
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qsl, quote_plus, unquote_plus, urlencode, urlsplit

import jwt as pyjwt

from ...crypto import (
    _constant_time_equal,
    _signature,
    default_key_hasher,
    generate_random_string,
    symmetric_decrypt,
    symmetric_encrypt,
)
from ...session import utcnow
from ...types import AuthResponse, Ctx
from ..jwt import key_from_jwk
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


def append_query_params(url: str, params: Pairs) -> str:
    """Append ``params`` before the fragment, keeping the existing query text, TS core
    ``appendQueryParams`` (utils/url.ts:61). An empty http(s) path becomes ``/`` like
    ``URL.href``."""
    query = urlencode(params, quote_via=quote_plus)
    if not query:
        return url
    base, hash_mark, fragment = url.partition("#")
    parts = urlsplit(base)
    if not base.startswith("/") and parts.scheme.lower() in ("http", "https") and not parts.path:
        base = base.split("?", 1)[0] + "/" + (f"?{parts.query}" if parts.query else "")
    head, _, existing = base.partition("?")
    search = f"{existing}{'' if existing.endswith('&') else '&'}{query}" if existing else query
    return f"{head}?{search}{hash_mark}{fragment}"


def format_error_url(
    url: str,
    error: str,
    description: str,
    state: str | None = None,
    iss: str | None = None,
    mode: str = "query",
) -> str:
    """Build ``redirect_uri?error&error_description[&state][&iss]``, or the same parameters in
    the fragment for ``mode="fragment"``, TS ``formatErrorURL`` (authorize.ts:76)."""
    params: Pairs = [("error", error), ("error_description", description)]
    if state:
        params.append(("state", state))
    if iss:
        params.append(("iss", iss))
    if mode == "fragment":
        return f"{url}#{urlencode(params, quote_via=quote_plus)}"
    return append_query_params(url, params)


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


# --- client authentication parameters (utils/index.ts:500-965) ----------------------

CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

#: TS core ``PRIVATE_KEY_JWT_SIGNING_ALGORITHMS`` (oauth2/client-assertion.ts:6).
PRIVATE_KEY_JWT_SIGNING_ALGORITHMS = (
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
    "EdDSA",
)

#: RFC 7235 §2.1: the scheme is case-insensitive and followed by one or more SP.
_BASIC_SCHEME_PREFIX = re.compile(r"^Basic +", re.IGNORECASE)
_BASIC_AUTHORIZATION = re.compile(r"^Basic +(.*)$", re.IGNORECASE)
_AUTH_SCHEME_TOKEN = re.compile(r"^([!#$%&'*+\-.^_`|~0-9A-Za-z]+)(?=\s|$)")
_CLIENT_AUTHENTICATION_FIELDS = ("client_secret", "client_assertion", "client_assertion_type")


def _decode_basic_credentials(authorization: str) -> tuple[str, str]:
    """TS core ``decodeBasicCredentials`` (oauth2/basic-credentials.ts:60): split on the first
    ``:``, both halves non-empty, each half form-url-decoded (RFC 6749 §2.3.1)."""
    import base64

    match = _BASIC_AUTHORIZATION.match(authorization)
    if not match:
        raise ValueError("Authorization header is not a Basic credential")
    decoded = base64.b64decode(match.group(1) + "===").decode("utf-8", "replace")
    client_id, sep, client_secret = decoded.partition(":")
    if not sep or not client_id or not client_secret:
        raise ValueError("Basic credential client id and secret must both be non-empty")
    return unquote_plus(client_id), unquote_plus(client_secret)


def basic_to_client_credentials(authorization: str) -> dict[str, str] | None:
    """Decode an HTTP Basic ``id:secret`` header — TS ``basicToClientCredentials``
    (utils/index.ts:621). ``None`` when the header is not Basic; a malformed pair is a 401
    ``invalid_client`` challenged with ``WWW-Authenticate: Basic``."""
    if not _BASIC_SCHEME_PREFIX.match(authorization):
        return None
    try:
        client_id, client_secret = _decode_basic_credentials(authorization)
    except Exception:
        raise OAuthError(
            401,
            "invalid_client",
            "invalid authorization header format",
            headers=[("WWW-Authenticate", "Basic")],
        ) from None
    return {"client_id": client_id, "client_secret": client_secret}


def throw_invalid_client(
    description: str, *, method: str | None = None, scheme: str | None = None
) -> OAuthError:
    """TS ``throwInvalidClient`` (utils/index.ts:688): a 401 challenge when the caller tried
    HTTP authentication (Basic or another scheme), otherwise a plain 400. Returned so callers
    ``raise`` it (keeps type checkers aware the branch ends)."""
    challenge = scheme or ("Basic" if method == "client_secret_basic" else None)
    if challenge:
        return OAuthError(
            401, "invalid_client", description, headers=[("WWW-Authenticate", challenge)]
        )
    return OAuthError(400, "invalid_client", description)


def _form_pairs(ctx: Ctx) -> list[tuple[str, str]] | None:
    ctype = (ctx.request.headers.get("content-type") or "").lower()
    if "application/x-www-form-urlencoded" not in ctype:
        return None
    return parse_qsl(ctx.request.body.decode("utf-8", "replace"), keep_blank_values=True)


def normalize_client_authentication_parameters(ctx: Ctx, body: dict[str, Any]) -> None:
    """Enforce RFC 6749 §2.3 credential cardinality in place, TS
    ``normalizeClientAuthenticationParameters`` (utils/index.ts:545). Empty values are dropped,
    repeated credentials and mixed authentication methods are ``invalid_request``."""

    def fail(description: str) -> OAuthError:
        return OAuthError(400, "invalid_request", description)

    client_id = body.get("client_id")
    if client_id == "":
        client_id = None
    if client_id is not None and not isinstance(client_id, str):
        raise fail("client_id must be a string")
    fields: dict[str, str] = {}
    for field in _CLIENT_AUTHENTICATION_FIELDS:
        value = body.get(field)
        if value is None or value == "":
            continue
        if not isinstance(value, str):
            raise fail(f"{field} must be a string")
        fields[field] = value

    has_authorization = bool(ctx.request.headers.get("authorization"))
    pairs = _form_pairs(ctx)
    if pairs is not None:
        ids = [v for k, v in pairs if k == "client_id" and v]
        if len(ids) > 1:
            raise fail("client_id must not be repeated")
        client_id = ids[0] if ids else None
        for field in _CLIENT_AUTHENTICATION_FIELDS:
            values = [v for k, v in pairs if k == field and v]
            if len(values) > 1:
                raise fail(f"{field} must not be repeated")
            if values:
                fields[field] = values[0]

    has_secret = "client_secret" in fields
    has_assertion = "client_assertion" in fields or "client_assertion_type" in fields
    if (has_authorization and (has_secret or has_assertion)) or (has_secret and has_assertion):
        raise fail("A request must use only one client authentication method")
    body["client_id"] = client_id
    for field in _CLIENT_AUTHENTICATION_FIELDS:
        body[field] = fields.get(field)


async def extract_client_credentials(
    ctx: Ctx, opts: Any, body: dict[str, Any], expected_audience: str
) -> dict[str, Any] | None:
    """Resolve how the client authenticates, TS ``extractClientCredentials``
    (utils/index.ts:861). Returns ``{kind, method, clientId[, clientSecret]}`` for
    ``private_key_jwt`` (``pre_verified``), Basic, post, or public ``none``; ``None`` when
    the request names no client.

    ponytail: extension client-authentication strategies (TS ``extensions.ts``) are not
    ported; only the built-in ``private_key_jwt`` assertion type is recognized."""
    body = dict(body)
    normalize_client_authentication_parameters(ctx, body)
    authorization = ctx.request.headers.get("authorization")

    if body.get("client_assertion_type") or body.get("client_assertion"):
        if not body.get("client_assertion") or not body.get("client_assertion_type"):
            raise OAuthError(
                400,
                "invalid_client",
                "client_assertion and client_assertion_type must both be provided",
            )
        from .client_assertion import verify_client_assertion

        client_id = await verify_client_assertion(
            ctx,
            opts,
            body["client_assertion"],
            body["client_assertion_type"],
            body.get("client_id"),
            expected_audience,
        )
        return {"kind": "pre_verified", "method": "private_key_jwt", "clientId": client_id}

    if authorization and not _BASIC_SCHEME_PREFIX.match(authorization):
        match = _AUTH_SCHEME_TOKEN.match(authorization)
        if not match:
            raise OAuthError(400, "invalid_request", "Invalid authorization header format")
        raise throw_invalid_client("unsupported authorization scheme", scheme=match.group(1))

    if authorization:
        creds = basic_to_client_credentials(authorization)
        if creds:
            return {
                "kind": "client_secret",
                "method": "client_secret_basic",
                "clientId": creds["client_id"],
                "clientSecret": creds["client_secret"],
            }

    if body.get("client_id") and body.get("client_secret"):
        return {
            "kind": "client_secret",
            "method": "client_secret_post",
            "clientId": body["client_id"],
            "clientSecret": body["client_secret"],
        }
    if body.get("client_id"):
        return {"kind": "public", "method": "none", "clientId": body["client_id"]}
    return None


def destructure_credentials(credentials: dict[str, Any] | None) -> dict[str, Any]:
    """TS ``destructureCredentials`` (utils/index.ts:839)."""
    creds = credentials or {}
    return {
        "client_id": creds.get("clientId"),
        "client_secret": creds.get("clientSecret"),
        "pre_verified": creds.get("kind") == "pre_verified",
        "auth_method": creds.get("method"),
    }


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


def safe_url_issue(value: str) -> str | None:
    """The first ``SafeUrlSchema`` issue message for ``value`` (core utils/redirect-uri.ts:39),
    or ``None`` when it passes: an absolute URL, no ``javascript:``/``data:``/``vbscript:``, no
    fragment, and HTTPS except for loopback hosts. Custom app schemes (``myapp://cb``) pass."""
    parts = urlsplit(value.strip())
    if not parts.scheme:
        return "Invalid URL"  # z.url() rejects relative URLs
    scheme = parts.scheme.lower() + ":"
    if scheme in DANGEROUS_URL_SCHEMES:
        return "URL cannot use javascript:, data:, or vbscript: scheme"
    if "#" in value:
        return "Redirect URI must not contain a fragment component"
    if scheme == "http:" and not is_loopback_host(parts.netloc):
        return "Redirect URI must use HTTPS (HTTP allowed only for loopback hosts)"
    return None


def is_safe_url(value: str) -> bool:
    """Port of ``SafeUrlSchema`` as a predicate (see :func:`safe_url_issue`)."""
    return isinstance(value, str) and safe_url_issue(value) is None


# --- jwt plugin lookup (item 2) ------------------------------------------------------


def get_jwt_plugin(auth: BetterAuth) -> Any:
    """Return the installed ``jwt`` plugin instance, or raise if absent — TS ``getJwtPlugin``
    (``jwt_config`` error). The provider is JWT-first, so callers on the JWT-enabled path assume
    it is present; callers must gate this behind ``disable_jwt_plugin`` themselves (the disabled
    path signs with the client secret and installs no jwt plugin)."""
    plugin = next((p for p in auth.plugins if getattr(p, "id", None) == "jwt"), None)
    if plugin is None:
        raise ValueError("oauth-provider requires the jwt plugin to be installed")
    return plugin


def resolve_ctx_secret_config(ctx: Ctx) -> Any:
    """The versioned ``SecretConfig`` (or plain-string secret) used to encrypt/decrypt stored
    client secrets — TS ``ctx.context.secretConfig``."""
    return getattr(ctx.auth, "secret_config", None) or ctx.auth.secret


def resolved_issuer(ctx: Ctx, opts: Any) -> str:
    """id_token / access-token / introspection ``iss`` — TS ``jwtPluginOptions?.jwt?.issuer ??
    ctx.context.baseURL``. When ``disable_jwt_plugin`` there is no jwt plugin, so the issuer is
    simply the base URL."""
    base = f"{ctx.auth.base_url}{ctx.auth.base_path}"
    if getattr(opts, "disable_jwt_plugin", False):
        return base
    return getattr(get_jwt_plugin(ctx.auth), "issuer", None) or base


# --- client secret storage (item 8) --------------------------------------------------


async def _maybe_await(value: Any) -> Any:
    return await value if inspect.isawaitable(value) else value


def _client_secret_prefix(opts: Any) -> str | None:
    prefix = getattr(opts, "prefix", None) or {}
    return prefix.get("clientSecret") if isinstance(prefix, dict) else None


async def store_client_secret(opts: Any, client_secret: str, secret_config: Any = None) -> str:
    """Store a client secret per ``store_client_secret`` — TS ``storeClientSecret``
    (utils/index.ts:314). ``"hashed"`` (default) hashes via ``default_key_hasher``;
    ``"encrypted"`` symmetric-encrypts with ``secret_config`` (``str`` or ``SecretConfig``);
    a custom ``{"hash": fn}`` or ``{"encrypt": fn}`` object delegates.

    The plugin init guard (oauth.ts:157-178) rejects ``"encrypted"``/``{encrypt}`` while the
    jwt plugin is enabled, and this port rejects ``disable_jwt_plugin`` outright — so at
    runtime only the hashed/{hash} branches are reachable; the encrypt branches exist for the
    util-level API (and the future HS256 path)."""
    method = getattr(opts, "store_client_secret", None) or "hashed"
    if method == "encrypted":
        return symmetric_encrypt(secret_config, client_secret)
    if method == "hashed":
        return default_key_hasher(client_secret)
    if isinstance(method, dict) and "hash" in method:
        return await _maybe_await(method["hash"](client_secret))
    if isinstance(method, dict) and "encrypt" in method:
        return await _maybe_await(method["encrypt"](client_secret))
    raise ValueError(f"unsupported store_client_secret: {method!r}")


async def _decrypt_stored_client_secret(method: Any, stored: str, secret_config: Any) -> str:
    """TS ``decryptStoredClientSecret`` (utils/index.ts:213)."""
    if method == "encrypted":
        return symmetric_decrypt(secret_config, stored)
    if isinstance(method, dict) and "decrypt" in method:
        return await _maybe_await(method["decrypt"](stored))
    raise ValueError(f"Unsupported decryption storageMethod type {method!r}")


async def verify_client_secret(
    opts: Any, stored: str, provided: str | None, secret_config: Any = None
) -> bool:
    """Constant-time verify a presented secret against the stored value — TS
    ``verifyStoredClientSecret`` (utils/index.ts:237). Strips ``prefix.clientSecret`` first
    (never stored); a present-but-mismatched prefix is a hard reject. ``"encrypted"`` decrypts
    then constant-time compares, swallowing decrypt errors as ``False`` (matching the TS
    try/catch); a custom ``{"decrypt": fn}`` compares without the catch."""
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
    if method == "encrypted":
        try:
            decrypted = await _decrypt_stored_client_secret(method, stored, secret_config)
        except Exception:
            return False
        return bool(provided) and constant_time_equal(decrypted, provided)
    if isinstance(method, dict) and "decrypt" in method:
        decrypted = await _decrypt_stored_client_secret(method, stored, secret_config)
        return bool(provided) and constant_time_equal(decrypted, provided)
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


def remove_max_age_from_query(pairs: Pairs) -> Pairs:
    """TS ``removeMaxAgeFromQuery`` (utils/index.ts:1075)."""
    return [(k, v) for k, v in pairs if k != "max_age"]


def is_session_fresh_for_signed_query(session_created_at: Any, issued_at: datetime | None) -> bool:
    """A session created at or after the signed query was issued satisfies a forced
    re-authentication, TS ``isSessionFreshForSignedQuery`` (utils/index.ts:1052)."""
    if issued_at is None:
        return False
    normalized = normalize_timestamp_value(session_created_at)
    if normalized is None:
        return False
    return normalized.timestamp() >= issued_at.timestamp()


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
PKCE_OFFLINE_ACCESS = "pkce or OIDC nonce is required when requesting offline_access scope"
PKCE_CLIENT_REQUIRE = "pkce is required for this client"


def is_pkce_required(
    client: dict[str, Any], requested_scopes: list[str] | None, nonce: str | None = None
) -> str | None:
    """Return the reason PKCE is required, or ``None`` if not, TS ``isPKCERequired``
    (utils/index.ts:1107). Public clients always need it; ``offline_access`` needs it unless an
    OIDC request (``openid``) carries a ``nonce`` (dd42701af); ``requirePKCE ?? True`` last.

    ponytail: public detection still honors the legacy ``type``/``public`` columns; TS 1.7 keys
    on ``tokenEndpointAuthMethod == "none"`` only, which lands with the client-model package."""
    is_public = (
        client.get("tokenEndpointAuthMethod") == "none"
        or client.get("type") in ("native", "user-agent-based")
        or client.get("public") is True
    )
    if is_public:
        return PKCE_PUBLIC_CLIENT
    scopes = requested_scopes or []
    has_oidc_nonce = "openid" in scopes and isinstance(nonce, str) and len(nonce) > 0
    if "offline_access" in scopes and not has_oidc_nonce:
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


#: Instance-keyed cache of verify keys ({kid: public key}) so repeated introspections
#: read the signing keys once per jwt-plugin instance (TS ``jwksCacheKey: jwtPlugin``).
_verify_key_cache: weakref.WeakKeyDictionary = weakref.WeakKeyDictionary()


async def _load_verify_keys(jwt_plugin: Any, *, refresh: bool = False) -> dict[str, Any]:
    cache = None if refresh else _verify_key_cache.get(jwt_plugin)
    if cache is None:
        cache = {}
        for key in await jwt_plugin._get_all_keys():
            cache[key["id"]] = key_from_jwk(json.loads(key["publicKey"]))
        _verify_key_cache[jwt_plugin] = cache
    return cache


async def verify_jws_access_token(
    jwt_plugin: Any,
    token: str,
    *,
    audience: str | list[str] | None,
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

    # ``audience=None`` verifies signature + issuer only; the caller checks ``aud`` (TS 1.7).
    auds = list(audience) if isinstance(audience, (list, tuple)) else audience
    try:
        return pyjwt.decode(
            token,
            public_key,
            algorithms=[jwt_plugin._alg()],
            audience=auds,
            issuer=issuer,
            options={"verify_aud": audience is not None},
        )
    except pyjwt.ExpiredSignatureError as exc:
        raise JwsAccessTokenExpired() from exc
    except (pyjwt.InvalidAudienceError, pyjwt.InvalidIssuerError) as exc:
        raise JwsAccessTokenClaimInvalid() from exc
    except Exception as exc:  # bad signature / malformed -> likely an opaque token
        raise JwsAccessTokenInvalid(str(exc)) from exc
