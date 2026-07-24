"""Signed-query canonicalization + declared-param-names codec.

Port of TS ``packages/oauth-provider/src/signed-query.ts`` (v1.6.23). The provider
redirects the user-agent to app-hosted login/consent pages carrying the authorization
query **signed** (cookie-free, native-app friendly); this module is the pure codec that
canonicalizes and declares which parameter names are covered by the signature. The HMAC
signing/verification lives in :mod:`.utils` (they need the crypto seam).

``URLSearchParams`` maps to an ordered ``list[tuple[str, str]]`` — multi-valued keys and
insertion order are preserved exactly as TS relies on.
"""

from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import parse_qsl, quote_plus, urlencode

#: TS ``signedQueryIssuedAtParam`` — issued-at (ms) marker.
SIGNED_QUERY_ISSUED_AT_PARAM = "ba_iat"
#: TS ``postLoginClearedParam`` — server-minted, session-bound post-login-cleared marker.
POST_LOGIN_CLEARED_PARAM = "ba_pl"
#: TS ``signedQueryParameterNameParam`` — declares which param names the sig covers.
SIGNED_PARAM_NAME_PARAM = "ba_param"

Pairs = list[tuple[str, str]]


def parse_query(query: str) -> Pairs:
    """Parse a query string into ordered (key, value) pairs (blank values kept)."""
    return parse_qsl(query.lstrip("?"), keep_blank_values=True)


def canonicalize_oauth_query_params(pairs: Pairs) -> str:
    """Sort by key then value and re-encode — TS ``canonicalizeOAuthQueryParams``.

    Python tuple-sort ``(key, value)`` is exactly TS's key-then-value comparator; for the
    ASCII query params OAuth carries it is byte-identical to JS UTF-16 code-unit ordering.
    ``urlencode`` (``quote_plus``) reproduces ``URLSearchParams.toString()`` for these values.
    """
    ordered = sorted(pairs, key=lambda kv: (kv[0], kv[1]))
    return urlencode(ordered, quote_via=quote_plus)


def set_signed_oauth_query_parameter_names(pairs: Pairs) -> Pairs:
    """Declare the signed param names via repeated ``ba_param`` entries — TS
    ``setSignedOAuthQueryParameterNames``. Drops any existing declaration, then appends one
    ``ba_param=<name>`` per sorted-unique remaining key (including ``ba_param`` itself)."""
    filtered = [(k, v) for k, v in pairs if k != SIGNED_PARAM_NAME_PARAM]
    names = sorted({k for k, _ in filtered} | {SIGNED_PARAM_NAME_PARAM})
    return filtered + [(SIGNED_PARAM_NAME_PARAM, name) for name in names]


def _get_signed_parameter_names(pairs: Pairs) -> set[str] | None:
    names = {v for k, v in pairs if k == SIGNED_PARAM_NAME_PARAM}
    return names or None


def build_signed_oauth_query(search: str) -> str | None:
    """Extract only the signed params from a returned page query — TS
    ``buildSignedOAuthQuery``. Returns ``None`` for legacy/unsigned queries (no ``sig`` or no
    ``ba_param`` declaration). Keeps ``sig``, ``ba_param``, and every declared name; drops
    any front-channel param the signature did not cover."""
    pairs = parse_query(search)
    if not any(k == "sig" for k, _ in pairs):
        return None
    signed_names = _get_signed_parameter_names(pairs)
    if signed_names is None:
        return None
    kept = [
        (k, v)
        for k, v in pairs
        if k == "sig" or k == SIGNED_PARAM_NAME_PARAM or k in signed_names
    ]
    return urlencode(kept, quote_via=quote_plus)


def get_signed_query_issued_at(oauth_query: str) -> datetime | None:
    """Parse ``ba_iat`` (epoch ms) into a datetime — TS ``getSignedQueryIssuedAt``.
    Returns ``None`` when absent or non-positive/non-finite."""
    raw = next((v for k, v in parse_query(oauth_query) if k == SIGNED_QUERY_ISSUED_AT_PARAM), None)
    if not raw:
        return None
    try:
        issued_at = float(raw)
    except ValueError:
        return None
    if issued_at <= 0:
        return None
    return datetime.fromtimestamp(issued_at / 1000, tz=timezone.utc)
