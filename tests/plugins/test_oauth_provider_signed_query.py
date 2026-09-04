"""oauth-provider signed-query codec + verify.

Verified against TS ``packages/oauth-provider/src/signed-query.ts``,
``signed-query.test.ts``, and ``utils/index.ts`` (verifyOAuthQueryParams) at v1.6.23.
"""

from __future__ import annotations

import time

from better_auth.plugins_ext.oauth_provider.signed_query import (
    build_signed_oauth_query,
    canonicalize_oauth_query_params,
    set_signed_oauth_query_parameter_names,
)
from better_auth.plugins_ext.oauth_provider.utils import (
    make_signature,
    sign_oauth_query,
    verify_oauth_query_params,
)

SECRET = "test-secret-0123456789-abcdefghijklmnop"


# --- canonicalization (signed-query.test.ts) -----------------------------------------


def test_canonicalizes_repeated_params_by_key_and_value():
    pairs = [
        ("resource", "https://b.example.com"),
        ("client_id", "client-a"),
        ("resource", "https://a.example.com"),
    ]
    assert canonicalize_oauth_query_params(pairs) == (
        "client_id=client-a"
        "&resource=https%3A%2F%2Fa.example.com"
        "&resource=https%3A%2F%2Fb.example.com"
    )


def test_builds_oauth_query_from_declared_signed_params():
    signed = [
        ("client_id", "client-a"),
        ("custom_authorization_context", "tenant-a"),
        ("resource", "https://api.example.com"),
        ("exp", "123"),
    ]
    signed = set_signed_oauth_query_parameter_names(signed)
    signed.append(("sig", "test-sig"))
    # reorder + inject an unsigned param
    reordered = list(reversed(signed))
    reordered.append(("utm_email", "user@example.com"))
    query = build_signed_oauth_query("&".join(f"{k}={v}" for k, v in reordered))
    assert query is not None
    from urllib.parse import parse_qs

    parsed = parse_qs(query)
    assert parsed["custom_authorization_context"] == ["tenant-a"]
    assert parsed["resource"] == ["https://api.example.com"]
    assert "utm_email" not in parsed
    assert "custom_authorization_context" in parsed["ba_param"]


def test_ignores_legacy_signed_queries_without_declared_signed_params():
    assert build_signed_oauth_query("client_id=client-a&sig=test-sig") is None


# --- make_signature (crypto _signature arg-flip) -------------------------------------


def test_make_signature_matches_padded_base64_hmac():
    from better_auth.crypto import _signature

    assert make_signature("payload", SECRET) == _signature(SECRET, "payload")
    assert make_signature("payload", SECRET).endswith("=")


# --- verify (verify/tamper/duplicate-sig/reorder vectors) ----------------------------


def _signed(**params):
    now = int(time.time())
    return sign_oauth_query(list(params.items()), SECRET, exp=now + 600, issued_at_ms=now * 1000)


def test_verify_accepts_valid_signed_query():
    query = _signed(client_id="client-a", redirect_uri="https://app.example.com/cb")
    assert verify_oauth_query_params(query, SECRET) is True


def test_verify_survives_param_reordering():
    query = _signed(client_id="client-a", resource="https://api.example.com", state="xyz")
    from urllib.parse import parse_qsl, urlencode

    reordered = urlencode(list(reversed(parse_qsl(query, keep_blank_values=True))))
    assert verify_oauth_query_params(reordered, SECRET) is True


def test_verify_rejects_tampered_param():
    query = _signed(client_id="client-a", redirect_uri="https://app.example.com/cb")
    tampered = query.replace("client-a", "client-evil")
    assert verify_oauth_query_params(tampered, SECRET) is False


def test_verify_rejects_duplicate_sig():
    query = _signed(client_id="client-a")
    sig = dict(__import__("urllib.parse", fromlist=["parse_qsl"]).parse_qsl(query))["sig"]
    doubled = f"{query}&sig={sig}"
    assert verify_oauth_query_params(doubled, SECRET) is False


def test_verify_rejects_expired_query():
    past = int(time.time()) - 10
    query = sign_oauth_query(
        [("client_id", "client-a")], SECRET, exp=past, issued_at_ms=int(time.time() * 1000)
    )
    assert verify_oauth_query_params(query, SECRET) is False


def test_verify_rejects_wrong_secret():
    query = _signed(client_id="client-a")
    assert verify_oauth_query_params(query, "another-secret-that-is-long-enough-xx") is False
