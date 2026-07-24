"""Tests for the sso OIDC discovery pipeline + SSRF guards (Wave B).

TS source verified against:
  packages/sso/src/oidc/discovery.ts
  packages/sso/src/oidc/types.ts
  packages/sso/src/oidc/errors.ts
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from better_auth.plugins_ext.sso.discovery import (
    DiscoveryError,
    assert_endpoint_resolves_public,
    assert_oidc_endpoints_resolve_public,
    compute_discovery_url,
    discover_oidc_config,
    fetch_discovery_document,
    map_discovery_error_to_api_error,
    needs_runtime_discovery,
    normalize_discovery_urls,
    select_token_endpoint_auth_method,
    validate_discovery_document,
    validate_discovery_url,
    validate_skip_discovery_endpoints,
)

IDP = "http://localhost:8080"  # loopback => private; allowlisted via trusted origins


def trust_only(*origins: str):
    allowed = set(origins)

    def _pred(url: str) -> bool:
        for origin in allowed:
            if url == origin or url.startswith(origin + "/") or url.startswith(origin):
                return True
        return False

    return _pred


def full_doc(issuer: str = IDP, **overrides: Any) -> dict[str, Any]:
    doc = {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/authorize",
        "token_endpoint": f"{issuer}/token",
        "jwks_uri": f"{issuer}/jwks",
        "userinfo_endpoint": f"{issuer}/userinfo",
    }
    doc.update(overrides)
    return doc


def mock_http(response: httpx.Response) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(lambda _req: response))


# --- compute_discovery_url -----------------------------------------------------------


def test_compute_discovery_url_trailing_slash() -> None:
    assert (
        compute_discovery_url("https://idp.example.com")
        == "https://idp.example.com/.well-known/openid-configuration"
    )
    assert (
        compute_discovery_url("https://idp.example.com/")
        == "https://idp.example.com/.well-known/openid-configuration"
    )


# --- validate_skip_discovery_endpoints (SSRF gate on body endpoints) -----------------


def test_skip_endpoints_public_allowed() -> None:
    validate_skip_discovery_endpoints(
        {"tokenEndpoint": "https://idp.example.com/token"}, trust_only()
    )


def test_skip_endpoints_private_rejected() -> None:
    with pytest.raises(DiscoveryError) as exc:
        validate_skip_discovery_endpoints(
            {"tokenEndpoint": "http://127.0.0.1/token"}, trust_only()
        )
    assert exc.value.code == "discovery_private_host"


def test_skip_endpoints_private_allowlisted_via_trusted_origin() -> None:
    validate_skip_discovery_endpoints(
        {"tokenEndpoint": f"{IDP}/token"}, trust_only(IDP)
    )


def test_skip_endpoints_non_http_scheme_rejected() -> None:
    with pytest.raises(DiscoveryError) as exc:
        validate_skip_discovery_endpoints(
            {"jwksEndpoint": "ftp://idp.example.com/jwks"}, trust_only()
        )
    assert exc.value.code == "discovery_invalid_url"


def test_skip_endpoints_omitted_fields_skipped() -> None:
    validate_skip_discovery_endpoints({"tokenEndpoint": None}, trust_only())


# --- validate_discovery_url ----------------------------------------------------------


def test_validate_discovery_url_untrusted_rejected() -> None:
    with pytest.raises(DiscoveryError) as exc:
        validate_discovery_url("https://idp.example.com/.well-known", trust_only())
    assert exc.value.code == "discovery_untrusted_origin"


def test_validate_discovery_url_trusted_ok() -> None:
    validate_discovery_url(f"{IDP}/.well-known/openid-configuration", trust_only(IDP))


def test_validate_discovery_url_invalid() -> None:
    with pytest.raises(DiscoveryError) as exc:
        validate_discovery_url("not-a-url", trust_only())
    assert exc.value.code == "discovery_invalid_url"


# --- validate_discovery_document -----------------------------------------------------


def test_validate_document_ok() -> None:
    validate_discovery_document(full_doc(), IDP)


def test_validate_document_missing_fields() -> None:
    doc = full_doc()
    del doc["token_endpoint"]
    with pytest.raises(DiscoveryError) as exc:
        validate_discovery_document(doc, IDP)
    assert exc.value.code == "discovery_incomplete"


def test_validate_document_issuer_mismatch() -> None:
    with pytest.raises(DiscoveryError) as exc:
        validate_discovery_document(full_doc(issuer="http://evil.com"), IDP)
    assert exc.value.code == "issuer_mismatch"


def test_validate_document_issuer_trailing_slash_normalized() -> None:
    validate_discovery_document(full_doc(issuer=f"{IDP}/"), IDP)


# --- select_token_endpoint_auth_method -----------------------------------------------


def test_select_auth_existing_wins() -> None:
    assert (
        select_token_endpoint_auth_method(full_doc(), "client_secret_post")
        == "client_secret_post"
    )


def test_select_auth_basic_preferred() -> None:
    doc = full_doc(
        token_endpoint_auth_methods_supported=["client_secret_post", "client_secret_basic"]
    )
    assert select_token_endpoint_auth_method(doc) == "client_secret_basic"


def test_select_auth_post_when_only_post() -> None:
    doc = full_doc(token_endpoint_auth_methods_supported=["client_secret_post"])
    assert select_token_endpoint_auth_method(doc) == "client_secret_post"


def test_select_auth_default_basic() -> None:
    assert select_token_endpoint_auth_method(full_doc()) == "client_secret_basic"


# --- needs_runtime_discovery ---------------------------------------------------------


def test_needs_runtime_discovery() -> None:
    assert needs_runtime_discovery(None) is True
    assert needs_runtime_discovery({"tokenEndpoint": "t"}) is True  # missing others
    assert (
        needs_runtime_discovery(
            {"tokenEndpoint": "t", "jwksEndpoint": "j", "authorizationEndpoint": "a"}
        )
        is False
    )


# --- normalize_discovery_urls --------------------------------------------------------


def test_normalize_absolute_unchanged() -> None:
    out = normalize_discovery_urls(full_doc(), IDP, trust_only(IDP))
    assert out["token_endpoint"] == f"{IDP}/token"


def test_normalize_untrusted_rejected() -> None:
    doc = full_doc()
    doc["token_endpoint"] = "https://evil.com/token"
    with pytest.raises(DiscoveryError) as exc:
        normalize_discovery_urls(doc, IDP, trust_only(IDP))
    assert exc.value.code == "discovery_untrusted_origin"


# --- fetch_discovery_document (async) ------------------------------------------------


async def test_fetch_success() -> None:
    async with mock_http(httpx.Response(200, json=full_doc())) as http:
        doc = await fetch_discovery_document(http, f"{IDP}/.well-known/openid-configuration")
    assert doc["issuer"] == IDP


async def test_fetch_404_not_found() -> None:
    async with mock_http(httpx.Response(404, json={})) as http:
        with pytest.raises(DiscoveryError) as exc:
            await fetch_discovery_document(http, f"{IDP}/.well-known")
    assert exc.value.code == "discovery_not_found"


async def test_fetch_redirect_rejected() -> None:
    async with mock_http(httpx.Response(302, headers={"location": "http://127.0.0.1/"})) as http:
        with pytest.raises(DiscoveryError) as exc:
            await fetch_discovery_document(http, f"{IDP}/.well-known")
    assert exc.value.code == "discovery_unexpected_error"


async def test_fetch_empty_invalid_json() -> None:
    async with mock_http(httpx.Response(200, json={})) as http:
        with pytest.raises(DiscoveryError) as exc:
            await fetch_discovery_document(http, f"{IDP}/.well-known")
    assert exc.value.code == "discovery_invalid_json"


# --- discover_oidc_config (async, full pipeline) -------------------------------------


async def test_discover_full_happy_path() -> None:
    async with mock_http(httpx.Response(200, json=full_doc())) as http:
        cfg = await discover_oidc_config(
            issuer=IDP, is_trusted_origin=trust_only(IDP), http=http
        )
    assert cfg.token_endpoint == f"{IDP}/token"
    assert cfg.authorization_endpoint == f"{IDP}/authorize"
    assert cfg.jwks_endpoint == f"{IDP}/jwks"
    assert cfg.token_endpoint_authentication == "client_secret_basic"


async def test_discover_existing_config_wins() -> None:
    async with mock_http(httpx.Response(200, json=full_doc())) as http:
        cfg = await discover_oidc_config(
            issuer=IDP,
            existing_config={"tokenEndpoint": f"{IDP}/custom-token"},
            is_trusted_origin=trust_only(IDP),
            http=http,
        )
    assert cfg.token_endpoint == f"{IDP}/custom-token"


async def test_discover_issuer_mismatch_raises() -> None:
    async with mock_http(httpx.Response(200, json=full_doc(issuer="http://evil.com"))) as http:
        with pytest.raises(DiscoveryError) as exc:
            await discover_oidc_config(issuer=IDP, is_trusted_origin=trust_only(IDP), http=http)
    assert exc.value.code == "issuer_mismatch"


# --- map_discovery_error_to_api_error ------------------------------------------------


@pytest.mark.parametrize(
    "code,status",
    [
        ("discovery_timeout", 502),
        ("discovery_unexpected_error", 502),
        ("discovery_not_found", 400),
        ("discovery_invalid_url", 400),
        ("discovery_private_host", 400),
        ("issuer_mismatch", 400),
        ("discovery_incomplete", 400),
    ],
)
def test_map_error_status(code: str, status: int) -> None:
    api_error = map_discovery_error_to_api_error(DiscoveryError(code, "boom"))
    assert api_error.status == status
    assert api_error.code == code


# --- DNS resolve-check (SSRF DNS-rebind defense) -------------------------------------


async def test_resolve_check_rebind_private_rejected() -> None:
    async def resolver(_host: str) -> list[str]:
        return ["10.0.0.5"]  # FQDN that resolves to a private address

    with pytest.raises(DiscoveryError) as exc:
        await assert_endpoint_resolves_public(
            "tokenEndpoint",
            "https://idp.example.com/token",
            trust_only(),
            resolve_host=resolver,
        )
    assert exc.value.code == "discovery_private_host"


async def test_resolve_check_public_ok() -> None:
    async def resolver(_host: str) -> list[str]:
        return ["93.184.216.34"]

    await assert_endpoint_resolves_public(
        "tokenEndpoint", "https://idp.example.com/token", trust_only(), resolve_host=resolver
    )


async def test_resolve_check_ip_literal_skipped() -> None:
    async def resolver(_host: str) -> list[str]:
        raise AssertionError("IP literals must not be resolved")

    # public IP literal — synchronous check already covers it, resolver not called
    await assert_endpoint_resolves_public(
        "tokenEndpoint", "https://93.184.216.34/token", trust_only(), resolve_host=resolver
    )


async def test_resolve_check_trusted_origin_skipped() -> None:
    async def resolver(_host: str) -> list[str]:
        raise AssertionError("allowlisted origins must not be resolved")

    await assert_endpoint_resolves_public(
        "tokenEndpoint",
        "https://internal-idp.corp/token",
        trust_only("https://internal-idp.corp"),
        resolve_host=resolver,
    )


async def test_resolve_check_resolver_failure_falls_back() -> None:
    async def resolver(_host: str) -> list[str]:
        raise OSError("resolution failed")

    # resolver failure => best-effort skip, no raise
    await assert_endpoint_resolves_public(
        "tokenEndpoint", "https://idp.example.com/token", trust_only(), resolve_host=resolver
    )


async def test_assert_oidc_endpoints_resolve_public_matrix() -> None:
    async def resolver(host: str) -> list[str]:
        return ["10.0.0.5"] if host == "userinfo.example.com" else ["93.184.216.34"]

    with pytest.raises(DiscoveryError) as exc:
        await assert_oidc_endpoints_resolve_public(
            {
                "tokenEndpoint": "https://idp.example.com/token",
                "userInfoEndpoint": "https://userinfo.example.com/me",
                "jwksEndpoint": "https://idp.example.com/jwks",
            },
            trust_only(),
            resolve_host=resolver,
        )
    assert exc.value.code == "discovery_private_host"
