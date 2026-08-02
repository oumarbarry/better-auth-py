"""Tests for the sso plugin's utils + RFC-6890 host classifier (Waves A/B foundations).

TS source verified against:
  packages/sso/src/utils.ts
  packages/core/src/utils/host.ts
"""

from __future__ import annotations

import pytest

from better_auth.plugins_ext.sso.host import classify_host, is_public_routable_host
from better_auth.plugins_ext.sso.utils import (
    domain_matches,
    mask_client_id,
    parse_provider_domains,
    parse_provider_email_verified,
    safe_json_parse,
    validate_email_domain,
)

# --- utils.safe_json_parse -----------------------------------------------------------


def test_safe_json_parse_string() -> None:
    assert safe_json_parse('{"a": 1}') == {"a": 1}


def test_safe_json_parse_already_object() -> None:
    obj = {"a": 1}
    assert safe_json_parse(obj) is obj


def test_safe_json_parse_none() -> None:
    assert safe_json_parse(None) is None
    assert safe_json_parse("") is None


def test_safe_json_parse_invalid_raises() -> None:
    with pytest.raises(ValueError):
        safe_json_parse("{not json")


# --- utils.mask_client_id ------------------------------------------------------------


def test_mask_client_id_short() -> None:
    assert mask_client_id("abcd") == "****"
    assert mask_client_id("ab") == "****"


def test_mask_client_id_long() -> None:
    assert mask_client_id("abc123") == "****c123"


# --- utils.parse_provider_email_verified (strict) ------------------------------------


@pytest.mark.parametrize(
    "value,expected",
    [
        (True, True),
        ("true", True),
        (False, False),
        ("false", False),
        ("0", False),
        ("", False),
        (1, False),
        (None, False),
        ([], False),
    ],
)
def test_parse_provider_email_verified(value: object, expected: bool) -> None:
    assert parse_provider_email_verified(value) is expected


# --- utils.parse_provider_domains ----------------------------------------------------


def test_parse_provider_domains_single() -> None:
    assert parse_provider_domains("company.com") == ["company.com"]


def test_parse_provider_domains_multi_lowercased_deduped() -> None:
    assert parse_provider_domains("Company.com, sub.com ,company.com") == [
        "company.com",
        "sub.com",
    ]


def test_parse_provider_domains_empty() -> None:
    assert parse_provider_domains("") is None
    assert parse_provider_domains("  ,  ") is None


# --- utils.domain_matches ------------------------------------------------------------


def test_domain_matches_exact() -> None:
    assert domain_matches("company.com", "company.com") is True


def test_domain_matches_subdomain() -> None:
    assert domain_matches("mail.company.com", "company.com") is True


def test_domain_matches_case_insensitive() -> None:
    assert domain_matches("MAIL.Company.COM", "company.com") is True


def test_domain_matches_no_match() -> None:
    assert domain_matches("evil.com", "company.com") is False
    # not a suffix boundary match
    assert domain_matches("notcompany.com", "company.com") is False


def test_domain_matches_comma_list() -> None:
    assert domain_matches("sub.com", "company.com,sub.com") is True


# --- utils.validate_email_domain -----------------------------------------------------


def test_validate_email_domain_match() -> None:
    assert validate_email_domain("user@company.com", "company.com") is True
    assert validate_email_domain("user@mail.company.com", "company.com") is True


def test_validate_email_domain_no_at() -> None:
    assert validate_email_domain("not-an-email", "company.com") is False


def test_validate_email_domain_mismatch() -> None:
    assert validate_email_domain("user@evil.com", "company.com") is False


# --- host classifier: SSRF matrix ----------------------------------------------------


@pytest.mark.parametrize(
    "host",
    [
        "127.0.0.1",  # loopback
        "127.5.5.5",  # loopback /8
        "10.0.0.1",  # RFC1918 private
        "172.16.0.1",  # RFC1918 private
        "192.168.1.1",  # RFC1918 private
        "169.254.169.254",  # link-local / AWS IMDS
        "100.64.0.1",  # shared address space (CGN)
        "0.0.0.0",  # unspecified
        "255.255.255.255",  # broadcast
        "224.0.0.1",  # multicast
        "192.0.2.1",  # documentation (reserved)
        "240.0.0.1",  # reserved
        "::1",  # IPv6 loopback
        "[::1]",  # bracketed IPv6 loopback
        "fe80::1",  # IPv6 link-local
        "fc00::1",  # IPv6 ULA private
        "ff02::1",  # IPv6 multicast
        "::ffff:127.0.0.1",  # IPv4-mapped loopback
        "::ffff:10.0.0.1",  # IPv4-mapped private
        "metadata.google.internal",  # cloud metadata FQDN
        "metadata",  # cloud metadata FQDN
        "localhost",  # localhost
        "tenant.localhost",  # RFC 6761 .localhost
    ],
)
def test_non_public_hosts_rejected(host: str) -> None:
    assert is_public_routable_host(host) is False


@pytest.mark.parametrize(
    "host",
    [
        "example.com",
        "idp.example.com",
        "8.8.8.8",  # public IPv4
        "1.1.1.1",
        "2606:4700:4700::1111",  # public IPv6 (cloudflare)
        "accounts.google.com",
    ],
)
def test_public_hosts_allowed(host: str) -> None:
    assert is_public_routable_host(host) is True


def test_host_with_port_stripped() -> None:
    assert is_public_routable_host("127.0.0.1:8080") is False
    assert is_public_routable_host("example.com:443") is True
    assert is_public_routable_host("[::1]:8080") is False


def test_classify_host_literal() -> None:
    assert classify_host("127.0.0.1").literal == "ipv4"
    assert classify_host("::1").literal == "ipv6"
    assert classify_host("example.com").literal == "fqdn"
    # IPv4-mapped IPv6 reported as ipv4
    assert classify_host("::ffff:192.0.2.1").literal == "ipv4"


def test_classify_host_trailing_dot_metadata() -> None:
    # RFC 1034 absolute form must not bypass the cloud-metadata check
    assert is_public_routable_host("metadata.google.internal.") is False
