"""siwe plugin — Sign-In with Ethereum (ERC-4361) wallet authentication.

Verified against TS ``packages/better-auth/src/plugins/siwe/`` (``index.ts``,
``parse-message.ts``, ``schema.ts``, ``types.ts``) and ``siwe.test.ts`` at v1.6.23.

The ERC-4361 parser (``parse_siwe_message`` / ``normalize_siwe_domain``) is a
verbatim port of ``parse-message.ts`` — same grammar, same tolerant rejects.
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timedelta, timezone

import pytest

from better_auth.adapters.base import Where
from better_auth.plugins_ext.siwe import (
    SiwePlugin,
    normalize_siwe_domain,
    parse_siwe_message,
    to_checksum_address,
)
from conftest import make_auth, make_client

# --- test fixtures (mirroring siwe.test.ts) ---------------------------------------

WALLET = "0x000000000000000000000000000000000000dEaD"  # EIP-55 checksum of the dead addr
OTHER_WALLET = "0x000000000000000000000000000000000000bEEF"
DOMAIN = "example.com"
CHAIN_ID = 1
NONCE = "A1b2C3d4E5f6G7h8J"  # 17 alphanumerics, like getNonce in the TS tests


def siwe_message(
    *,
    domain: str = DOMAIN,
    address: str = WALLET,
    chain_id: int = CHAIN_ID,
    nonce: str = NONCE,
    expiration_time: str | None = None,
    not_before: str | None = None,
) -> str:
    """Build a valid ERC-4361 message bound to the server-issued nonce (TS
    ``siweMessage`` helper)."""
    msg = (
        f"{domain} wants you to sign in with your Ethereum account:\n"
        f"{address}\n\n"
        f"Sign in.\n\n"
        f"URI: https://{domain}\n"
        f"Version: 1\n"
        f"Chain ID: {chain_id}\n"
        f"Nonce: {nonce}\n"
        f"Issued At: 2024-01-01T00:00:00.000Z"
    )
    if expiration_time:
        msg += f"\nExpiration Time: {expiration_time}"
    if not_before:
        msg += f"\nNot Before: {not_before}"
    return msg


async def _default_get_nonce() -> str:
    return NONCE


async def _default_verify_message(args: dict) -> bool:
    # Mirrors the documented viem pattern: signature recovery only, no message-body
    # inspection.
    return args["signature"] == "valid_signature"


def siwe_auth(**kwargs):
    kwargs.setdefault("domain", DOMAIN)
    kwargs.setdefault("get_nonce", _default_get_nonce)
    kwargs.setdefault("verify_message", _default_verify_message)
    return make_auth(plugins=[SiwePlugin(**kwargs)])


async def _issue_nonce(client, address=WALLET, chain_id=CHAIN_ID):
    return await client.post(
        "/api/auth/siwe/nonce", json={"walletAddress": address, "chainId": chain_id}
    )


async def _verify(client, **overrides):
    body = {
        "message": siwe_message(),
        "signature": "valid_signature",
        "walletAddress": WALLET,
        "chainId": CHAIN_ID,
    }
    body.update(overrides)
    return await client.post("/api/auth/siwe/verify", json=body)


# =================================================================================
# Part A — ERC-4361 parser (parse-message.ts, ported verbatim)
# =================================================================================


def test_parses_full_message():
    parsed = parse_siwe_message(siwe_message())
    assert parsed.scheme is None
    assert parsed.domain == "example.com"
    assert parsed.address == WALLET
    assert parsed.uri == "https://example.com"
    assert parsed.version == "1"
    assert parsed.chain_id == 1
    assert parsed.nonce == NONCE
    assert parsed.issued_at == "2024-01-01T00:00:00.000Z"


def test_parses_scheme_prefix():
    msg = "https://example.com wants you to sign in with your Ethereum account:"
    parsed = parse_siwe_message(msg)
    assert parsed.scheme == "https"
    assert parsed.domain == "example.com"


def test_no_scheme_leaves_scheme_none():
    parsed = parse_siwe_message(siwe_message())
    assert parsed.scheme is None
    assert parsed.domain == "example.com"


def test_address_on_second_line_parsed():
    parsed = parse_siwe_message(siwe_message())
    assert parsed.address == WALLET


def test_invalid_address_line_ignored():
    msg = (
        "example.com wants you to sign in with your Ethereum account:\n"
        "not-an-address\n\nSign in.\n\nNonce: abc"
    )
    parsed = parse_siwe_message(msg)
    assert parsed.address is None
    assert parsed.nonce == "abc"


def test_statement_with_colon_does_not_break_suffix_fields():
    # A statement that itself contains ": " must not shadow the suffix Nonce field.
    msg = (
        "example.com wants you to sign in with your Ethereum account:\n"
        f"{WALLET}\n\n"
        "Welcome: please read the terms\n\n"
        "URI: https://example.com\n"
        "Version: 1\n"
        "Chain ID: 1\n"
        f"Nonce: {NONCE}\n"
        "Issued At: 2024-01-01T00:00:00.000Z"
    )
    parsed = parse_siwe_message(msg)
    assert parsed.nonce == NONCE
    assert parsed.uri == "https://example.com"


def test_suffix_field_last_occurrence_wins():
    # Line-by-line parse walks top-to-bottom; the suffix field (later) overwrites an
    # earlier same-key line embedded in the statement.
    msg = (
        "example.com wants you to sign in with your Ethereum account:\n"
        f"{WALLET}\n\n"
        "Nonce: fake-from-statement\n\n"
        "Nonce: real-suffix-nonce"
    )
    parsed = parse_siwe_message(msg)
    assert parsed.nonce == "real-suffix-nonce"


def test_chain_id_integer_parsed():
    parsed = parse_siwe_message(siwe_message(chain_id=137))
    assert parsed.chain_id == 137


def test_chain_id_non_integer_rejected():
    msg = siwe_message().replace("Chain ID: 1", "Chain ID: 1.5")
    parsed = parse_siwe_message(msg)
    assert parsed.chain_id is None


def test_chain_id_hex_parsed_like_js_number():
    # JS Number("0x10") === 16 and Number.isInteger(16); the port mirrors that.
    msg = siwe_message().replace("Chain ID: 1", "Chain ID: 0x10")
    parsed = parse_siwe_message(msg)
    assert parsed.chain_id == 16


def test_optional_time_and_request_fields():
    msg = (
        siwe_message(
            expiration_time="2030-01-01T00:00:00.000Z", not_before="2020-01-01T00:00:00.000Z"
        )
        + "\nRequest ID: req-123"
    )
    parsed = parse_siwe_message(msg)
    assert parsed.expiration_time == "2030-01-01T00:00:00.000Z"
    assert parsed.not_before == "2020-01-01T00:00:00.000Z"
    assert parsed.request_id == "req-123"


def test_crlf_line_endings_tolerated():
    parsed = parse_siwe_message(siwe_message().replace("\n", "\r\n"))
    assert parsed.domain == "example.com"
    assert parsed.address == WALLET
    assert parsed.nonce == NONCE


def test_empty_message_yields_all_none():
    parsed = parse_siwe_message("")
    assert parsed.domain is None
    assert parsed.address is None
    assert parsed.nonce is None
    assert parsed.chain_id is None


def test_arbitrary_non_siwe_message_has_no_fields():
    parsed = parse_siwe_message("gm, please sign this to continue")
    assert parsed.domain is None
    assert parsed.nonce is None
    assert parsed.address is None


def test_malformed_header_leaves_domain_none():
    parsed = parse_siwe_message("just some random first line\n" + WALLET)
    assert parsed.domain is None
    # the address line is still line[1] and matches the address regex
    assert parsed.address == WALLET


# --- normalize_siwe_domain --------------------------------------------------------


def test_normalize_strips_scheme():
    assert normalize_siwe_domain("https://example.com") == "example.com"


def test_normalize_lowercases():
    assert normalize_siwe_domain("EXAMPLE.COM") == "example.com"


def test_normalize_strips_path():
    assert normalize_siwe_domain("example.com/foo/bar") == "example.com"


def test_normalize_trims_whitespace():
    assert normalize_siwe_domain("  example.com  ") == "example.com"


def test_normalize_keeps_host_and_port():
    assert normalize_siwe_domain("https://Example.com:3000/login") == "example.com:3000"


# =================================================================================
# Part B — EIP-55 checksum (toChecksumAddress, keccak256)
# =================================================================================


@pytest.mark.parametrize(
    "addr",
    [
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    ],
)
def test_checksum_eip55_canonical_vectors_are_fixed_points(addr):
    assert to_checksum_address(addr) == addr


def test_checksum_from_lowercase():
    assert to_checksum_address(WALLET.lower()) == WALLET


def test_checksum_from_uppercase():
    assert to_checksum_address("0x" + WALLET[2:].upper()) == WALLET


# =================================================================================
# Part C — endpoints (index.ts / siwe.test.ts)
# =================================================================================

# --- /siwe/nonce ------------------------------------------------------------------


async def test_nonce_returns_string_for_valid_address():
    async with make_client(siwe_auth()) as client:
        r = await _issue_nonce(client)
        assert r.status_code == 200
        nonce = r.json()["nonce"]
        assert isinstance(nonce, str)
        assert re.fullmatch(r"[a-zA-Z0-9]{17}", nonce)


async def test_nonce_default_chain_id():
    async with make_client(siwe_auth()) as client:
        r = await client.post("/api/auth/siwe/nonce", json={"walletAddress": WALLET})
        assert r.status_code == 200
        assert re.fullmatch(r"[a-zA-Z0-9]{17}", r.json()["nonce"])


async def test_get_nonce_alias_with_address_input():
    async with make_client(siwe_auth()) as client:
        r = await client.post(
            "/api/auth/siwe/get-nonce", json={"address": WALLET, "chainId": CHAIN_ID}
        )
        assert r.status_code == 200
        assert r.json()["nonce"] == NONCE


async def test_nonce_rejects_invalid_public_key():
    async with make_client(siwe_auth()) as client:
        r = await client.post("/api/auth/siwe/nonce", json={"walletAddress": "invalid"})
        assert r.status_code == 400


async def test_nonce_rejects_invalid_wallet_format():
    async with make_client(siwe_auth()) as client:
        r = await client.post("/api/auth/siwe/nonce", json={"walletAddress": "not_a_valid_key"})
        assert r.status_code == 400


async def test_nonce_requires_wallet_or_address():
    async with make_client(siwe_auth()) as client:
        r = await client.post("/api/auth/siwe/nonce", json={"chainId": 1})
        assert r.status_code == 400


# --- /siwe/verify: nonce gate -----------------------------------------------------


async def test_verify_rejects_missing_nonce():
    async with make_client(siwe_auth()) as client:
        r = await _verify(client)
        assert r.status_code == 401
        assert r.json()["code"] == "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE"
        assert "nonce" in r.json()["message"].lower()


async def test_verify_rejects_invalid_signature_message_without_nonce():
    # TS parity: no nonce issued, so the nonce gate fires first (401).
    async with make_client(siwe_auth()) as client:
        r = await _verify(client, message="Sign in with Ethereum.", signature="invalid_signature")
        assert r.status_code == 401


async def test_verify_rejects_arbitrary_message_without_nonce():
    async with make_client(siwe_auth()) as client:
        r = await _verify(client, message="invalid_message")
        assert r.status_code == 401


async def test_expired_nonce_rejected_and_row_consumed():
    auth = siwe_auth()
    async with make_client(auth) as client:
        identifier = f"siwe:{WALLET}:{CHAIN_ID}"
        await auth.internal.create_verification_value(
            {
                "identifier": identifier,
                "value": NONCE,
                "expiresAt": datetime.now(timezone.utc) - timedelta(seconds=1),
            }
        )
        r = await _verify(client)
        assert r.status_code == 401
        assert r.json()["code"] == "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE"
        # the expired row is burned, so a retry cannot replay it
        assert await auth.internal.find_verification_value(identifier) is None


async def test_no_nonce_reuse():
    async with make_client(siwe_auth()) as client:
        await _issue_nonce(client)
        first = await _verify(client)
        assert first.status_code == 200
        assert first.json()["success"] is True

        second = await _verify(client)
        assert second.status_code == 401
        assert second.json()["code"] == "UNAUTHORIZED_INVALID_OR_EXPIRED_NONCE"


async def test_mint_exactly_one_session_when_nonce_verified_concurrently():
    # The nonce is single-use. Two requests presenting the same valid nonce at the
    # same time must collapse to exactly one authenticated session (the atomic
    # consume rejects the racer before it reaches verify_message).
    async def slow_verify(args):
        await asyncio.sleep(0.05)
        return args["signature"] == "valid_signature"

    auth = siwe_auth(verify_message=slow_verify)
    async with make_client(auth) as client:
        await _issue_nonce(client)
        sessions_before = await auth.adapter.find_many("session")

        first, second = await asyncio.gather(_verify(client), _verify(client))
        results = [first, second]
        successes = [r for r in results if r.status_code == 200 and r.json().get("success")]
        failures = [r for r in results if r.status_code != 200]
        assert len(successes) == 1
        assert len(failures) == 1
        assert failures[0].status_code == 401

        wallets = await auth.adapter.find_many("walletAddress", [Where("address", WALLET)])
        assert len(wallets) == 1
        sessions_after = await auth.adapter.find_many("session")
        assert len(sessions_after) == len(sessions_before) + 1


# --- /siwe/verify: message binding ------------------------------------------------


async def test_binding_rejects_non_matching_nonce():
    async with make_client(siwe_auth()) as client:
        await _issue_nonce(client)
        r = await _verify(client, message=siwe_message(nonce="some-other-nonce"))
        assert r.status_code == 401
        assert r.json()["code"] == "UNAUTHORIZED_SIWE_MESSAGE_MISMATCH"


async def test_binding_rejects_different_domain():
    async with make_client(siwe_auth()) as client:
        await _issue_nonce(client)
        r = await _verify(client, message=siwe_message(domain="other.example.com"))
        assert r.status_code == 401
        assert r.json()["code"] == "UNAUTHORIZED_SIWE_MESSAGE_MISMATCH"


async def test_binding_rejects_different_chain_id():
    async with make_client(siwe_auth()) as client:
        await _issue_nonce(client)
        r = await _verify(client, message=siwe_message(chain_id=137))
        assert r.status_code == 401
        assert r.json()["code"] == "UNAUTHORIZED_SIWE_MESSAGE_MISMATCH"


async def test_binding_rejects_arbitrary_non_siwe_message():
    async with make_client(siwe_auth()) as client:
        await _issue_nonce(client)
        r = await _verify(client, message="gm, please sign this to continue")
        assert r.status_code == 401
        assert r.json()["code"] == "UNAUTHORIZED_SIWE_MESSAGE_MISMATCH"


async def test_binding_rejects_expired_siwe_message():
    async with make_client(siwe_auth()) as client:
        await _issue_nonce(client)
        r = await _verify(client, message=siwe_message(expiration_time="2020-01-01T00:00:00.000Z"))
        assert r.status_code == 401
        assert r.json()["code"] == "UNAUTHORIZED_SIWE_MESSAGE_EXPIRED"


async def test_binding_rejects_not_yet_valid_siwe_message():
    async with make_client(siwe_auth()) as client:
        await _issue_nonce(client)
        r = await _verify(client, message=siwe_message(not_before="2999-01-01T00:00:00.000Z"))
        assert r.status_code == 401
        assert r.json()["code"] == "UNAUTHORIZED_SIWE_MESSAGE_NOT_YET_VALID"


async def test_binding_no_session_for_reused_unrelated_signature():
    auth = siwe_auth()
    async with make_client(auth) as client:
        # a legit wallet sign-in creates the wallet user
        await _issue_nonce(client)
        legit = await _verify(client)
        assert legit.json()["success"] is True
        sessions_before = await auth.adapter.find_many("session")

        # a fresh nonce, then a previously-produced signature over an unrelated message
        await _issue_nonce(client)
        second = await _verify(client, message="Approve transfer of 1 ETH")
        assert second.status_code == 401
        sessions_after = await auth.adapter.find_many("session")
        assert len(sessions_after) == len(sessions_before)


# --- /siwe/verify: email / anonymous semantics ------------------------------------


async def test_rejects_without_email_when_anonymous_false():
    async with make_client(siwe_auth(anonymous=False)) as client:
        r = await _verify(client)
        assert r.status_code == 400


async def test_accepts_with_email_when_anonymous_false():
    async with make_client(siwe_auth(anonymous=False)) as client:
        await _issue_nonce(client)
        r = await _verify(client, email="user@example.com")
        assert r.status_code == 200
        assert r.json()["success"] is True


async def test_rejects_invalid_email_when_anonymous_false():
    async with make_client(siwe_auth(anonymous=False)) as client:
        r = await _verify(client, email="not-an-email")
        assert r.status_code == 400


async def test_rejects_empty_string_email_when_anonymous_false():
    async with make_client(siwe_auth(anonymous=False)) as client:
        await _issue_nonce(client)
        r = await _verify(client, email="")
        assert r.status_code == 400


async def test_allows_verification_without_email_when_anonymous_true():
    async with make_client(siwe_auth()) as client:
        await _issue_nonce(client)
        r = await _verify(client)
        assert r.status_code == 200
        assert r.json()["success"] is True


async def test_does_not_bind_caller_email_owned_by_another_account():
    auth = siwe_auth(anonymous=False)
    async with make_client(auth) as client:
        await auth.internal.create_user(
            {"name": "Ada", "email": "ada@example.com", "emailVerified": True}
        )
        await _issue_nonce(client)
        r = await _verify(client, email="ada@example.com")
        assert r.status_code == 200
        assert r.json()["success"] is True

        siwe_user = await auth.adapter.find_one("user", [Where("id", r.json()["user"]["id"])])
        assert siwe_user["email"] != "ada@example.com"
        owners = await auth.adapter.find_many("user", [Where("email", "ada@example.com")])
        assert len(owners) == 1


async def test_case_variant_email_treated_as_existing():
    auth = siwe_auth(anonymous=False)
    async with make_client(auth) as client:
        # first wallet claims a mixed-case email; stored normalized (lowercased)
        await _issue_nonce(client)
        first = await _verify(client, email="Mixed@Case.com")
        assert first.status_code == 200
        u1 = await auth.adapter.find_one("user", [Where("id", first.json()["user"]["id"])])
        assert u1["email"] == "mixed@case.com"

        # a different wallet presenting the lowercase variant must not claim it
        await _issue_nonce(client, address=OTHER_WALLET)
        second = await _verify(
            client,
            message=siwe_message(address=OTHER_WALLET),
            walletAddress=OTHER_WALLET,
            email="mixed@case.com",
        )
        assert second.status_code == 200
        u2 = await auth.adapter.find_one("user", [Where("id", second.json()["user"]["id"])])
        assert u2["email"] != "mixed@case.com"


# --- /siwe/verify: user + wallet + account resolution -----------------------------


async def test_verify_response_shape_and_session_cookie():
    auth = siwe_auth()
    async with make_client(auth) as client:
        await _issue_nonce(client)
        r = await _verify(client)
        assert r.status_code == 200
        body = r.json()
        assert body["token"]
        assert body["success"] is True
        assert body["user"]["walletAddress"] == WALLET
        assert body["user"]["chainId"] == CHAIN_ID
        assert body["user"]["id"]
        # the session cookie was set: a follow-up get-session resolves to this user
        session = (await client.get("/api/auth/get-session")).json()
        assert session["user"]["id"] == body["user"]["id"]


async def test_stores_wallet_address_in_checksum_format():
    auth = siwe_auth()
    async with make_client(auth) as client:
        # lowercase input is checksummed on the way in
        await _issue_nonce(client, address=WALLET.lower())
        r = await _verify(client, walletAddress=WALLET.lower())
        assert r.json()["success"] is True

        wallets = await auth.adapter.find_many("walletAddress", [Where("address", WALLET)])
        assert len(wallets) == 1
        assert wallets[0]["address"] == WALLET  # checksummed

        # uppercase input resolves to the same address — no new row
        upper = "0x" + WALLET[2:].upper()
        await _issue_nonce(client, address=upper)
        r2 = await _verify(client, walletAddress=upper)
        assert r2.json()["success"] is True
        after = await auth.adapter.find_many("walletAddress", [Where("address", WALLET)])
        assert len(after) == 1


async def test_duplicate_wallet_reuses_same_user():
    auth = siwe_auth()
    async with make_client(auth) as client:
        await _issue_nonce(client)
        first = await _verify(client)
        assert first.json()["success"] is True

        wallets = await auth.adapter.find_many(
            "walletAddress", [Where("address", WALLET), Where("chainId", CHAIN_ID)]
        )
        assert len(wallets) == 1
        assert wallets[0]["isPrimary"] is True

        await _issue_nonce(client)
        second = await _verify(client)
        assert second.json()["success"] is True
        assert second.json()["user"]["id"] == first.json()["user"]["id"]

        after = await auth.adapter.find_many(
            "walletAddress", [Where("address", WALLET), Where("chainId", CHAIN_ID)]
        )
        assert len(after) == 1


async def test_same_address_different_chains_same_user():
    auth = siwe_auth()
    async with make_client(auth) as client:
        await _issue_nonce(client, chain_id=1)
        eth = await _verify(client, message=siwe_message(chain_id=1), chainId=1)
        assert eth.json()["success"] is True

        await _issue_nonce(client, chain_id=137)
        poly = await _verify(client, message=siwe_message(chain_id=137), chainId=137)
        assert poly.json()["success"] is True
        assert poly.json()["user"]["id"] == eth.json()["user"]["id"]  # same user

        rows = await auth.adapter.find_many("walletAddress", [Where("address", WALLET)])
        assert len(rows) == 2
        eth_row = next(w for w in rows if w["chainId"] == 1)
        poly_row = next(w for w in rows if w["chainId"] == 137)
        assert eth_row["isPrimary"] is True  # first address is primary
        assert poly_row["isPrimary"] is False  # additional addresses are not
        assert eth_row["userId"] == poly_row["userId"]


async def test_creates_siwe_account_with_provider_and_account_id():
    auth = siwe_auth()
    async with make_client(auth) as client:
        await _issue_nonce(client)
        r = await _verify(client)
        user_id = r.json()["user"]["id"]
        accounts = await auth.adapter.find_many("account", [Where("userId", user_id)])
        siwe_accounts = [a for a in accounts if a["providerId"] == "siwe"]
        assert len(siwe_accounts) == 1
        assert siwe_accounts[0]["accountId"] == f"{WALLET}:{CHAIN_ID}"


# --- config: ens_lookup + email domain --------------------------------------------


async def test_ens_lookup_sets_name_and_avatar():
    async def ens(args):
        assert args["walletAddress"] == WALLET
        return {"name": "vitalik.eth", "avatar": "https://avatar.example/v.png"}

    auth = siwe_auth(ens_lookup=ens)
    async with make_client(auth) as client:
        await _issue_nonce(client)
        r = await _verify(client)
        user = await auth.adapter.find_one("user", [Where("id", r.json()["user"]["id"])])
        assert user["name"] == "vitalik.eth"
        assert user["image"] == "https://avatar.example/v.png"


async def test_new_user_name_defaults_to_wallet_address():
    auth = siwe_auth()
    async with make_client(auth) as client:
        await _issue_nonce(client)
        r = await _verify(client)
        user = await auth.adapter.find_one("user", [Where("id", r.json()["user"]["id"])])
        assert user["name"] == WALLET


async def test_email_domain_name_shapes_wallet_derived_email():
    auth = siwe_auth(email_domain_name="wallet.example")
    async with make_client(auth) as client:
        await _issue_nonce(client)
        r = await _verify(client)
        user = await auth.adapter.find_one("user", [Where("id", r.json()["user"]["id"])])
        assert user["email"] == f"{WALLET.lower()}@wallet.example"


async def test_wallet_derived_email_defaults_to_base_url_origin():
    # No emailDomainName -> getOrigin(baseURL); the test base_url is http://testserver.
    auth = siwe_auth()
    async with make_client(auth) as client:
        await _issue_nonce(client)
        r = await _verify(client)
        user = await auth.adapter.find_one("user", [Where("id", r.json()["user"]["id"])])
        assert user["email"] == f"{WALLET.lower()}@http://testserver"
