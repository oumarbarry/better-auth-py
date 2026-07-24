"""Versioned-secret (SecretConfig) crypto parity tests.

Ports better-auth's key-rotation machinery: ``options.secrets`` -> ``SecretConfig``
(``context/secret-utils.ts``, ``crypto/index.ts``). The ``$ba$<version>$<hex>`` envelope
vectors below were minted by the real ``better-auth@1.6.23`` ``symmetricEncrypt`` with a
versioned ``SecretConfig`` (node, scratchpad w4-vectors), so a passing suite proves the
Python port decrypts a TS-minted rotated payload byte-for-byte. The plain-string bare-hex
path stays byte-identical (proved separately in ``test_w4_crypto.py``, untouched).
"""

from __future__ import annotations

import re

import pytest
from nacl.exceptions import CryptoError

from better_auth.crypto import (
    DEFAULT_SECRET,
    SecretConfig,
    format_envelope,
    parse_secrets_env,
    resolve_secret_config,
    symmetric_decrypt,
    symmetric_encrypt,
)

# --- ground-truth vectors: real better-auth@1.6.23 SecretConfig symmetricEncrypt --------
# cfg: keys {1:"old-secret-v1-retired", 2:"current-secret-v2-abcdefgh"}, current 2,
#      legacySecret "legacy-bare-hex-secret"
KEYS = {1: "old-secret-v1-retired", 2: "current-secret-v2-abcdefgh"}
LEGACY = "legacy-bare-hex-secret"
PLAINTEXT = "rotate me: cross-runtime envelope"

# current-version (2) envelope minted by TS
ENV_V2 = (
    "$ba$2$01f559eaf8cbd711f28415cc6f321c3686495c4bac3dcd565ec333c4f910964e"
    "3f3ac7f96d6552dda76deed76d5f5ff6da04d726d5aabe95b949d4b9f91be41e7b44826226cac900ad"
)
# retired-but-present version (1) envelope minted by TS -> proves fallback resolves by version
ENV_V1 = (
    "$ba$1$c858dda8369f90ff60fd86302abfbb0b0a213585011e4eaafa6ad4bea4695940"
    "a23cde9919413448a214066be7ac345fa465db7ee33465d28727c41c88cb10b10a5b8554c2ab189b11"
)
# bare-hex minted by TS with the legacySecret -> proves legacy fallback for pre-rotation rows
LEGACY_BARE = (
    "a53d97b5df541eab055b60759a96da35c4c719ad41cff611ed3c38bcac76ee02"
    "4c069129469891c7cecaa61b17cabf8d1c7d6d3849103ceb27fbf7fe528b8ada243de5d34d96026ca7"
)


def make_cfg(legacy_secret=LEGACY):
    return SecretConfig(keys=dict(KEYS), current_version=2, legacy_secret=legacy_secret)


# --- resolve_secret_config (context/create-context.ts + secret-utils.ts) ----------------


def test_resolve_plain_string_returns_string():
    # no `secrets` -> plain-string bare-hex path (secretConfig = secret)
    assert resolve_secret_config("plain-secret") == "plain-secret"


def test_resolve_secrets_builds_config_current_is_first():
    cfg = resolve_secret_config("legacy", secrets=[(2, "current"), (1, "old")])
    assert isinstance(cfg, SecretConfig)
    assert cfg.current_version == 2
    assert cfg.keys == {2: "current", 1: "old"}
    assert cfg.legacy_secret == "legacy"


def test_resolve_secrets_accepts_mapping_entries():
    cfg = resolve_secret_config(
        "legacy", secrets=[{"version": 5, "value": "cur"}, {"version": 4, "value": "old"}]
    )
    assert isinstance(cfg, SecretConfig)
    assert cfg.current_version == 5
    assert cfg.keys == {5: "cur", 4: "old"}


def test_resolve_default_secret_is_not_used_as_legacy():
    cfg = resolve_secret_config(DEFAULT_SECRET, secrets=[(1, "cur")])
    assert isinstance(cfg, SecretConfig)
    assert cfg.legacy_secret is None


def test_resolve_rejects_duplicate_version():
    with pytest.raises(ValueError, match=r"[Dd]uplicate"):
        resolve_secret_config("s", secrets=[(1, "a"), (1, "b")])


def test_resolve_rejects_negative_version():
    with pytest.raises(ValueError, match="version"):
        resolve_secret_config("s", secrets=[(-1, "a")])


def test_resolve_rejects_empty_value():
    with pytest.raises(ValueError, match=r"[Ee]mpty"):
        resolve_secret_config("s", secrets=[(1, "")])


def test_resolve_rejects_empty_secrets():
    with pytest.raises(ValueError, match="at least one"):
        resolve_secret_config("s", secrets=[])  # empty list is an explicit misconfig


# --- parse_secrets_env (BETTER_AUTH_SECRETS "<v>:<secret>,..") ---------------------------


def test_parse_secrets_env_none():
    assert parse_secrets_env(None) is None
    assert parse_secrets_env("") is None


def test_parse_secrets_env_pairs():
    assert parse_secrets_env("2:current, 1:old") == [(2, "current"), (1, "old")]


def test_parse_secrets_env_missing_colon_raises():
    with pytest.raises(ValueError, match="Expected format"):
        parse_secrets_env("nocolon")


# --- symmetric_encrypt / symmetric_decrypt with SecretConfig ----------------------------


def test_encrypt_with_config_mints_current_version_envelope():
    ct = symmetric_encrypt(make_cfg(), PLAINTEXT)
    assert ct.startswith("$ba$2$")
    assert re.fullmatch(r"\$ba\$2\$[0-9a-f]+", ct)


def test_encrypt_config_round_trip():
    cfg = make_cfg()
    assert symmetric_decrypt(cfg, symmetric_encrypt(cfg, PLAINTEXT)) == PLAINTEXT


def test_encrypt_missing_current_version_raises():
    cfg = SecretConfig(keys={1: "a"}, current_version=9)
    with pytest.raises(ValueError, match="version 9"):
        symmetric_encrypt(cfg, PLAINTEXT)


def test_plain_string_encrypt_stays_bare_hex():
    # sacred: string-key path must not gain an envelope prefix
    ct = symmetric_encrypt("plain-secret", PLAINTEXT)
    assert re.fullmatch(r"[0-9a-f]+", ct)
    assert symmetric_decrypt("plain-secret", ct) == PLAINTEXT


def test_decrypt_ts_current_version_envelope():
    assert symmetric_decrypt(make_cfg(), ENV_V2) == PLAINTEXT


def test_decrypt_ts_retired_version_envelope_resolves_by_version():
    # a $ba$1$ payload must decrypt with keys[1], not currentVersion(2)
    assert symmetric_decrypt(make_cfg(), ENV_V1) == PLAINTEXT


def test_decrypt_ts_legacy_bare_hex_via_config_fallback():
    # pre-rotation bare-hex row decrypts through cfg.legacy_secret
    assert symmetric_decrypt(make_cfg(), LEGACY_BARE) == PLAINTEXT


def test_decrypt_envelope_unknown_version_raises_retired():
    cfg = SecretConfig(keys={2: KEYS[2]}, current_version=2)  # version 1 retired
    with pytest.raises(ValueError, match="retired"):
        symmetric_decrypt(cfg, ENV_V1)


def test_decrypt_bare_hex_without_legacy_secret_raises():
    cfg = SecretConfig(keys=dict(KEYS), current_version=2)  # no legacy_secret
    with pytest.raises(ValueError, match=r"[Ll]egacy"):
        symmetric_decrypt(cfg, LEGACY_BARE)


def test_decrypt_wrong_key_for_version_raises_crypto():
    cfg = SecretConfig(keys={1: KEYS[1], 2: "wrong-key"}, current_version=2)
    with pytest.raises(CryptoError):
        symmetric_decrypt(cfg, ENV_V2)


def test_format_envelope_grammar():
    assert format_envelope(2, "deadbeef") == "$ba$2$deadbeef"
