"""oauth-provider client-secret storage: encrypted + custom {encrypt,decrypt}.

Ports TS ``packages/oauth-provider/src/utils/index.ts:237-338`` (storeClientSecret /
verifyStoredClientSecret / decryptStoredClientSecret) and the init guard truth table at
``oauth.ts:157-178``. ``"encrypted"`` is the default and only permitted storage when
``disable_jwt_plugin=True`` (see test_oauth_provider_disable_jwt.py for the end-to-end flow);
these tests exercise the store/verify util round-trips directly.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from better_auth.crypto import SecretConfig
from better_auth.plugins_ext.oauth_provider import OAuthProviderPlugin
from better_auth.plugins_ext.oauth_provider.utils import (
    store_client_secret,
    verify_client_secret,
)

# --- init guard truth table (oauth.ts:157-178) --------------------------------------


def test_hashed_with_jwt_disabled_rejected():
    # disableJwtPlugin && hashed -> throw (id tokens are HS256-signed with the secret)
    with pytest.raises(ValueError, match="id tokens will be signed with secret"):
        OAuthProviderPlugin(disable_jwt_plugin=True, store_client_secret="hashed")


def test_encrypted_with_jwt_enabled_rejected():
    # !disableJwtPlugin && encrypted -> throw
    with pytest.raises(ValueError, match="encryption method not recommended"):
        OAuthProviderPlugin(store_client_secret="encrypted")


def test_custom_encrypt_object_with_jwt_enabled_rejected():
    # !disableJwtPlugin && {encrypt} -> throw
    with pytest.raises(ValueError, match="encryption method not recommended"):
        OAuthProviderPlugin(store_client_secret={"encrypt": lambda s: s, "decrypt": lambda s: s})


def test_hashed_with_jwt_enabled_allowed():
    # default combination must still construct fine
    OAuthProviderPlugin(store_client_secret="hashed")


# --- util round-trips (create + verify) ---------------------------------------------


@pytest.mark.asyncio
async def test_encrypted_store_verify_with_secret_config():
    cfg = SecretConfig(keys={1: "rotation-key-v1-abcdefghij"}, current_version=1)
    opts = SimpleNamespace(store_client_secret="encrypted", prefix=None)
    stored = await store_client_secret(opts, "s3cr3t", secret_config=cfg)
    assert stored.startswith("$ba$1$")  # rotated envelope
    assert await verify_client_secret(opts, stored, "s3cr3t", secret_config=cfg) is True
    assert await verify_client_secret(opts, stored, "wrong", secret_config=cfg) is False


@pytest.mark.asyncio
async def test_encrypted_verify_returns_false_on_garbage_ciphertext():
    # verify swallows decrypt errors and returns False (TS try/catch)
    cfg = SecretConfig(keys={1: "rotation-key-v1-abcdefghij"}, current_version=1)
    opts = SimpleNamespace(store_client_secret="encrypted", prefix=None)
    assert await verify_client_secret(opts, "not-hex-garbage", "x", secret_config=cfg) is False


@pytest.mark.asyncio
async def test_custom_encrypt_decrypt_object_round_trip():
    # a reversible (test-only) transform; proves the {encrypt,decrypt} util path works
    method = {
        "encrypt": lambda s: s[::-1],
        "decrypt": lambda s: s[::-1],
    }
    opts = SimpleNamespace(store_client_secret=method, prefix=None)
    stored = await store_client_secret(opts, "hunter2")
    assert stored == "2retnuh"
    assert await verify_client_secret(opts, stored, "hunter2") is True
    assert await verify_client_secret(opts, stored, "nope") is False


@pytest.mark.asyncio
async def test_custom_async_encrypt_decrypt_object_round_trip():
    async def enc(s):
        return "enc:" + s

    async def dec(s):
        return s[len("enc:") :]

    opts = SimpleNamespace(store_client_secret={"encrypt": enc, "decrypt": dec}, prefix=None)
    stored = await store_client_secret(opts, "async-secret")
    assert stored == "enc:async-secret"
    assert await verify_client_secret(opts, stored, "async-secret") is True
