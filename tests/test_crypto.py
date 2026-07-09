import re
from urllib.parse import unquote

from better_auth.crypto import (
    generate_id,
    generate_random_string,
    hash_password,
    sign_value,
    unsign_value,
    verify_password,
)


def test_hash_matches_better_auth_format():
    hashed = hash_password("hello-world")
    assert re.fullmatch(r"[0-9a-f]{32}:[0-9a-f]{128}", hashed)


def test_verify_password():
    hashed = hash_password("correct horse battery staple")
    assert verify_password(hashed, "correct horse battery staple")
    assert not verify_password(hashed, "wrong password")
    assert not verify_password("garbage", "whatever")


def test_verify_nfkc_normalization():
    # "ﬁ" (U+FB01) normalizes to "fi" under NFKC, like better-auth
    hashed = hash_password("ﬁsh-and-chips")
    assert verify_password(hashed, "fish-and-chips")


def test_sign_round_trip():
    secret = "s" * 32
    signed = sign_value(secret, "my-token")
    assert unsign_value(secret, signed) == "my-token"


def test_signed_value_shape():
    signed = unquote(sign_value("s" * 32, "tok"))
    value, _, signature = signed.rpartition(".")
    assert value == "tok"
    assert len(signature) == 44 and signature.endswith("=")


def test_unsign_rejects_tampering():
    secret = "s" * 32
    signed = sign_value(secret, "my-token")
    assert unsign_value(secret, signed.replace("my-token", "other-token")) is None
    assert unsign_value("x" * 32, signed) is None
    assert unsign_value(secret, "no-dot-here") is None
    assert unsign_value(secret, "value.badsig") is None


def test_generate_id_alphabet():
    token = generate_id()
    assert len(token) == 32
    assert re.fullmatch(r"[a-zA-Z0-9]{32}", token)


def test_generate_random_string_alphabet():
    value = generate_random_string(128)
    assert len(value) == 128
    assert re.fullmatch(r"[a-zA-Z0-9_\-]{128}", value)
