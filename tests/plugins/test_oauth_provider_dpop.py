"""RFC 9449 DPoP primitives, anchored to TS v1.7.6 core ``oauth2/dpop.ts``, its tests
``oauth2/dpop.test.ts``, oauth-provider ``dpop.ts`` and the DPoP challenge half of
``resource-challenge.ts`` (+ ``resource-challenge.test.ts:157``)."""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from jwt.algorithms import ECAlgorithm, OKPAlgorithm, RSAAlgorithm

from better_auth import BetterAuth
from better_auth.plugins_ext.oauth_provider.dpop import (
    DPOP_SIGNING_ALGORITHMS,
    AccessTokenAuthorization,
    AccessTokenAuthorizationScheme,
    DpopBindingError,
    DpopProofError,
    build_dpop_challenge,
    create_dpop_replay_store,
    create_in_memory_dpop_replay_store,
    derive_dpop_ath,
    derive_dpop_jkt,
    enforce_dpop_binding,
    get_confirmation_jkt,
    get_dpop_jkt_from_payload,
    get_dpop_proof_jwt,
    get_endpoint_url,
    is_dpop_binding_error,
    is_dpop_challenge_error,
    is_dpop_proof_error,
    normalize_dpop_htu,
    parse_access_token_authorization,
    strip_access_token_authorization_scheme,
    verify_dpop_proof,
)
from better_auth.types import AuthRequest, Ctx

METHOD = "GET"
URL = "https://api.example.com/resource"
ACCESS_TOKEN = "access-token-value"
NOW = 1_700_000_000


def _es256_key() -> tuple[Any, dict[str, Any]]:
    private = ec.generate_private_key(ec.SECP256R1())
    public_jwk = json.loads(ECAlgorithm.to_jwk(private.public_key()))
    return private, public_jwk


async def _proof(
    *,
    private_key: Any = None,
    public_jwk: dict[str, Any] | None = None,
    header_jwk: dict[str, Any] | None = None,
    access_token: str | None = None,
    alg: str = "ES256",
    typ: str = "dpop+jwt",
    **claims: Any,
) -> str:
    """TS dpop.test.ts:22 ``createProof``."""
    if private_key is None:
        private_key, public_jwk = _es256_key()
    payload: dict[str, Any] = {"jti": "proof-jti", "htm": METHOD, "htu": URL, "iat": NOW}
    payload.update(claims)
    if access_token:
        payload["ath"] = await derive_dpop_ath(access_token)
    return pyjwt.encode(
        payload,
        private_key,
        algorithm=alg,
        headers={"typ": typ, "jwk": header_jwk or public_jwk},
    )


async def _fails(message: str, **kwargs: Any) -> None:
    kwargs.setdefault("method", METHOD)
    kwargs.setdefault("url", URL)
    kwargs.setdefault("now_seconds", NOW)
    with pytest.raises(DpopProofError) as info:
        await verify_dpop_proof(**kwargs)
    assert info.value.code == "invalid_dpop_proof"
    assert str(info.value) == message


# --- thumbprint / ath -------------------------------------------------------------


async def test_jkt_matches_rfc7638_known_answer():
    # RFC 7638 section 3.1 example key; members beyond kty/n/e are ignored
    jwk = {
        "kty": "RSA",
        "n": (
            "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1"
            "L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4"
            "QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbO"
            "pbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csF"
            "Cur-kEgU8awapJzKnqDKgw"
        ),
        "e": "AQAB",
        "alg": "RS256",
        "kid": "2011-04-29",
    }
    assert await derive_dpop_jkt(jwk) == "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"


async def test_jkt_uses_required_ec_members_only():
    jwk = {"kty": "EC", "crv": "P-256", "x": "xx", "y": "yy", "kid": "ignored", "use": "sig"}
    canonical = b'{"crv":"P-256","kty":"EC","x":"xx","y":"yy"}'
    expected = base64.urlsafe_b64encode(hashlib.sha256(canonical).digest()).rstrip(b"=")
    assert await derive_dpop_jkt(jwk) == expected.decode()


async def test_ath_is_base64url_sha256_of_the_token():
    digest = hashlib.sha256(ACCESS_TOKEN.encode()).digest()
    assert await derive_dpop_ath(ACCESS_TOKEN) == (
        base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    )


# --- verify_dpop_proof (TS dpop.test.ts:88) -----------------------------------------


async def test_verifies_token_endpoint_proof_and_returns_thumbprint():
    # TS dpop.test.ts:89
    private, public_jwk = _es256_key()
    proof = await verify_dpop_proof(
        proof_jwt=await _proof(private_key=private, public_jwk=public_jwk),
        method=METHOD,
        url=URL,
        now_seconds=NOW,
    )
    assert proof.jkt == await derive_dpop_jkt(public_jwk)
    assert (proof.htm, proof.htu, proof.jti, proof.iat, proof.ath) == (
        METHOD,
        URL,
        "proof-jti",
        NOW,
        None,
    )
    assert proof.expires_at == datetime.fromtimestamp(NOW + 300, tz=timezone.utc)
    replay_input = f"{proof.jkt}\nGET\n{URL}\nproof-jti".encode()
    assert proof.replay_key == (
        base64.urlsafe_b64encode(hashlib.sha256(replay_input).digest()).rstrip(b"=").decode()
    )


async def test_accepts_eddsa_and_rs256_proofs():
    ed = ed25519.Ed25519PrivateKey.generate()
    ed_jwk = json.loads(OKPAlgorithm.to_jwk(ed.public_key()))
    rs = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rs_jwk = json.loads(RSAAlgorithm.to_jwk(rs.public_key()))
    for private, jwk, alg in ((ed, ed_jwk, "EdDSA"), (rs, rs_jwk, "RS256")):
        proof = await verify_dpop_proof(
            proof_jwt=await _proof(private_key=private, public_jwk=jwk, alg=alg),
            method=METHOD,
            url=URL,
            now_seconds=NOW,
        )
        assert proof.jkt == await derive_dpop_jkt(jwk)


async def test_requires_ath_for_protected_resource_request():
    # TS dpop.test.ts:108
    await _fails(
        "DPoP proof must include an ath claim",
        proof_jwt=await _proof(),
        access_token=ACCESS_TOKEN,
        require_ath=True,
    )


async def test_accepts_resource_proof_bound_to_token_hash():
    # TS dpop.test.ts:126
    proof = await verify_dpop_proof(
        proof_jwt=await _proof(access_token=ACCESS_TOKEN),
        method=METHOD,
        url=URL,
        access_token=ACCESS_TOKEN,
        require_ath=True,
        now_seconds=NOW,
    )
    assert proof.ath == await derive_dpop_ath(ACCESS_TOKEN)


async def test_rejects_ath_for_a_different_token():
    await _fails(
        "DPoP proof ath does not match the access token",
        proof_jwt=await _proof(access_token="other-token"),
        access_token=ACCESS_TOKEN,
    )


async def test_rejects_proof_reuse_within_replay_window():
    # TS dpop.test.ts:142
    store = create_in_memory_dpop_replay_store()
    kwargs: dict[str, Any] = {
        "proof_jwt": await _proof(access_token=ACCESS_TOKEN),
        "access_token": ACCESS_TOKEN,
        "require_ath": True,
        "replay_store": store,
    }
    await verify_dpop_proof(method=METHOD, url=URL, now_seconds=NOW, **kwargs)
    await _fails("DPoP proof jti has already been used", **kwargs)


async def test_replay_key_normalizes_method_case_and_query():
    # TS dpop.ts:449: the key uses the compared method and normalized URL
    private, public_jwk = _es256_key()
    store = create_in_memory_dpop_replay_store()
    first = await _proof(private_key=private, public_jwk=public_jwk, htm="get")
    second = await _proof(private_key=private, public_jwk=public_jwk, htu=URL + "?x=1")
    await verify_dpop_proof(
        proof_jwt=first, method=METHOD, url=URL, now_seconds=NOW, replay_store=store
    )
    await _fails("DPoP proof jti has already been used", proof_jwt=second, replay_store=store)


async def test_rejects_method_mismatch_and_private_jwk():
    # TS dpop.test.ts:162
    private, public_jwk = _es256_key()
    private_jwk = json.loads(ECAlgorithm.to_jwk(private))
    await _fails(
        "DPoP proof htm does not match the request method",
        proof_jwt=await _proof(private_key=private, public_jwk=public_jwk, htm="POST"),
    )
    await _fails(
        "DPoP proof jwk must not contain private key material",
        proof_jwt=await _proof(private_key=private, header_jwk=private_jwk),
    )


async def test_rejects_header_jwk_that_fails_to_import():
    # TS dpop.test.ts:206: shape checks pass, import fails, still a protocol error
    with pytest.raises(DpopProofError):
        await verify_dpop_proof(
            proof_jwt=await _proof(
                header_jwk={"kty": "EC", "crv": "P-256", "x": "AAAA", "y": "AAAA"}
            ),
            method=METHOD,
            url=URL,
            now_seconds=NOW,
        )


async def test_rejects_signature_from_another_key():
    other_private, _ = _es256_key()
    _, public_jwk = _es256_key()
    await _fails(
        "signature verification failed",
        proof_jwt=await _proof(private_key=other_private, public_jwk=public_jwk),
    )


async def test_rejects_key_that_does_not_match_the_algorithm():
    # a P-384 key presented under an ES256 header must not verify
    p384 = ec.generate_private_key(ec.SECP384R1())
    jwk = json.loads(ECAlgorithm.to_jwk(p384.public_key()))
    signing_input = ".".join(
        base64.urlsafe_b64encode(json.dumps(part).encode()).rstrip(b"=").decode()
        for part in (
            {"typ": "dpop+jwt", "alg": "ES256", "jwk": jwk},
            {"jti": "j", "htm": METHOD, "htu": URL, "iat": NOW},
        )
    )
    es384 = ECAlgorithm(ECAlgorithm.SHA384)
    signature = es384.sign(signing_input.encode(), p384)
    proof = f"{signing_input}.{base64.urlsafe_b64encode(signature).rstrip(b'=').decode()}"
    with pytest.raises(DpopProofError):
        await verify_dpop_proof(proof_jwt=proof, method=METHOD, url=URL, now_seconds=NOW)


@pytest.mark.filterwarnings("ignore::jwt.warnings.InsecureKeyLengthWarning")
async def test_rejects_small_rsa_keys():
    small = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    jwk = json.loads(RSAAlgorithm.to_jwk(small.public_key()))
    await _fails(
        "RS256 requires key modulusLength to be 2048 bits or larger",
        proof_jwt=await _proof(private_key=small, public_jwk=jwk, alg="RS256"),
    )


async def test_structural_header_checks():
    # TS dpop.ts:348-373, 234-273
    await _fails("DPoP proof must be a compact JWT", proof_jwt="a.b")
    await _fails("DPoP proof must be a compact JWT", proof_jwt="")
    await _fails("Invalid Token or Protected Header formatting", proof_jwt="!!.b.c")
    await _fails('DPoP proof typ must be "dpop+jwt"', proof_jwt=await _proof(typ="JWT"))
    hs = pyjwt.encode(
        {"jti": "j"}, "secret-secret-secret-secret-secret", headers={"typ": "dpop+jwt"}
    )
    await _fails("DPoP proof must use an asymmetric JWS algorithm", proof_jwt=hs)
    await _fails(
        "DPoP proof uses an unsupported JWS algorithm",
        proof_jwt=await _proof(),
        signing_algorithms=["RS256"],
    )
    no_jwk = pyjwt.encode(
        {"jti": "j"}, _es256_key()[0], algorithm="ES256", headers={"typ": "dpop+jwt"}
    )
    await _fails("DPoP proof header must include a public jwk", proof_jwt=no_jwk)
    await _fails(
        "DPoP proof jwk must be asymmetric",
        proof_jwt=await _proof(header_jwk={"kty": "oct", "x": "y"}),
    )


async def test_claim_checks():
    # TS dpop.ts:393-437
    await _fails(
        "DPoP proof must include htm, htu, jti, and iat claims", proof_jwt=await _proof(jti="")
    )
    await _fails(
        "DPoP proof must include htm, htu, jti, and iat claims",
        proof_jwt=await _proof(htm=None),
    )
    await _fails('"iat" claim must be a number', proof_jwt=await _proof(iat="1700000000"))
    await _fails("DPoP proof jti is too large", proof_jwt=await _proof(jti="j" * 513))
    await _fails(
        "DPoP proof htu does not match the request URL",
        proof_jwt=await _proof(htu="https://api.example.com/other"),
    )
    await _fails(
        "DPoP proof htu must not contain a fragment", proof_jwt=await _proof(htu=URL + "#frag")
    )
    await _fails(
        "DPoP proof iat is outside the accepted window", proof_jwt=await _proof(iat=NOW + 6)
    )
    await _fails(
        "DPoP proof iat is outside the accepted window", proof_jwt=await _proof(iat=NOW - 301)
    )
    await _fails(
        "DPoP proof iat is outside the accepted window",
        proof_jwt=await _proof(iat=NOW - 61),
        proof_max_age_seconds=60,
    )
    # the edges are inclusive
    for iat in (NOW + 5, NOW - 300):
        await verify_dpop_proof(
            proof_jwt=await _proof(iat=iat), method=METHOD, url=URL, now_seconds=NOW
        )


async def test_rejects_expired_exp_claim():
    # jose jwtVerify checks exp against the wall clock
    await _fails('"exp" claim timestamp check failed', proof_jwt=await _proof(exp=NOW))


async def test_rejects_key_not_matching_the_bound_token():
    await _fails(
        "DPoP proof key does not match the bound token",
        proof_jwt=await _proof(),
        expected_jkt="some-other-thumbprint",
    )


async def test_default_now_uses_the_wall_clock():
    now = int(datetime.now(timezone.utc).timestamp())
    await verify_dpop_proof(proof_jwt=await _proof(iat=now), method=METHOD, url=URL)


# --- htu / authorization parsing -------------------------------------------------


def test_normalize_htu():
    # TS dpop.ts:179: origin + pathname, no query
    assert normalize_dpop_htu("https://API.Example.com:443/token?x=1") == (
        "https://api.example.com/token"
    )
    assert normalize_dpop_htu("http://localhost:3000/api/auth/oauth2/token") == (
        "http://localhost:3000/api/auth/oauth2/token"
    )
    assert normalize_dpop_htu("https://api.example.com") == "https://api.example.com/"
    assert normalize_dpop_htu("https://user:pw@[::1]:8443/a") == "https://[::1]:8443/a"
    assert normalize_dpop_htu("https://a.example/b#") == "https://a.example/b"
    with pytest.raises(ValueError, match="must not contain a fragment"):
        normalize_dpop_htu("https://a.example/b#c")
    for bad in ("not a url", "/relative", "https://"):
        with pytest.raises(ValueError, match="Invalid URL"):
            normalize_dpop_htu(bad)


def test_parse_access_token_authorization():
    # TS dpop.ts:153
    assert parse_access_token_authorization(None) is None
    assert parse_access_token_authorization("   ") is None
    assert parse_access_token_authorization("bearer  abc ") == AccessTokenAuthorization(
        "Bearer", "abc"
    )
    assert parse_access_token_authorization("DPOP abc") == AccessTokenAuthorization("DPoP", "abc")
    assert parse_access_token_authorization("raw-token") == AccessTokenAuthorization(
        "Unknown", "raw-token"
    )
    assert parse_access_token_authorization("Basic abc") == AccessTokenAuthorization(
        "Unknown", "Basic abc"
    )
    assert strip_access_token_authorization_scheme("DPoP abc") == "abc"
    assert strip_access_token_authorization_scheme("raw") == "raw"
    assert strip_access_token_authorization_scheme("") == ""


def test_get_confirmation_jkt():
    # TS dpop.test.ts:356
    assert get_confirmation_jkt({"jkt": "thumbprint"}) == "thumbprint"
    for value in ({"x5t#S256": "h"}, {"jkt": ""}, {"jkt": 123}, None, "malformed", 42, ["jkt"]):
        assert get_confirmation_jkt(value) is None
    assert get_dpop_jkt_from_payload({"cnf": {"jkt": "t"}}) == "t"
    assert get_dpop_jkt_from_payload({"sub": "u"}) is None


# --- replay stores ----------------------------------------------------------------


async def test_in_memory_store_evicts_expired_reservations():
    store = create_in_memory_dpop_replay_store()
    now = datetime.fromtimestamp(NOW, tz=timezone.utc)
    later = now + timedelta(seconds=10)
    assert await store.reserve(key="k", expires_at=later, now=now) is True
    assert await store.reserve(key="k", expires_at=later, now=now) is False
    assert await store.reserve(key="k", expires_at=later, now=later) is True


async def test_db_store_delegates_to_reserve_verification_value():
    # TS dpop.test.ts:331
    seen: set[str] = set()
    calls: list[tuple[str, str, datetime]] = []

    class Reservations:
        async def reserve_verification_value(
            self, identifier: str, value: str, expires_at: datetime
        ) -> bool:
            calls.append((identifier, value, expires_at))
            if identifier in seen:
                return False
            seen.add(identifier)
            return True

    store = create_dpop_replay_store(Reservations())
    now = datetime.now(timezone.utc)
    expires = now + timedelta(minutes=5)
    assert await store.reserve(key="replay-key", expires_at=expires, now=now) is True
    assert await store.reserve(key="replay-key", expires_at=expires, now=now) is False
    assert calls[0] == ("dpop-proof:replay-key", "replay-key", expires)


# --- enforce_dpop_binding (TS dpop.test.ts:250) --------------------------------------


async def _enforce(
    payload: dict[str, Any],
    scheme: AccessTokenAuthorizationScheme,
    proof_jwt: str | None = None,
    **kw: Any,
):
    await enforce_dpop_binding(
        payload=payload,
        authorization=AccessTokenAuthorization(scheme, ACCESS_TOKEN),
        proof_jwt=proof_jwt,
        method=METHOD,
        url=URL,
        **kw,
    )


async def test_enforce_passes_unbound_bearer_token():
    assert await _enforce({"sub": "user"}, "Bearer") is None


@pytest.mark.parametrize(
    ("payload", "scheme", "code", "message"),
    [
        (
            {"sub": "user"},
            "DPoP",
            "invalid_token",
            "DPoP authorization requires a DPoP-bound access token",
        ),
        (
            {"sub": "user", "cnf": {"jkt": "t"}},
            "Bearer",
            "invalid_token",
            "DPoP-bound access token requires the DPoP authorization scheme",
        ),
        (
            {"sub": "user", "cnf": {"jkt": "t"}},
            "DPoP",
            "invalid_dpop_proof",
            "DPoP proof header is required",
        ),
    ],
)
async def test_enforce_rejections(payload, scheme, code, message):
    # TS dpop.test.ts:264, 276, 290
    with pytest.raises(DpopBindingError) as info:
        await _enforce(payload, scheme)
    assert (info.value.code, str(info.value)) == (code, message)
    assert is_dpop_binding_error(info.value)
    assert not is_dpop_proof_error(info.value) or code == "invalid_dpop_proof"


async def test_enforce_accepts_matching_ath_bound_proof():
    # TS dpop.test.ts:304
    private, public_jwk = _es256_key()
    now = int(datetime.now(timezone.utc).timestamp())
    proof = await _proof(
        private_key=private, public_jwk=public_jwk, access_token=ACCESS_TOKEN, iat=now
    )
    payload = {"sub": "user", "cnf": {"jkt": await derive_dpop_jkt(public_jwk)}}
    store = create_in_memory_dpop_replay_store()
    assert await _enforce(payload, "DPoP", proof, replay_store=store) is None
    # the proof must carry ath and match the key
    with pytest.raises(DpopBindingError) as info:
        await _enforce(payload, "DPoP", proof, replay_store=store)
    assert info.value.code == "invalid_dpop_proof"
    unbound = await _proof(private_key=private, public_jwk=public_jwk, iat=now, jti="no-ath")
    with pytest.raises(DpopBindingError, match="must include an ath claim"):
        await _enforce(payload, "DPoP", unbound)


# --- oauth-provider dpop.ts -------------------------------------------------------


def test_proof_header_and_endpoint_url():
    auth = BetterAuth(secret="s" * 32, base_url="http://localhost:3000")
    bare = Ctx(auth=auth, request=AuthRequest(method="POST", path="/oauth2/token"))
    assert get_dpop_proof_jwt(bare) is None
    assert get_endpoint_url(bare, "/oauth2/token") == "http://localhost:3000/api/auth/oauth2/token"
    real = Ctx(
        auth=auth,
        request=AuthRequest(
            method="POST",
            path="/oauth2/token",
            headers={"dpop": "proof"},
            url="https://issuer.example/api/auth/oauth2/token",
        ),
    )
    assert get_dpop_proof_jwt(real) == "proof"
    assert get_endpoint_url(real, "/oauth2/token") == "https://issuer.example/api/auth/oauth2/token"


# --- resource-challenge.ts DPoP challenge -------------------------------------------


def test_dpop_challenge():
    # TS resource-challenge.test.ts:157
    assert build_dpop_challenge(
        error_code="invalid_dpop_proof",
        description="DPoP proof header is required",
        dpop_signing_algorithms=["ES256"],
    ) == (
        'DPoP error="invalid_dpop_proof", '
        'error_description="DPoP proof header is required", algs="ES256"'
    )
    assert build_dpop_challenge(error_code=None, description="x").endswith(
        f'algs="{" ".join(DPOP_SIGNING_ALGORITHMS)}"'
    )
    assert build_dpop_challenge(error_code=None, description="x").startswith(
        'DPoP error="invalid_dpop_proof"'
    )


@pytest.mark.parametrize(
    "description", ['bad "quote"', "bad\\slash", "café", "bad\r\ninjected", ""]
)
def test_dpop_challenge_rejects_invalid_description(description):
    # TS resource-challenge.test.ts:172
    with pytest.raises(ValueError, match="invalid error_description"):
        build_dpop_challenge(error_code="invalid_dpop_proof", description=description)


def test_dpop_challenge_quotes_and_rejects_control_chars():
    assert 'error="a\\"b"' in build_dpop_challenge(error_code='a"b', description="x")
    with pytest.raises(ValueError, match="invalid WWW-Authenticate parameter"):
        build_dpop_challenge(error_code="a\nb", description="x")


def test_is_dpop_challenge_error():
    # TS resource-challenge.ts:56
    assert is_dpop_challenge_error(error_code="invalid_dpop_proof", description="anything")
    assert is_dpop_challenge_error(error_code="invalid_token", description="needs DPoP proof")
    assert not is_dpop_challenge_error(error_code="invalid_token", description="expired")
    assert not is_dpop_challenge_error(error_code=None, description="DPoP")
