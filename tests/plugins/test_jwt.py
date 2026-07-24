"""Tests for the jwt plugin (parity with better-auth's plugins/jwt/).

Covers the spec's endpoints, storage format (jwks row cross-runtime with TS),
EdDSA-signed token claims, key rotation + grace, the set-auth-jwt after-hook, the
server-only sign/verify helpers, config guards, and toExpJWT.

Prime directive under test: storage fidelity — a jwks row written by this port must
decode with the crypto codec TS uses (decode_jwk_private_key), and a hand-built
TS-layout row must be usable by the plugin.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

import jwt as pyjwt
import pytest
from jwt import PyJWKSet

from better_auth import Where
from better_auth.crypto import encode_jwk_private_key, generate_ed25519_jwk_pair
from better_auth.plugins_ext.jwt import JWTPlugin, to_exp_jwt
from better_auth.session import utcnow

# tests/plugins/ has no conftest of its own; pytest imports tests/conftest.py first.
from conftest import SECRET, make_auth, make_client, sign_up

API = "/api/auth"
BASE = "http://testserver"  # conftest make_auth base_url


def jwt_auth(**plugin_kwargs):
    """Build an auth with the jwt plugin; return ``(auth, plugin)``."""
    plugin = JWTPlugin(**plugin_kwargs)
    return make_auth(plugins=[plugin]), plugin


def decode_with_jwks(token: str, jwks: dict, *, audience: str = BASE, issuer: str = BASE) -> dict:
    """Verify ``token`` against a served JWK Set exactly as an external verifier would
    (mirrors the TS test's ``createLocalJWKSet`` + ``jwtVerify``)."""
    ks = PyJWKSet.from_dict(jwks)
    kid = pyjwt.get_unverified_header(token)["kid"]
    key = ks[kid]
    return pyjwt.decode(token, key.key, algorithms=["EdDSA"], audience=audience, issuer=issuer)


async def fetch_jwks(client, path: str = "/jwks") -> dict:
    response = await client.get(f"{API}{path}")
    assert response.status_code == 200, response.text
    return response.json()


# --- /jwks endpoint --------------------------------------------------------------------


async def test_jwks_lazily_creates_key_and_returns_public_jwk_set():
    auth, _ = jwt_auth()
    async with make_client(auth) as client:
        assert await auth.adapter.find_many("jwks") == []  # no key yet
        jwks = await fetch_jwks(client)
        assert len(jwks["keys"]) == 1
        key = jwks["keys"][0]
        assert key["alg"] == "EdDSA"
        assert key["kty"] == "OKP"
        assert key["crv"] == "Ed25519"
        assert "x" in key and "d" not in key  # public only, no private component
        assert key["kid"] == (await auth.adapter.find_many("jwks"))[0]["id"]


async def test_jwks_entry_field_order_matches_ts():
    # TS merges {alg, crv, ...JSON.parse(publicKey), kid}: alg, crv (kept in place by the
    # publicKey spread), kty, x, kid.
    auth, _ = jwt_auth()
    async with make_client(auth) as client:
        jwks = await fetch_jwks(client)
        assert list(jwks["keys"][0].keys()) == ["alg", "crv", "kty", "x", "kid"]


async def test_jwks_404_when_remote_url_set():
    auth, _ = jwt_auth(remote_url="https://example.com/jwks", key_pair_config={"alg": "EdDSA"})
    async with make_client(auth) as client:
        response = await client.get(f"{API}/jwks")
        assert response.status_code == 404


async def test_custom_jwks_path_serves_and_old_path_404s():
    auth, _ = jwt_auth(jwks_path="/.well-known/jwks.json")
    async with make_client(auth) as client:
        jwks = await fetch_jwks(client, "/.well-known/jwks.json")
        assert len(jwks["keys"]) > 0
        old = await client.get(f"{API}/jwks")
        assert old.status_code == 404


# --- /token endpoint -------------------------------------------------------------------


async def test_token_endpoint_returns_verifiable_jwt_with_default_claims():
    auth, _ = jwt_auth()
    async with make_client(auth) as client:
        signup = await sign_up(client)
        token = (await client.get(f"{API}/token")).json()["token"]
        jwks = await fetch_jwks(client)
        decoded = decode_with_jwks(token, jwks)
        # sub defaults to user id (also spread as an `id` claim by the definePayload default)
        assert decoded["sub"] == signup["user"]["id"]
        assert decoded["sub"] == decoded["id"]
        assert decoded["iss"] == BASE
        assert decoded["aud"] == BASE
        assert decoded["exp"] - decoded["iat"] == 15 * 60  # default expirationTime "15m"
        assert decoded["email"] == "ada@example.com"


async def test_token_requires_session():
    auth, _ = jwt_auth()
    async with make_client(auth) as client:
        response = await client.get(f"{API}/token")
        assert response.status_code == 401


async def test_define_payload_and_get_subject_overrides():
    def define_payload(session):
        return {"role": "admin", "email": session["user"]["email"]}

    def get_subject(session):
        return "custom-" + session["user"]["id"]

    auth, _ = jwt_auth(define_payload=define_payload, get_subject=get_subject)
    async with make_client(auth) as client:
        signup = await sign_up(client)
        token = (await client.get(f"{API}/token")).json()["token"]
        jwks = await fetch_jwks(client)
        decoded = decode_with_jwks(token, jwks)
        assert decoded["role"] == "admin"
        assert decoded["email"] == "ada@example.com"
        assert decoded["sub"] == "custom-" + signup["user"]["id"]
        assert "id" not in decoded  # definePayload replaced the default user payload


# --- set-auth-jwt after-hook -----------------------------------------------------------


async def test_set_auth_jwt_header_on_get_session():
    auth, _ = jwt_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        response = await client.get(f"{API}/get-session")
        token = response.headers.get("set-auth-jwt")
        assert token and len(token) > 10
        jwks = await fetch_jwks(client)
        decoded = decode_with_jwks(token, jwks)
        assert decoded["email"] == "ada@example.com"
        exposed = [
            h.strip() for h in response.headers.get("access-control-expose-headers", "").split(",")
        ]
        assert "set-auth-jwt" in exposed


async def test_no_set_auth_jwt_when_unauthenticated():
    auth, _ = jwt_auth()
    async with make_client(auth) as client:
        response = await client.get(f"{API}/get-session")
        assert response.json() is None
        assert "set-auth-jwt" not in response.headers


async def test_disable_setting_jwt_header():
    auth, _ = jwt_auth(disable_setting_jwt_header=True)
    async with make_client(auth) as client:
        await sign_up(client)
        response = await client.get(f"{API}/get-session")
        assert "set-auth-jwt" not in response.headers


async def test_set_auth_jwt_merges_existing_expose_headers():
    # A plugin registered before jwt seeds its own expose-header on /get-session; jwt must
    # MERGE set-auth-jwt in, not clobber the existing value.
    from better_auth.plugins import HookSet, Plugin, PluginHook, add_expose_headers

    class _ExposeXPlugin(Plugin):
        id = "expose-x"

        def hooks(self):
            async def handler(ctx):
                add_expose_headers(ctx.response, "x-custom")
                return None

            return HookSet(
                after=[PluginHook(lambda ctx: ctx.request.path == "/get-session", handler)]
            )

    auth = make_auth(plugins=[_ExposeXPlugin(), JWTPlugin()])
    async with make_client(auth) as client:
        await sign_up(client)
        response = await client.get(f"{API}/get-session")
        exposed = [
            h.strip() for h in response.headers.get("access-control-expose-headers", "").split(",")
        ]
        assert "set-auth-jwt" in exposed
        assert "x-custom" in exposed


# --- storage format (cross-runtime fidelity) -------------------------------------------


async def test_jwks_row_storage_shape_and_private_key_codec():
    auth, _ = jwt_auth()
    async with make_client(auth) as client:
        await fetch_jwks(client)  # lazily create the key
    rows = await auth.adapter.find_many("jwks")
    assert len(rows) == 1
    row = rows[0]
    # exactly the TS schema.ts columns (+ id PK); NO alg/crv/expiresAt columns persisted
    assert set(row.keys()) == {"id", "publicKey", "privateKey", "createdAt"}
    assert isinstance(row["createdAt"], datetime)
    # publicKey column = JSON.stringify(publicWebKey) — a bare JWK object
    public_jwk = json.loads(row["publicKey"])
    assert public_jwk == {"kty": "OKP", "crv": "Ed25519", "x": public_jwk["x"]}
    # privateKey column decodes with the exact TS codec (JSON.parse -> decrypt -> JSON.parse)
    from better_auth.crypto import decode_jwk_private_key

    private_jwk = decode_jwk_private_key(SECRET, row["privateKey"])
    assert private_jwk["x"] == public_jwk["x"]
    assert set(private_jwk) == {"kty", "crv", "x", "d"}


async def test_ts_written_row_is_usable_by_python():
    # A jwks row a TS app would write (encrypted private key, JSON public key) must work here.
    auth, plugin = jwt_auth()
    public_jwk, private_jwk = generate_ed25519_jwk_pair()
    created = await auth.adapter.create(
        "jwks",
        {
            "publicKey": json.dumps(public_jwk),
            "privateKey": encode_jwk_private_key(SECRET, private_jwk),
            "createdAt": utcnow(),
        },
    )
    async with make_client(auth) as client:
        token = await plugin.sign_jwt(payload={"sub": "u1"})
        assert pyjwt.get_unverified_header(token)["kid"] == created["id"]  # signed with the TS row
        jwks = await fetch_jwks(client)
        assert jwks["keys"][0]["x"] == public_jwk["x"]
        decoded = decode_with_jwks(token, jwks)
        assert decoded["sub"] == "u1"


async def test_disable_private_key_encryption_row_readable():
    auth, plugin = jwt_auth(disable_private_key_encryption=True)
    async with make_client(auth) as client:
        token = await plugin.sign_jwt(payload={"sub": "plain"})
        row = (await auth.adapter.find_many("jwks"))[0]
        # plain: privateKey column = JSON.stringify(privateWebKey), directly a JWK with 'd'
        stored = json.loads(row["privateKey"])
        assert set(stored) == {"kty", "crv", "x", "d"}
        jwks = await fetch_jwks(client)
        assert decode_with_jwks(token, jwks)["sub"] == "plain"


# --- server-only sign_jwt / verify_jwt -------------------------------------------------


async def test_sign_jwt_server_only_verifiable_and_claims_preserved():
    auth, plugin = jwt_auth()
    now = int(time.time())
    async with make_client(auth) as client:
        token = await plugin.sign_jwt(
            payload={
                "sub": "123",
                "exp": now + 600,
                "iat": now,
                "iss": BASE,
                "aud": BASE,
                "custom": "c",
            }
        )
        header = pyjwt.get_unverified_header(token)
        assert header["alg"] == "EdDSA" and "kid" in header
        jwks = await fetch_jwks(client)
        assert header["kid"] in {k["kid"] for k in jwks["keys"]}
        decoded = decode_with_jwks(token, jwks)
        assert decoded["sub"] == "123"
        assert decoded["custom"] == "c"
        assert decoded["iss"] == BASE and decoded["aud"] == BASE


async def test_sign_jwt_defaults_iss_aud_exp():
    auth, plugin = jwt_auth()
    async with make_client(auth) as client:
        token = await plugin.sign_jwt(payload={"sub": "x", "iat": int(time.time())})
        jwks = await fetch_jwks(client)
        decoded = decode_with_jwks(token, jwks)
        assert decoded["iss"] == BASE and decoded["aud"] == BASE
        assert decoded["exp"] - decoded["iat"] == 15 * 60


async def test_verify_jwt_server_only():
    _auth, plugin = jwt_auth()
    token = await plugin.sign_jwt(payload={"sub": "abc", "iat": int(time.time())})
    payload = await plugin.verify_jwt(token)
    assert payload is not None
    assert payload["sub"] == "abc"
    assert payload["aud"] == BASE


async def test_verify_jwt_rejects_garbage_and_missing_kid():
    _auth, plugin = jwt_auth()
    await plugin.sign_jwt(payload={"sub": "abc"})  # ensure a key exists
    assert await plugin.verify_jwt("not-a-jwt") is None
    # a well-formed JWT with no kid header
    bogus = pyjwt.encode({"sub": "x", "aud": BASE, "iss": BASE}, "x" * 32, algorithm="HS256")
    assert await plugin.verify_jwt(bogus) is None


async def test_verify_jwt_issuer_override():
    _auth, plugin = jwt_auth()
    token = await plugin.sign_jwt(
        payload={"sub": "abc", "iss": "https://issuer.example", "iat": int(time.time())}
    )
    # default issuer (BASE) mismatches -> None
    assert await plugin.verify_jwt(token) is None
    # explicit issuer matches -> payload
    payload = await plugin.verify_jwt(token, issuer="https://issuer.example")
    assert payload is not None and payload["sub"] == "abc"


async def test_server_only_helpers_not_http_mounted():
    auth, _ = jwt_auth()
    async with make_client(auth) as client:
        assert (
            await client.post(f"{API}/sign-jwt", json={"payload": {"sub": "1"}})
        ).status_code == 404
        assert (await client.post(f"{API}/verify-jwt", json={"token": "x"})).status_code == 404


# --- key rotation + grace --------------------------------------------------------------


async def test_rotation_creates_new_key_when_latest_expired():
    auth, plugin = jwt_auth(rotation_interval=3600)
    t1 = await plugin.sign_jwt(payload={"sub": "u1"})
    k1 = (await auth.adapter.find_many("jwks"))[0]["id"]
    await auth.adapter.update(
        "jwks", [Where("id", k1)], {"expiresAt": utcnow() - timedelta(seconds=1)}
    )
    t2 = await plugin.sign_jwt(payload={"sub": "u1"})
    rows = await auth.adapter.find_many("jwks")
    assert len(rows) == 2
    assert pyjwt.get_unverified_header(t1)["kid"] == k1
    assert pyjwt.get_unverified_header(t2)["kid"] != k1  # newest key signs


async def test_old_key_stays_published_within_grace_then_dropped():
    auth, plugin = jwt_auth(rotation_interval=3600, grace_period=86400)
    async with make_client(auth) as client:
        t1 = await plugin.sign_jwt(payload={"sub": "u1"})
        k1 = (await auth.adapter.find_many("jwks"))[0]["id"]
        # expire k1 but keep it within the grace window, then rotate
        await auth.adapter.update(
            "jwks", [Where("id", k1)], {"expiresAt": utcnow() - timedelta(seconds=1)}
        )
        await plugin.sign_jwt(payload={"sub": "u1"})  # creates k2
        jwks = await fetch_jwks(client)
        kids = {k["kid"] for k in jwks["keys"]}
        assert k1 in kids and len(kids) == 2
        # a token signed by the old key still verifies against the published set
        assert decode_with_jwks(t1, jwks)["sub"] == "u1"
        # push k1 past grace -> dropped from /jwks
        await auth.adapter.update(
            "jwks", [Where("id", k1)], {"expiresAt": utcnow() - timedelta(seconds=86400 + 10)}
        )
        jwks2 = await fetch_jwks(client)
        assert k1 not in {k["kid"] for k in jwks2["keys"]}


# --- config guards ---------------------------------------------------------------------


def test_sign_without_remote_url_raises():
    with pytest.raises(ValueError, match=r"remoteUrl must be set when using options\.jwt\.sign"):
        JWTPlugin(sign=lambda payload: "x")


def test_remote_url_without_alg_raises():
    with pytest.raises(ValueError, match=r"keyPairConfig\.alg must be specified"):
        JWTPlugin(remote_url="https://example.com/jwks")


@pytest.mark.parametrize("bad_path", ["", "no-leading-slash", "/has/../dotdot"])
def test_invalid_jwks_path_raises(bad_path):
    with pytest.raises(ValueError, match="jwksPath must be a non-empty string"):
        JWTPlugin(jwks_path=bad_path)


async def test_non_eddsa_algorithm_raises_not_implemented():
    # construction is fine (matches TS remoteUrl+alg guard semantics); local key gen is not
    _auth, plugin = jwt_auth(key_pair_config={"alg": "ES256"})
    with pytest.raises(NotImplementedError, match="EdDSA"):
        await plugin.sign_jwt(payload={"sub": "1"})


# --- toExpJWT --------------------------------------------------------------------------


def test_to_exp_jwt_number_passthrough():
    assert to_exp_jwt(3600, 1000) == 3600
    assert to_exp_jwt(0, 1000) == 0


def test_to_exp_jwt_datetime_floors_to_seconds():
    dt = datetime(2024, 1, 1, tzinfo=timezone.utc)
    assert to_exp_jwt(dt, 1000) == int(dt.timestamp())
    assert to_exp_jwt(datetime.fromtimestamp(1704067200.5, tz=timezone.utc), 1000) == 1704067200


@pytest.mark.parametrize(
    ("span", "expected"),
    [
        ("1h", 1000 + 3600),
        ("7d", 1000 + 604800),
        ("30m", 1000 + 1800),
        ("1s", 1000 + 1),
        ("1 hour", 1000 + 3600),
        ("30 minutes", 1000 + 1800),
        ("-1h", 1000 - 3600),
        ("1h ago", 1000 - 3600),
        ("15m", 1000 + 900),
    ],
)
def test_to_exp_jwt_time_span(span, expected):
    assert to_exp_jwt(span, 1000) == expected


@pytest.mark.parametrize("bad", ["invalid", "", "abc123"])
def test_to_exp_jwt_invalid_raises(bad):
    with pytest.raises((TypeError, ValueError)):
        to_exp_jwt(bad, 1000)
