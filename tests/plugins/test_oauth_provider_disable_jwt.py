"""oauth-provider ``disable_jwt_plugin`` mode — HS256 id tokens + encrypted client secrets.

Verified against TS ``packages/oauth-provider/src/`` at v1.6.23: the init truth table
(``oauth.ts:157-178``), HS256 id-token signing (``token.ts:180``), opaque-only access tokens
(``token.ts:519`` ``isJwtAccessToken = audience && !disableJwtPlugin``), the introspection JWT
skip (``introspect.ts:44``), end-session HS256 verify (``logout.ts:86-107``), and discovery
(``metadata.ts:99-104`` HS256 / no ``jwks_uri``). No ``jwt`` plugin is installed in this mode.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlencode, urlsplit

import jwt as pyjwt
import pytest
from httpx import ASGITransport, AsyncClient

from better_auth.adapters.base import Where
from better_auth.crypto import default_key_hasher, symmetric_decrypt, symmetric_encrypt
from better_auth.oauth.machinery import code_challenge
from better_auth.plugins_ext.oauth_provider import OAuthProviderPlugin
from better_auth.types import AuthRequest
from conftest import make_app, make_auth, sign_up

ORIGIN = "http://localhost:3000"
ISSUER = "http://localhost:3000/api/auth"  # disabled mode: iss = baseURL
LOGIN = "https://app.example.com/login"
CONSENT = "https://app.example.com/consent"
CB = "https://app.example.com/cb"
POST_LOGOUT = "https://app.example.com/logout-done"
RESOURCE = "https://api.example.com"
# 32+ chars, as real generated client secrets are (generate_random_string(32)).
SECRET = "cs-secret-value-0123456789-abcdefgh"
VERIFIER = "verifier-" + "a" * 40


def disabled_auth(**kwargs):
    kwargs.setdefault("login_page", LOGIN)
    kwargs.setdefault("consent_page", CONSENT)
    return make_auth(
        base_url=ORIGIN,
        plugins=[OAuthProviderPlugin(disable_jwt_plugin=True, **kwargs)],
    )


def make_client(auth):
    return AsyncClient(
        transport=ASGITransport(app=make_app(auth)), base_url=ORIGIN, headers={"origin": ORIGIN}
    )


async def seed_encrypted(auth, *, client_id="client-1", secret=SECRET, **fields):
    """Seed a confidential client whose secret is stored ENCRYPTED at rest (as disabled mode
    requires so it can be recovered to HS256-sign id tokens)."""
    stored = symmetric_encrypt(auth.secret_config, secret)
    data = {
        "clientId": client_id,
        "redirectUris": [CB],
        "scopes": ["openid", "profile", "email", "offline_access"],
        "grantTypes": ["authorization_code", "client_credentials", "refresh_token"],
        "public": False,
        "disabled": False,
        "requirePKCE": False,
        "skipConsent": True,
        "clientSecret": stored,
    }
    data.update(fields)
    await auth.adapter.create("oauthClient", data)
    return stored


def authorize_url(client_id="client-1", redirect_uri=CB, **params):
    q = {"client_id": client_id, "response_type": "code", "redirect_uri": redirect_uri, **params}
    return "/api/auth/oauth2/authorize?" + urlencode({k: v for k, v in q.items() if v is not None})


async def get_code(client, *, scope, client_id="client-1", verifier=None, **authz):
    if verifier is not None:
        authz.setdefault("code_challenge", code_challenge(verifier))
        authz.setdefault("code_challenge_method", "S256")
    res = await client.get(authorize_url(client_id=client_id, scope=scope, **authz))
    assert res.status_code == 302, res.text
    return parse_qs(urlsplit(res.headers["location"]).query)["code"][0]


async def token(client, **form):
    return await client.post("/api/auth/oauth2/token", data=form)


# --- init truth table (oauth.ts:157-178) ---------------------------------------------


def test_disable_jwt_plugin_allowed():
    OAuthProviderPlugin(disable_jwt_plugin=True)


def test_disable_jwt_default_store_is_encrypted():
    assert OAuthProviderPlugin(disable_jwt_plugin=True).store_client_secret == "encrypted"


def test_jwt_enabled_default_store_is_hashed():
    assert OAuthProviderPlugin().store_client_secret == "hashed"


def test_disable_jwt_with_hashed_rejected():
    with pytest.raises(ValueError, match="id tokens will be signed with secret"):
        OAuthProviderPlugin(disable_jwt_plugin=True, store_client_secret="hashed")


def test_disable_jwt_with_hash_object_rejected():
    with pytest.raises(ValueError, match="id tokens will be signed with secret"):
        OAuthProviderPlugin(disable_jwt_plugin=True, store_client_secret={"hash": lambda s: s})


def test_disable_jwt_with_encrypted_allowed():
    OAuthProviderPlugin(disable_jwt_plugin=True, store_client_secret="encrypted")


def test_jwt_enabled_encrypted_still_rejected():
    with pytest.raises(ValueError, match="encryption method not recommended"):
        OAuthProviderPlugin(store_client_secret="encrypted")


def test_disable_jwt_does_not_require_jwt_plugin():
    # init() must run cleanly with no jwt plugin installed
    disabled_auth()


# --- encrypted secret storage reachable end-to-end -----------------------------------


async def test_create_client_stores_secret_encrypted_at_rest():
    auth = disabled_auth()
    async with make_client(auth) as c:
        await sign_up(c)
        res = await c.post(
            "/api/auth/oauth2/create-client",
            json={
                "redirect_uris": [CB],
                "client_name": "App",
                "token_endpoint_auth_method": "client_secret_basic",
            },
        )
        assert res.status_code == 201, res.text
        body = res.json()
        secret = body["client_secret"]
        row = await auth.adapter.find_one("oauthClient", [Where("clientId", body["client_id"])])
        stored = row["clientSecret"]
        assert stored != secret  # not plaintext
        assert stored != default_key_hasher(secret)  # not hashed
        assert symmetric_decrypt(auth.secret_config, stored) == secret  # recoverable


async def test_encrypted_secret_at_rest_uses_rotation_envelope():
    auth = make_auth(
        base_url=ORIGIN,
        secrets=[(1, "rotation-key-abcdefghijklmnop-01234")],
        plugins=[
            OAuthProviderPlugin(disable_jwt_plugin=True, login_page=LOGIN, consent_page=CONSENT)
        ],
    )
    async with make_client(auth) as c:
        await sign_up(c)
        res = await c.post(
            "/api/auth/oauth2/create-client",
            json={"redirect_uris": [CB], "token_endpoint_auth_method": "client_secret_basic"},
        )
        assert res.status_code == 201, res.text
        row = await auth.adapter.find_one(
            "oauthClient", [Where("clientId", res.json()["client_id"])]
        )
        assert row is not None
        assert row["clientSecret"].startswith("$ba$1$")


# --- HS256 id token full flow --------------------------------------------------------


async def test_hs256_id_token_verifies_with_client_secret():
    auth = disabled_auth()
    stored = await seed_encrypted(auth, scopes=["openid"])
    assert stored != SECRET and stored != default_key_hasher(SECRET)  # encrypted at rest
    async with make_client(auth) as c:
        await sign_up(c)
        code = await get_code(c, scope="openid")
        res = await token(
            c,
            grant_type="authorization_code",
            client_id="client-1",
            client_secret=SECRET,
            code=code,
            redirect_uri=CB,
        )
        assert res.status_code == 200, res.text
        body = res.json()
        id_token = body["id_token"]
        assert pyjwt.get_unverified_header(id_token)["alg"] == "HS256"
        # verifies HS256 with the client secret (decrypted server-side end-to-end)
        decoded = pyjwt.decode(id_token, SECRET, algorithms=["HS256"], audience="client-1")
        assert decoded["iss"] == ISSUER
        assert decoded["sub"]
        # a wrong key must NOT verify
        with pytest.raises(pyjwt.InvalidSignatureError):
            pyjwt.decode(id_token, "x" * len(SECRET), algorithms=["HS256"], audience="client-1")
        # access token is opaque, never a JWT
        assert len(body["access_token"].split(".")) != 3


async def test_public_client_without_secret_gets_no_id_token():
    auth = disabled_auth()
    await auth.adapter.create(
        "oauthClient",
        {
            "clientId": "pub-1",
            "redirectUris": [CB],
            "scopes": ["openid"],
            "grantTypes": ["authorization_code"],
            "public": True,
            "disabled": False,
            "requirePKCE": True,
            "skipConsent": True,
        },
    )
    async with make_client(auth) as c:
        await sign_up(c)
        code = await get_code(c, client_id="pub-1", scope="openid", verifier=VERIFIER)
        res = await token(
            c,
            grant_type="authorization_code",
            client_id="pub-1",
            code=code,
            redirect_uri=CB,
            code_verifier=VERIFIER,
        )
        assert res.status_code == 200, res.text
        assert "id_token" not in res.json()


async def test_access_token_always_opaque_even_with_resource():
    auth = disabled_auth(valid_audiences=[RESOURCE])
    await seed_encrypted(auth, scopes=["openid", "offline_access"])
    async with make_client(auth) as c:
        await sign_up(c)
        code = await get_code(c, scope="openid offline_access", verifier=VERIFIER)
        body = (
            await token(
                c,
                grant_type="authorization_code",
                client_id="client-1",
                client_secret=SECRET,
                code=code,
                redirect_uri=CB,
                code_verifier=VERIFIER,
                resource=RESOURCE,
            )
        ).json()
        assert len(body["access_token"].split(".")) != 3  # opaque despite resource present


# --- introspection under disabled mode -----------------------------------------------


async def test_introspection_opaque_access_when_disabled():
    auth = disabled_auth()
    await seed_encrypted(auth, scopes=["openid"])
    async with make_client(auth) as c:
        await sign_up(c)
        code = await get_code(c, scope="openid")
        access = (
            await token(
                c,
                grant_type="authorization_code",
                client_id="client-1",
                client_secret=SECRET,
                code=code,
                redirect_uri=CB,
            )
        ).json()["access_token"]
        res = await c.post(
            "/api/auth/oauth2/introspect",
            data={"client_id": "client-1", "client_secret": SECRET, "token": access},
        )
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["active"] is True
        assert body["client_id"] == "client-1"
        assert body["iss"] == ISSUER


# --- end-session HS256 verify (logout.ts:86-107) -------------------------------------


async def test_end_session_hs256_verify_and_redirect():
    auth = disabled_auth()
    await seed_encrypted(
        auth, scopes=["openid"], enableEndSession=True, postLogoutRedirectUris=[POST_LOGOUT]
    )
    async with make_client(auth) as c:
        await sign_up(c)
        code = await get_code(c, scope="openid")
        id_token = (
            await token(
                c,
                grant_type="authorization_code",
                client_id="client-1",
                client_secret=SECRET,
                code=code,
                redirect_uri=CB,
            )
        ).json()["id_token"]
        res = await c.get(
            "/api/auth/oauth2/end-session?"
            + urlencode(
                {
                    "id_token_hint": id_token,
                    "client_id": "client-1",
                    "post_logout_redirect_uri": POST_LOGOUT,
                    "state": "xyz",
                }
            )
        )
        assert res.status_code == 302, res.text
        assert res.headers["location"].startswith(POST_LOGOUT)
        assert "state=xyz" in res.headers["location"]


# --- discovery (metadata.ts:99-104) --------------------------------------------------


async def test_discovery_hs256_and_no_jwks_uri():
    auth = disabled_auth()
    oidc = await auth.handle(AuthRequest(method="GET", path="/.well-known/openid-configuration"))
    assert oidc.status == 200
    assert oidc.body["id_token_signing_alg_values_supported"] == ["HS256"]
    assert "jwks_uri" not in oidc.body
    server = await auth.handle(
        AuthRequest(method="GET", path="/.well-known/oauth-authorization-server")
    )
    assert server.status == 200
    assert "jwks_uri" not in server.body
