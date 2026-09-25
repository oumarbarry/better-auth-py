"""oauth-provider core at TS v1.7.6: error envelopes, client authentication (basic, post,
private_key_jwt), token grants, code replay revocation, refresh rotation replay, revocation and
introspection. Each test names its TS anchor (``packages/oauth-provider/src``)."""

from __future__ import annotations

import base64
import hashlib
import json
import time
import uuid
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import ec
from httpx import ASGITransport, AsyncClient
from jwt.algorithms import ECAlgorithm

from better_auth.adapters.base import Where
from better_auth.adapters.memory import MemoryAdapter
from better_auth.crypto import default_key_hasher
from better_auth.oauth.machinery import code_challenge
from better_auth.plugins_ext.jwt import JWTPlugin
from better_auth.plugins_ext.oauth_provider import OAuthProviderPlugin
from better_auth.plugins_ext.oauth_provider import client_assertion as ca
from conftest import make_app, make_auth, sign_up

LOGIN = "https://app.example.com/login"
CONSENT = "https://app.example.com/consent"
ORIGIN = "http://localhost:3000"
BASE = "http://localhost:3000/api/auth"
TOKEN_URL = f"{BASE}/oauth2/token"
CB = "https://app.example.com/cb"
RESOURCE = "https://api.example.com"
SECRET = "cs-secret-value"
VERIFIER = "verifier-" + "a" * 40
ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"


class PKMemoryAdapter(MemoryAdapter):
    """Memory adapter that rejects a duplicate primary key, like every real database."""

    async def create(self, model: str, data: dict[str, Any], **kwargs: Any) -> Any:
        if "id" in data and await self.find_one(model, [Where("id", data["id"])]):
            raise RuntimeError("duplicate primary key")
        return await super().create(model, data, **kwargs)


def provider_auth(**kwargs):
    kwargs.setdefault("login_page", LOGIN)
    kwargs.setdefault("consent_page", CONSENT)
    kwargs.setdefault("scopes", ["openid", "profile", "email", "offline_access", "read:posts"])
    extra = {k: kwargs.pop(k) for k in ("adapter", "trusted_origins") if k in kwargs}
    return make_auth(base_url=ORIGIN, plugins=[JWTPlugin(), OAuthProviderPlugin(**kwargs)], **extra)


def client_for(auth):
    return AsyncClient(
        transport=ASGITransport(app=make_app(auth)), base_url=ORIGIN, headers={"origin": ORIGIN}
    )


async def seed(auth, *, client_id="client-1", secret=SECRET, **fields):
    data = {
        "clientId": client_id,
        "redirectUris": [CB],
        "scopes": ["openid", "profile", "email", "offline_access"],
        "grantTypes": ["authorization_code", "client_credentials", "refresh_token"],
        "tokenEndpointAuthMethod": "client_secret_post",
        "disabled": False,
        "requirePKCE": False,
        "skipConsent": True,
    }
    if secret is not None:
        data["clientSecret"] = default_key_hasher(secret)
    data.update(fields)
    await auth.adapter.create("oauthClient", data)
    return client_id


def basic(client_id: str, secret: str) -> str:
    return "Basic " + base64.b64encode(f"{client_id}:{secret}".encode()).decode()


async def token(c, headers=None, **form):
    return await c.post("/api/auth/oauth2/token", data=form, headers=headers or {})


async def raw_form(c, path: str, pairs: list[tuple[str, str]], headers=None):
    return await c.post(
        path,
        content=urlencode(pairs),
        headers={"content-type": "application/x-www-form-urlencoded", **(headers or {})},
    )


async def get_code(c, *, scope, client_id="client-1", verifier=None, **authz):
    if verifier is not None:
        authz.setdefault("code_challenge", code_challenge(verifier))
        authz.setdefault("code_challenge_method", "S256")
    q = {"client_id": client_id, "response_type": "code", "redirect_uri": CB, "scope": scope}
    q.update(authz)
    res = await c.get("/api/auth/oauth2/authorize?" + urlencode(q))
    assert res.status_code == 302, res.text
    return parse_qs(urlsplit(res.headers["location"]).query)["code"][0]


async def code_tokens(c, *, scope="openid offline_access", **extra):
    code = await get_code(c, scope=scope, verifier=VERIFIER)
    res = await token(
        c,
        grant_type="authorization_code",
        client_id="client-1",
        client_secret=SECRET,
        code=code,
        redirect_uri=CB,
        code_verifier=VERIFIER,
        **extra,
    )
    assert res.status_code == 200, res.text
    return code, res.json()


def unverified(tok):
    return pyjwt.decode(tok, options={"verify_signature": False})


# --- validation envelopes (oauth-endpoint.ts mapIssuesToOAuthError, oauth.ts:875) ----


async def test_missing_grant_type_is_invalid_request_envelope():
    auth = provider_auth()
    async with client_for(auth) as c:
        res = await token(c)
    assert res.status_code == 400
    assert res.json() == {"error": "invalid_request", "error_description": "grant_type is required"}
    # Validation failures run before the handler, so noStore does not apply (core api/index.ts:21).
    assert "cache-control" not in res.headers


async def test_blank_grant_type_reports_zod_too_small():
    auth = provider_auth()
    async with client_for(auth) as c:
        res = await token(c, grant_type="  ")
    assert res.json() == {
        "error": "invalid_request",
        "error_description": "grant_type: Too small: expected string to have >=1 characters",
    }


async def test_unsupported_grant_type_carries_no_store_headers():
    auth = provider_auth()
    async with client_for(auth) as c:
        res = await token(c, grant_type="password")
    assert res.status_code == 400
    assert res.json() == {
        "error": "unsupported_grant_type",
        "error_description": "unsupported grant_type password",
    }
    assert res.headers["cache-control"] == "no-store"
    assert res.headers["pragma"] == "no-cache"


async def test_unsafe_redirect_uri_rejected_by_schema():
    auth = provider_auth()
    async with client_for(auth) as c:
        res = await token(c, grant_type="authorization_code", code="x", redirect_uri="http://a.io")
    assert res.json() == {
        "error": "invalid_request",
        "error_description": (
            "redirect_uri: Redirect URI must use HTTPS (HTTP allowed only for loopback hosts)"
        ),
    }


# --- client authentication (utils/index.ts:545-965) ----------------------------------


async def test_registered_basic_client_cannot_use_post():
    auth = provider_auth()
    await seed(auth, tokenEndpointAuthMethod=None, clientCredentialsScopes=["read:posts"])
    async with client_for(auth) as c:
        res = await token(
            c, grant_type="client_credentials", client_id="client-1", client_secret=SECRET
        )
    assert res.status_code == 400
    assert res.json() == {
        "error": "invalid_client",
        "error_description": "client registered for client_secret_basic cannot use "
        "client_secret_post",
    }
    assert "www-authenticate" not in res.headers


async def test_bind_client_auth_method_false_keeps_old_behavior():
    auth = provider_auth(bind_client_auth_method=False)
    await seed(auth, tokenEndpointAuthMethod=None, clientCredentialsScopes=["read:posts"])
    async with client_for(auth) as c:
        res = await token(
            c, grant_type="client_credentials", client_id="client-1", client_secret=SECRET
        )
    assert res.status_code == 200, res.text


async def test_basic_wrong_secret_challenges_with_basic():
    auth = provider_auth()
    await seed(auth, tokenEndpointAuthMethod="client_secret_basic")
    async with client_for(auth) as c:
        res = await token(
            c, {"authorization": basic("client-1", "wrong")}, grant_type="client_credentials"
        )
    assert res.status_code == 401
    assert res.json() == {"error": "invalid_client", "error_description": "invalid client_secret"}
    assert res.headers["www-authenticate"] == "Basic"


async def test_basic_without_secret_challenges():
    auth = provider_auth()
    async with client_for(auth) as c:
        res = await token(
            c, {"authorization": basic("client-1", "")}, grant_type="client_credentials"
        )
    assert res.status_code == 401
    assert res.json()["error_description"] == "invalid authorization header format"
    assert res.headers["www-authenticate"] == "Basic"


async def test_unknown_basic_client_challenges():
    auth = provider_auth()
    async with client_for(auth) as c:
        res = await token(
            c, {"authorization": basic("nobody", "x")}, grant_type="client_credentials"
        )
    assert res.status_code == 401
    assert res.json() == {"error": "invalid_client", "error_description": "missing client"}
    assert res.headers["www-authenticate"] == "Basic"


async def test_post_wrong_secret_is_400_without_challenge():
    auth = provider_auth()
    await seed(auth)
    async with client_for(auth) as c:
        res = await token(
            c, grant_type="client_credentials", client_id="client-1", client_secret="wrong"
        )
    assert res.status_code == 400
    assert res.json()["error"] == "invalid_client"
    assert "www-authenticate" not in res.headers


async def test_two_authentication_methods_rejected():
    auth = provider_auth()
    async with client_for(auth) as c:
        res = await token(
            c,
            {"authorization": basic("client-1", SECRET)},
            grant_type="client_credentials",
            client_secret=SECRET,
        )
    assert res.json() == {
        "error": "invalid_request",
        "error_description": "A request must use only one client authentication method",
    }


async def test_repeated_client_id_rejected():
    auth = provider_auth()
    async with client_for(auth) as c:
        res = await raw_form(
            c,
            "/api/auth/oauth2/token",
            [("grant_type", "client_credentials"), ("client_id", "a"), ("client_id", "b")],
        )
    assert res.json() == {
        "error": "invalid_request",
        "error_description": "client_id must not be repeated",
    }


async def test_unsupported_authorization_scheme_challenges_that_scheme():
    auth = provider_auth()
    async with client_for(auth) as c:
        res = await token(c, {"authorization": "Bearer abc"}, grant_type="client_credentials")
    assert res.status_code == 401
    assert res.json() == {
        "error": "invalid_client",
        "error_description": "unsupported authorization scheme",
    }
    assert res.headers["www-authenticate"] == "Bearer"


async def test_basic_credentials_are_form_url_decoded_and_scheme_case_insensitive():
    # core oauth2/basic-credentials.ts decodeBasicCredentials (RFC 6749 §2.3.1).
    auth = provider_auth()
    await seed(
        auth,
        secret="s p+x",
        tokenEndpointAuthMethod="client_secret_basic",
        clientCredentialsScopes=["read:posts"],
    )
    header = "basic  " + base64.b64encode(b"client-1:s+p%2Bx").decode()
    async with client_for(auth) as c:
        res = await token(c, {"authorization": header}, grant_type="client_credentials")
    assert res.status_code == 200, res.text


# --- authorization_code grant (token.ts:1361-1688) ------------------------------------


async def test_invalid_code_is_400_invalid_grant():
    auth = provider_auth()
    await seed(auth)
    async with client_for(auth) as c:
        res = await token(
            c,
            grant_type="authorization_code",
            client_id="client-1",
            client_secret=SECRET,
            code="nope",
            redirect_uri=CB,
        )
    assert res.status_code == 400
    assert res.json() == {"error": "invalid_grant", "error_description": "invalid code"}


async def test_code_replay_revokes_tokens_issued_for_the_code():
    # token.ts:1382 revokeTokensIssuedForAuthorizationCode (508d8d6f0).
    auth = provider_auth()
    await seed(auth)
    async with client_for(auth) as c:
        await sign_up(c)
        code, _ = await code_tokens(c)
        code_id = default_key_hasher(code)
        [refresh] = await auth.adapter.find_many("oauthRefreshToken", [])
        [access] = await auth.adapter.find_many("oauthAccessToken", [])
        assert refresh["authorizationCodeId"] == code_id
        assert access["authorizationCodeId"] == code_id
        replay = await token(
            c,
            grant_type="authorization_code",
            client_id="client-1",
            client_secret=SECRET,
            code=code,
            redirect_uri=CB,
            code_verifier=VERIFIER,
        )
    assert replay.status_code == 400
    assert replay.json()["error"] == "invalid_grant"
    assert await auth.adapter.find_many("oauthRefreshToken", []) == []
    assert await auth.adapter.find_many("oauthAccessToken", []) == []


async def test_refresh_rotation_carries_authorization_code_id():
    auth = provider_auth()
    await seed(auth)
    async with client_for(auth) as c:
        await sign_up(c)
        code, first = await code_tokens(c)
        res = await token(
            c,
            grant_type="refresh_token",
            client_id="client-1",
            client_secret=SECRET,
            refresh_token=first["refresh_token"],
        )
        assert res.status_code == 200, res.text
    rows = await auth.adapter.find_many("oauthRefreshToken", [])
    assert {r["authorizationCodeId"] for r in rows} == {default_key_hasher(code)}


async def test_code_client_id_mismatch_is_invalid_grant():
    auth = provider_auth()
    await seed(auth)
    await seed(auth, client_id="client-2")
    async with client_for(auth) as c:
        await sign_up(c)
        code = await get_code(c, scope="openid")
        res = await token(
            c,
            grant_type="authorization_code",
            client_id="client-2",
            client_secret=SECRET,
            code=code,
            redirect_uri=CB,
        )
    assert res.status_code == 400
    assert res.json() == {"error": "invalid_grant", "error_description": "invalid client_id"}


async def test_bound_redirect_uri_required_then_matched():
    # token.ts:1420-1441 (7d1288e7c).
    auth = provider_auth()
    await seed(auth)
    async with client_for(auth) as c:
        await sign_up(c)
        code = await get_code(c, scope="openid")
        missing = await token(
            c,
            grant_type="authorization_code",
            client_id="client-1",
            client_secret=SECRET,
            code=code,
        )
        code = await get_code(c, scope="openid")
        wrong = await token(
            c,
            grant_type="authorization_code",
            client_id="client-1",
            client_secret=SECRET,
            code=code,
            redirect_uri="https://app.example.com/other",
        )
    assert missing.json() == {
        "error": "invalid_request",
        "error_description": "redirect_uri is required",
    }
    assert wrong.status_code == 400
    assert wrong.json() == {"error": "invalid_grant", "error_description": "redirect_uri mismatch"}


async def test_nonce_bound_offline_access_without_pkce():
    # utils/index.ts:1107 isPKCERequired (dd42701af).
    auth = provider_auth()
    await seed(auth)
    async with client_for(auth) as c:
        await sign_up(c)
        code = await get_code(c, scope="openid offline_access", nonce="n-1")
        res = await token(
            c,
            grant_type="authorization_code",
            client_id="client-1",
            client_secret=SECRET,
            code=code,
            redirect_uri=CB,
        )
    assert res.status_code == 200, res.text
    assert res.json()["refresh_token"]


async def test_offline_access_without_nonce_or_pkce_redirects_new_message():
    auth = provider_auth()
    await seed(auth)
    async with client_for(auth) as c:
        await sign_up(c)
        q = {
            "client_id": "client-1",
            "response_type": "code",
            "redirect_uri": CB,
            "scope": "openid offline_access",
        }
        res = await c.get("/api/auth/oauth2/authorize?" + urlencode(q))
    loc = parse_qs(urlsplit(res.headers["location"]).query)
    assert loc["error_description"] == [
        "pkce or OIDC nonce is required when requesting offline_access scope"
    ]


async def test_id_token_carries_at_hash():
    # token.ts:300 computeOidcHash (6f2948e87): EdDSA -> SHA-512 left half.
    auth = provider_auth()
    await seed(auth)
    async with client_for(auth) as c:
        await sign_up(c)
        _, body = await code_tokens(c)
    digest = hashlib.sha512(body["access_token"].encode()).digest()
    expected = base64.urlsafe_b64encode(digest[:32]).rstrip(b"=").decode()
    assert unverified(body["id_token"])["at_hash"] == expected


# --- client_credentials grant (token.ts:1696-1774) ------------------------------------


async def test_client_credentials_uses_client_credentials_scopes():
    auth = provider_auth()
    await seed(auth, clientCredentialsScopes=["read:posts"])
    async with client_for(auth) as c:
        res = await token(
            c, grant_type="client_credentials", client_id="client-1", client_secret=SECRET
        )
        bad = await token(
            c,
            grant_type="client_credentials",
            client_id="client-1",
            client_secret=SECRET,
            scope="openid",
        )
    assert res.status_code == 200, res.text
    assert res.json()["scope"] == "read:posts"
    assert bad.json() == {
        "error": "invalid_scope",
        "error_description": "The following scopes are invalid: openid",
    }


async def test_client_credentials_requires_client_credentials_scopes():
    auth = provider_auth()
    await seed(auth)
    async with client_for(auth) as c:
        res = await token(
            c, grant_type="client_credentials", client_id="client-1", client_secret=SECRET
        )
    assert res.json() == {
        "error": "unauthorized_client",
        "error_description": "client has no authorized client_credentials scopes",
    }


async def test_legacy_default_scopes_option_keeps_old_client_credentials_behavior():
    auth = provider_auth(client_credential_grant_default_scopes=["read:posts"])
    await seed(auth, scopes=None)
    async with client_for(auth) as c:
        res = await token(
            c, grant_type="client_credentials", client_id="client-1", client_secret=SECRET
        )
    assert res.status_code == 200, res.text
    assert res.json()["scope"] == "read:posts"


async def test_public_client_cannot_use_client_credentials():
    auth = provider_auth()
    await seed(auth, secret=None, tokenEndpointAuthMethod="none")
    async with client_for(auth) as c:
        res = await token(c, grant_type="client_credentials", client_id="client-1")
    assert res.json() == {
        "error": "unauthorized_client",
        "error_description": "public clients cannot use the client_credentials grant",
    }


async def test_client_credentials_missing_client_id_is_invalid_request():
    auth = provider_auth()
    async with client_for(auth) as c:
        res = await token(c, grant_type="client_credentials")
    assert res.json() == {
        "error": "invalid_request",
        "error_description": "Missing required client_id",
    }


async def test_m2m_jwt_access_token_shape():
    # token.ts:223 createJwtAccessToken: typ at+jwt, sub=client, client_id, jti.
    auth = provider_auth(valid_audiences=[RESOURCE])
    await seed(auth, clientCredentialsScopes=["read:posts"])
    async with client_for(auth) as c:
        res = await token(
            c,
            grant_type="client_credentials",
            client_id="client-1",
            client_secret=SECRET,
            resource=RESOURCE,
        )
    at = res.json()["access_token"]
    assert pyjwt.get_unverified_header(at)["typ"] == "at+jwt"
    claims = unverified(at)
    assert claims["sub"] == "client-1"
    assert claims["client_id"] == "client-1"
    assert claims["azp"] == "client-1"
    assert len(claims["jti"]) == 32


async def test_custom_access_token_claims_cannot_override_reserved():
    auth = provider_auth(
        valid_audiences=[RESOURCE],
        custom_access_token_claims=lambda info: {"iss": "evil", "client_id": "x", "tier": 1},
    )
    await seed(auth, clientCredentialsScopes=["read:posts"])
    async with client_for(auth) as c:
        res = await token(
            c,
            grant_type="client_credentials",
            client_id="client-1",
            client_secret=SECRET,
            resource=RESOURCE,
        )
    claims = unverified(res.json()["access_token"])
    assert claims["tier"] == 1
    assert claims["client_id"] == "client-1"
    assert claims["iss"] == BASE


# --- refresh_token grant (token.ts:1782-1959, 5838df2f4) -------------------------------


async def test_refresh_missing_token_and_cross_client():
    auth = provider_auth()
    await seed(auth)
    await seed(auth, client_id="client-2")
    async with client_for(auth) as c:
        await sign_up(c)
        _, first = await code_tokens(c)
        missing = await token(
            c, grant_type="refresh_token", client_id="client-1", client_secret=SECRET
        )
        cross = await token(
            c,
            grant_type="refresh_token",
            client_id="client-2",
            client_secret=SECRET,
            refresh_token=first["refresh_token"],
        )
    assert missing.json() == {
        "error": "invalid_request",
        "error_description": "Missing a required refresh_token for refresh_token grant",
    }
    assert cross.json() == {"error": "invalid_grant", "error_description": "invalid refresh token"}


async def test_rotation_writes_rotated_at_without_reuse_window():
    auth = provider_auth()
    await seed(auth)
    async with client_for(auth) as c:
        await sign_up(c)
        _, first = await code_tokens(c)
        await token(
            c,
            grant_type="refresh_token",
            client_id="client-1",
            client_secret=SECRET,
            refresh_token=first["refresh_token"],
        )
    parent = await auth.adapter.find_one(
        "oauthRefreshToken", [Where("token", default_key_hasher(first["refresh_token"]))]
    )
    assert parent["rotatedAt"] == parent["revoked"]
    assert parent.get("rotationReplayExpiresAt") is None
    assert parent.get("rotationReplayResponse") is None


async def test_reuse_interval_replays_the_same_response():
    auth = provider_auth(refresh_token_reuse_interval=30)
    await seed(auth)
    async with client_for(auth) as c:
        await sign_up(c)
        _, first = await code_tokens(c)
        form = {
            "grant_type": "refresh_token",
            "client_id": "client-1",
            "client_secret": SECRET,
            "refresh_token": first["refresh_token"],
        }
        rotated = await token(c, **form)
        replayed = await token(c, **form)
        narrowed = await token(c, scope="openid", **form)
    assert rotated.status_code == 200 and replayed.status_code == 200, replayed.text
    a, b = rotated.json(), replayed.json()
    assert b["access_token"] == a["access_token"]
    assert b["refresh_token"] == a["refresh_token"]
    assert b["expires_at"] == a["expires_at"]
    assert replayed.headers["cache-control"] == "no-store"
    # A different request inside the window is refused but does not tear down the family.
    assert narrowed.json() == {
        "error": "invalid_grant",
        "error_description": "invalid refresh token",
    }
    parent = await auth.adapter.find_one(
        "oauthRefreshToken", [Where("token", default_key_hasher(first["refresh_token"]))]
    )
    assert (parent["rotationReplayExpiresAt"] - parent["rotatedAt"]).total_seconds() == 30
    assert a["access_token"] not in parent["rotationReplayResponse"]  # stored encrypted
    assert len(await auth.adapter.find_many("oauthRefreshToken", [])) == 2


async def test_revoked_refresh_checks_client_before_family_teardown():
    auth = provider_auth()
    await seed(auth)
    async with client_for(auth) as c:
        await sign_up(c)
        _, first = await code_tokens(c)
        await token(
            c,
            grant_type="refresh_token",
            client_id="client-1",
            client_secret=SECRET,
            refresh_token=first["refresh_token"],
        )
        res = await token(
            c,
            grant_type="refresh_token",
            client_id="client-1",
            client_secret="wrong",
            refresh_token=first["refresh_token"],
        )
    assert res.json()["error"] == "invalid_client"
    assert len(await auth.adapter.find_many("oauthRefreshToken", [])) == 2


# --- private_key_jwt (utils/client-assertion.ts) -------------------------------------


def _ec_keypair():
    key = ec.generate_private_key(ec.SECP256R1())
    jwk = json.loads(ECAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": "k1", "alg": "ES256"})
    return key, jwk


def _assertion(key, *, aud=TOKEN_URL, sub="pk-client", **overrides):
    now = int(time.time())
    claims = {"iss": sub, "sub": sub, "aud": aud, "exp": now + 60, "iat": now, "jti": "j-1"}
    claims.update(overrides)
    claims = {k: v for k, v in claims.items() if v is not None}
    return pyjwt.encode(claims, key, algorithm="ES256", headers={"kid": "k1"})


async def _pk_setup(**provider):
    key, jwk = _ec_keypair()
    auth = provider_auth(**provider)
    await seed(
        auth,
        client_id="pk-client",
        secret=None,
        tokenEndpointAuthMethod="private_key_jwt",
        jwks=json.dumps({"keys": [jwk]}),
        clientCredentialsScopes=["read:posts"],
    )
    return auth, key


async def test_private_key_jwt_authenticates_and_jti_is_single_use():
    auth, key = await _pk_setup(adapter=PKMemoryAdapter())
    assertion = _assertion(key)
    form = {
        "grant_type": "client_credentials",
        "client_assertion_type": ASSERTION_TYPE,
        "client_assertion": assertion,
    }
    async with client_for(auth) as c:
        first = await token(c, **form)
        replay = await token(c, **form)
    assert first.status_code == 200, first.text
    assert replay.json() == {
        "error": "invalid_client",
        "error_description": "client assertion jti has already been used",
    }
    digest = hashlib.sha256(b"private_key_jwt:pk-client:j-1").digest()[:24]
    [row] = await auth.adapter.find_many("oauthClientAssertion", [])
    assert row["id"] == base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    assert row["expiresAt"].timestamp() == unverified(assertion)["exp"]


async def test_private_key_jwt_accepts_issuer_audience():
    # client-assertion.ts:538-541 (801968e35).
    auth, key = await _pk_setup()
    async with client_for(auth) as c:
        res = await token(
            c,
            grant_type="client_credentials",
            client_assertion_type=ASSERTION_TYPE,
            client_assertion=_assertion(key, aud=BASE),
        )
    assert res.status_code == 200, res.text


async def test_private_key_jwt_rejections():
    auth, key = await _pk_setup()
    cases = [
        (
            {"client_assertion": _assertion(key, aud="https://x.io")},
            401,
            "client assertion signature verification failed",
        ),
        (
            {"client_assertion": _assertion(key, exp=int(time.time()) + 3600)},
            400,
            "client assertion exp is too far in the future (max 300s)",
        ),
        (
            {"client_assertion": _assertion(key, jti=None)},
            400,
            "client assertion must include jti claim",
        ),
        (
            {"client_assertion": _assertion(key), "client_assertion_type": "urn:other"},
            400,
            "unsupported client_assertion_type",
        ),
        (
            {"client_assertion": _assertion(key), "client_id": "someone-else"},
            400,
            "client_id in body does not match assertion sub/iss",
        ),
    ]
    async with client_for(auth) as c:
        for extra, status, description in cases:
            form = {"grant_type": "client_credentials", "client_assertion_type": ASSERTION_TYPE}
            form.update(extra)
            res = await token(c, **form)
            assert res.status_code == status, (description, res.text)
            assert res.json() == {"error": "invalid_client", "error_description": description}
        lone = await token(c, grant_type="client_credentials", client_assertion="abc")
    assert lone.json()["error_description"] == (
        "client_assertion and client_assertion_type must both be provided"
    )


async def test_private_key_jwt_client_cannot_use_a_secret():
    auth, _ = await _pk_setup()
    async with client_for(auth) as c:
        res = await token(
            c, grant_type="client_credentials", client_id="pk-client", client_secret="x"
        )
    assert res.json() == {
        "error": "invalid_client",
        "error_description": "client registered for private_key_jwt cannot use client_secret_post",
    }


async def test_private_key_jwt_jwks_uri_fetch_and_ssrf_gate(monkeypatch):
    key, jwk = _ec_keypair()
    auth = provider_auth(trusted_origins=["https://keys.example.com"])
    fetched: list[str] = []

    async def fake_fetch(uri):
        fetched.append(uri)
        return {"keys": [jwk]}

    monkeypatch.setattr(ca, "_fetch_jwks_from_uri", fake_fetch)
    base = {
        "secret": None,
        "tokenEndpointAuthMethod": "private_key_jwt",
        "clientCredentialsScopes": ["read:posts"],
    }
    await seed(auth, client_id="pk-client", jwksUri="https://keys.example.com/jwks", **base)
    await seed(auth, client_id="pk-http", jwksUri="http://keys.example.com/jwks", **base)
    await seed(auth, client_id="pk-private", jwksUri="https://10.0.0.1/jwks", **base)
    async with client_for(auth) as c:
        ok = await token(
            c,
            grant_type="client_credentials",
            client_assertion_type=ASSERTION_TYPE,
            client_assertion=_assertion(key, jti=str(uuid.uuid4())),
        )
        http = await token(
            c,
            grant_type="client_credentials",
            client_assertion_type=ASSERTION_TYPE,
            client_assertion=_assertion(key, sub="pk-http"),
        )
        private = await token(
            c,
            grant_type="client_credentials",
            client_assertion_type=ASSERTION_TYPE,
            client_assertion=_assertion(key, sub="pk-private"),
        )
    assert ok.status_code == 200, ok.text
    assert fetched == ["https://keys.example.com/jwks"]
    assert http.json()["error_description"] == "jwks_uri must use HTTPS"
    assert private.json()["error_description"] == (
        "jwks_uri must not point to a private or reserved address"
    )


async def test_introspect_with_private_key_jwt():
    auth, key = await _pk_setup()
    async with client_for(auth) as c:
        at = (
            await token(
                c,
                grant_type="client_credentials",
                client_assertion_type=ASSERTION_TYPE,
                client_assertion=_assertion(key, jti="a"),
            )
        ).json()["access_token"]
        res = await c.post(
            "/api/auth/oauth2/introspect",
            data={
                "token": at,
                "client_assertion_type": ASSERTION_TYPE,
                "client_assertion": _assertion(key, aud=f"{BASE}/oauth2/introspect", jti="b"),
            },
        )
    assert res.json()["active"] is True


def test_public_client_jwks_validation():
    ok = ca.validate_public_client_jwks({"keys": [{"kty": "OKP", "crv": "Ed25519", "x": "a"}]})
    assert ok["valid"] is True
    rsa_private = {"kty": "RSA", "n": "a", "e": "b", "d": "c"}
    private = ca.validate_public_client_jwks({"keys": [rsa_private]})
    assert private == {"valid": False, "error": "jwks must contain only public asymmetric keys"}


async def test_metadata_advertises_private_key_jwt():
    auth = provider_auth()
    async with client_for(auth) as c:
        res = await c.get("/api/auth/.well-known/openid-configuration")
    body = res.json()
    algs = ["RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512"]
    algs.append("EdDSA")
    assert body["token_endpoint_auth_methods_supported"] == [
        "client_secret_basic",
        "client_secret_post",
        "private_key_jwt",
    ]
    assert body["introspection_endpoint_auth_methods_supported"][-1] == "private_key_jwt"
    assert body["revocation_endpoint_auth_methods_supported"][-1] == "private_key_jwt"
    assert body["token_endpoint_auth_signing_alg_values_supported"] == algs
    assert body["introspection_endpoint_auth_signing_alg_values_supported"] == algs
    assert body["revocation_endpoint_auth_signing_alg_values_supported"] == algs


# --- revocation (revoke.ts) ----------------------------------------------------------


async def test_revoke_verified_jwt_access_is_unsupported_token_type():
    # revoke.ts:113 (3e852a265).
    auth = provider_auth(valid_audiences=[RESOURCE])
    await seed(auth)
    async with client_for(auth) as c:
        await sign_up(c)
        _, body = await code_tokens(c, resource=RESOURCE)
        res = await c.post(
            "/api/auth/oauth2/revoke",
            data={"client_id": "client-1", "client_secret": SECRET, "token": body["access_token"]},
        )
    assert res.status_code == 400
    assert res.json() == {
        "error": "unsupported_token_type",
        "error_description": "JWT access tokens are self-contained and cannot be revoked "
        "server-side",
    }


async def test_revoke_missing_and_empty_token():
    auth = provider_auth()
    await seed(auth)
    async with client_for(auth) as c:
        missing = await c.post(
            "/api/auth/oauth2/revoke", data={"client_id": "client-1", "client_secret": SECRET}
        )
        empty = await c.post(
            "/api/auth/oauth2/revoke",
            data={"client_id": "client-1", "client_secret": SECRET, "token": ""},
        )
    assert missing.json() == {"error": "invalid_request", "error_description": "token is required"}
    assert empty.json() == {
        "error": "invalid_request",
        "error_description": "missing a required token for introspection",
    }


async def test_revoke_ignores_unknown_hint():
    auth = provider_auth()
    await seed(auth)
    async with client_for(auth) as c:
        await sign_up(c)
        _, body = await code_tokens(c)
        res = await c.post(
            "/api/auth/oauth2/revoke",
            data={
                "client_id": "client-1",
                "client_secret": SECRET,
                "token": body["refresh_token"],
                "token_type_hint": "weird",
            },
        )
    assert res.status_code == 200
    [row] = await auth.adapter.find_many(
        "oauthRefreshToken", [Where("token", default_key_hasher(body["refresh_token"]))]
    )
    assert row["revoked"] is not None


# --- introspection (introspect.ts) ---------------------------------------------------


async def test_introspect_shape_headers_and_missing_token():
    auth = provider_auth()
    await seed(auth)
    async with client_for(auth) as c:
        await sign_up(c)
        _, body = await code_tokens(c)
        res = await c.post(
            "/api/auth/oauth2/introspect",
            data={"client_id": "client-1", "client_secret": SECRET, "token": body["access_token"]},
        )
        missing = await c.post(
            "/api/auth/oauth2/introspect", data={"client_id": "client-1", "client_secret": SECRET}
        )
    payload = res.json()
    assert payload["active"] is True
    assert payload["token_type"] == "Bearer"
    assert payload["azp"] == "client-1"
    assert res.headers["cache-control"] == "no-store"
    assert res.headers["pragma"] == "no-cache"
    assert missing.json() == {"error": "invalid_request", "error_description": "token is required"}


async def test_introspect_inactive_after_session_ends():
    # introspect.ts:325-343 (opaque) and 226-239 (JWT).
    auth = provider_auth(valid_audiences=[RESOURCE])
    await seed(auth)
    async with client_for(auth) as c:
        await sign_up(c)
        _, opaque = await code_tokens(c)
        _, jwt_body = await code_tokens(c, resource=RESOURCE)
        await auth.adapter.delete_many("session", [])
        results = [
            (
                await c.post(
                    "/api/auth/oauth2/introspect",
                    data={"client_id": "client-1", "client_secret": SECRET, "token": tok},
                )
            ).json()
            for tok in (opaque["access_token"], jwt_body["access_token"])
        ]
    assert results == [{"active": False}, {"active": False}]


async def test_invalid_access_token_challenges_at_userinfo():
    # introspect.ts:514 createInvalidAccessTokenError.
    auth = provider_auth()
    async with client_for(auth) as c:
        res = await c.get(
            "/api/auth/oauth2/userinfo", headers={"authorization": "Bearer not-a-token"}
        )
    assert res.status_code == 401
    assert res.json() == {"error": "invalid_token", "error_description": "Invalid access token"}
    assert res.headers["www-authenticate"] == (
        'Bearer error="invalid_token", error_description="Invalid access token"'
    )


async def test_userinfo_rejects_inactive_token_with_challenge():
    auth = provider_auth()
    await seed(auth)
    async with client_for(auth) as c:
        await sign_up(c)
        _, body = await code_tokens(c)
        await auth.adapter.delete_many("session", [])
        res = await c.get(
            "/api/auth/oauth2/userinfo",
            headers={"authorization": f"Bearer {body['access_token']}"},
        )
    assert res.status_code == 401
    assert res.json()["error"] == "invalid_token"
    assert res.headers["www-authenticate"].startswith('Bearer error="invalid_token"')
