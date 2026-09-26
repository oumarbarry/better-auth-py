"""oauth-provider: DPoP-bound tokens at /oauth2/token, /oauth2/userinfo and introspection.

Anchored to TS v1.7.6 ``token.ts`` resolveDpopTokenBinding (token.ts:789), ``userinfo.ts:141``
enforceDpopBinding and ``introspect.ts:245/418/509`` (aedcb974f).
"""

from __future__ import annotations

import json
import secrets
import time
from typing import Any

import jwt as pyjwt
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm
from test_oauth_provider_token import (
    CB,
    ORIGIN,
    SECRET,
    VERIFIER,
    get_code,
    introspect,
    make_client,
    provider_auth,
    seed,
    unverified,
)

from better_auth.plugins_ext.oauth_provider.dpop import derive_dpop_ath, derive_dpop_jkt
from conftest import sign_up

TOKEN_URL = f"{ORIGIN}/api/auth/oauth2/token"
USERINFO_URL = f"{ORIGIN}/api/auth/oauth2/userinfo"
API = "https://api.example.com"


class Key:
    def __init__(self) -> None:
        self.private = ec.generate_private_key(ec.SECP256R1())
        self.jwk: dict[str, Any] = json.loads(ECAlgorithm.to_jwk(self.private.public_key()))

    async def jkt(self) -> str:
        return await derive_dpop_jkt(self.jwk)

    async def proof(self, method: str, url: str, access_token: str | None = None) -> str:
        claims: dict[str, Any] = {
            "jti": secrets.token_urlsafe(16),
            "htm": method,
            "htu": url,
            "iat": int(time.time()),
        }
        if access_token:
            claims["ath"] = await derive_dpop_ath(access_token)
        return pyjwt.encode(
            claims, self.private, algorithm="ES256", headers={"typ": "dpop+jwt", "jwk": self.jwk}
        )


async def post_token(c, form, proof=None):
    headers = {"dpop": proof} if proof else {}
    return await c.post("/api/auth/oauth2/token", data=form, headers=headers)


async def code_form(c, **authz):
    code = await get_code(c, scope=authz.pop("scope", "openid"), **authz)
    return {
        "grant_type": "authorization_code",
        "client_id": "client-1",
        "client_secret": SECRET,
        "code": code,
        "redirect_uri": CB,
    }


async def test_proof_binds_the_opaque_token_and_userinfo_requires_the_dpop_scheme():
    auth = provider_auth()
    await seed(auth)
    key = Key()
    async with make_client(auth) as c:
        await sign_up(c)
        form = await code_form(c, scope="openid email")
        res = await post_token(c, form, await key.proof("POST", TOKEN_URL))
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["token_type"] == "DPoP"
        row = (await auth.adapter.find_many("oauthAccessToken", []))[0]
        assert row["confirmation"] == {"jkt": await key.jkt()}

        access = body["access_token"]
        info = await c.get(USERINFO_URL, headers={"authorization": f"Bearer {access}"})
        assert info.status_code == 401
        assert info.json() == {
            "error": "invalid_token",
            "error_description": "DPoP-bound access token requires the DPoP authorization scheme",
        }
        info = await c.get(
            USERINFO_URL,
            headers={
                "authorization": f"DPoP {access}",
                "dpop": await key.proof("GET", USERINFO_URL, access),
            },
        )
        assert info.status_code == 200, info.text
        assert info.json()["email"] == "ada@example.com"

        intro = (
            await introspect(c, client_id="client-1", client_secret=SECRET, token=access)
        ).json()
        assert intro["token_type"] == "DPoP"
        assert intro["cnf"] == {"jkt": await key.jkt()}


async def test_jwt_access_token_carries_cnf():
    auth = provider_auth(resources=[API], enforce_per_client_resources=False)
    await seed(auth)
    key = Key()
    async with make_client(auth) as c:
        await sign_up(c)
        form = await code_form(c)
        form["resource"] = API
        body = (await post_token(c, form, await key.proof("POST", TOKEN_URL))).json()
        assert body["token_type"] == "DPoP"
        assert unverified(body["access_token"])["cnf"] == {"jkt": await key.jkt()}


async def test_dpop_jkt_on_authorize_requires_a_matching_proof():
    # token.ts:799-811: a dpop_jkt binding makes the proof mandatory.
    auth = provider_auth()
    await seed(auth)
    key, other = Key(), Key()
    async with make_client(auth) as c:
        await sign_up(c)
        form = await code_form(c, dpop_jkt=await key.jkt())
        res = await post_token(c, form)
        assert res.status_code == 400
        assert res.json() == {
            "error": "invalid_dpop_proof",
            "error_description": "DPoP proof header is required",
        }
        form = await code_form(c, dpop_jkt=await key.jkt())
        res = await post_token(c, form, await other.proof("POST", TOKEN_URL))
        assert res.json()["error"] == "invalid_dpop_proof"
        form = await code_form(c, dpop_jkt=await key.jkt())
        res = await post_token(c, form, await key.proof("POST", TOKEN_URL))
        assert res.json()["token_type"] == "DPoP"


async def test_resource_requiring_dpop_rejects_bearer_issuance():
    auth = provider_auth(
        resources=[{"identifier": API, "dpopBoundAccessTokensRequired": True}],
        enforce_per_client_resources=False,
    )
    await seed(auth)
    async with make_client(auth) as c:
        await sign_up(c)
        form = await code_form(c)
        form["resource"] = API
        res = await post_token(c, form)
        assert res.json()["error_description"] == "DPoP proof header is required"


async def test_refresh_family_stays_bound_to_the_key():
    auth = provider_auth()
    await seed(auth)
    key = Key()
    async with make_client(auth) as c:
        await sign_up(c)
        form = await code_form(c, scope="openid offline_access", verifier=VERIFIER)
        form["code_verifier"] = VERIFIER
        body = (await post_token(c, form, await key.proof("POST", TOKEN_URL))).json()
        refresh = {
            "grant_type": "refresh_token",
            "client_id": "client-1",
            "client_secret": SECRET,
            "refresh_token": body["refresh_token"],
        }
        res = await post_token(c, refresh)
        assert res.json()["error"] == "invalid_dpop_proof"
        res = await post_token(c, refresh, await key.proof("POST", TOKEN_URL))
        assert res.status_code == 200, res.text
        assert res.json()["token_type"] == "DPoP"
        rows = await auth.adapter.find_many("oauthRefreshToken", [])
        jkt = await key.jkt()
        assert all(r["confirmation"] == {"jkt": jkt} for r in rows)
