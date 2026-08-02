"""oauth-provider Phase C — /oauth2/token (3 grants) + minting + /oauth2/introspect.

Verified against TS ``packages/oauth-provider/src/token.ts`` (1128 LOC) and ``introspect.ts``
(522 LOC) at v1.6.23. Covers the scope->token-shape matrix, PKCE token-side downgrade matrix,
refresh rotation + family teardown (RFC 9700 §4.14), concurrency (single winner), the
client_credentials OIDC-scope rejection, pinned-vs-custom id_token claims, pairwise sub, and
the introspection azp/token-type-confusion gate.
"""

from __future__ import annotations

import asyncio

import jwt as pyjwt
from httpx import ASGITransport, AsyncClient
from jwt import PyJWKSet

from better_auth.adapters.base import Where
from better_auth.crypto import default_key_hasher
from better_auth.oauth.machinery import code_challenge
from better_auth.plugins_ext.jwt import JWTPlugin
from better_auth.plugins_ext.oauth_provider import OAuthProviderPlugin
from conftest import make_app, make_auth, sign_up

LOGIN = "https://app.example.com/login"
CONSENT = "https://app.example.com/consent"
ORIGIN = "http://localhost:3000"
ISSUER = "http://localhost:3000/api/auth"
CB = "https://app.example.com/cb"
RESOURCE = "https://api.example.com"
SECRET = "cs-secret-value"
PAIRWISE = "pairwise-secret-abcdefghijklmnop-0123456789"
VERIFIER = "verifier-" + "a" * 40  # offline_access forces PKCE at the authorize gate


def provider_auth(**kwargs):
    kwargs.setdefault("login_page", LOGIN)
    kwargs.setdefault("consent_page", CONSENT)
    return make_auth(base_url=ORIGIN, plugins=[JWTPlugin(), OAuthProviderPlugin(**kwargs)])


def make_client(auth):
    return AsyncClient(
        transport=ASGITransport(app=make_app(auth)), base_url=ORIGIN, headers={"origin": ORIGIN}
    )


async def seed(auth, *, client_id="client-1", secret=SECRET, public=False, **fields):
    data = {
        "clientId": client_id,
        "redirectUris": [CB],
        "scopes": ["openid", "profile", "email", "offline_access"],
        "grantTypes": ["authorization_code", "client_credentials", "refresh_token"],
        "public": public,
        "disabled": False,
        "requirePKCE": False,
        "skipConsent": True,
    }
    if not public and secret is not None:
        data["clientSecret"] = default_key_hasher(secret)
    data.update(fields)
    await auth.adapter.create("oauthClient", data)
    return data["clientId"]


def authorize_url(client_id="client-1", redirect_uri=CB, **params):
    from urllib.parse import urlencode

    q = {"client_id": client_id, "response_type": "code", "redirect_uri": redirect_uri, **params}
    return "/api/auth/oauth2/authorize?" + urlencode({k: v for k, v in q.items() if v is not None})


async def get_code(client, *, scope, client_id="client-1", redirect_uri=CB, verifier=None, **authz):
    from urllib.parse import parse_qs, urlsplit

    if verifier is not None:
        authz.setdefault("code_challenge", code_challenge(verifier))
        authz.setdefault("code_challenge_method", "S256")
    res = await client.get(
        authorize_url(client_id=client_id, redirect_uri=redirect_uri, scope=scope, **authz)
    )
    assert res.status_code == 302, res.text
    return parse_qs(urlsplit(res.headers["location"]).query)["code"][0]


async def token(client, **form):
    return await client.post("/api/auth/oauth2/token", data=form)


async def introspect(client, **form):
    return await client.post("/api/auth/oauth2/introspect", data=form)


def unverified(tok):
    return pyjwt.decode(tok, options={"verify_signature": False})


# --- scope -> token-shape matrix -----------------------------------------------------


async def test_openid_scope_yields_id_token_opaque_access_no_refresh():
    auth = provider_auth()
    await seed(auth, scopes=["openid"])
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
        assert body["token_type"] == "Bearer"
        assert body["id_token"]
        assert "refresh_token" not in body
        # opaque access (no resource) -> not a JWT
        assert "." not in body["access_token"] or len(body["access_token"].split(".")) != 3
        assert res.headers["cache-control"] == "no-store"
        assert res.headers["pragma"] == "no-cache"


async def test_offline_access_yields_opaque_access_plus_refresh():
    auth = provider_auth()
    await seed(auth, scopes=["openid", "offline_access"])
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
            )
        ).json()
        assert body["refresh_token"]
        assert body["id_token"]
        assert len(body["access_token"].split(".")) != 3  # opaque


async def test_offline_access_plus_resource_yields_jwt_access():
    auth = provider_auth(valid_audiences=[RESOURCE])
    await seed(auth, scopes=["openid", "offline_access"])
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
                resource=RESOURCE,
                code_verifier=VERIFIER,
            )
        ).json()
        assert body["refresh_token"]
        assert body["id_token"]
        claims = unverified(body["access_token"])  # JWT access
        assert claims["azp"] == "client-1"
        assert claims["scope"] == "openid offline_access"
        # openid adds the userinfo URL, so aud is a multi-element array (TS keeps it a list)
        assert RESOURCE in claims["aud"]
        assert f"{ISSUER}/oauth2/userinfo" in claims["aud"]


async def test_es256_jwt_plugin_mints_and_verifies_id_token_and_jwt_access():
    # The provider signs/verifies on whatever the jwt plugin is configured with
    # (jwt/types.ts:176-196 union); nothing here is EdDSA-specific.
    auth = make_auth(
        base_url=ORIGIN,
        plugins=[
            JWTPlugin(key_pair_config={"alg": "ES256"}),
            OAuthProviderPlugin(
                login_page=LOGIN, consent_page=CONSENT, valid_audiences=[RESOURCE]
            ),
        ],
    )
    await seed(auth, scopes=["openid", "offline_access"])
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
                resource=RESOURCE,
                code_verifier=VERIFIER,
            )
        ).json()
        jwks = (await c.get("/api/auth/jwks")).json()
        assert jwks["keys"][0]["alg"] == "ES256"
        key_set = PyJWKSet.from_dict(jwks)
        for tok in (body["id_token"], body["access_token"]):
            key = key_set[pyjwt.get_unverified_header(tok)["kid"]]
            claims = pyjwt.decode(tok, key.key, algorithms=["ES256"], options={"verify_aud": False})
            assert claims["iss"] == ISSUER
        # provider-side verification (verify_jws_access_token) accepts the ES256 access token
        introspected = (
            await introspect(
                c, client_id="client-1", client_secret=SECRET, token=body["access_token"]
            )
        ).json()
        assert introspected["active"] is True


# --- custom fields / claims override rules -------------------------------------------


async def test_custom_token_response_fields_cannot_override_standard():
    auth = provider_auth(
        custom_token_response_fields=lambda ctx: {"token_type": "hacked", "extra": "x"}
    )
    await seed(auth, scopes=["openid"])
    async with make_client(auth) as c:
        await sign_up(c)
        code = await get_code(c, scope="openid")
        body = (
            await token(
                c,
                grant_type="authorization_code",
                client_id="client-1",
                client_secret=SECRET,
                code=code,
                redirect_uri=CB,
            )
        ).json()
        assert body["token_type"] == "Bearer"  # standard wins
        assert body["extra"] == "x"


async def test_custom_id_token_claims_override_acr_not_pinned():
    auth = provider_auth(
        custom_id_token_claims=lambda ctx: {
            "acr": "custom-acr",
            "auth_time": 123,
            "iss": "evil",
            "sub": "evil",
            "aud": "evil",
            "iat": 1,
            "exp": 2,
        }
    )
    await seed(auth, scopes=["openid"])
    async with make_client(auth) as c:
        await sign_up(c)
        code = await get_code(c, scope="openid")
        body = (
            await token(
                c,
                grant_type="authorization_code",
                client_id="client-1",
                client_secret=SECRET,
                code=code,
                redirect_uri=CB,
            )
        ).json()
        claims = unverified(body["id_token"])
        assert claims["acr"] == "custom-acr"  # overridable
        assert claims["auth_time"] == 123  # overridable
        assert claims["iss"] == ISSUER  # pinned
        assert claims["aud"] == "client-1"  # pinned
        assert claims["iss"] != "evil" and claims["sub"] != "evil"
        assert claims["iat"] != 1 and claims["exp"] != 2


# --- client_credentials grant --------------------------------------------------------


async def test_client_credentials_success_no_refresh_no_id_token():
    auth = provider_auth()
    await seed(auth, scopes=["read", "write"])
    async with make_client(auth) as c:
        body = (
            await token(
                c,
                grant_type="client_credentials",
                client_id="client-1",
                client_secret=SECRET,
                scope="read",
            )
        ).json()
        assert body["access_token"]
        assert body["scope"] == "read"
        assert "refresh_token" not in body
        assert "id_token" not in body


async def test_client_credentials_rejects_oidc_scopes():
    auth = provider_auth()
    await seed(auth, scopes=["openid", "read"])
    async with make_client(auth) as c:
        res = await token(
            c,
            grant_type="client_credentials",
            client_id="client-1",
            client_secret=SECRET,
            scope="openid",
        )
        assert res.status_code == 400
        assert res.json()["error"] == "invalid_scope"


async def test_client_credentials_defaults_to_client_scopes():
    auth = provider_auth()
    await seed(auth, scopes=["read", "write"])
    async with make_client(auth) as c:
        body = (
            await token(
                c, grant_type="client_credentials", client_id="client-1", client_secret=SECRET
            )
        ).json()
        assert set(body["scope"].split(" ")) == {"read", "write"}


# --- PKCE token-side matrix ----------------------------------------------------------


async def test_pkce_public_client_full_flow():
    auth = provider_auth()
    await seed(auth, public=True, scopes=["openid"], tokenEndpointAuthMethod="none")
    verifier = "verifier-" + "a" * 40
    async with make_client(auth) as c:
        await sign_up(c)
        code = await get_code(
            c, scope="openid", code_challenge=code_challenge(verifier), code_challenge_method="S256"
        )
        res = await token(
            c,
            grant_type="authorization_code",
            client_id="client-1",
            code=code,
            redirect_uri=CB,
            code_verifier=verifier,
        )
        assert res.status_code == 200, res.text


async def test_pkce_missing_verifier_when_required_rejected():
    auth = provider_auth()
    await seed(auth, public=True, scopes=["openid"], tokenEndpointAuthMethod="none")
    verifier = "verifier-" + "a" * 40
    async with make_client(auth) as c:
        await sign_up(c)
        code = await get_code(
            c, scope="openid", code_challenge=code_challenge(verifier), code_challenge_method="S256"
        )
        # public client cannot present a secret and omits the verifier
        res = await token(
            c, grant_type="authorization_code", client_id="client-1", code=code, redirect_uri=CB
        )
        assert res.status_code == 400
        assert res.json()["error"] == "invalid_request"


async def test_pkce_used_in_auth_not_token_rejected():
    auth = provider_auth()
    await seed(auth, scopes=["openid"], requirePKCE=False)
    verifier = "verifier-" + "a" * 40
    async with make_client(auth) as c:
        await sign_up(c)
        code = await get_code(
            c, scope="openid", code_challenge=code_challenge(verifier), code_challenge_method="S256"
        )
        # secret present, but no verifier though auth used PKCE -> downgrade rejected
        res = await token(
            c,
            grant_type="authorization_code",
            client_id="client-1",
            client_secret=SECRET,
            code=code,
            redirect_uri=CB,
        )
        assert res.status_code == 401
        assert res.json()["error"] == "invalid_request"


async def test_pkce_used_in_token_not_auth_rejected():
    auth = provider_auth()
    await seed(auth, scopes=["openid"], requirePKCE=False)
    verifier = "verifier-" + "a" * 40
    async with make_client(auth) as c:
        await sign_up(c)
        code = await get_code(c, scope="openid")  # no challenge in auth
        res = await token(
            c,
            grant_type="authorization_code",
            client_id="client-1",
            client_secret=SECRET,
            code=code,
            redirect_uri=CB,
            code_verifier=verifier,
        )
        assert res.status_code == 401
        assert res.json()["error"] == "invalid_request"


async def test_pkce_mismatched_challenge_rejected():
    # public client so the flow reaches the PKCE challenge compare (a confidential client
    # without a secret would fail earlier at "client secret must be provided").
    auth = provider_auth()
    await seed(auth, public=True, scopes=["openid"], tokenEndpointAuthMethod="none")
    verifier = "verifier-" + "a" * 40
    async with make_client(auth) as c:
        await sign_up(c)
        code = await get_code(
            c, scope="openid", code_challenge=code_challenge("other"), code_challenge_method="S256"
        )
        res = await token(
            c,
            grant_type="authorization_code",
            client_id="client-1",
            code=code,
            redirect_uri=CB,
            code_verifier=verifier,
        )
        assert res.status_code == 401
        assert res.json()["error"] == "invalid_request"


# --- authorization_code guards -------------------------------------------------------


async def test_redirect_uri_mismatch_rejected():
    auth = provider_auth()
    await seed(auth, scopes=["openid"])
    async with make_client(auth) as c:
        await sign_up(c)
        code = await get_code(c, scope="openid")
        res = await token(
            c,
            grant_type="authorization_code",
            client_id="client-1",
            client_secret=SECRET,
            code=code,
            redirect_uri="https://app.example.com/other",
        )
        assert res.status_code == 400
        assert res.json()["error"] == "invalid_request"


async def test_wrong_client_secret_rejected():
    auth = provider_auth()
    await seed(auth, scopes=["openid"])
    async with make_client(auth) as c:
        await sign_up(c)
        code = await get_code(c, scope="openid")
        res = await token(
            c,
            grant_type="authorization_code",
            client_id="client-1",
            client_secret="wrong",
            code=code,
            redirect_uri=CB,
        )
        assert res.status_code == 401
        assert res.json()["error"] == "invalid_client"


# --- refresh grant: rotation, scope narrowing, auth_time -----------------------------


async def _issue_refresh(c, *, scope="openid offline_access"):
    code = await get_code(c, scope=scope, verifier=VERIFIER)
    body = (
        await token(
            c,
            grant_type="authorization_code",
            client_id="client-1",
            client_secret=SECRET,
            code=code,
            redirect_uri=CB,
            code_verifier=VERIFIER,
        )
    ).json()
    return body["refresh_token"]


async def test_refresh_rotation_issues_new_tokens():
    auth = provider_auth()
    await seed(auth, scopes=["openid", "offline_access"])
    async with make_client(auth) as c:
        await sign_up(c)
        rt = await _issue_refresh(c)
        res = await token(
            c,
            grant_type="refresh_token",
            client_id="client-1",
            client_secret=SECRET,
            refresh_token=rt,
        )
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["access_token"]
        assert body["refresh_token"] and body["refresh_token"] != rt


async def test_refresh_narrows_scope_but_cannot_widen():
    auth = provider_auth()
    await seed(auth, scopes=["openid", "profile", "offline_access"])
    async with make_client(auth) as c:
        await sign_up(c)
        rt = await _issue_refresh(c, scope="openid profile offline_access")
        ok = await token(
            c,
            grant_type="refresh_token",
            client_id="client-1",
            client_secret=SECRET,
            refresh_token=rt,
            scope="openid",
        )
        assert ok.status_code == 200
        assert ok.json()["scope"] == "openid"
        # widen back beyond original -> invalid_scope
        rt2 = ok.json()["refresh_token"]
        bad = await token(
            c,
            grant_type="refresh_token",
            client_id="client-1",
            client_secret=SECRET,
            refresh_token=rt2,
            scope="openid profile",
        )
        assert bad.status_code == 400
        assert bad.json()["error"] == "invalid_scope"


async def test_refresh_preserves_auth_time():
    auth = provider_auth(valid_audiences=[RESOURCE])
    await seed(auth, scopes=["openid", "offline_access"])
    async with make_client(auth) as c:
        await sign_up(c)
        code = await get_code(c, scope="openid offline_access", verifier=VERIFIER)
        first = (
            await token(
                c,
                grant_type="authorization_code",
                client_id="client-1",
                client_secret=SECRET,
                code=code,
                redirect_uri=CB,
                resource=RESOURCE,
                code_verifier=VERIFIER,
            )
        ).json()
        at1 = unverified(first["id_token"])["auth_time"]
        after = (
            await token(
                c,
                grant_type="refresh_token",
                client_id="client-1",
                client_secret=SECRET,
                refresh_token=first["refresh_token"],
                resource=RESOURCE,
            )
        ).json()
        assert unverified(after["id_token"])["auth_time"] == at1


# --- refresh replay -> family teardown (RFC 9700 §4.14) ------------------------------


async def test_revoked_refresh_replay_tears_down_family():
    auth = provider_auth()
    await seed(auth, scopes=["openid", "offline_access"])
    async with make_client(auth) as c:
        await sign_up(c)
        rt = await _issue_refresh(c)
        rotated = (
            await token(
                c,
                grant_type="refresh_token",
                client_id="client-1",
                client_secret=SECRET,
                refresh_token=rt,
            )
        ).json()
        new_rt = rotated["refresh_token"]
        # replay the OLD (now revoked) refresh -> invalid_grant + family teardown
        replay = await token(
            c,
            grant_type="refresh_token",
            client_id="client-1",
            client_secret=SECRET,
            refresh_token=rt,
        )
        assert replay.status_code == 400
        assert replay.json()["error"] == "invalid_grant"
        # whole family gone: the freshly rotated token is now rejected too
        after = await token(
            c,
            grant_type="refresh_token",
            client_id="client-1",
            client_secret=SECRET,
            refresh_token=new_rt,
        )
        assert after.status_code == 400
        rows = await auth.adapter.find_many("oauthRefreshToken", [Where("clientId", "client-1")])
        assert rows == []


# --- concurrency: single winner ------------------------------------------------------


async def test_concurrent_code_redemption_one_winner():
    auth = provider_auth()
    await seed(auth, scopes=["openid"])
    async with make_client(auth) as c:
        await sign_up(c)
        code = await get_code(c, scope="openid")
        form = dict(
            grant_type="authorization_code",
            client_id="client-1",
            client_secret=SECRET,
            code=code,
            redirect_uri=CB,
        )
        r1, r2 = await asyncio.gather(token(c, **form), token(c, **form))
        codes = sorted([r1.status_code, r2.status_code])
        # loser: consumed code -> invalid_grant (TS UNAUTHORIZED = 401)
        assert codes == [200, 401], (r1.text, r2.text)


async def test_concurrent_refresh_rotation_one_winner():
    auth = provider_auth()
    await seed(auth, scopes=["openid", "offline_access"])
    async with make_client(auth) as c:
        await sign_up(c)
        rt = await _issue_refresh(c)
        form = dict(
            grant_type="refresh_token", client_id="client-1", client_secret=SECRET, refresh_token=rt
        )
        r1, r2 = await asyncio.gather(token(c, **form), token(c, **form))
        assert sorted([r1.status_code, r2.status_code]) == [200, 400]


async def test_concurrent_revoke_vs_rotate_one_winner():
    # revoke.ts:179 CAS vs token.ts:365 rotation CAS race the same revoked=null guard, so exactly
    # one mutates. /oauth2/revoke is RFC 7009 always-200, so the outcome is observable through the
    # refresh result: rotate won -> new refresh_token; revoke won -> refresh is invalid_grant.
    auth = provider_auth()
    await seed(auth, scopes=["openid", "offline_access"])
    async with make_client(auth) as c:
        await sign_up(c)
        rt = await _issue_refresh(c)

        async def rotate():
            return await token(
                c, grant_type="refresh_token", client_id="client-1",
                client_secret=SECRET, refresh_token=rt,
            )

        async def revoke():
            return await c.post(
                "/api/auth/oauth2/revoke",
                data=dict(
                    client_id="client-1", client_secret=SECRET, token=rt,
                    token_type_hint="refresh_token",
                ),
            )

        rotate_res, revoke_res = await asyncio.gather(rotate(), revoke())
        assert revoke_res.status_code == 200  # RFC 7009 §2.2 always-200
        if rotate_res.status_code == 200:
            assert rotate_res.json()["refresh_token"]
        else:
            assert rotate_res.json()["error"] == "invalid_grant"
        # in both orderings, replaying the parent now fails closed
        replay = await token(
            c, grant_type="refresh_token", client_id="client-1",
            client_secret=SECRET, refresh_token=rt,
        )
        assert replay.status_code == 400
        assert replay.json()["error"] == "invalid_grant"


# --- hashed-at-rest ------------------------------------------------------------------


async def test_refresh_token_stored_hashed():
    auth = provider_auth()
    await seed(auth, scopes=["openid", "offline_access"])
    async with make_client(auth) as c:
        await sign_up(c)
        rt = await _issue_refresh(c)
        rows = await auth.adapter.find_many("oauthRefreshToken", [Where("clientId", "client-1")])
        assert rows and rows[0]["token"] != rt
        assert rows[0]["token"] == default_key_hasher(rt)


# --- introspection -------------------------------------------------------------------


async def test_introspect_opaque_access_active():
    auth = provider_auth()
    await seed(auth, scopes=["openid"])
    async with make_client(auth) as c:
        await sign_up(c)
        code = await get_code(c, scope="openid")
        at = (
            await token(
                c,
                grant_type="authorization_code",
                client_id="client-1",
                client_secret=SECRET,
                code=code,
                redirect_uri=CB,
            )
        ).json()["access_token"]
        res = await introspect(c, client_id="client-1", client_secret=SECRET, token=at)
        body = res.json()
        assert body["active"] is True
        assert body["client_id"] == "client-1"
        assert body["scope"] == "openid"


async def test_introspect_jwt_access_active():
    auth = provider_auth(valid_audiences=[RESOURCE])
    await seed(auth, scopes=["openid", "offline_access"])
    async with make_client(auth) as c:
        await sign_up(c)
        code = await get_code(c, scope="openid offline_access", verifier=VERIFIER)
        at = (
            await token(
                c,
                grant_type="authorization_code",
                client_id="client-1",
                client_secret=SECRET,
                code=code,
                redirect_uri=CB,
                resource=RESOURCE,
                code_verifier=VERIFIER,
            )
        ).json()["access_token"]
        body = (await introspect(c, client_id="client-1", client_secret=SECRET, token=at)).json()
        assert body["active"] is True
        assert body["client_id"] == "client-1"


async def test_introspect_refresh_active():
    auth = provider_auth()
    await seed(auth, scopes=["openid", "offline_access"])
    async with make_client(auth) as c:
        await sign_up(c)
        rt = await _issue_refresh(c)
        body = (
            await introspect(
                c, client_id="client-1", client_secret=SECRET, token=rt,
                token_type_hint="refresh_token",
            )
        ).json()
        assert body["active"] is True


async def test_introspect_rejects_jwt_plugin_session_token():
    auth = provider_auth()
    await seed(auth, scopes=["openid"])
    async with make_client(auth) as c:
        await sign_up(c)
        session_jwt = (await c.get("/api/auth/token")).json()["token"]
        body = (
            await introspect(c, client_id="client-1", client_secret=SECRET, token=session_jwt)
        ).json()
        assert body["active"] is False  # no azp -> token-type confusion rejected


async def test_introspect_requires_client_credentials():
    auth = provider_auth()
    await seed(auth, scopes=["openid"])
    async with make_client(auth) as c:
        res = await introspect(c, token="whatever")
        assert res.status_code == 401
        assert res.json()["error"] == "invalid_client"


async def test_introspect_unknown_token_inactive():
    auth = provider_auth()
    await seed(auth, scopes=["openid"])
    async with make_client(auth) as c:
        body = (
            await introspect(c, client_id="client-1", client_secret=SECRET, token="nope")
        ).json()
        assert body["active"] is False


async def test_introspect_sid_cleared_on_dead_session():
    auth = provider_auth()
    await seed(auth, scopes=["openid"])
    async with make_client(auth) as c:
        await sign_up(c)
        code = await get_code(c, scope="openid")
        at = (
            await token(
                c,
                grant_type="authorization_code",
                client_id="client-1",
                client_secret=SECRET,
                code=code,
                redirect_uri=CB,
            )
        ).json()["access_token"]
        await auth.adapter.delete_many("session", [])  # kill all sessions
        body = (await introspect(c, client_id="client-1", client_secret=SECRET, token=at)).json()
        assert body["active"] is True
        assert not body.get("sid")


# --- pairwise sub --------------------------------------------------------------------


async def test_pairwise_sub_in_id_token_and_introspection_jwt_access_stays_real():
    auth = provider_auth(pairwise_secret=PAIRWISE, valid_audiences=[RESOURCE])
    await seed(auth, scopes=["openid", "offline_access"], subjectType="pairwise")
    async with make_client(auth) as c:
        signup = await sign_up(c)
        real_uid = signup["user"]["id"]
        code = await get_code(c, scope="openid offline_access", verifier=VERIFIER)
        body = (
            await token(
                c,
                grant_type="authorization_code",
                client_id="client-1",
                client_secret=SECRET,
                code=code,
                redirect_uri=CB,
                resource=RESOURCE,
                code_verifier=VERIFIER,
            )
        ).json()
        id_sub = unverified(body["id_token"])["sub"]
        jwt_access_sub = unverified(body["access_token"])["sub"]
        assert id_sub != real_uid  # pairwise pseudonym
        assert jwt_access_sub == real_uid  # JWT access sub stays real
        introspected = (
            await introspect(
                c, client_id="client-1", client_secret=SECRET, token=body["access_token"]
            )
        ).json()
        assert introspected["active"] is True
        assert introspected["sub"] == id_sub  # pairwise resolved at presentation


# --- jwks read-once cache ------------------------------------------------------------


async def test_introspect_reads_signing_keys_once(monkeypatch):
    auth = provider_auth(valid_audiences=[RESOURCE])
    await seed(auth, scopes=["openid", "offline_access"])
    async with make_client(auth) as c:
        await sign_up(c)
        code = await get_code(c, scope="openid offline_access", verifier=VERIFIER)
        at = (
            await token(
                c,
                grant_type="authorization_code",
                client_id="client-1",
                client_secret=SECRET,
                code=code,
                redirect_uri=CB,
                resource=RESOURCE,
                code_verifier=VERIFIER,
            )
        ).json()["access_token"]

        jwt_plugin = next(p for p in auth.plugins if p.id == "jwt")
        calls = {"n": 0}
        original = jwt_plugin._get_all_keys

        async def counting():
            calls["n"] += 1
            return await original()

        monkeypatch.setattr(jwt_plugin, "_get_all_keys", counting)
        await introspect(c, client_id="client-1", client_secret=SECRET, token=at)
        await introspect(c, client_id="client-1", client_secret=SECRET, token=at)
        assert calls["n"] <= 1  # keys fetched once, then cached per plugin instance
