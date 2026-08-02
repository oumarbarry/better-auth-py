"""oauth-provider Phase D — /oauth2/userinfo, /oauth2/revoke, /oauth2/end-session + pairwise.

Verified against TS ``packages/oauth-provider/src/userinfo.ts`` (100 LOC), ``revoke.ts`` (355),
and ``logout.ts`` (193) at v1.6.23. Covers UserInfo (GET+POST, JWT and opaque bearer, openid-scope
gate, scoped claim subsets, bare 401 wire parity), revocation (opaque row delete, refresh CAS +
cascaded access deletion, already-revoked family teardown, idempotency, wrong-client rejection),
RP-initiated logout (sid-session delete + post-logout redirect, enableEndSession gate, iss/aud
verification, non-registered redirect), and pairwise sub consistency across id_token / userinfo /
introspection.
"""

from __future__ import annotations

import jwt as pyjwt
from httpx import ASGITransport, AsyncClient

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
LOGOUT_URI = "https://app.example.com/loggedout"
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


async def seed(auth, *, client_id="client-1", secret=SECRET, public=False, redirect=CB, **fields):
    data = {
        "clientId": client_id,
        "redirectUris": [redirect],
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


async def revoke(client, **form):
    return await client.post("/api/auth/oauth2/revoke", data=form)


async def userinfo(client, tok=None, *, method="GET"):
    headers = {"authorization": f"Bearer {tok}"} if tok else {}
    if method == "GET":
        return await client.get("/api/auth/oauth2/userinfo", headers=headers)
    return await client.post("/api/auth/oauth2/userinfo", headers=headers)


async def end_session(client, **params):
    from urllib.parse import urlencode

    q = urlencode({k: v for k, v in params.items() if v is not None})
    return await client.get("/api/auth/oauth2/end-session?" + q)


def unverified(tok):
    return pyjwt.decode(tok, options={"verify_signature": False})


async def _access(c, *, scope="openid", client_id="client-1", redirect_uri=CB, resource=None):
    """Run the auth-code flow and return the token response body."""
    verifier = VERIFIER if "offline_access" in scope else None
    code = await get_code(
        c, scope=scope, client_id=client_id, redirect_uri=redirect_uri, verifier=verifier
    )
    form = dict(
        grant_type="authorization_code",
        client_id=client_id,
        client_secret=SECRET,
        code=code,
        redirect_uri=redirect_uri,
    )
    if verifier:
        form["code_verifier"] = verifier
    if resource:
        form["resource"] = resource
    res = await token(c, **form)
    assert res.status_code == 200, res.text
    return res.json()


# --- UserInfo ------------------------------------------------------------------------


async def test_userinfo_get_with_opaque_bearer():
    auth = provider_auth()
    await seed(auth, scopes=["openid", "profile"])
    async with make_client(auth) as c:
        signup = await sign_up(c)
        at = (await _access(c, scope="openid"))["access_token"]
        res = await userinfo(c, at)
        assert res.status_code == 200, res.text
        assert res.json()["sub"] == signup["user"]["id"]


async def test_userinfo_post_with_bearer():
    auth = provider_auth()
    await seed(auth, scopes=["openid"])
    async with make_client(auth) as c:
        await sign_up(c)
        at = (await _access(c, scope="openid"))["access_token"]
        res = await userinfo(c, at, method="POST")
        assert res.status_code == 200, res.text
        assert res.json()["sub"]


async def test_userinfo_jwt_bearer():
    auth = provider_auth(valid_audiences=[RESOURCE])
    await seed(auth, scopes=["openid", "offline_access"])
    async with make_client(auth) as c:
        signup = await sign_up(c)
        body = await _access(c, scope="openid offline_access", resource=RESOURCE)
        assert len(body["access_token"].split(".")) == 3  # JWT access
        res = await userinfo(c, body["access_token"])
        assert res.status_code == 200, res.text
        assert res.json()["sub"] == signup["user"]["id"]


async def test_userinfo_requires_openid_scope():
    auth = provider_auth()
    await seed(auth, scopes=["profile", "email"])
    async with make_client(auth) as c:
        await sign_up(c)
        at = (await _access(c, scope="profile email"))["access_token"]
        res = await userinfo(c, at)
        assert res.status_code == 400
        assert res.json()["error"] == "invalid_scope"


async def test_userinfo_missing_bearer_401():
    auth = provider_auth()
    await seed(auth, scopes=["openid"])
    async with make_client(auth) as c:
        res = await userinfo(c, None)
        assert res.status_code == 401
        assert res.json()["error"] == "invalid_request"
        assert res.json()["error_description"] == "authorization header not found"
        # Wire parity with userinfo.ts:46 — TS sets no WWW-Authenticate header
        # (only the client-side mcp.ts, excluded from the port, does).
        assert "www-authenticate" not in res.headers


async def test_userinfo_profile_claims_subset():
    auth = provider_auth()
    await seed(auth, scopes=["openid", "profile"])
    async with make_client(auth) as c:
        await sign_up(c)  # name "Ada Lovelace"
        at = (await _access(c, scope="openid profile"))["access_token"]
        body = (await userinfo(c, at)).json()
        assert body["name"] == "Ada Lovelace"
        assert body["given_name"] == "Ada"
        assert body["family_name"] == "Lovelace"
        assert "email" not in body  # email scope not granted


async def test_userinfo_email_claims_subset():
    auth = provider_auth()
    await seed(auth, scopes=["openid", "email"])
    async with make_client(auth) as c:
        await sign_up(c)
        at = (await _access(c, scope="openid email"))["access_token"]
        body = (await userinfo(c, at)).json()
        assert body["email"] == "ada@example.com"
        assert body["email_verified"] is False
        assert "name" not in body  # profile scope not granted


async def test_userinfo_custom_claims_merged():
    auth = provider_auth(custom_user_info_claims=lambda ctx: {"custom": "yes"})
    await seed(auth, scopes=["openid"])
    async with make_client(auth) as c:
        await sign_up(c)
        at = (await _access(c, scope="openid"))["access_token"]
        assert (await userinfo(c, at)).json()["custom"] == "yes"


async def test_sub_consistent_id_token_userinfo_introspection():
    auth = provider_auth()
    await seed(auth, scopes=["openid"])
    async with make_client(auth) as c:
        signup = await sign_up(c)
        real_uid = signup["user"]["id"]
        body = await _access(c, scope="openid")
        at = body["access_token"]
        id_sub = unverified(body["id_token"])["sub"]
        ui_sub = (await userinfo(c, at)).json()["sub"]
        intro_sub = (
            await introspect(c, client_id="client-1", client_secret=SECRET, token=at)
        ).json()["sub"]
        assert id_sub == ui_sub == intro_sub == real_uid


# --- pairwise finalization -----------------------------------------------------------


async def test_pairwise_sub_consistent_id_token_userinfo_introspection_jwt_access_real():
    auth = provider_auth(pairwise_secret=PAIRWISE, valid_audiences=[RESOURCE])
    await seed(auth, scopes=["openid", "offline_access"], subjectType="pairwise")
    async with make_client(auth) as c:
        signup = await sign_up(c)
        real_uid = signup["user"]["id"]
        body = await _access(c, scope="openid offline_access", resource=RESOURCE)
        at = body["access_token"]
        id_sub = unverified(body["id_token"])["sub"]
        jwt_access_sub = unverified(at)["sub"]
        ui_sub = (await userinfo(c, at)).json()["sub"]
        intro_sub = (
            await introspect(c, client_id="client-1", client_secret=SECRET, token=at)
        ).json()["sub"]
        assert jwt_access_sub == real_uid  # JWT access sub stays real
        assert id_sub != real_uid  # pairwise pseudonym
        assert id_sub == ui_sub == intro_sub  # consistent pairwise across surfaces


async def test_pairwise_distinct_subs_across_clients_on_different_hosts():
    auth = provider_auth(pairwise_secret=PAIRWISE)
    await seed(auth, client_id="client-a", scopes=["openid"], subjectType="pairwise", redirect=CB)
    await seed(
        auth,
        client_id="client-b",
        scopes=["openid"],
        subjectType="pairwise",
        redirect="https://other.example.com/cb",
    )
    async with make_client(auth) as c:
        await sign_up(c)
        a = await _access(c, scope="openid", client_id="client-a", redirect_uri=CB)
        b = await _access(
            c, scope="openid", client_id="client-b", redirect_uri="https://other.example.com/cb"
        )
        assert unverified(a["id_token"])["sub"] != unverified(b["id_token"])["sub"]


def test_pairwise_secret_below_32_rejected_canary():
    import pytest

    with pytest.raises(ValueError):
        OAuthProviderPlugin(pairwise_secret="too-short")


# --- Revocation (RFC 7009) -----------------------------------------------------------


async def test_revoke_opaque_deletes_row():
    auth = provider_auth()
    await seed(auth, scopes=["openid"])
    async with make_client(auth) as c:
        await sign_up(c)
        at = (await _access(c, scope="openid"))["access_token"]
        assert await auth.adapter.find_many("oauthAccessToken", [Where("clientId", "client-1")])
        res = await revoke(c, client_id="client-1", client_secret=SECRET, token=at)
        assert res.status_code == 200, res.text
        where = [Where("clientId", "client-1")]
        assert await auth.adapter.find_many("oauthAccessToken", where) == []


async def test_revoke_refresh_cas_and_cascades_access_deletion():
    auth = provider_auth()
    await seed(auth, scopes=["openid", "offline_access"])
    async with make_client(auth) as c:
        await sign_up(c)
        body = await _access(c, scope="openid offline_access")
        rt = body["refresh_token"]
        assert await auth.adapter.find_many("oauthAccessToken", [Where("clientId", "client-1")])
        res = await revoke(
            c,
            client_id="client-1",
            client_secret=SECRET,
            token=rt,
            token_type_hint="refresh_token",
        )
        assert res.status_code == 200, res.text
        # refresh row CAS-revoked (not deleted); access tokens cascaded away
        rows = await auth.adapter.find_many("oauthRefreshToken", [Where("clientId", "client-1")])
        assert rows and rows[0]["revoked"] is not None
        access = await auth.adapter.find_many("oauthAccessToken", [Where("clientId", "client-1")])
        assert access == []


async def test_revoke_already_revoked_tears_down_family():
    auth = provider_auth()
    await seed(auth, scopes=["openid", "offline_access"])
    async with make_client(auth) as c:
        await sign_up(c)
        rt = (await _access(c, scope="openid offline_access"))["refresh_token"]
        first = await revoke(
            c,
            client_id="client-1",
            client_secret=SECRET,
            token=rt,
            token_type_hint="refresh_token",
        )
        assert first.status_code == 200
        # replay the now-revoked refresh -> family teardown, still 200 (RFC 7009 idempotent)
        second = await revoke(
            c,
            client_id="client-1",
            client_secret=SECRET,
            token=rt,
            token_type_hint="refresh_token",
        )
        assert second.status_code == 200
        rows = await auth.adapter.find_many("oauthRefreshToken", [Where("clientId", "client-1")])
        assert rows == []


async def test_revoke_unknown_token_idempotent_success():
    auth = provider_auth()
    await seed(auth, scopes=["openid"])
    async with make_client(auth) as c:
        res = await revoke(c, client_id="client-1", client_secret=SECRET, token="does-not-exist")
        assert res.status_code == 200, res.text


async def test_revoke_wrong_client_secret_rejected():
    auth = provider_auth()
    await seed(auth, scopes=["openid"])
    async with make_client(auth) as c:
        res = await revoke(c, client_id="client-1", client_secret="wrong", token="whatever")
        assert res.status_code == 401
        assert res.json()["error"] == "invalid_client"


async def test_revoke_missing_client_id_rejected():
    auth = provider_auth()
    await seed(auth, scopes=["openid"])
    async with make_client(auth) as c:
        res = await revoke(c, token="whatever")
        assert res.status_code == 401
        assert res.json()["error"] == "invalid_client"


# --- RP-Initiated Logout (/oauth2/end-session) ---------------------------------------


async def test_end_session_deletes_sid_session_and_redirects_with_state():
    auth = provider_auth()
    await seed(auth, scopes=["openid"], enableEndSession=True, postLogoutRedirectUris=[LOGOUT_URI])
    async with make_client(auth) as c:
        await sign_up(c)
        id_token = (await _access(c, scope="openid"))["id_token"]
        sid = unverified(id_token)["sid"]
        assert await auth.adapter.find_one("session", [Where("id", sid)]) is not None
        res = await end_session(
            c,
            id_token_hint=id_token,
            client_id="client-1",
            post_logout_redirect_uri=LOGOUT_URI,
            state="xyz",
        )
        assert res.status_code == 302, res.text
        loc = res.headers["location"]
        assert loc.startswith(LOGOUT_URI)
        assert "state=xyz" in loc
        assert await auth.adapter.find_one("session", [Where("id", sid)]) is None


async def test_end_session_verifies_id_token_hint_with_configured_alg():
    # logout.ts:86-107 verifies the hint on the jwt plugin's keys — whatever alg they use.
    auth = make_auth(
        base_url=ORIGIN,
        plugins=[
            JWTPlugin(key_pair_config={"alg": "ES256"}),
            OAuthProviderPlugin(login_page=LOGIN, consent_page=CONSENT),
        ],
    )
    await seed(auth, scopes=["openid"], enableEndSession=True, postLogoutRedirectUris=[LOGOUT_URI])
    async with make_client(auth) as c:
        await sign_up(c)
        id_token = (await _access(c, scope="openid"))["id_token"]
        sid = unverified(id_token)["sid"]
        res = await end_session(
            c, id_token_hint=id_token, client_id="client-1", post_logout_redirect_uri=LOGOUT_URI
        )
        assert res.status_code == 302, res.text
        assert await auth.adapter.find_one("session", [Where("id", sid)]) is None


async def test_end_session_requires_enable_end_session():
    auth = provider_auth()
    await seed(auth, scopes=["openid"])  # enableEndSession unset
    async with make_client(auth) as c:
        res = await end_session(c, id_token_hint="anything", client_id="client-1")
        assert res.status_code == 401
        assert res.json()["error"] == "invalid_client"


async def test_end_session_bad_audience_rejected():
    auth = provider_auth()
    await seed(auth, scopes=["openid"], enableEndSession=True)
    await seed(
        auth, client_id="client-2", enableEndSession=True, redirect="https://c2.example.com/cb"
    )
    async with make_client(auth) as c:
        await sign_up(c)
        id_token = (await _access(c, scope="openid"))["id_token"]  # aud = client-1
        res = await end_session(c, id_token_hint=id_token, client_id="client-2")
        assert res.status_code == 400
        assert res.json()["error"] == "invalid_request"


async def test_end_session_bad_issuer_rejected():
    auth = provider_auth()
    await seed(auth, scopes=["openid"], enableEndSession=True)
    async with make_client(auth) as c:
        await sign_up(c)
        jwt_plugin = next(p for p in auth.plugins if p.id == "jwt")
        forged = await jwt_plugin.sign_jwt(
            payload={"iss": "https://evil.example.com", "aud": "client-1", "sid": "x"}
        )
        res = await end_session(c, id_token_hint=forged, client_id="client-1")
        assert res.status_code == 500
        assert res.json()["error"] == "invalid_request"


async def test_end_session_non_registered_redirect_not_followed():
    auth = provider_auth()
    await seed(auth, scopes=["openid"], enableEndSession=True, postLogoutRedirectUris=[LOGOUT_URI])
    async with make_client(auth) as c:
        await sign_up(c)
        id_token = (await _access(c, scope="openid"))["id_token"]
        sid = unverified(id_token)["sid"]
        res = await end_session(
            c,
            id_token_hint=id_token,
            client_id="client-1",
            post_logout_redirect_uri="https://attacker.example.com/steal",
        )
        assert res.status_code != 302  # no redirect to an unregistered URI
        # session still logged out even without a redirect target
        assert await auth.adapter.find_one("session", [Where("id", sid)]) is None


async def test_dcr_cannot_register_enable_end_session():
    auth = provider_auth(allow_dynamic_client_registration=True)
    async with make_client(auth) as c:
        await sign_up(c)
        res = await c.post(
            "/api/auth/oauth2/register",
            json={"redirect_uris": [CB], "enable_end_session": True},
        )
        assert res.status_code == 201, res.text
        client_id = res.json()["client_id"]
        row = await auth.adapter.find_one("oauthClient", [Where("clientId", client_id)])
        assert not row.get("enableEndSession")  # server-only field stripped by DCR
