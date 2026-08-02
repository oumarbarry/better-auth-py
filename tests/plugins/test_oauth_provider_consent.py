"""oauth-provider Phase B — signed-query resume, consent, continue, consent CRUD.

Verified against TS ``consent.ts``, ``continue.ts``, ``oauth.ts`` hooks (481-580),
``oauthConsent/endpoints.ts`` at v1.6.23. Covers: login -> after-hook re-drives authorize,
login-prompt satisfied only when ``session.createdAt >= ba_iat``, ``ba_pl`` trusted only
server-minted, consent accept/deny + scope narrowing, consent-required when stored scopes
are a strict subset, and consent CRUD ownership + scope-subset validation.
"""

from __future__ import annotations

import time
from urllib.parse import parse_qs, urlencode, urlsplit

from httpx import ASGITransport, AsyncClient

from better_auth.adapters.base import Where
from better_auth.plugins_ext.jwt import JWTPlugin
from better_auth.plugins_ext.oauth_provider import OAuthProviderPlugin
from better_auth.plugins_ext.oauth_provider.utils import sign_oauth_query
from conftest import SECRET, make_app, make_auth, sign_up

LOGIN = "https://app.example.com/login"
CONSENT = "https://app.example.com/consent"
POSTLOGIN = "https://app.example.com/post-login"
CB = "https://app.example.com/cb"
ORIGIN = "http://localhost:3000"


def provider_auth(**kwargs):
    kwargs.setdefault("login_page", LOGIN)
    kwargs.setdefault("consent_page", CONSENT)
    return make_auth(base_url=ORIGIN, plugins=[JWTPlugin(), OAuthProviderPlugin(**kwargs)])


def make_client(auth):
    return AsyncClient(
        transport=ASGITransport(app=make_app(auth)), base_url=ORIGIN, headers={"origin": ORIGIN}
    )


async def seed_client(auth, **fields):
    data = {
        "clientId": fields.pop("clientId", "client-1"),
        "redirectUris": [CB],
        "scopes": ["openid", "profile"],
        "grantTypes": ["authorization_code"],
        "public": False,
        "disabled": False,
        "requirePKCE": False,
        "skipConsent": False,
    }
    data.update(fields)
    await auth.adapter.create("oauthClient", data)
    return data["clientId"]


def authorize_url(**params):
    q = {"client_id": "client-1", "response_type": "code", "redirect_uri": CB, **params}
    return "/api/auth/oauth2/authorize?" + urlencode({k: v for k, v in q.items() if v is not None})


async def user_id(auth):
    users = await auth.adapter.find_many("user", [])
    return users[0]["id"]


def signed(*, issued_at_ms=None, exp=None, **params):
    now = int(time.time())
    q = {"client_id": "client-1", "response_type": "code", "redirect_uri": CB, **params}
    return sign_oauth_query(
        list(q.items()),
        SECRET,
        exp=exp if exp is not None else now + 600,
        issued_at_ms=issued_at_ms if issued_at_ms is not None else now * 1000,
    )


# --- signed-query resume end-to-end (login -> after-hook re-drives authorize) ---------


async def test_login_resume_redirects_to_authorization_code():
    auth = provider_auth()
    await seed_client(auth, scopes=["openid"], skipConsent=True)
    async with make_client(auth) as setup:
        await sign_up(setup)  # create the user
    async with make_client(auth) as client:  # fresh, unauthenticated
        res = await client.get(authorize_url(scope="openid"))
        assert res.status_code == 302
        signed_query = urlsplit(res.headers["location"]).query
        assert res.headers["location"].startswith(LOGIN)

        login = await client.post(
            "/api/auth/sign-in/email",
            json={
                "email": "ada@example.com",
                "password": "s3cret-password",
                "oauth_query": signed_query,
            },
        )
        assert login.status_code == 200, login.text
        body = login.json()
        assert body["redirect"] is True
        assert body["url"].startswith(CB)
        assert "code=" in body["url"]
        # the resume redirect must still carry the freshly issued session cookie
        assert any(c.lower() == "set-cookie" for c in login.headers)


async def test_invalid_signature_rejected():
    auth = provider_auth()
    await seed_client(auth, scopes=["openid"], skipConsent=True)
    async with make_client(auth) as setup:
        await sign_up(setup)
    async with make_client(auth) as client:
        login = await client.post(
            "/api/auth/sign-in/email",
            json={
                "email": "ada@example.com",
                "password": "s3cret-password",
                "oauth_query": "client_id=client-1&sig=forged",
            },
        )
        assert login.status_code == 400
        assert login.json()["error"] == "invalid_signature"


# --- login prompt satisfied only when session.createdAt >= ba_iat ---------------------


async def test_stale_session_does_not_satisfy_login_prompt():
    auth = provider_auth()
    await seed_client(auth, scopes=["openid"], skipConsent=True)
    async with make_client(auth) as client:
        await sign_up(client)  # session created at ~now
        # ba_iat far in the future -> session predates it -> login NOT satisfied
        future = int((time.time() + 600) * 1000)
        query = signed(scope="openid", prompt="login", issued_at_ms=future)
        res = await client.post(
            "/api/auth/oauth2/consent", json={"accept": True, "oauth_query": query}
        )
        assert res.status_code == 200, res.text
        # re-driven authorize still forces the login page (prompt=login kept)
        assert res.json()["url"].startswith(LOGIN)


async def test_fresh_session_satisfies_login_prompt_and_mints_code():
    auth = provider_auth()
    await seed_client(auth, scopes=["openid"], skipConsent=True)
    async with make_client(auth) as client:
        await sign_up(client)
        past = int((time.time() - 600) * 1000)  # session created after ba_iat
        query = signed(scope="openid", prompt="login", issued_at_ms=past)
        res = await client.post(
            "/api/auth/oauth2/consent", json={"accept": True, "oauth_query": query}
        )
        assert res.status_code == 200, res.text
        assert res.json()["url"].startswith(CB)  # login satisfied -> code


# --- ba_pl trusted only when server-minted (client-asserted postLogin rejected) -------


async def test_client_asserted_post_login_does_not_clear_gate():
    calls = []

    def should_redirect(info):
        calls.append(True)
        return True

    auth = provider_auth(
        post_login={
            "page": POSTLOGIN,
            "shouldRedirect": should_redirect,
            "consentReferenceId": None,
        }
    )
    await seed_client(auth, scopes=["openid"], skipConsent=True)
    async with make_client(auth) as client:
        await sign_up(client)
        # oauth_query carries NO ba_pl -> the post-login gate must NOT be considered cleared
        query = signed(scope="openid")
        res = await client.post(
            "/api/auth/oauth2/continue", json={"postLogin": True, "oauth_query": query}
        )
        assert res.status_code == 200, res.text
        assert res.json()["url"].startswith(POSTLOGIN)  # gate re-runs, still redirects
        assert calls  # shouldRedirect was consulted against the live session


# --- consent accept / deny / narrowing ------------------------------------------------


async def _consent_redirect_query(client, **params):
    res = await client.get(authorize_url(**params))
    assert res.status_code == 302, res.text
    assert res.headers["location"].startswith(CONSENT)
    return urlsplit(res.headers["location"]).query


async def test_consent_deny_redirects_access_denied():
    auth = provider_auth()
    await seed_client(auth, scopes=["openid"])
    async with make_client(auth) as client:
        await sign_up(client)
        query = await _consent_redirect_query(client, scope="openid", state="s1")
        res = await client.post(
            "/api/auth/oauth2/consent", json={"accept": False, "oauth_query": query}
        )
        assert res.status_code == 200, res.text
        url = res.json()["url"]
        q = parse_qs(urlsplit(url).query)
        assert q["error"] == ["access_denied"]
        assert q["state"] == ["s1"]


async def test_consent_accept_upserts_and_mints_code():
    auth = provider_auth()
    await seed_client(auth, scopes=["openid", "profile"])
    async with make_client(auth) as client:
        await sign_up(client)
        query = await _consent_redirect_query(client, scope="openid profile")
        res = await client.post(
            "/api/auth/oauth2/consent", json={"accept": True, "oauth_query": query}
        )
        assert res.status_code == 200, res.text
        assert "code=" in res.json()["url"]

    uid = await user_id(auth)
    row = await auth.adapter.find_one(
        "oauthConsent", [Where("clientId", "client-1"), Where("userId", uid)]
    )
    assert row is not None
    assert set(row["scopes"]) == {"openid", "profile"}


async def test_consent_accept_narrows_scopes():
    auth = provider_auth()
    await seed_client(auth, scopes=["openid", "profile"])
    async with make_client(auth) as client:
        await sign_up(client)
        query = await _consent_redirect_query(client, scope="openid profile")
        res = await client.post(
            "/api/auth/oauth2/consent",
            json={"accept": True, "scope": "openid", "oauth_query": query},
        )
        assert res.status_code == 200, res.text

    uid = await user_id(auth)
    row = await auth.adapter.find_one(
        "oauthConsent", [Where("clientId", "client-1"), Where("userId", uid)]
    )
    assert row["scopes"] == ["openid"]  # narrowed to the accepted subset


async def test_consent_rejects_scopes_not_originally_requested():
    auth = provider_auth()
    await seed_client(auth, scopes=["openid", "profile"])
    async with make_client(auth) as client:
        await sign_up(client)
        query = await _consent_redirect_query(client, scope="openid")
        res = await client.post(
            "/api/auth/oauth2/consent",
            json={"accept": True, "scope": "openid profile", "oauth_query": query},
        )
        assert res.status_code == 400
        assert res.json()["error"] == "invalid_request"


# --- consent-required when stored scopes are a strict subset of requested -------------


async def test_consent_required_when_stored_scopes_subset():
    auth = provider_auth()
    await seed_client(auth, scopes=["openid", "profile"])
    async with make_client(auth) as client:
        await sign_up(client)
        uid = await user_id(auth)
        # stored consent grants only openid
        await auth.adapter.create(
            "oauthConsent", {"clientId": "client-1", "userId": uid, "scopes": ["openid"]}
        )
        res = await client.get(authorize_url(scope="openid profile"))
        assert res.status_code == 302
        assert res.headers["location"].startswith(CONSENT)  # profile not yet consented


async def test_stored_consent_superset_mints_code_directly():
    auth = provider_auth()
    await seed_client(auth, scopes=["openid", "profile"])
    async with make_client(auth) as client:
        await sign_up(client)
        uid = await user_id(auth)
        await auth.adapter.create(
            "oauthConsent",
            {"clientId": "client-1", "userId": uid, "scopes": ["openid", "profile"]},
        )
        res = await client.get(authorize_url(scope="openid"))
        assert res.status_code == 302
        assert res.headers["location"].startswith(CB)
        assert "code=" in res.headers["location"]


# --- continue: selected / created resume ----------------------------------------------


async def test_continue_selected_resumes_authorize():
    auth = provider_auth()
    await seed_client(auth, scopes=["openid"], skipConsent=True)
    async with make_client(auth) as client:
        await sign_up(client)
        query = signed(scope="openid", prompt="select_account")
        res = await client.post(
            "/api/auth/oauth2/continue", json={"selected": True, "oauth_query": query}
        )
        assert res.status_code == 200, res.text
        assert res.json()["url"].startswith(CB)  # select_account prompt removed -> code


async def test_continue_missing_params_rejected():
    auth = provider_auth()
    await seed_client(auth, scopes=["openid"], skipConsent=True)
    async with make_client(auth) as client:
        await sign_up(client)
        query = signed(scope="openid")
        res = await client.post("/api/auth/oauth2/continue", json={"oauth_query": query})
        assert res.status_code == 400
        assert res.json()["error"] == "invalid_request"


# --- consent CRUD: ownership + scope-subset validation --------------------------------


async def _seed_consent(auth, uid, scopes):
    await auth.adapter.create(
        "oauthConsent", {"clientId": "client-1", "userId": uid, "scopes": scopes}
    )
    row = await auth.adapter.find_one("oauthConsent", [Where("userId", uid)])
    return row["id"]


async def test_get_consent_owner_only():
    auth = provider_auth()
    await seed_client(auth, scopes=["openid", "profile"])
    async with make_client(auth) as owner:
        await sign_up(owner)
        uid = await user_id(auth)
        cid = await _seed_consent(auth, uid, ["openid"])
        got = await owner.get(f"/api/auth/oauth2/get-consent?id={cid}")
        assert got.status_code == 200, got.text
        assert got.json()["scopes"] == ["openid"]

    async with make_client(auth) as other:
        await sign_up(other, email="mallory@example.com", password="s3cret-password")
        cross = await other.get(f"/api/auth/oauth2/get-consent?id={cid}")
        assert cross.status_code == 401


async def test_get_consents_lists_session_user():
    auth = provider_auth()
    await seed_client(auth, scopes=["openid"])
    async with make_client(auth) as client:
        await sign_up(client)
        uid = await user_id(auth)
        await _seed_consent(auth, uid, ["openid"])
        res = await client.get("/api/auth/oauth2/get-consents")
        assert res.status_code == 200
        assert len(res.json()) == 1


async def test_update_consent_scope_subset_enforced():
    auth = provider_auth()
    await seed_client(auth, scopes=["openid", "profile"])
    async with make_client(auth) as client:
        await sign_up(client)
        uid = await user_id(auth)
        cid = await _seed_consent(auth, uid, ["openid"])

        ok = await client.post(
            "/api/auth/oauth2/update-consent",
            json={"id": cid, "update": {"scopes": ["openid", "profile"]}},
        )
        assert ok.status_code == 200, ok.text

        bad = await client.post(
            "/api/auth/oauth2/update-consent",
            json={"id": cid, "update": {"scopes": ["banking"]}},
        )
        assert bad.status_code == 400
        assert bad.json()["error"] == "invalid_request"


async def test_delete_consent_owner_only():
    auth = provider_auth()
    await seed_client(auth, scopes=["openid"])
    async with make_client(auth) as owner:
        await sign_up(owner)
        uid = await user_id(auth)
        cid = await _seed_consent(auth, uid, ["openid"])

    async with make_client(auth) as other:
        await sign_up(other, email="mallory@example.com", password="s3cret-password")
        cross = await other.post("/api/auth/oauth2/delete-consent", json={"id": cid})
        assert cross.status_code == 401

    async with make_client(auth) as owner2:
        signin = await owner2.post(
            "/api/auth/sign-in/email",
            json={"email": "ada@example.com", "password": "s3cret-password"},
        )
        assert signin.status_code == 200, signin.text
        ok = await owner2.post("/api/auth/oauth2/delete-consent", json={"id": cid})
        assert ok.status_code == 200, ok.text
        assert await auth.adapter.find_one("oauthConsent", [Where("id", cid)]) is None
