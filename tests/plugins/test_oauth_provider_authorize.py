"""oauth-provider Phase B — /oauth2/authorize flow.

Verified against TS ``packages/oauth-provider/src/authorize.ts`` and ``utils/index.ts``
(isPKCERequired, clientAllowsGrant), ``authorize.test.ts`` / ``pkce-optional.test.ts`` at
v1.6.23. redirect_uri exact + RFC 8252 loopback matrix, PKCE downgrade matrix, prompt=none
OIDC errors, iss on success/error, and the authorization-code verification row shape.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

from httpx import ASGITransport, AsyncClient

from better_auth.crypto import default_key_hasher
from better_auth.plugins_ext.jwt import JWTPlugin
from better_auth.plugins_ext.oauth_provider import OAuthProviderPlugin
from conftest import make_app, make_auth, sign_up

LOGIN = "https://app.example.com/login"
CONSENT = "https://app.example.com/consent"
ORIGIN = "http://localhost:3000"
ISSUER = "http://localhost:3000/api/auth"


def provider_auth(**kwargs):
    kwargs.setdefault("login_page", LOGIN)
    kwargs.setdefault("consent_page", CONSENT)
    return make_auth(base_url=ORIGIN, plugins=[JWTPlugin(), OAuthProviderPlugin(**kwargs)])


def make_client(auth):
    # loopback origin matching base_url so signed-in POSTs pass the origin/CSRF check.
    return AsyncClient(
        transport=ASGITransport(app=make_app(auth)), base_url=ORIGIN, headers={"origin": ORIGIN}
    )


async def seed_client(auth, **fields):
    data = {
        "clientId": fields.pop("clientId", "client-1"),
        "redirectUris": ["https://app.example.com/cb"],
        "scopes": ["openid", "profile", "email", "offline_access"],
        "grantTypes": ["authorization_code"],
        "public": False,
        "disabled": False,
        "requirePKCE": False,
        "skipConsent": False,
    }
    data.update(fields)
    await auth.adapter.create("oauthClient", data)
    return data["clientId"]


def authorize_url(client_id="client-1", redirect_uri="https://app.example.com/cb", **params):
    q = {"client_id": client_id, "response_type": "code", "redirect_uri": redirect_uri, **params}
    from urllib.parse import urlencode

    return "/api/auth/oauth2/authorize?" + urlencode({k: v for k, v in q.items() if v is not None})


def loc_of(res):
    assert res.status_code == 302, res.text
    return res.headers["location"]


# --- grant gate + client validation --------------------------------------------------


async def test_authorize_404_when_authorization_code_grant_disabled():
    auth = provider_auth(grant_types=["client_credentials"])
    await seed_client(auth)
    async with make_client(auth) as client:
        res = await client.get(authorize_url())
        assert res.status_code == 404


async def test_disabled_client_redirects_client_disabled():
    auth = provider_auth()
    await seed_client(auth, disabled=True)
    async with make_client(auth) as client:
        loc = loc_of(await client.get(authorize_url()))
        assert "/error" in loc and "client_disabled" in loc


async def test_client_not_allowing_authorization_code_is_unauthorized_client():
    auth = provider_auth()
    await seed_client(auth, grantTypes=["client_credentials"])
    async with make_client(auth) as client:
        loc = loc_of(await client.get(authorize_url()))
        assert "/error" in loc and "unauthorized_client" in loc


# --- redirect_uri exact + RFC 8252 loopback matrix -----------------------------------


async def _redirect_probe(auth, registered, requested):
    await seed_client(auth, redirectUris=[registered], scopes=["openid"])
    async with make_client(auth) as client:
        return loc_of(await client.get(authorize_url(redirect_uri=requested, scope="openid")))


async def test_redirect_exact_match_passes_to_login():
    loc = await _redirect_probe(
        provider_auth(), "https://app.example.com/cb", "https://app.example.com/cb"
    )
    assert loc.startswith(LOGIN)


async def test_loopback_127_different_port_matches():
    loc = await _redirect_probe(
        provider_auth(), "http://127.0.0.1:8080/cb", "http://127.0.0.1:9090/cb"
    )
    assert loc.startswith(LOGIN)


async def test_loopback_ipv6_different_port_matches():
    loc = await _redirect_probe(provider_auth(), "http://[::1]:8080/cb", "http://[::1]:9090/cb")
    assert loc.startswith(LOGIN)


async def test_loopback_different_path_rejected():
    loc = await _redirect_probe(
        provider_auth(), "http://127.0.0.1:8080/cb", "http://127.0.0.1:9090/other"
    )
    assert "invalid_redirect" in loc


async def test_non_loopback_different_port_rejected():
    loc = await _redirect_probe(
        provider_auth(), "https://app.example.com:8080/cb", "https://app.example.com:9090/cb"
    )
    assert "invalid_redirect" in loc


async def test_dns_localhost_not_port_agnostic():
    loc = await _redirect_probe(
        provider_auth(), "http://localhost:8080/cb", "http://localhost:9090/cb"
    )
    assert "invalid_redirect" in loc


# --- scope validation ----------------------------------------------------------------


async def test_invalid_scope_redirects_with_iss():
    auth = provider_auth()
    await seed_client(auth, scopes=["openid"])
    async with make_client(auth) as client:
        loc = loc_of(await client.get(authorize_url(scope="openid banking")))
        q = parse_qs(urlsplit(loc).query)
        assert q["error"] == ["invalid_scope"]
        assert q["iss"] == [ISSUER]
        assert loc.startswith("https://app.example.com/cb")


# --- PKCE downgrade matrix (auth-side) -----------------------------------------------


async def _pkce_probe(client_fields, **query):
    auth = provider_auth()
    await seed_client(auth, scopes=["openid", "offline_access"], **client_fields)
    async with make_client(auth) as c:
        return loc_of(await c.get(authorize_url(**query)))


async def test_public_client_without_pkce_fails():
    loc = await _pkce_probe({"public": True}, scope="openid")
    q = parse_qs(urlsplit(loc).query)
    assert q["error"] == ["invalid_request"]
    assert "public" in q["error_description"][0]


async def test_confidential_without_pkce_fails_by_default():
    # requirePKCE defaults to True when unset
    auth = provider_auth()
    await seed_client(auth, scopes=["openid"], requirePKCE=None)
    async with make_client(auth) as c:
        loc = loc_of(await c.get(authorize_url(scope="openid")))
    assert parse_qs(urlsplit(loc).query)["error"] == ["invalid_request"]


async def test_confidential_without_pkce_succeeds_when_require_pkce_false():
    loc = await _pkce_probe({"requirePKCE": False}, scope="openid")
    assert loc.startswith(LOGIN)  # past PKCE gate -> login redirect


async def test_offline_access_without_pkce_fails_even_when_require_pkce_false():
    loc = await _pkce_probe({"requirePKCE": False}, scope="openid offline_access")
    q = parse_qs(urlsplit(loc).query)
    assert q["error"] == ["invalid_request"]
    assert "offline_access" in q["error_description"][0]


async def test_non_s256_challenge_method_rejected():
    loc = await _pkce_probe(
        {"requirePKCE": False},
        scope="openid",
        code_challenge="abc",
        code_challenge_method="plain",
    )
    q = parse_qs(urlsplit(loc).query)
    assert q["error"] == ["invalid_request"]
    assert "S256" in q["error_description"][0]


async def test_valid_s256_challenge_passes_to_login():
    loc = await _pkce_probe(
        {"requirePKCE": False},
        scope="openid",
        code_challenge="E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        code_challenge_method="S256",
    )
    assert loc.startswith(LOGIN)


# --- prompt=none OIDC error matrix ---------------------------------------------------


async def test_prompt_none_without_session_login_required():
    auth = provider_auth()
    await seed_client(auth, scopes=["openid"], requirePKCE=False)
    async with make_client(auth) as client:
        loc = loc_of(await client.get(authorize_url(scope="openid", prompt="none")))
        q = parse_qs(urlsplit(loc).query)
        assert q["error"] == ["login_required"]
        assert q["iss"] == [ISSUER]


async def test_prompt_none_with_session_but_no_consent_consent_required():
    auth = provider_auth()
    await seed_client(auth, scopes=["openid"], requirePKCE=False)
    async with make_client(auth) as client:
        await sign_up(client)
        loc = loc_of(await client.get(authorize_url(scope="openid", prompt="none")))
        assert parse_qs(urlsplit(loc).query)["error"] == ["consent_required"]


# --- code minting: success + row shape (iss on success) ------------------------------


async def test_skip_consent_mints_code_with_iss_and_row_shape():
    auth = provider_auth()
    await seed_client(auth, scopes=["openid"], requirePKCE=False, skipConsent=True)
    async with make_client(auth) as client:
        await sign_up(client)
        loc = loc_of(await client.get(authorize_url(scope="openid", state="xyz")))
        assert loc.startswith("https://app.example.com/cb")
        q = parse_qs(urlsplit(loc).query)
        code = q["code"][0]
        assert q["state"] == ["xyz"]
        assert q["iss"] == [ISSUER]

    row = await auth.internal.find_verification_value(default_key_hasher(code))
    assert row is not None
    import json

    value = json.loads(row["value"])
    assert value["type"] == "authorization_code"
    assert value["userId"]
    assert value["sessionId"]
    assert value["authTime"]
    assert value["query"]["client_id"] == "client-1"
    assert value["query"]["redirect_uri"] == "https://app.example.com/cb"


async def test_missing_client_id_redirects_to_error_page():
    auth = provider_auth()
    await seed_client(auth)
    async with make_client(auth) as client:
        from urllib.parse import urlencode

        url = "/api/auth/oauth2/authorize?" + urlencode({"response_type": "code"})
        res = await client.get(url)
        # client_id is required by the route schema -> handled as an error redirect/response
        assert res.status_code in (302, 400)
