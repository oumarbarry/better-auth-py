"""oauth-provider logout at TS v1.7.6: RP-Initiated Logout with OP confirmation (``logout.ts``
331-1033, f451d1c75), back-channel logout (``logout.ts`` 22-329, e0d2b9eb9) and its deferral
until the session deletion commits (69acb7a3d). Anchors name ``packages/oauth-provider/src``
files; test names follow ``logout.test.ts`` and ``backchannel-logout.test.ts``."""

from __future__ import annotations

import contextlib
import json
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
import jwt as pyjwt
from httpx import ASGITransport, AsyncClient

from better_auth.adapters.base import Where
from better_auth.crypto import default_key_hasher, sign_value, unsign_value
from better_auth.oauth.machinery import code_challenge
from better_auth.plugins_ext.jwt import JWTPlugin
from better_auth.plugins_ext.oauth_provider import OAuthProviderPlugin
from conftest import SIGNUP, make_app, make_auth, sign_up

LOGIN = "https://app.example.com/login"
CONSENT = "https://app.example.com/consent"
ORIGIN = "http://localhost:3000"
BASE = f"{ORIGIN}/api/auth"
END_SESSION = "/api/auth/oauth2/end-session"
CONFIRM = f"{END_SESSION}/confirm"
CB = "https://app.example.com/cb"
LOGOUT_URI = "https://app.example.com/loggedout"
RP_BACKCHANNEL = "https://rp.example.com/logout/backchannel"
SECRET = "cs-secret-value"
VERIFIER = "verifier-" + "a" * 40
HTML = {"accept": "text/html"}
JSON = {"accept": "application/json"}
CSP = "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"
CONFIRM_COOKIE = "better-auth.session_token.oauth_logout_confirmation"
EVENT = "http://schemas.openid.net/event/backchannel-logout"


def page(title: str, body: str) -> str:
    """logout.ts:389-404 page shell."""
    return (
        f'<!doctype html><html><head><meta charset="utf-8"><title>{title}</title></head>'
        f"<body>{body}</body></html>"
    )


def confirmation_page(base: str = BASE) -> str:
    """logout.ts:419-425."""
    return page(
        "Confirm logout",
        "<main><h1>Confirm logout</h1><p>Do you want to log out of this account?</p>"
        f'<form method="post" data-oidc-logout-confirmation action="{base}/oauth2/end-session/'
        'confirm"><button type="submit" name="action" value="confirm">Confirm logout</button>'
        "</form></main>",
    )


def success_page(note: str | None = None) -> str:
    """logout.ts:427-433."""
    message = f"Logged out. {note}" if note else "Logged out."
    return page("Logged out", f'<main><p data-oidc-logout-state="logged-out">{message}</p></main>')


class RP:
    """Mock relying party behind ``auth.http`` recording back-channel POSTs."""

    def __init__(self, status: int = 200) -> None:
        self.status = status
        self.received: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.received.append(request)
        return httpx.Response(self.status)

    def logout_tokens(self) -> list[str]:
        return [parse_qs(r.content.decode())["logout_token"][0] for r in self.received]


def provider_auth(*, rp: RP | None = None, jwt: bool = True, **kwargs: Any):
    kwargs.setdefault("login_page", LOGIN)
    kwargs.setdefault("consent_page", CONSENT)
    extra = {k: kwargs.pop(k) for k in ("database_hooks", "base_path") if k in kwargs}
    if rp is not None:
        extra["http_client"] = httpx.AsyncClient(transport=httpx.MockTransport(rp.handler))
    plugins: list[Any] = [OAuthProviderPlugin(disable_jwt_plugin=not jwt, **kwargs)]
    if jwt:
        plugins.insert(0, JWTPlugin())
    return make_auth(base_url=ORIGIN, plugins=plugins, **extra)


def make_client(auth) -> AsyncClient:
    return AsyncClient(
        transport=ASGITransport(app=make_app(auth)), base_url=ORIGIN, headers={"origin": ORIGIN}
    )


async def seed(auth, *, client_id="client-1", **fields):
    data = {
        "clientId": client_id,
        "redirectUris": [CB],
        "scopes": ["openid", "profile", "email", "offline_access"],
        "grantTypes": ["authorization_code", "refresh_token"],
        "tokenEndpointAuthMethod": "client_secret_post",
        "clientSecret": default_key_hasher(SECRET),
        "disabled": False,
        "requirePKCE": False,
        "skipConsent": True,
        "enableEndSession": True,
    }
    data.update(fields)
    await auth.adapter.create("oauthClient", data)
    return client_id


async def issue(c: AsyncClient, *, scope="openid profile offline_access", client_id="client-1"):
    """Auth-code flow for the session cookie ``c`` carries; returns the token response."""
    authz = {"client_id": client_id, "response_type": "code", "redirect_uri": CB, "scope": scope}
    if "offline_access" in scope:
        authz.update(code_challenge=code_challenge(VERIFIER), code_challenge_method="S256")
    res = await c.get("/api/auth/oauth2/authorize?" + urlencode(authz))
    assert res.status_code == 302, res.text
    code = parse_qs(urlsplit(res.headers["location"]).query)["code"][0]
    form = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "client_secret": SECRET,
        "code": code,
        "redirect_uri": CB,
    }
    if "offline_access" in scope:
        form["code_verifier"] = VERIFIER
    res = await c.post("/api/auth/oauth2/token", data=form)
    assert res.status_code == 200, res.text
    return res.json()


async def second_session(auth) -> AsyncClient:
    c = make_client(auth)
    res = await c.post(
        "/api/auth/sign-in/email", json={"email": SIGNUP["email"], "password": SIGNUP["password"]}
    )
    assert res.status_code == 200, res.text
    return c


def claims(token: str) -> dict[str, Any]:
    return pyjwt.decode(token, options={"verify_signature": False})


def confirm_cookie(c: AsyncClient) -> str:
    value = c.cookies.get(CONFIRM_COOKIE, path=CONFIRM)
    assert value is not None
    return value


def set_cookies(res: httpx.Response) -> list[str]:
    return res.headers.get_list("set-cookie")


async def session_exists(auth, session_id: str) -> bool:
    return await auth.adapter.find_one("session", [Where("id", session_id)]) is not None


async def current_session_id(auth, c: AsyncClient) -> str:
    res = await c.get("/api/auth/get-session")
    return res.json()["session"]["id"]


def assert_no_store(res: httpx.Response) -> None:
    assert res.headers.get_list("cache-control") == ["no-store"]
    assert res.headers.get_list("pragma") == ["no-cache"]


# --- RP-Initiated Logout: confirmation flow (logout.ts:788-872) ------------------------


async def test_requires_confirmation_before_deleting_the_session_without_a_hint():
    auth = provider_auth()
    async with make_client(auth) as c:
        await sign_up(c)
        sid = await current_session_id(auth, c)
        res = await c.get(END_SESSION, headers=HTML)
        assert res.status_code == 200
        assert res.text == confirmation_page()
        assert res.headers["content-type"] == "text/html; charset=utf-8"
        assert res.headers["content-security-policy"] == CSP
        assert res.headers["x-content-type-options"] == "nosniff"
        assert_no_store(res)
        [cookie] = [s for s in set_cookies(res) if s.startswith(CONFIRM_COOKIE)]
        # logout.ts:464-476: session cookie attributes, confirm path, 5 minute lifetime.
        assert "Path=/api/auth/oauth2/end-session/confirm" in cookie
        assert "Max-Age=300" in cookie and "HttpOnly" in cookie and "SameSite=Lax" in cookie
        state = json.loads(unsign_value(auth.secret, confirm_cookie(c)) or "")
        assert set(state) == {"sessionId", "expiresAt"} and state["sessionId"] == sid
        assert await session_exists(auth, sid)

        done = await c.post(CONFIRM, data={"action": "confirm"}, headers=HTML)
        assert done.status_code == 200
        assert done.text == success_page()
        assert "location" not in done.headers
        assert_no_store(done)
        assert not await session_exists(auth, sid)
        cleared = set_cookies(done)
        assert any(s.startswith("better-auth.session_token=;") for s in cleared)
        assert any(s.startswith(f"{CONFIRM_COOKIE}=;") and "Max-Age=0" in s for s in cleared)


async def test_does_not_delete_on_an_initial_no_hint_post():
    auth = provider_auth()
    async with make_client(auth) as c:
        await sign_up(c)
        sid = await current_session_id(auth, c)
        res = await c.post(END_SESSION, data={}, headers=HTML)
        assert res.status_code == 200
        assert "data-oidc-logout-confirmation" in res.text
        assert await session_exists(auth, sid)


async def test_confirms_a_no_hint_form_post_when_the_initial_navigation_omits_the_cookie():
    auth = provider_auth()
    async with make_client(auth) as c:
        await sign_up(c)
        sid = await current_session_id(auth, c)
        async with make_client(auth) as bare:
            res = await bare.post(
                END_SESSION, data={}, headers={**HTML, "origin": "https://rp.example"}
            )
        assert res.status_code == 200
        assert res.text == confirmation_page()
        c.cookies.update(res.cookies)
        done = await c.post(CONFIRM, data={"action": "confirm"}, headers=HTML)
        assert done.status_code == 200
        assert done.text == success_page()
        assert not await session_exists(auth, sid)


async def test_json_without_a_hint_requires_confirmation_or_a_session():
    auth = provider_auth()
    async with make_client(auth) as c:
        # logout.ts:799-803: no current session and no browser navigation.
        res = await c.get(END_SESSION, headers=JSON)
        assert res.status_code == 400
        assert res.json() == {
            "error": "invalid_request",
            "error_description": "No active session is available for logout",
        }
        assert_no_store(res)
        await sign_up(c)
        # logout.ts:805-811 (oauth-endpoint.integration.test.ts:482).
        res = await c.get(END_SESSION, headers=JSON)
        assert res.status_code == 400
        assert res.json() == {
            "error": "invalid_request",
            "error_description": "User confirmation is required to complete logout",
        }


async def test_does_not_delete_when_the_confirmation_state_is_missing_or_tampered():
    auth = provider_auth()
    async with make_client(auth) as c:
        await sign_up(c)
        sid = await current_session_id(auth, c)
        missing = await c.post(CONFIRM, data={"action": "confirm"}, headers=HTML)
        assert missing.status_code == 400
        assert missing.text == page(
            "Logout error",
            '<main><h1>Logout error</h1><p data-oidc-logout-state="error">'
            "The logout confirmation is invalid or expired</p></main>",
        )
        assert missing.headers["content-security-policy"] == CSP
        assert_no_store(missing)
        missing_json = await c.post(CONFIRM, data={"action": "confirm"}, headers=JSON)
        assert missing_json.json() == {
            "error": "invalid_request",
            "error_description": "The logout confirmation is invalid or expired",
        }

        await c.get(END_SESSION, headers=HTML)
        c.cookies.set(CONFIRM_COOKIE, "tampered", path=CONFIRM)
        tampered = await c.post(CONFIRM, data={"action": "confirm"}, headers=HTML)
        assert tampered.status_code == 400
        # logout.ts:827-834: an expired state is rejected the same way.
        expired = json.dumps({"sessionId": sid, "expiresAt": 0})
        c.cookies.set(CONFIRM_COOKIE, sign_value(auth.secret, expired), path=CONFIRM)
        stale = await c.post(CONFIRM, data={"action": "confirm"}, headers=HTML)
        assert stale.status_code == 400
        assert await session_exists(auth, sid)


async def test_rejects_confirmation_state_bound_to_a_different_current_session():
    auth = provider_auth()
    async with make_client(auth) as c:
        await sign_up(c)
        sid = await current_session_id(auth, c)
        await c.get(END_SESSION, headers=HTML)
        confirmation = confirm_cookie(c)
        other = await second_session(auth)
        other_sid = await current_session_id(auth, other)
        other.cookies.set(CONFIRM_COOKIE, confirmation, path=CONFIRM)
        res = await other.post(CONFIRM, data={"action": "confirm"}, headers=HTML)
        await other.aclose()
        assert res.status_code == 400
        assert await session_exists(auth, sid)
        assert await session_exists(auth, other_sid)


async def test_rejects_a_cross_origin_confirmation_post():
    auth = provider_auth()
    async with make_client(auth) as c:
        await sign_up(c)
        sid = await current_session_id(auth, c)
        await c.get(END_SESSION, headers=HTML)
        res = await c.post(
            CONFIRM,
            data={"action": "confirm"},
            headers={**HTML, "origin": "https://attacker.example"},
        )
        assert res.status_code == 403
        assert await session_exists(auth, sid)


async def test_confirmation_requires_the_confirm_action():
    # oauth.ts:1491-1493: body {action: "confirm"}.
    auth = provider_auth()
    async with make_client(auth) as c:
        res = await c.post(CONFIRM, data={"action": "nope"}, headers=JSON)
        assert res.status_code == 400
        assert res.json() == {
            "error": "invalid_request",
            "error_description": "action must be one of: confirm",
        }
        res = await c.post(CONFIRM, data={}, headers=JSON)
        assert res.json()["error_description"] == "action is required"


async def test_rejects_an_unsafe_post_logout_redirect_uri():
    # oauth.ts:83-88: SafeUrlSchema on post_logout_redirect_uri.
    auth = provider_auth()
    async with make_client(auth) as c:
        res = await c.get(
            END_SESSION, params={"post_logout_redirect_uri": "javascript:alert(1)"}, headers=JSON
        )
        assert res.status_code == 400
        assert res.json() == {
            "error": "invalid_request",
            "error_description": "post_logout_redirect_uri: URL cannot use javascript:, data:, "
            "or vbscript: scheme",
        }


async def test_does_not_redirect_or_delete_for_a_redirect_request_without_a_hint():
    auth = provider_auth()
    async with make_client(auth) as c:
        await sign_up(c)
        sid = await current_session_id(auth, c)
        res = await c.get(
            END_SESSION, params={"post_logout_redirect_uri": LOGOUT_URI}, headers=HTML
        )
        assert res.status_code == 200
        assert "location" not in res.headers
        assert "data-oidc-logout-confirmation" in res.text
        assert await session_exists(auth, sid)


async def test_redirects_after_confirming_a_no_hint_request_for_an_identified_client():
    auth = provider_auth()
    await seed(auth, postLogoutRedirectUris=[LOGOUT_URI])
    async with make_client(auth) as c:
        await sign_up(c)
        sid = await current_session_id(auth, c)
        params = {
            "client_id": "client-1",
            "post_logout_redirect_uri": LOGOUT_URI,
            "state": "confirmed-state",
        }
        res = await c.get(END_SESSION, params=params, headers=HTML)
        assert res.status_code == 200
        assert "location" not in res.headers
        done = await c.post(CONFIRM, data={"action": "confirm"}, headers=HTML)
        assert done.status_code == 302
        assert done.headers["location"] == f"{LOGOUT_URI}?state=confirmed-state"
        assert_no_store(done)
        assert not await session_exists(auth, sid)


async def test_revalidates_a_no_hint_redirect_before_completing_confirmation():
    auth = provider_auth()
    await seed(auth, postLogoutRedirectUris=[LOGOUT_URI])
    async with make_client(auth) as c:
        await sign_up(c)
        sid = await current_session_id(auth, c)
        params = {
            "client_id": "client-1",
            "post_logout_redirect_uri": LOGOUT_URI,
            "state": "stale-registration-state",
        }
        await c.get(END_SESSION, params=params, headers=HTML)
        await auth.adapter.update(
            "oauthClient", [Where("clientId", "client-1")], {"postLogoutRedirectUris": []}
        )
        done = await c.post(CONFIRM, data={"action": "confirm"}, headers=HTML)
        assert done.status_code == 200
        assert done.text == success_page("The requested post-logout redirect was not registered.")
        assert not await session_exists(auth, sid)


async def test_requires_confirmation_for_a_state_only_request():
    auth = provider_auth()
    async with make_client(auth) as c:
        await sign_up(c)
        res = await c.get(END_SESSION, params={"state": "opaque-state"}, headers=HTML)
        assert res.status_code == 200
        assert res.text == confirmation_page()
        assert "opaque-state" not in confirm_cookie(c)


async def test_no_hint_client_gates():
    # logout.ts:900-925.
    auth = provider_auth()
    await seed(auth, client_id="off", enableEndSession=False)
    await seed(auth, client_id="gone", disabled=True)
    async with make_client(auth) as c:
        cases = [
            ("unknown", 400, "The logout client does not exist"),
            ("gone", 400, "The logout client is disabled"),
            ("off", 401, "The client is not allowed to initiate logout"),
        ]
        for client_id, status, description in cases:
            res = await c.get(END_SESSION, params={"client_id": client_id}, headers=JSON)
            assert res.status_code == status
            assert res.json() == {"error": "invalid_client", "error_description": description}


# --- RP-Initiated Logout: id_token_hint (logout.ts:931-1021) ----------------------------


async def test_should_fail_with_invalid_id_token_hint():
    auth = provider_auth()
    async with make_client(auth) as c:
        res = await c.get(END_SESSION, params={"id_token_hint": ""}, headers=JSON)
        assert res.status_code == 400
        assert res.json() == {
            "error": "invalid_client",
            "error_description": "The logout client does not exist",
        }
        assert_no_store(res)


async def test_rejects_alg_none_hints_as_controlled_errors():
    auth = provider_auth()
    await seed(auth)
    async with make_client(auth) as c:
        await sign_up(c)
        sid = await current_session_id(auth, c)
        hint = pyjwt.encode({"sid": sid, "iss": BASE, "aud": "client-1"}, "", algorithm="none")
        res = await c.get(END_SESSION, params={"id_token_hint": hint}, headers=JSON)
        assert res.status_code == 401
        assert res.json() == {
            "error": "invalid_token",
            "error_description": "The id_token_hint is invalid",
        }
        assert await session_exists(auth, sid)


async def test_offers_confirmation_for_an_invalid_hint_without_an_unsafe_redirect():
    auth = provider_auth()
    async with make_client(auth) as c:
        await sign_up(c)
        sid = await current_session_id(auth, c)
        params = {
            "id_token_hint": "not-a-jwt",
            "post_logout_redirect_uri": "https://evil.example/logout",
        }
        res = await c.get(END_SESSION, params=params, headers=HTML)
        assert res.status_code == 200
        assert res.text == confirmation_page()
        assert "evil.example" not in confirm_cookie(c)
        assert await session_exists(auth, sid)


async def test_does_not_fan_out_client_lookups_across_unverified_hint_audiences():
    auth = provider_auth()
    lookups: list[str] = []
    original = auth.adapter.find_one

    async def spy(model, where, *args, **kwargs):
        lookups.append(model)
        return await original(model, where, *args, **kwargs)

    auth.adapter.find_one = spy  # type: ignore[method-assign]
    async with make_client(auth) as c:
        await sign_up(c)
        audiences = [f"unknown-client-{i}" for i in range(100)]
        hint = pyjwt.encode({"sid": "x", "sub": "u", "aud": audiences}, "k" * 32)
        res = await c.get(END_SESSION, params={"id_token_hint": hint}, headers=HTML)
        assert res.status_code == 200
        assert "data-oidc-logout-confirmation" in res.text
        assert "oauthClient" not in lookups


async def test_resolves_a_valid_multi_audience_logout_hint_through_azp():
    auth = provider_auth()
    await seed(auth)
    async with make_client(auth) as c:
        await sign_up(c)
        payload = claims((await issue(c))["id_token"])
        jwt_plugin = next(p for p in auth.plugins if p.id == "jwt")
        hint = await jwt_plugin.sign_jwt(
            payload={**payload, "aud": ["client-1", "https://other.example"], "azp": "client-1"}
        )
        res = await c.get(END_SESSION, params={"id_token_hint": hint}, headers=HTML)
        assert res.status_code == 200
        assert res.text == success_page()
        assert not await session_exists(auth, payload["sid"])


async def test_should_fail_for_clients_without_enable_end_session_access():
    auth = provider_auth()
    await seed(auth, enableEndSession=False)
    async with make_client(auth) as c:
        await sign_up(c)
        id_token = (await issue(c))["id_token"]
        assert "sid" not in claims(id_token)
        res = await c.get(END_SESSION, params={"id_token_hint": id_token}, headers=JSON)
        assert res.status_code == 401
        assert res.json()["error"] == "invalid_client"


async def test_should_pass_for_clients_with_enable_end_session_access():
    auth = provider_auth()
    await seed(auth)
    async with make_client(auth) as c:
        await sign_up(c)
        id_token = (await issue(c))["id_token"]
        sid = claims(id_token)["sid"]
        res = await c.get(END_SESSION, params={"id_token_hint": id_token}, headers=JSON)
        assert res.status_code == 200
        assert res.json() is None
        assert_no_store(res)
        assert not await session_exists(auth, sid)
        assert any(s.startswith("better-auth.session_token=;") for s in set_cookies(res))
        assert (await c.get("/api/auth/get-session")).json() is None


async def test_supports_a_valid_hint_in_a_form_post_and_a_json_body():
    auth = provider_auth()
    await seed(auth)
    async with make_client(auth) as c:
        await sign_up(c)
        id_token = (await issue(c))["id_token"]
        res = await c.post(END_SESSION, data={"id_token_hint": id_token}, headers=JSON)
        assert res.status_code == 200
        assert "location" not in res.headers
        assert not await session_exists(auth, claims(id_token)["sid"])

        await c.post(
            "/api/auth/sign-in/email",
            json={"email": SIGNUP["email"], "password": SIGNUP["password"]},
        )
        id_token = (await issue(c))["id_token"]
        res = await c.post(END_SESSION, json={"id_token_hint": id_token})
        assert res.status_code == 200
        assert not await session_exists(auth, claims(id_token)["sid"])


async def test_logs_out_a_valid_hinted_session_without_browser_cookies():
    auth = provider_auth()
    await seed(auth)
    async with make_client(auth) as c:
        await sign_up(c)
        id_token = (await issue(c))["id_token"]
    async with make_client(auth) as bare:
        res = await bare.get(END_SESSION, params={"id_token_hint": id_token}, headers=JSON)
    assert res.status_code == 200
    assert not await session_exists(auth, claims(id_token)["sid"])


async def test_requires_confirmation_when_a_valid_hint_conflicts_with_the_current_session():
    auth = provider_auth()
    await seed(auth)
    async with make_client(auth) as c:
        await sign_up(c)
        sid = await current_session_id(auth, c)
        other = await second_session(auth)
        other_token = (await issue(other))["id_token"]
        await other.aclose()
        res = await c.get(END_SESSION, params={"id_token_hint": other_token}, headers=HTML)
        assert res.status_code == 200
        assert res.text == confirmation_page()
        assert await session_exists(auth, sid)
        assert await session_exists(auth, claims(other_token)["sid"])


async def test_rejects_a_bad_signed_hint_without_deleting_the_session():
    auth = provider_auth()
    await seed(auth)
    async with make_client(auth) as c:
        await sign_up(c)
        id_token = (await issue(c))["id_token"]
        header, payload, signature = id_token.split(".")
        bad = f"{header}.{payload}.{'B' if signature[0] == 'A' else 'A'}{signature[1:]}"
        res = await c.get(END_SESSION, params={"id_token_hint": bad}, headers=JSON)
        assert res.status_code == 401
        assert res.json()["error"] == "invalid_token"
        assert await session_exists(auth, claims(id_token)["sid"])


async def test_rejects_a_hint_for_another_audience_or_issuer():
    # logout.ts:713-716 (the 1.6 audience 400 and issuer 500 became invalid_token 401).
    auth = provider_auth()
    await seed(auth)
    await seed(auth, client_id="client-2")
    async with make_client(auth) as c:
        await sign_up(c)
        id_token = (await issue(c))["id_token"]
        res = await c.get(
            END_SESSION, params={"id_token_hint": id_token, "client_id": "client-2"}, headers=JSON
        )
        assert res.status_code == 401
        assert res.json()["error"] == "invalid_token"
        jwt_plugin = next(p for p in auth.plugins if p.id == "jwt")
        forged = await jwt_plugin.sign_jwt(
            payload={"iss": "https://evil.example.com", "aud": "client-1", "sid": "x", "sub": "u"}
        )
        res = await c.get(END_SESSION, params={"id_token_hint": forged}, headers=JSON)
        assert res.status_code == 401
        assert res.json()["error"] == "invalid_token"


async def test_logs_out_and_suppresses_an_unregistered_or_query_added_redirect():
    auth = provider_auth()
    await seed(auth, postLogoutRedirectUris=[LOGOUT_URI])
    async with make_client(auth) as c:
        await sign_up(c)
        for uri in ("https://evil.example/logout", f"{LOGOUT_URI}?attacker=1"):
            await c.post(
                "/api/auth/sign-in/email",
                json={"email": SIGNUP["email"], "password": SIGNUP["password"]},
            )
            id_token = (await issue(c))["id_token"]
            params = {"id_token_hint": id_token, "post_logout_redirect_uri": uri}
            res = await c.get(END_SESSION, params=params, headers=HTML)
            assert res.status_code == 200
            assert "location" not in res.headers
            assert res.text == success_page(
                "The requested post-logout redirect was not registered."
            )
            assert not await session_exists(auth, claims(id_token)["sid"])


async def test_surfaces_session_deletion_failures_without_redirecting_as_successful():
    auth = provider_auth()
    await seed(auth)
    async with make_client(auth) as c:
        await sign_up(c)
        id_token = (await issue(c))["id_token"]

        async def broken(token: str) -> None:
            raise RuntimeError("adapter failure")

        auth.internal.delete_session = broken  # type: ignore[method-assign]
        res = await c.get(END_SESSION, params={"id_token_hint": id_token}, headers=JSON)
        assert res.status_code == 500
        assert res.json() == {
            "error": "server_error",
            "error_description": "Unable to complete logout",
        }
        assert await session_exists(auth, claims(id_token)["sid"])


async def test_should_pass_with_redirection():
    auth = provider_auth()
    await seed(auth, postLogoutRedirectUris=[LOGOUT_URI])
    async with make_client(auth) as c:
        await sign_up(c)
        id_token = (await issue(c))["id_token"]
        params = {"id_token_hint": id_token, "post_logout_redirect_uri": LOGOUT_URI, "state": "123"}
        res = await c.get(END_SESSION, params=params)
        assert res.status_code == 302
        assert res.headers["location"] == f"{LOGOUT_URI}?state=123"
        assert any(s.startswith("better-auth.session_token=;") for s in set_cookies(res))
        assert_no_store(res)


async def test_uses_the_custom_base_path_for_confirmation_navigation_and_cookies():
    auth = provider_auth(base_path="/custom/auth")
    async with AsyncClient(
        transport=ASGITransport(app=make_app(auth)), base_url=ORIGIN, headers={"origin": ORIGIN}
    ) as c:
        res = await c.post("/custom/auth/sign-up/email", json=SIGNUP)
        assert res.status_code == 200, res.text
        res = await c.get("/custom/auth/oauth2/end-session", headers=HTML)
        assert res.status_code == 200
        assert res.text == confirmation_page(f"{ORIGIN}/custom/auth")
        [cookie] = [s for s in set_cookies(res) if s.startswith(CONFIRM_COOKIE)]
        assert "Path=/custom/auth/oauth2/end-session/confirm" in cookie


# --- discovery (metadata.ts:40-42,103-104) -------------------------------------------------


async def test_discovery_advertises_backchannel_logout_only_with_the_jwt_plugin():
    for jwt_enabled in (True, False):
        auth = provider_auth(jwt=jwt_enabled)
        async with make_client(auth) as c:
            body = (await c.get("/api/auth/.well-known/openid-configuration")).json()
        assert body["backchannel_logout_supported"] is jwt_enabled
        assert body["backchannel_logout_session_supported"] is jwt_enabled


# --- back-channel logout (backchannel-logout.test.ts) ------------------------------------


async def tokens_for(auth, client_id: str) -> tuple[list[dict], list[dict]]:
    where = [Where("clientId", client_id)]
    return (
        await auth.adapter.find_many("oauthAccessToken", where),
        await auth.adapter.find_many("oauthRefreshToken", where),
    )


async def test_dispatches_a_conformant_logout_token_when_the_session_is_signed_out():
    rp = RP()
    auth = provider_auth(rp=rp)
    await seed(auth, backchannelLogoutUri=RP_BACKCHANNEL)
    async with make_client(auth) as c:
        await sign_up(c)
        id_token = (await issue(c))["id_token"]
        res = await c.post("/api/auth/sign-out")
        assert res.status_code == 200
        jwks = (await c.get("/api/auth/jwks")).json()

    [request] = rp.received
    assert str(request.url) == RP_BACKCHANNEL
    assert request.headers["content-type"] == "application/x-www-form-urlencoded"
    assert request.headers["accept"] == "application/json"
    [token] = rp.logout_tokens()
    header = pyjwt.get_unverified_header(token)
    assert header["typ"] == "logout+jwt"
    key = pyjwt.PyJWK(next(k for k in jwks["keys"] if k["kid"] == header["kid"]))
    payload = pyjwt.decode(token, key, algorithms=[header["alg"]], audience="client-1")
    assert payload["iss"] == BASE
    assert payload["aud"] == "client-1"
    assert 0 < payload["exp"] - payload["iat"] <= 120
    assert isinstance(payload["jti"], str) and len(payload["jti"]) == 32
    assert payload["sub"] == claims(id_token)["sub"]
    assert payload["sid"] == claims(id_token)["sid"]
    assert "nonce" not in payload
    assert payload["events"] == {EVENT: {}}


async def test_marks_access_and_non_offline_refresh_tokens_revoked():
    # logout.ts:166-174 (spec 2.7): offline_access refresh tokens survive.
    rp = RP()
    auth = provider_auth(rp=rp)
    await seed(auth, backchannelLogoutUri=RP_BACKCHANNEL)
    async with make_client(auth) as c:
        await sign_up(c)
        await issue(c)
        sid = await current_session_id(auth, c)
        await auth.adapter.create(
            "oauthRefreshToken",
            {
                "token": "narrowed",
                "clientId": "client-1",
                "sessionId": sid,
                "userId": (await c.get("/api/auth/get-session")).json()["user"]["id"],
                "scopes": ["openid"],
            },
        )
        access, refresh = await tokens_for(auth, "client-1")
        assert access and len(refresh) == 2
        assert all(t.get("revoked") is None for t in access + refresh)
        await c.post("/api/auth/sign-out")

    access, refresh = await tokens_for(auth, "client-1")
    assert all(t["revoked"] is not None for t in access)
    for t in refresh:
        if "offline_access" in t["scopes"]:
            assert t.get("revoked") is None
        else:
            assert t["revoked"] is not None


async def test_does_not_dispatch_to_clients_without_a_backchannel_logout_uri():
    rp = RP()
    auth = provider_auth(rp=rp)
    await seed(auth)
    async with make_client(auth) as c:
        await sign_up(c)
        await issue(c, scope="openid")
        await c.post("/api/auth/sign-out")
    assert rp.received == []
    access, _ = await tokens_for(auth, "client-1")
    assert access and all(t["revoked"] is not None for t in access)


async def test_treats_rp_failures_as_non_fatal_for_the_user_facing_sign_out():
    rp = RP(status=500)
    auth = provider_auth(rp=rp)
    await seed(auth, backchannelLogoutUri=RP_BACKCHANNEL)
    async with make_client(auth) as c:
        await sign_up(c)
        await issue(c)
        res = await c.post("/api/auth/sign-out")
    assert res.status_code == 200
    assert len(rp.received) == 1


async def test_isolates_a_malformed_pairwise_client_from_revocation_and_healthy_delivery():
    rp = RP()
    auth = provider_auth(rp=rp, pairwise_secret="test-backchannel-pairwise-secret-32-chars")
    await seed(auth, backchannelLogoutUri=RP_BACKCHANNEL)
    await seed(
        auth, client_id="pairwise", backchannelLogoutUri=RP_BACKCHANNEL, subjectType="pairwise"
    )
    async with make_client(auth) as c:
        await sign_up(c)
        await issue(c)
        await issue(c, client_id="pairwise")
        await auth.adapter.update(
            "oauthClient", [Where("clientId", "pairwise")], {"redirectUris": []}
        )
        await c.post("/api/auth/sign-out")
    assert len(rp.received) == 1
    assert claims(rp.logout_tokens()[0])["aud"] == "client-1"
    for client_id in ("client-1", "pairwise"):
        access, _ = await tokens_for(auth, client_id)
        assert access and all(t["revoked"] is not None for t in access)


async def test_keeps_the_session_and_tokens_active_when_a_hook_vetoes_deletion():
    rp = RP()

    async def veto(session, ctx=None):
        return False

    auth = provider_auth(rp=rp, database_hooks={"session": {"delete": {"before": veto}}})
    await seed(auth, backchannelLogoutUri=RP_BACKCHANNEL)
    async with make_client(auth) as c:
        await sign_up(c)
        await issue(c)
        sid = await current_session_id(auth, c)
        await c.post("/api/auth/sign-out")
    assert await session_exists(auth, sid)
    assert rp.received == []
    access, refresh = await tokens_for(auth, "client-1")
    assert all(t.get("revoked") is None for t in access + refresh)


async def test_dispatches_logout_only_after_a_transactional_session_revocation_commits():
    rp = RP()
    auth = provider_auth(rp=rp)
    await seed(auth, backchannelLogoutUri=RP_BACKCHANNEL)
    async with make_client(auth) as c:
        await sign_up(c)
        await issue(c)
        token = str(c.cookies.get("better-auth.session_token")).split(".")[0]
        sid = await current_session_id(auth, c)

    class Rollback(Exception):
        pass

    async def revoke(tx):
        await tx.delete_session(token)
        raise Rollback

    with contextlib.suppress(Rollback):
        await auth.internal.transaction(revoke)
    assert rp.received == []
    assert await session_exists(auth, sid)
    access, refresh = await tokens_for(auth, "client-1")
    assert all(t.get("revoked") is None for t in access + refresh)

    async def commit(tx):
        await tx.delete_session(token)
        assert rp.received == []  # deferred until the transaction commits

    await auth.internal.transaction(commit)
    assert len(rp.received) == 1
    assert not await session_exists(auth, sid)
    access, _ = await tokens_for(auth, "client-1")
    assert all(t["revoked"] is not None for t in access)


async def test_dispatches_when_rp_initiated_logout_tears_down_the_session():
    rp = RP()
    auth = provider_auth(rp=rp)
    await seed(auth, backchannelLogoutUri=RP_BACKCHANNEL)
    async with make_client(auth) as c:
        await sign_up(c)
        id_token = (await issue(c))["id_token"]
        res = await c.get(END_SESSION, params={"id_token_hint": id_token}, headers=JSON)
        assert res.status_code == 200
    assert len(rp.received) == 1


async def test_does_not_dispatch_to_disabled_clients():
    # logout.ts:179-181.
    rp = RP()
    auth = provider_auth(rp=rp)
    await seed(auth, backchannelLogoutUri=RP_BACKCHANNEL)
    async with make_client(auth) as c:
        await sign_up(c)
        await issue(c)
        await auth.adapter.update(
            "oauthClient", [Where("clientId", "client-1")], {"disabled": True}
        )
        await c.post("/api/auth/sign-out")
    assert rp.received == []


async def test_revokes_session_bound_access_tokens_when_the_jwt_plugin_is_disabled():
    from better_auth.crypto import symmetric_encrypt

    rp = RP()
    auth = provider_auth(rp=rp, jwt=False)
    await seed(
        auth,
        clientSecret=symmetric_encrypt(auth.secret_config, SECRET),
        backchannelLogoutUri=RP_BACKCHANNEL,
    )
    async with make_client(auth) as c:
        await sign_up(c)
        await issue(c, scope="openid profile")
        await c.post("/api/auth/sign-out")
    assert rp.received == []
    access, _ = await tokens_for(auth, "client-1")
    assert access and all(t["revoked"] is not None for t in access)
