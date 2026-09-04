"""oauth-popup plugin — popup-based social OAuth whose callback swaps the redirect for
an HTML page that ``postMessage``s the session token (or error) back to the opener.

Ports better-auth's ``plugins/oauth-popup``. TS source verified against:
  packages/better-auth/src/plugins/oauth-popup/index.ts
  packages/better-auth/src/plugins/oauth-popup/constants.ts
  packages/better-auth/src/plugins/oauth-popup/error-codes.ts
  packages/better-auth/src/plugins/oauth-popup/oauth-popup.test.ts

Drives the full start -> provider-redirect -> callback -> completion-page flow through a
real HTTP round trip (``make_client`` / FastAPI ASGI); outbound OAuth calls (discovery /
token / userinfo) are stubbed with ``httpx.MockTransport`` injected via
``BetterAuth(http_client=...)`` — the same idiom as tests/plugins/test_generic_oauth.py.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import Any
from urllib.parse import parse_qs, quote, urlsplit

import httpx

from better_auth import BetterAuth
from better_auth.plugins_ext.bearer import BearerPlugin
from better_auth.plugins_ext.generic_oauth import GenericOAuthConfig, GenericOAuthPlugin
from better_auth.plugins_ext.oauth_popup import (
    OAUTH_POPUP_COMPLETE_SCRIPT,
    OAUTH_POPUP_DATA_ELEMENT_ID,
    OAUTH_POPUP_ERROR_CODES,
    OAUTH_POPUP_MESSAGE_TYPE,
    OAUTH_POPUP_SCRIPT_CSP_HASH,
    OAuthPopupPlugin,
)
from conftest import make_auth, make_client

PROVIDER = "test"
IDP = "https://idp.example.com"
DISCOVERY = f"{IDP}/.well-known/openid-configuration"
POPUP_ORIGIN = "http://testserver"  # equals the test base_url origin -> always trusted
EVIL = "https://evil.example.com"

POPUP_USER = {
    "sub": "popup",
    "email": "popup@test.com",
    "name": "Popup User",
    "email_verified": True,
}


def popup_http(*, userinfo: dict[str, Any] | None = None) -> httpx.AsyncClient:
    """MockTransport routing by path: discovery / token / userinfo (no id_token, so the
    generic callback falls to the bearer userinfo fetch)."""
    ui = userinfo if userinfo is not None else POPUP_USER
    disc = {
        "issuer": IDP,
        "authorization_endpoint": f"{IDP}/authorize",
        "token_endpoint": f"{IDP}/token",
        "userinfo_endpoint": f"{IDP}/userinfo",
    }

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path.endswith("/.well-known/openid-configuration"):
            return httpx.Response(200, json=disc)
        if path == "/token":
            return httpx.Response(200, json={"access_token": "at", "token_type": "bearer"})
        if path == "/userinfo":
            return httpx.Response(200, json=ui)
        return httpx.Response(404, json={"error": "not_found"})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def popup_auth(**overrides: Any) -> BetterAuth:
    return make_auth(
        plugins=[
            GenericOAuthPlugin(
                config=[
                    GenericOAuthConfig(
                        provider_id=PROVIDER,
                        discovery_url=DISCOVERY,
                        client_id="test-client-id",
                        client_secret="test-client-secret",
                        pkce=True,
                    )
                ]
            ),
            OAuthPopupPlugin(),
            BearerPlugin(),
        ],
        http_client=popup_http(),
        **overrides,
    )


def start_url(
    *, popup_origin: str = POPUP_ORIGIN, provider: str = PROVIDER, callback: str | None = None
) -> str:
    url = (
        f"/api/auth/oauth-popup/start?provider={provider}"
        f"&popupOrigin={quote(popup_origin, safe='')}&popupNonce=n1"
    )
    cb = callback if callback is not None else f"{POPUP_ORIGIN}/dashboard"
    if cb:
        url += f"&callbackURL={quote(cb, safe='')}"
    return url


async def run_popup_flow(client: httpx.AsyncClient) -> tuple[httpx.Response, httpx.Response]:
    """start (302 -> provider, sets marker+state cookies) -> callback (completion page)."""
    start = await client.get(start_url(), follow_redirects=False)
    assert start.status_code == 302, start.text
    state = parse_qs(urlsplit(start.headers["location"]).query)["state"][0]
    callback = await client.get(
        f"/api/auth/oauth2/callback/{PROVIDER}?code=the-code&state={state}",
        follow_redirects=False,
    )
    return start, callback


def data_block(body: str) -> dict[str, Any]:
    """The inert JSON payload the completion page embeds for its inline script."""
    match = re.search(r'id="' + OAUTH_POPUP_DATA_ELEMENT_ID + r'">(.*?)</script>', body, re.S)
    assert match, body
    return json.loads(match.group(1))


# --- byte-parity: the CSP-pinned completion script ---------------------------------------


def test_script_sha256_is_pinned_in_csp_hash():
    # The completion page runs this script inline and pins its sha256 in the CSP. If the
    # script body changes, recompute and update OAUTH_POPUP_SCRIPT_CSP_HASH.
    digest = base64.b64encode(
        hashlib.sha256(OAUTH_POPUP_COMPLETE_SCRIPT.encode()).digest()
    ).decode()
    assert f"sha256-{digest}" == OAUTH_POPUP_SCRIPT_CSP_HASH


def test_csp_hash_equals_ts_constant():
    # Byte-parity proof against the exact TS constant (index.ts OAUTH_POPUP_SCRIPT_CSP_HASH).
    assert OAUTH_POPUP_SCRIPT_CSP_HASH == "sha256-tIo2K8VBC9SnhvdZ+9GsGkQoZm+jm/JcxL+d+i8b8KQ="


def test_error_codes_exact_strings():
    assert OAUTH_POPUP_ERROR_CODES == {
        "POPUP_SIGN_IN_FAILED": "Popup sign-in failed",
        "POPUP_BLOCKED": "Sign-in popup was blocked by the browser",
        "POPUP_CLOSED": "Sign-in popup was closed before completing",
        "POPUP_TIMEOUT": "Sign-in popup timed out",
    }


def test_plugin_takes_no_options():
    plugin = OAuthPopupPlugin()
    assert plugin.id == "oauth-popup"
    assert plugin.error_codes["POPUP_BLOCKED"] == "Sign-in popup was blocked by the browser"


# --- start endpoint ----------------------------------------------------------------------


async def test_start_redirects_to_provider_and_sets_marker_cookie():
    async with make_client(popup_auth()) as client:
        start = await client.get(start_url(), follow_redirects=False)
    assert start.status_code == 302
    assert start.headers["location"].startswith(f"{IDP}/authorize")
    assert "better-auth.oauth_popup" in "".join(start.headers.get_list("set-cookie"))


async def test_rejects_untrusted_popup_origin():
    async with make_client(popup_auth()) as client:
        res = await client.get(start_url(popup_origin=EVIL), follow_redirects=False)
    assert res.status_code == 403


async def test_rejects_untrusted_callback_url_at_start():
    async with make_client(popup_auth()) as client:
        res = await client.get(start_url(callback=EVIL), follow_redirects=False)
    assert res.status_code == 200
    assert "invalid_callback_url" in res.text


async def test_relays_start_stage_error_unknown_provider():
    async with make_client(popup_auth()) as client:
        res = await client.get(start_url(provider="nope"), follow_redirects=False)
    assert res.status_code == 200
    body = res.text
    assert OAUTH_POPUP_DATA_ELEMENT_ID in body
    assert "provider_not_found" in body


async def test_strips_internal_state_keys_from_additional_data():
    auth = popup_auth()
    additional = quote(
        json.dumps({"link": {"email": "popup@test.com", "userId": "uid"}, "tenant": "acme"}),
        safe="",
    )
    async with make_client(auth) as client:
        start = await client.get(
            f"{start_url()}&additionalData={additional}", follow_redirects=False
        )
    assert start.status_code == 302
    records = await auth.adapter.find_many("verification", [])
    values = [json.loads(r["value"]) for r in records]
    stored = next(v for v in values if v.get("additionalData", {}).get("tenant") == "acme")
    assert stored["additionalData"]["tenant"] == "acme"
    # `link` is an INTERNAL_STATE_KEY: it must never survive in additionalData, and must
    # never be promoted to the top-level linking key (that would hijack the flow).
    assert "link" not in stored["additionalData"]
    assert "link" not in stored


# --- callback -> completion page ---------------------------------------------------------


async def test_returns_completion_page_instead_of_redirecting():
    async with make_client(popup_auth()) as client:
        _start, callback = await run_popup_flow(client)
    assert callback.status_code == 200
    assert "text/html" in callback.headers["content-type"]
    # The page carries the session token, so it must not be cached.
    assert callback.headers["cache-control"] == "no-store"
    assert callback.headers["pragma"] == "no-cache"
    assert callback.headers["content-security-policy"] == (
        f"default-src 'none'; script-src '{OAUTH_POPUP_SCRIPT_CSP_HASH}'; base-uri 'none'"
    )
    body = callback.text
    assert OAUTH_POPUP_DATA_ELEMENT_ID in body
    assert "postMessage" in body
    # The callback's session cookie must survive onto the completion response.
    assert "better-auth.session_token" in "".join(callback.headers.get_list("set-cookie"))


async def test_completion_payload_shape_success():
    async with make_client(popup_auth()) as client:
        _start, callback = await run_popup_flow(client)
    data = data_block(callback.text)
    assert data["type"] == OAUTH_POPUP_MESSAGE_TYPE
    # postMessage targetOrigin is the validated popupOrigin (untrusted origins never reach here).
    assert data["targetOrigin"] == POPUP_ORIGIN
    assert data["nonce"] == "n1"
    assert data["token"]
    assert data["redirectTo"] == f"{POPUP_ORIGIN}/dashboard"
    assert "error" not in data


async def test_hands_off_a_token_that_authenticates_via_bearer():
    auth = popup_auth()
    async with make_client(auth) as client:
        _start, callback = await run_popup_flow(client)
        token = callback.cookies.get("better-auth.session_token")
        assert token
        client.cookies.clear()
        session = await client.get(
            "/api/auth/get-session", headers={"authorization": f"Bearer {token}"}
        )
    assert session.status_code == 200
    assert session.json()["user"]["email"] == "popup@test.com"


async def test_completion_token_matches_posted_data_block():
    async with make_client(popup_auth()) as client:
        _start, callback = await run_popup_flow(client)
    posted = data_block(callback.text)["token"]
    assert posted == callback.cookies.get("better-auth.session_token")


async def test_keeps_redirect_when_not_a_popup_flow():
    # A normal (non-popup) generic-oauth sign-in has no marker cookie -> the callback keeps
    # its redirect untouched.
    async with make_client(popup_auth()) as client:
        signin = await client.post(
            "/api/auth/sign-in/oauth2",
            json={"providerId": PROVIDER, "callbackURL": f"{POPUP_ORIGIN}/dashboard"},
        )
        assert signin.status_code == 200, signin.text
        state = parse_qs(urlsplit(signin.json()["url"]).query)["state"][0]
        callback = await client.get(
            f"/api/auth/oauth2/callback/{PROVIDER}?code=the-code&state={state}",
            follow_redirects=False,
        )
    assert callback.status_code == 302
    assert callback.headers["location"] == f"{POPUP_ORIGIN}/dashboard"


async def test_relays_oauth_error_to_opener():
    async with make_client(popup_auth()) as client:
        start = await client.get(start_url(), follow_redirects=False)
        state = parse_qs(urlsplit(start.headers["location"]).query)["state"][0]
        callback = await client.get(
            f"/api/auth/oauth2/callback/{PROVIDER}?state={state}&error=access_denied",
            follow_redirects=False,
        )
    assert callback.status_code == 200
    body = callback.text
    assert OAUTH_POPUP_DATA_ELEMENT_ID in body
    data = data_block(body)
    assert data["error"]["code"] == "access_denied"
    assert "token" not in data
