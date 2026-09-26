"""OAuth state rides the verification storage (TS v1.7.6 state.ts:141-156, 243-298):
``createVerificationValue`` / ``findVerificationValue`` / ``deleteVerificationByIdentifier``,
so ``verification.storeIdentifier`` hashing and secondary storage apply to state rows too."""

import json
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx

from better_auth.crypto import default_key_hasher
from better_auth.internal_adapter import VerificationOptions
from better_auth.oauth.providers import ProviderConfig
from better_auth.secondary_storage import MemorySecondaryStorage
from conftest import make_auth, make_client

PROFILE = {"sub": "acme-1", "email": "octo@example.com", "email_verified": True, "name": "Octo"}


def _http() -> httpx.AsyncClient:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/token":
            return httpx.Response(200, json={"access_token": "at"})
        if request.url.path == "/userinfo":
            return httpx.Response(200, json=PROFILE)
        return httpx.Response(404)

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _auth(**kwargs: Any):
    return make_auth(
        social_providers={
            "acme": ProviderConfig(
                client_id="cid",
                client_secret="sec",
                provider_id="acme",
                authorization_endpoint="https://idp.test/authorize",
                token_endpoint="https://idp.test/token",
                userinfo_endpoint="https://idp.test/userinfo",
            )
        },
        http_client=_http(),
        **kwargs,
    )


async def _round_trip(auth) -> tuple[str, httpx.Response, list[dict[str, Any]]]:
    async with make_client(auth) as client:
        r = await client.post(
            "/api/auth/sign-in/social", json={"provider": "acme", "callbackURL": "/dash"}
        )
        state = parse_qs(urlsplit(r.json()["url"]).query)["state"][0]
        rows = await auth.adapter.find_many("verification")
        done = await client.get(f"/api/auth/callback/acme?code=abc&state={state}")
    return state, done, rows


async def test_state_identifier_is_hashed_at_rest_and_still_resolves():
    auth = _auth(verification=VerificationOptions(store_identifier="hashed"))
    state, done, rows = await _round_trip(auth)
    assert [row["identifier"] for row in rows] == [default_key_hasher(state)]
    assert done.status_code == 302
    assert done.headers["location"] == "http://testserver/dash"
    assert await auth.adapter.find_many("verification") == []


async def test_state_value_matches_ts_state_data_shape():
    # state.ts:141-147: the stored value carries `oauthState`; JSON.stringify drops
    # undefined, so absent optional keys are omitted rather than written as null.
    auth = _auth()
    state, _done, rows = await _round_trip(auth)
    value = json.loads(rows[0]["value"])
    assert value["oauthState"] == state
    assert None not in value.values()
    assert "errorURL" not in value and "newUserURL" not in value


async def test_state_lives_in_secondary_storage_when_configured():
    storage = MemorySecondaryStorage()
    auth = _auth(secondary_storage=storage)
    _state, done, rows = await _round_trip(auth)
    assert rows == []
    assert done.status_code == 302
    assert done.headers["location"] == "http://testserver/dash"
