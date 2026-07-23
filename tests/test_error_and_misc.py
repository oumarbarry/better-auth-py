"""onAPIError (item 16) + disabledPaths / skipTrailingSlashes (item 17)."""

from __future__ import annotations

import pytest

from better_auth.config import OnAPIError
from better_auth.types import APIError, AuthRequest
from conftest import make_auth, make_client

# --- onAPIError ---------------------------------------------------------------


async def _bad_origin_post(auth):
    request = AuthRequest(
        method="POST",
        path="/sign-out",
        headers={"cookie": "better-auth.session_token=x", "origin": "http://evil.example"},
    )
    return request


async def test_on_api_error_throw_reraises():
    auth = make_auth(on_api_error=OnAPIError(throw=True))
    with pytest.raises(APIError):
        await auth.handle(await _bad_origin_post(auth))


async def test_on_api_error_hook_runs():
    seen: list[str] = []

    async def on_error(error, request):
        seen.append(getattr(error, "code", type(error).__name__))

    auth = make_auth(on_api_error=OnAPIError(on_error=on_error))
    response = await auth.handle(await _bad_origin_post(auth))
    assert response.status == 403  # not re-raised (throw defaults False)
    assert seen == ["INVALID_ORIGIN"]


async def test_error_page_redirects_to_error_url():
    auth = make_auth(on_api_error=OnAPIError(error_url="https://app.example/oops"))
    async with make_client(auth) as client:
        response = await client.get("/api/auth/error?error=state_mismatch", follow_redirects=False)
        assert response.status_code == 302
        location = response.headers["location"]
        assert location.startswith("https://app.example/oops?")
        assert "error=state_mismatch" in location


async def test_error_page_renders_without_error_url():
    auth = make_auth()
    async with make_client(auth) as client:
        response = await client.get("/api/auth/error?error=state_mismatch")
        assert response.status_code == 200
        assert "state_mismatch" in response.text


# --- disabledPaths ------------------------------------------------------------


async def test_disabled_path_returns_404():
    auth = make_auth(disabled_paths=["/ok"])
    async with make_client(auth) as client:
        assert (await client.get("/api/auth/ok")).status_code == 404


async def test_non_disabled_path_still_works():
    auth = make_auth(disabled_paths=["/sign-up/email"])
    async with make_client(auth) as client:
        assert (await client.get("/api/auth/ok")).status_code == 200


# --- skipTrailingSlashes ------------------------------------------------------


async def test_trailing_slash_404_by_default():
    auth = make_auth()  # skip_trailing_slashes defaults False -> `/ok/` != `/ok`
    async with make_client(auth) as client:
        assert (await client.get("/api/auth/ok/")).status_code == 404


async def test_trailing_slash_ignored_when_enabled():
    auth = make_auth(skip_trailing_slashes=True)
    async with make_client(auth) as client:
        assert (await client.get("/api/auth/ok/")).status_code == 200
