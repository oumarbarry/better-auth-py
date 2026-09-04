"""magic-link plugin — parity with better-auth's plugins/magic-link.

Behaviours mirror packages/better-auth/src/plugins/magic-link/magic-link.test.ts:
single-use token semantics (consumed atomically on the first verify — even the
losers of a race burn it), storeToken plain/hashed/custom, origin-checked callback
URLs, sign-up vs adopt-unverified flows, and the redirect-with-error shape.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest

from better_auth import EmailAndPassword, Field, RateLimit
from better_auth.adapters.base import Where
from better_auth.config import UserOptions
from better_auth.crypto import default_key_hasher
from better_auth.plugins_ext.magic_link import MagicLinkPlugin
from better_auth.types import AuthRequest
from conftest import make_auth, make_client


def _mk(holder: dict[str, Any], **kw: Any):
    async def send(data: dict[str, Any], *_a: Any) -> None:
        holder.clear()
        holder.update(data)

    return MagicLinkPlugin(send_magic_link=send, **kw)


def _auth(holder: dict[str, Any], **kw: Any) -> Any:
    extra = {k: kw.pop(k) for k in list(kw) if k in ("email_and_password", "user")}
    return make_auth(plugins=[_mk(holder, **kw)], **extra)


async def _sign_in(client: Any, email: str, **body: Any) -> Any:
    return await client.post("/api/auth/sign-in/magic-link", json={"email": email, **body})


async def _verify(client: Any, token: str, **query: Any) -> Any:
    return await client.get("/api/auth/magic-link/verify", params={"token": token, **query})


# --- send -------------------------------------------------------------------------------


async def test_send_magic_link():
    holder: dict[str, Any] = {}
    async with make_client(_auth(holder)) as client:
        r = await _sign_in(client, "user@test.com")
        assert r.status_code == 200, r.text
        assert r.json() == {"status": True}
        assert holder["email"] == "user@test.com"
        assert "/api/auth/magic-link/verify" in holder["url"]
        assert holder.get("metadata") is None


async def test_forward_metadata():
    holder: dict[str, Any] = {}
    async with make_client(_auth(holder)) as client:
        await _sign_in(client, "user@test.com", metadata={"inviteId": "123"})
        assert holder["metadata"] == {"inviteId": "123"}


# --- verify (happy path) ----------------------------------------------------------------


async def test_verify_returns_token_and_cookie():
    holder: dict[str, Any] = {}
    async with make_client(_auth(holder)) as client:
        await _sign_in(client, "user@test.com")
        r = await _verify(client, holder["token"])
        assert r.status_code == 200, r.text
        assert r.json()["token"]
        assert r.json()["user"]["email"] == "user@test.com"
        assert "set-cookie" in r.headers


async def test_no_callback_returns_json_with_session():
    holder: dict[str, Any] = {}
    async with make_client(_auth(holder)) as client:
        await _sign_in(client, "user@test.com")
        r = await _verify(client, holder["token"])
        body = r.json()
        assert set(body) >= {"token", "user", "session"}
        assert body["session"]["token"] == body["token"]


# --- single-use semantics ---------------------------------------------------------------


async def test_second_verify_rejected():
    holder: dict[str, Any] = {}
    async with make_client(_auth(holder)) as client:
        await _sign_in(client, "user@test.com")
        token = holder["token"]
        assert (await _verify(client, token)).status_code == 200
        second = await _verify(client, token)
        assert second.status_code == 302
        assert "error=INVALID_TOKEN" in second.headers["location"]


async def test_second_verify_rejected_even_with_allowed_attempts_3():
    holder: dict[str, Any] = {}
    async with make_client(_auth(holder, allowed_attempts=3)) as client:
        await _sign_in(client, "user@test.com")
        token = holder["token"]
        assert (await _verify(client, token)).status_code == 200
        second = await _verify(client, token)
        assert second.status_code == 302
        assert "error=INVALID_TOKEN" in second.headers["location"]


async def test_allowed_attempts_non_one_logs_warning(caplog: pytest.LogCaptureFixture):
    holder: dict[str, Any] = {}
    with caplog.at_level(logging.WARNING, logger="better_auth"):
        _mk(holder, allowed_attempts=3)
    assert any("allowedAttempts" in r.message for r in caplog.records)


async def test_allowed_attempts_one_no_warning(caplog: pytest.LogCaptureFixture):
    holder: dict[str, Any] = {}
    with caplog.at_level(logging.WARNING, logger="better_auth"):
        _mk(holder, allowed_attempts=1)
    assert not any("allowedAttempts" in r.message for r in caplog.records)


async def test_concurrent_verify_mints_one_session():
    holder: dict[str, Any] = {}
    async with make_client(_auth(holder)) as client:
        await _sign_in(client, "race@test.com")
        token = holder["token"]
        results = await asyncio.gather(_verify(client, token), _verify(client, token))
        tokens = [r.json()["token"] for r in results if r.status_code == 200]
        assert len(tokens) == 1
        assert sum(1 for r in results if r.status_code == 302) == 1


# --- expiry -----------------------------------------------------------------------------


async def test_expired_token_rejected():
    holder: dict[str, Any] = {}
    auth = _auth(holder)
    async with make_client(auth) as client:
        await _sign_in(client, "user@test.com")
        token = holder["token"]
        # plain storeToken -> the identifier is the raw token; age it past expiry.
        past = datetime.now(timezone.utc) - timedelta(seconds=10)
        await auth.adapter.update("verification", [Where("identifier", token)], {"expiresAt": past})
        r = await _verify(client, token, callbackURL="/callback")
        assert r.status_code == 302
        assert "error=INVALID_TOKEN" in r.headers["location"]


# --- error redirect ---------------------------------------------------------------------


async def test_error_callback_url_preserves_params():
    holder: dict[str, Any] = {}
    async with make_client(_auth(holder)) as client:
        err = "http://testserver/error-page?foo=bar&baz=qux"
        r = await _verify(client, "invalid-token", errorCallbackURL=err)
        assert r.status_code == 302
        loc = urlsplit(r.headers["location"])
        assert loc.netloc == "testserver"
        assert loc.path == "/error-page"
        params = parse_qs(loc.query)
        assert params["foo"] == ["bar"]
        assert params["baz"] == ["qux"]
        assert params["error"] == ["INVALID_TOKEN"]


# --- sign-up / adopt --------------------------------------------------------------------


async def test_sign_up_new_user():
    holder: dict[str, Any] = {}
    async with make_client(_auth(holder)) as client:
        await _sign_in(client, "brand-new@test.com", name="Newbie")
        r = await _verify(client, holder["token"])
        user = r.json()["user"]
        assert user["email"] == "brand-new@test.com"
        assert user["name"] == "Newbie"
        assert user["emailVerified"] is True


async def test_existing_unverified_becomes_verified():
    holder: dict[str, Any] = {}
    async with make_client(_auth(holder)) as client:
        signup = await client.post(
            "/api/auth/sign-up/email",
            json={"email": "unv@test.com", "name": "U", "password": "s3cret-password"},
        )
        assert signup.json()["user"]["emailVerified"] is False
        await _sign_in(client, "unv@test.com")
        r = await _verify(client, holder["token"])
        assert r.json()["user"]["emailVerified"] is True


async def test_adopt_unverified_clears_credential_password():
    holder: dict[str, Any] = {}
    auth = _auth(
        holder,
        email_and_password=EmailAndPassword(enabled=True, require_email_verification=True),
    )
    async with make_client(auth) as client:
        creds_body = {"email": "pw@test.com", "password": "existing-password"}
        signup = await client.post("/api/auth/sign-up/email", json={**creds_body, "name": "U"})
        users = await auth.adapter.find_many("user", [Where("email", "pw@test.com")])
        user_id = users[0]["id"]
        # gate: unverified credential can't sign in
        gated = await client.post("/api/auth/sign-in/email", json=creds_body)
        assert gated.status_code == 403

        await _sign_in(client, "pw@test.com")
        r = await _verify(client, holder["token"])
        assert r.json()["user"]["emailVerified"] is True

        creds = await auth.adapter.find_many(
            "account", [Where("userId", user_id), Where("providerId", "credential")]
        )
        assert creds == []
        after = await client.post("/api/auth/sign-in/email", json=creds_body)
        assert after.status_code == 401
        assert signup.json()["user"]["emailVerified"] is False


async def test_disable_sign_up_new_user_errors():
    holder: dict[str, Any] = {}
    async with make_client(_auth(holder, disable_sign_up=True)) as client:
        await _sign_in(client, "nope@test.com")
        r = await _verify(client, holder["token"])
        assert r.status_code == 302
        assert "error=new_user_signup_disabled" in r.headers["location"]


# --- verify last of many ----------------------------------------------------------------


async def test_verify_last_of_multiple():
    holder: dict[str, Any] = {}
    async with make_client(_auth(holder)) as client:
        for _ in range(3):
            await _sign_in(client, "many@test.com")
        last_token = holder["token"]
        r = await _verify(client, last_token)
        assert r.status_code == 200
        assert r.json()["token"]


# --- token generation / storage ---------------------------------------------------------


async def test_custom_generate_token():
    holder: dict[str, Any] = {}
    auth = _auth(holder, generate_token=lambda email: "custom_token")
    async with make_client(auth) as client:
        await _sign_in(client, "user@test.com")
        assert holder["token"] == "custom_token"


async def test_store_token_hashed():
    holder: dict[str, Any] = {}
    auth = _auth(holder, store_token="hashed")
    async with make_client(auth) as client:
        await _sign_in(client, "user@test.com")
        raw = holder["token"]
        stored = await auth.internal.find_verification_value(default_key_hasher(raw))
        assert stored is not None
        # the DB never holds the raw token
        assert await auth.internal.find_verification_value(raw) is None
        assert (await _verify(client, raw)).status_code == 200


async def test_store_token_custom_hasher():
    holder: dict[str, Any] = {}
    auth = _auth(holder, store_token={"type": "custom-hasher", "hash": lambda t: t + "hashed"})
    async with make_client(auth) as client:
        await _sign_in(client, "user@test.com")
        raw = holder["token"]
        stored = await auth.internal.find_verification_value(f"{raw}hashed")
        assert stored is not None
        assert (await _verify(client, raw)).status_code == 200


# --- additional fields ------------------------------------------------------------------


async def test_additional_fields_returned():
    holder: dict[str, Any] = {}
    fields = {"foo": Field("string", required=False)}
    auth = _auth(holder, user=UserOptions(additional_fields=fields))
    async with make_client(auth) as client:
        await _sign_in(client, "af@test.com")
        first = await _verify(client, holder["token"])
        assert first.json()["user"].get("foo") is None
        token = first.json()["token"]
        await client.post(
            "/api/auth/update-user",
            json={"foo": "bar"},
            headers={"authorization": f"Bearer {token}"},
        )
        await _sign_in(client, "af@test.com")
        second = await _verify(client, holder["token"])
        assert second.json()["user"]["foo"] == "bar"


# --- origin check -----------------------------------------------------------------------


async def test_untrusted_callback_url_rejected():
    holder: dict[str, Any] = {}
    async with make_client(_auth(holder)) as client:
        await _sign_in(client, "user@test.com")
        r = await _verify(client, holder["token"], callbackURL="http://malicious.com")
        assert r.status_code == 403
        assert r.json()["code"] == "INVALID_CALLBACK_URL"


# --- rate limit -------------------------------------------------------------------------


async def test_rate_limit():
    holder: dict[str, Any] = {}

    async def send(data: dict[str, Any], *_a: Any) -> None:
        holder.update(data)

    auth = make_auth(
        plugins=[MagicLinkPlugin(send_magic_link=send, rate_limit={"window": 60, "max": 2})],
        rate_limit=RateLimit(enabled=True),
    )
    async with make_client(auth) as client:
        assert (await _sign_in(client, "user@test.com")).status_code == 200
        assert (await _sign_in(client, "user@test.com")).status_code == 200
        assert (await _sign_in(client, "user@test.com")).status_code == 429


# --- send endpoint origin/CSRF protection ------------------------------------------------
# TS 086ca91f5 put `formCsrfMiddleware` on `/sign-in/magic-link` so a cookieless
# cross-origin POST can't mail a magic link to an arbitrary address. This port's router
# already force-validates the origin for every `/sign-in*` / `/sign-up*` path
# (origin.check_origin -> _validate_form_csrf), so these are regression tests for that.
# @see https://github.com/better-auth/better-auth/issues/10304


async def _sign_in_raw(auth: Any, headers: dict[str, str], email: str = "attacker@evil.com"):
    return await auth.handle(
        AuthRequest(
            method="POST",
            path="/sign-in/magic-link",
            headers={"content-type": "application/json", **headers},
            body=json.dumps({"email": email}).encode(),
        )
    )


async def test_send_blocks_cross_site_navigation_without_cookies():
    holder: dict[str, Any] = {}
    r = await _sign_in_raw(
        _auth(holder),
        {
            "sec-fetch-site": "cross-site",
            "sec-fetch-mode": "navigate",
            "sec-fetch-dest": "document",
            "origin": "https://evil.com",
        },
    )
    assert r.status == 403
    assert holder == {}


async def test_send_rejects_cookieless_cross_origin_post():
    holder: dict[str, Any] = {}
    r = await _sign_in_raw(_auth(holder), {"origin": "https://evil.com"})
    assert r.status == 403
    assert holder == {}


async def test_send_allows_cookieless_request_without_origin():
    holder: dict[str, Any] = {}
    r = await _sign_in_raw(_auth(holder), {}, email="s2s@test.com")
    assert r.status == 200, r.body
    assert holder["email"] == "s2s@test.com"
