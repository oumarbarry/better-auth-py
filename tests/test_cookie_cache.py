"""session_data cookie cache: signed round-trip, cache-hit skips the DB, tamper/
version/expiry rejection, and cross-subdomain domain widening."""

from __future__ import annotations

from datetime import timedelta

from better_auth.config import CookieCache, SessionOptions
from better_auth.cookie_cache import get_cookie_cache, make_cache_value, set_cookie_cache
from better_auth.crypto import sign_value
from better_auth.session import cookie_name, get_session, utcnow
from better_auth.types import AuthRequest
from conftest import make_auth


def _cached_auth(**extra):
    return make_auth(session=SessionOptions(cookie_cache=CookieCache(enabled=True)), **extra)


def _session_user():
    now = utcnow()
    session = {
        "id": "s1",
        "token": "tok",
        "userId": "u1",
        "expiresAt": now + timedelta(days=1),
        "ipAddress": "",
        "userAgent": "",
        "createdAt": now,
        "updatedAt": now,
    }
    user = {
        "id": "u1",
        "email": "a@b.com",
        "name": "Ada",
        "emailVerified": True,
        "createdAt": now,
        "updatedAt": now,
    }
    return session, user


def _request_with_cache(auth, value: str, token: str | None = None) -> AuthRequest:
    cookie = f"{cookie_name(auth, 'session_data')}={value}"
    if token is not None:
        cookie += f"; {cookie_name(auth)}={sign_value(auth.secret, token)}"
    return AuthRequest(method="GET", path="/get-session", headers={"cookie": cookie})


def _expires_session_data(cookies: list[str]) -> bool:
    return any(c.startswith("better-auth.session_data=;") and "Max-Age=0" in c for c in cookies)


async def test_cache_round_trip():
    auth = _cached_auth()
    session, user = _session_user()
    value = make_cache_value(auth, session, user)
    cached = get_cookie_cache(auth, _request_with_cache(auth, value))
    assert cached is not None
    assert cached["user"]["email"] == "a@b.com"
    assert cached["session"]["token"] == "tok"


async def test_cache_hit_skips_db():
    # empty adapter: if the cache is honoured, get_session returns without a DB read
    auth = _cached_auth()
    session, user = _session_user()
    value = make_cache_value(auth, session, user)
    result, _cookies = await get_session(auth, _request_with_cache(auth, value, "tok"))
    assert result is not None and result["user"]["email"] == "a@b.com"


async def test_disable_cache_falls_through_to_db():
    auth = _cached_auth()
    session, user = _session_user()
    value = make_cache_value(auth, session, user)
    # with the cache disabled and no real session cookie, the DB read finds nothing
    result, _ = await get_session(auth, _request_with_cache(auth, value), disable_cache=True)
    assert result is None


async def test_tampered_signature_rejected():
    auth = _cached_auth()
    session, user = _session_user()
    value = make_cache_value(auth, session, user)
    tampered = value[:-4] + ("AAAA" if not value.endswith("AAAA") else "BBBB")
    assert get_cookie_cache(auth, _request_with_cache(auth, tampered)) is None


async def test_wrong_secret_rejected():
    auth = _cached_auth()
    session, user = _session_user()
    value = make_cache_value(auth, session, user)
    other = _cached_auth()
    other.secret = "a-totally-different-secret-key-01234567"
    assert get_cookie_cache(other, _request_with_cache(other, value)) is None


async def test_version_mismatch_rejected():
    auth = _cached_auth()
    session, user = _session_user()
    value = make_cache_value(auth, session, user)
    # bump the configured version so the cached "1" no longer matches
    auth.session_options.cookie_cache.version = "2"
    assert get_cookie_cache(auth, _request_with_cache(auth, value)) is None


async def test_cookie_format_and_flags():
    auth = _cached_auth()
    session, user = _session_user()
    cookie = set_cookie_cache(auth, session, user, dont_remember=False)
    assert cookie is not None
    assert cookie.startswith("better-auth.session_data=")
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie and "Path=/" in cookie
    assert "Max-Age=300" in cookie  # default cookie_cache.max_age


async def test_disabled_cache_emits_no_cookie():
    auth = make_auth()  # cookie cache off by default
    session, user = _session_user()
    assert set_cookie_cache(auth, session, user, dont_remember=False) is None


async def test_cross_subdomain_widens_domain():
    from better_auth.config import CrossSubDomainCookies

    auth = _cached_auth(
        base_url="https://app.example.com",
        cross_sub_domain_cookies=CrossSubDomainCookies(enabled=True),
    )
    session, user = _session_user()
    cookie = set_cookie_cache(auth, session, user, dont_remember=False)
    assert cookie is not None and "Domain=app.example.com" in cookie


# --- v1.7.6 session.ts:84-240 -------------------------------------------------------


async def test_cache_needs_a_session_token_cookie():
    # session.ts:94-96: no session_token cookie means no session, cache or not
    auth = _cached_auth()
    session, user = _session_user()
    value = make_cache_value(auth, session, user)
    assert await get_session(auth, _request_with_cache(auth, value)) == (None, [])


async def test_cache_for_another_session_token_is_expired():
    # session.ts:135-136: the cached session must belong to the session_token cookie
    auth = _cached_auth()
    session, user = _session_user()
    value = make_cache_value(auth, session, user)
    result, cookies = await get_session(auth, _request_with_cache(auth, value, "other"))
    assert result is None
    assert _expires_session_data(cookies)


async def test_stale_cache_cookie_is_cleared_when_cache_disabled():
    # 7ec71461f: a session_data cookie left over from an enabled cache is cleared
    auth = make_auth()
    session, user = _session_user()
    value = make_cache_value(_cached_auth(), session, user)
    _result, cookies = await get_session(auth, _request_with_cache(auth, value))
    assert _expires_session_data(cookies)


async def test_tampered_cache_is_expired():
    auth = _cached_auth()
    session, user = _session_user()
    value = make_cache_value(auth, session, user)
    tampered = value[:-4] + ("AAAA" if not value.endswith("AAAA") else "BBBB")
    _result, cookies = await get_session(auth, _request_with_cache(auth, tampered, "tok"))
    assert _expires_session_data(cookies)


async def test_invalid_cache_payload_warns_and_is_expired(caplog):
    # cookies/cache.ts:20-39 (c7a5c1a7e): a signed payload that fails the schema is logged
    from better_auth.cookie_cache import _dumps
    from better_auth.crypto import b64url_encode_nopad, sign_hmac_b64url

    auth = _cached_auth()
    payload = {"session": {"token": "tok"}, "user": {"id": "u1"}, "updatedAt": 1, "version": "1"}
    expires_at = 10**13
    signature = sign_hmac_b64url(auth.secret, _dumps({**payload, "expiresAt": expires_at}))
    envelope = {"session": payload, "expiresAt": expires_at, "signature": signature}
    value = b64url_encode_nopad(_dumps(envelope).encode())
    with caplog.at_level("WARNING", logger="better_auth"):
        _result, cookies = await get_session(auth, _request_with_cache(auth, value, "tok"))
    assert "Cookie cache payload failed schema validation" in caplog.text
    assert _expires_session_data(cookies)


# --- jwt strategy (cookies/index.ts:202-210, 291-316) ----------------------------------


def _jwt_auth(**extra):
    return make_auth(
        session=SessionOptions(cookie_cache=CookieCache(enabled=True, strategy="jwt")), **extra
    )


async def test_jwt_strategy_round_trip():
    import jwt as pyjwt

    auth = _jwt_auth()
    session, user = _session_user()
    value = make_cache_value(auth, session, user)
    assert pyjwt.get_unverified_header(value) == {"alg": "HS256"}
    claims = pyjwt.decode(value, auth.secret, algorithms=["HS256"])
    assert claims["session"]["token"] == "tok" and claims["exp"] - claims["iat"] == 300
    result, _cookies = await get_session(auth, _request_with_cache(auth, value, "tok"))
    assert result is not None and result["user"]["id"] == "u1"


async def test_jwt_strategy_rejects_a_compact_value():
    auth = _jwt_auth()
    session, user = _session_user()
    value = make_cache_value(_cached_auth(), session, user)
    result, cookies = await get_session(auth, _request_with_cache(auth, value, "tok"))
    assert result is None and _expires_session_data(cookies)


async def test_sign_up_sets_the_cache_cookie():
    # cookies/index.ts:350-392: setSessionCookie always writes the cache alongside
    from conftest import SIGNUP, make_client

    auth = _cached_auth()
    async with make_client(auth) as client:
        response = await client.post("/api/auth/sign-up/email", json=SIGNUP)
    names = [c.split("=", 1)[0] for c in response.headers.get_list("set-cookie")]
    assert "better-auth.session_data" in names


async def test_dont_remember_cache_window_is_one_minute():
    # cookies/index.ts:189-191: a browser-session cache (no maxAge) is stamped for 60s
    import json
    import time

    from better_auth.crypto import b64url_decode_nopad

    auth = _cached_auth()
    session, user = _session_user()
    cookie = set_cookie_cache(auth, session, user, dont_remember=True)
    assert cookie is not None and "Max-Age" not in cookie
    value = cookie.split(";", 1)[0].split("=", 1)[1]
    envelope = json.loads(b64url_decode_nopad(value))
    assert abs(envelope["expiresAt"] - (time.time() * 1000 + 60_000)) < 5_000


async def test_update_user_refreshes_the_cache():
    # update-user.ts setSessionCookie -> setCookieCache with the updated user
    from conftest import SIGNUP, make_client

    auth = _cached_auth()
    async with make_client(auth) as client:
        await client.post("/api/auth/sign-up/email", json=SIGNUP)
        await client.post("/api/auth/update-user", json={"name": "Grace"})
        session = await client.get("/api/auth/get-session")
    assert session.json()["user"]["name"] == "Grace"


async def test_update_session_refreshes_the_cache():
    from better_auth import Field
    from conftest import SIGNUP, make_client

    auth = make_auth(
        session=SessionOptions(
            cookie_cache=CookieCache(enabled=True),
            additional_fields={"theme": Field(type="string", required=False)},
        )
    )
    async with make_client(auth) as client:
        await client.post("/api/auth/sign-up/email", json=SIGNUP)
        await client.post("/api/auth/update-session", json={"theme": "dark"})
        session = await client.get("/api/auth/get-session")
    assert session.json()["session"]["theme"] == "dark"
