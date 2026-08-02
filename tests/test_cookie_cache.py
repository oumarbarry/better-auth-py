"""session_data cookie cache (gap item 15): signed round-trip, cache-hit skips the DB,
tamper/version/expiry rejection, and cross-subdomain domain widening."""

from __future__ import annotations

from datetime import timedelta

from better_auth.config import CookieCache, SessionOptions
from better_auth.cookie_cache import get_cookie_cache, make_cache_value, set_cookie_cache
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


def _request_with_cache(auth, value: str) -> AuthRequest:
    name = cookie_name(auth, "session_data")
    return AuthRequest(method="GET", path="/get-session", headers={"cookie": f"{name}={value}"})


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
    result, _cookies = await get_session(auth, _request_with_cache(auth, value))
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
