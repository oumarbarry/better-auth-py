"""CSRF / trusted-origin parity (gap item 9) + the disable_origin_check per-path
security fix. Requests go through ``auth.handle`` with hand-built headers so the origin
check can be exercised in isolation (the origin check runs before route matching, so a
403 here never depends on a valid session)."""

from __future__ import annotations

from better_auth.types import AuthRequest
from conftest import make_auth

COOKIE = "better-auth.session_token=abc.def"


async def _post(auth, path="/sign-out", headers=None, body=b""):
    request = AuthRequest(method="POST", path=path, headers=headers or {}, body=body)
    return await auth.handle(request)


def _is_origin_reject(response) -> bool:
    return response.status == 403 and response.body.get("code") == "INVALID_ORIGIN"


# --- MISSING_OR_NULL_ORIGIN (cookies present, no origin) -----------------------


async def test_missing_origin_with_cookies_rejected():
    auth = make_auth()
    r = await _post(auth, headers={"cookie": COOKIE})
    assert r.status == 403 and r.body["code"] == "MISSING_OR_NULL_ORIGIN"


async def test_null_origin_with_cookies_rejected():
    auth = make_auth()
    r = await _post(auth, headers={"cookie": COOKIE, "origin": "null"})
    assert r.status == 403 and r.body["code"] == "MISSING_OR_NULL_ORIGIN"


async def test_no_cookies_no_origin_passes_origin_check():
    # non-browser clients (no cookie, no origin) are not force-validated
    auth = make_auth()
    r = await _post(auth, headers={})
    assert not _is_origin_reject(r)


# --- Referer fallback ----------------------------------------------------------


async def test_referer_used_when_origin_absent():
    auth = make_auth()
    trusted = await _post(auth, headers={"cookie": COOKIE, "referer": "http://testserver/x"})
    assert not _is_origin_reject(trusted)
    evil = await _post(auth, headers={"cookie": COOKIE, "referer": "http://evil.example/x"})
    assert _is_origin_reject(evil)


# --- Fetch-Metadata first-login protection -------------------------------------


async def test_cross_site_navigation_login_blocked():
    auth = make_auth()
    r = await _post(
        auth,
        path="/sign-in/email",
        headers={"sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate"},
    )
    assert r.status == 403 and r.body["code"] == "CROSS_SITE_NAVIGATION_LOGIN_BLOCKED"


async def test_same_origin_fetch_metadata_not_blocked():
    auth = make_auth()
    r = await _post(
        auth,
        path="/sign-in/email",
        headers={"sec-fetch-site": "same-origin", "sec-fetch-mode": "cors"},
    )
    assert r.body.get("code") != "CROSS_SITE_NAVIGATION_LOGIN_BLOCKED"


# --- wildcard + callable trusted origins ---------------------------------------


async def test_wildcard_trusted_origin():
    auth = make_auth(trusted_origins=["https://*.example.com"])
    ok = await _post(auth, headers={"cookie": COOKIE, "origin": "https://app.example.com"})
    assert not _is_origin_reject(ok)
    bad = await _post(auth, headers={"cookie": COOKIE, "origin": "https://evil.com"})
    assert _is_origin_reject(bad)


async def test_callable_trusted_origins():
    auth = make_auth(trusted_origins=lambda request: ["http://dynamic.example"])
    ok = await _post(auth, headers={"cookie": COOKIE, "origin": "http://dynamic.example"})
    assert not _is_origin_reject(ok)
    bad = await _post(auth, headers={"cookie": COOKIE, "origin": "http://other.example"})
    assert _is_origin_reject(bad)


# --- disable_origin_check: the per-path security fix (coordinator-mandated) -----


async def test_disable_origin_check_true_skips_globally():
    auth = make_auth(disable_origin_check=True)
    r = await _post(auth, headers={"cookie": COOKIE, "origin": "http://evil.example"})
    assert not _is_origin_reject(r)


async def test_disable_origin_check_list_skips_only_listed_path():
    auth = make_auth(disable_origin_check=["/sign-out"])
    # listed path: origin check skipped even for an untrusted origin
    listed = await _post(
        auth, path="/sign-out", headers={"cookie": COOKIE, "origin": "http://evil.example"}
    )
    assert not _is_origin_reject(listed)
    # any other path still rejects an untrusted origin — a non-empty list must NOT
    # disable the check globally (the CSRF-bypass this test guards against)
    other = await _post(
        auth, path="/update-user", headers={"cookie": COOKIE, "origin": "http://evil.example"}
    )
    assert _is_origin_reject(other)


async def test_disable_origin_check_empty_list_behaves_as_enabled():
    auth = make_auth(disable_origin_check=[])
    r = await _post(auth, headers={"cookie": COOKIE, "origin": "http://evil.example"})
    assert _is_origin_reject(r)


async def test_disable_csrf_check_skips_origin():
    auth = make_auth(disable_csrf_check=True)
    r = await _post(auth, headers={"cookie": COOKIE, "origin": "http://evil.example"})
    assert not _is_origin_reject(r)
