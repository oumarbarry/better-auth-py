"""CSRF / trusted-origin parity, plus the disable_origin_check per-path
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


# --- form-encoded bodies (OAuth response_mode=form_post parity) -----------------


async def test_form_encoded_post_does_not_die_with_invalid_body():
    # regression: check_origin JSON-parsed every POST body, so a form-encoded
    # OAuth form_post callback was rejected with INVALID_BODY before any handler
    auth = make_auth()
    r = await _post(
        auth,
        path="/callback/github",
        headers={
            "cookie": COOKIE,
            "origin": "http://testserver",
            "content-type": "application/x-www-form-urlencoded",
        },
        body=b"code=abc&state=xyz",
    )
    body = r.body if isinstance(r.body, dict) else {}
    assert body.get("code") != "INVALID_BODY"


async def test_form_encoded_callback_url_is_still_validated():
    # TS parses forms too — a malicious callbackURL in a form body must not
    # bypass the trusted-origin validation
    auth = make_auth()
    r = await _post(
        auth,
        headers={
            "cookie": COOKIE,
            "origin": "http://testserver",
            "content-type": "application/x-www-form-urlencoded",
        },
        body=b"callbackURL=https://evil.example.com/",
    )
    assert r.status == 403 and r.body["code"] == "INVALID_CALLBACK_URL"


def test_validate_form_csrf_is_a_public_seam():
    """Plugins force per-endpoint form-CSRF validation through the public name
    (TS ``formCsrfMiddleware``), not through the module-private helper."""
    from better_auth import origin
    from better_auth.plugins_ext import email_otp

    assert origin.validate_form_csrf is origin._validate_form_csrf
    assert email_otp.validate_form_csrf is origin.validate_form_csrf


# --- v1.7.6 trusted-origins.ts: custom schemes and relative URLs ---------------

import pytest  # noqa: E402

from better_auth.origin import matches_origin_pattern  # noqa: E402


@pytest.mark.parametrize(
    ("url", "pattern", "expected"),
    [
        # trusted-origins.ts:143-164: a host-pinned pattern needs the exact authority
        ("myapp://callback", "myapp://callback", True),
        ("myapp://callback.attacker.tld", "myapp://callback", False),
        ("MYAPP://Callback/x", "myapp://callback", True),
        # a host-less pattern trusts every host of the scheme
        ("myapp://anything/here", "myapp://", True),
        ("exp://192.168.1.2:8081/--/cb", "exp://", True),
        ("otherapp://callback", "myapp://", False),
        # a path-pinned pattern matches the path or below, never a sibling or traversal
        ("myapp://host/cb/done", "myapp://host/cb", True),
        ("myapp://host/cb?x=1#f", "myapp://host/cb", True),
        ("myapp://host/cbx", "myapp://host/cb", False),
        ("myapp://host/cb/../evil", "myapp://host/cb", False),
        ("myapp://host/cb/%2e%2e/evil", "myapp://host/cb", False),
        ("myapp://host\x00/cb", "myapp://host", False),
    ],
)
def test_custom_scheme_matching(url, pattern, expected):
    assert matches_origin_pattern(url, pattern) is expected


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("/dashboard", True),
        ("/dashboard#section", True),  # 79904f0be
        ("/p?next=/a#frag", True),
        ("/~user/page", True),  # f6891a2d2
        ("/search?q=a%2Fb", True),  # encoded separators are fine in the query
        ("//evil.example", False),
        ("/\\evil.example", False),
        ("/%2fevil.example", False),
        ("/a%5Cb", False),
        ("/\tevil", False),
    ],
)
def test_relative_url_safety(url, expected):
    # trusted-origins.ts:80-105 isSafeRelativeURL
    assert matches_origin_pattern(url, "http://testserver", allow_relative=True) is expected


def test_relative_url_needs_allow_relative():
    assert matches_origin_pattern("/dashboard", "http://testserver") is False


# --- c8dcfa57e: a null Origin inferred from Fetch Metadata ---------------------


async def _form_post(auth, url, headers):
    request = AuthRequest(
        method="POST",
        path="/sign-in/email",
        headers={"content-type": "application/x-www-form-urlencoded", **headers},
        body=b"email=a%40b.co&password=secret-123",
        url=url,
    )
    return await auth.handle(request)


async def test_null_origin_same_origin_trusted_target_accepted():
    auth = make_auth()
    r = await _form_post(
        auth,
        "http://testserver/api/auth/sign-in/email",
        {"origin": "null", "sec-fetch-site": "same-origin"},
    )
    assert r.body.get("code") not in ("MISSING_OR_NULL_ORIGIN", "INVALID_ORIGIN")


async def test_null_origin_through_trusted_proxy_accepted():
    auth = make_auth(trusted_origins=["https://app.example.com"], trusted_proxy_headers=True)
    r = await _form_post(
        auth,
        "http://internal:3000/api/auth/sign-in/email",
        {
            "origin": "null",
            "sec-fetch-site": "same-origin",
            "x-forwarded-host": "app.example.com",
            "x-forwarded-proto": "https",
        },
    )
    assert r.body.get("code") not in ("MISSING_OR_NULL_ORIGIN", "INVALID_ORIGIN")


async def test_null_origin_ignores_forwarded_headers_when_untrusted():
    auth = make_auth()
    r = await _form_post(
        auth,
        "https://untrusted.example/api/auth/sign-in/email",
        {
            "origin": "null",
            "sec-fetch-site": "same-origin",
            "x-forwarded-host": "testserver",
            "x-forwarded-proto": "http",
        },
    )
    assert r.status == 403
    assert r.body == {"code": "INVALID_ORIGIN", "message": "Invalid origin"}


@pytest.mark.parametrize("site", ["cross-site", "same-site", None])
async def test_null_origin_without_same_origin_metadata_rejected(site):
    headers = {"origin": "null"}
    if site:
        headers["sec-fetch-site"] = site
    r = await _form_post(make_auth(), "http://testserver/api/auth/sign-in/email", headers)
    assert r.status == 403
    assert r.body == {"code": "MISSING_OR_NULL_ORIGIN", "message": "Missing or null Origin"}


async def test_missing_origin_rejected_even_when_same_origin():
    r = await _form_post(
        make_auth(),
        "http://testserver/api/auth/sign-in/email",
        {"sec-fetch-site": "same-origin", "cookie": COOKIE},
    )
    assert r.status == 403 and r.body["code"] == "MISSING_OR_NULL_ORIGIN"


async def test_cross_site_navigation_message_matches_ts():
    r = await _post(
        make_auth(),
        path="/sign-in/email",
        headers={"sec-fetch-site": "cross-site", "sec-fetch-mode": "navigate"},
    )
    assert r.body["message"] == (
        "Cross-site navigation login blocked. This request appears to be a CSRF attack."
    )


async def test_fastapi_integration_passes_the_request_url():
    from conftest import make_client

    auth = make_auth()
    async with make_client(auth) as client:
        r = await client.post(
            "/api/auth/sign-in/email",
            json={"email": "a@b.co", "password": "secret-123"},
            headers={"origin": "null", "sec-fetch-site": "same-origin"},
        )
    assert r.json()["code"] == "INVALID_EMAIL_OR_PASSWORD"
