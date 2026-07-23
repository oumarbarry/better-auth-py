"""last-login-method plugin — records the auth method used on the most recent
successful login, in a cookie and optionally in the DB.

Verified against TS `packages/better-auth/src/plugins/last-login-method/index.ts`,
`last-login-method.test.ts` and `custom-prefix.test.ts`.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

from better_auth.config import CrossSubDomainCookies
from better_auth.plugins_ext.last_login_method import (
    LastLoginMethodPlugin,
    _default_resolve_method,
)
from better_auth.types import AuthRequest, Ctx
from conftest import make_auth, make_client, sign_up
from test_oauth import github_http, oauth_auth


def llm_auth(**plugin_kwargs):
    plugin = LastLoginMethodPlugin(**plugin_kwargs)
    return make_auth(plugins=[plugin]), plugin


# --- default resolver (pure function) --------------------------------------------------


def test_default_resolver_email_paths():
    assert _default_resolve_method("/sign-in/email", {}) == "email"
    assert _default_resolve_method("/sign-up/email", {}) == "email"


def test_default_resolver_oauth_callback_paths():
    assert _default_resolve_method("/callback/google", {}) == "google"
    assert _default_resolve_method("/callback/google", {"id": "explicit-id"}) == "explicit-id"
    assert _default_resolve_method("/oauth2/callback/my-provider-id", {}) == "my-provider-id"


def test_default_resolver_siwe_passkey_magic_link():
    assert _default_resolve_method("/siwe/verify", {}) == "siwe"
    assert _default_resolve_method("/passkey/verify-authentication", {}) == "passkey"
    assert _default_resolve_method("/magic-link/verify", {}) == "magic-link"


def test_default_resolver_unrecognized_path_is_none():
    assert _default_resolve_method("/sign-out", {}) is None
    assert _default_resolve_method("", {}) is None


# --- cookie-on-success / no-cookie-on-failure -------------------------------------------


async def test_sets_cookie_on_email_sign_in():
    auth, _ = llm_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        response = await client.post(
            "/api/auth/sign-in/email",
            json={"email": "ada@example.com", "password": "s3cret-password"},
        )
        cookie = response.headers.get("set-cookie", "")
        assert "better-auth.last_used_login_method=email" in cookie


async def test_does_not_set_cookie_on_failed_sign_in():
    auth, _ = llm_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        response = await client.post(
            "/api/auth/sign-in/email",
            json={"email": "ada@example.com", "password": "wrong-password"},
        )
        assert response.status_code == 401
        assert "last_used_login_method" not in response.headers.get("set-cookie", "")


async def test_sets_cookie_for_oauth_callback_using_provider_id():
    auth = oauth_auth(plugins=[LastLoginMethodPlugin()])
    async with make_client(auth) as client:
        start = await client.post(
            "/api/auth/sign-in/social", json={"provider": "github", "callbackURL": "/dash"}
        )
        state = parse_qs(urlsplit(start.json()["url"]).query)["state"][0]
        response = await client.get(f"/api/auth/callback/github?code=abc&state={state}")
        assert response.status_code == 302
        cookie = response.headers.get("set-cookie", "")
        assert "better-auth.last_used_login_method=github" in cookie


async def test_does_not_set_cookie_on_failed_oauth_callback():
    auth = oauth_auth(plugins=[LastLoginMethodPlugin()], http_client=github_http())
    async with make_client(auth) as client:
        response = await client.get(
            "/api/auth/callback/github?error=access_denied&state=bogus-state"
        )
        assert response.status_code == 302
        assert "last_used_login_method" not in response.headers.get("set-cookie", "")


# --- config: cookie name / max-age / custom resolver ------------------------------------


async def test_custom_cookie_name_and_max_age():
    auth, _ = llm_auth(cookie_name="my-app.last_method", max_age=123)
    async with make_client(auth) as client:
        response = await client.post(
            "/api/auth/sign-up/email",
            json={"name": "Ada", "email": "ada@example.com", "password": "s3cret-password"},
        )
        cookie = response.headers.get("set-cookie", "")
        assert "my-app.last_method=email" in cookie
        assert "Max-Age=123" in cookie


async def test_default_cookie_name_ignores_custom_cookie_prefix():
    # TS: ctx.setCookie bypasses createCookieGetter entirely -- the configured (or
    # default) cookieName is used verbatim, never re-prefixed by advanced.cookiePrefix.
    auth, _ = llm_auth()
    auth.cookie_prefix = "custom-auth"
    async with make_client(auth) as client:
        response = await client.post(
            "/api/auth/sign-up/email",
            json={"name": "Ada", "email": "ada@example.com", "password": "s3cret-password"},
        )
        cookie = response.headers.get("set-cookie", "")
        assert "better-auth.last_used_login_method=email" in cookie


async def test_custom_resolve_method_overrides_default():
    auth, _ = llm_auth(custom_resolve_method=lambda ctx: "custom-method")
    async with make_client(auth) as client:
        response = await client.post(
            "/api/auth/sign-up/email",
            json={"name": "Ada", "email": "ada@example.com", "password": "s3cret-password"},
        )
        cookie = response.headers.get("set-cookie", "")
        assert "better-auth.last_used_login_method=custom-method" in cookie


# --- cookie attribute inheritance --------------------------------------------------------


async def test_cross_subdomain_cookie_gets_domain_attribute():
    auth, _ = llm_auth()
    auth.base_url = "https://auth.example.com"
    auth.use_secure_cookies = True
    auth.cross_sub_domain_cookies = CrossSubDomainCookies(enabled=True, domain="example.com")
    async with make_client(auth) as client:
        response = await client.post(
            "/api/auth/sign-up/email",
            json={"name": "Ada", "email": "ada@example.com", "password": "s3cret-password"},
            headers={"origin": "https://auth.example.com"},
        )
        cookie = response.headers.get("set-cookie", "")
        assert "better-auth.last_used_login_method=email" in cookie
        assert "Domain=example.com" in cookie
        assert "SameSite=Lax" in cookie
        # the plugin cookie is not httpOnly (JS-readable), unlike the session cookie
        llm_cookie = next(c for c in response.headers.get_list("set-cookie") if "last_used" in c)
        assert "HttpOnly" not in llm_cookie


async def test_multiple_set_cookie_headers_coexist():
    auth, _ = llm_auth()
    async with make_client(auth) as client:
        response = await client.post(
            "/api/auth/sign-up/email",
            json={"name": "Ada", "email": "ada@example.com", "password": "s3cret-password"},
        )
        cookies = response.headers.get_list("set-cookie")
        assert any("better-auth.session_token" in c for c in cookies)
        assert any("better-auth.last_used_login_method=email" in c for c in cookies)


# --- storeInDatabase ----------------------------------------------------------------------


async def test_store_in_database_sets_field_on_sign_up():
    auth, _ = llm_auth(store_in_database=True)
    async with make_client(auth) as client:
        await sign_up(client)
        session = (await client.get("/api/auth/get-session")).json()
        assert session["user"]["lastLoginMethod"] == "email"


async def test_store_in_database_updates_on_subsequent_sign_in():
    auth, _ = llm_auth(store_in_database=True)
    async with make_client(auth) as client:
        await sign_up(client)
        await client.post("/api/auth/sign-out")
        await client.post(
            "/api/auth/sign-in/email",
            json={"email": "ada@example.com", "password": "s3cret-password"},
        )
        session = (await client.get("/api/auth/get-session")).json()
        assert session["user"]["lastLoginMethod"] == "email"


async def test_store_in_database_for_oauth():
    auth = oauth_auth(plugins=[LastLoginMethodPlugin(store_in_database=True)])
    async with make_client(auth) as client:
        start = await client.post(
            "/api/auth/sign-in/social", json={"provider": "github", "callbackURL": "/dash"}
        )
        state = parse_qs(urlsplit(start.json()["url"]).query)["state"][0]
        await client.get(f"/api/auth/callback/github?code=abc&state={state}")
        session = (await client.get("/api/auth/get-session")).json()
        assert session["user"]["lastLoginMethod"] == "github"


def test_schema_only_present_when_store_in_database():
    without_db = LastLoginMethodPlugin()
    assert without_db.schema == {}
    with_db = LastLoginMethodPlugin(store_in_database=True)
    assert "lastLoginMethod" in with_db.schema["user"]
    assert with_db.schema["user"]["lastLoginMethod"].input is False
    assert with_db.schema["user"]["lastLoginMethod"].required is False


async def test_schema_merged_into_auth_only_when_store_in_database():
    auth_without = make_auth(plugins=[LastLoginMethodPlugin()])
    assert "lastLoginMethod" not in auth_without.schema["user"]
    auth_with = make_auth(plugins=[LastLoginMethodPlugin(store_in_database=True)])
    assert "lastLoginMethod" in auth_with.schema["user"]


# --- databaseHooks edge cases (direct unit calls, mirroring TS's direct handler calls) --


async def test_user_create_before_hook_ignores_missing_ctx():
    plugin = LastLoginMethodPlugin(store_in_database=True)
    result = await plugin._user_create_before({"email": "test@example.com"}, None)
    assert result is None


def _has_user_create_hook(auth) -> bool:
    return any("user" in h and "create" in h.get("user", {}) for h in auth.internal.hooks)


async def test_init_registers_database_hook_only_when_store_in_database():
    auth_without = make_auth(plugins=[LastLoginMethodPlugin()])
    assert not _has_user_create_hook(auth_without)
    auth_with = make_auth(plugins=[LastLoginMethodPlugin(store_in_database=True)])
    assert _has_user_create_hook(auth_with)


async def test_user_create_before_hook_sets_field_directly():
    plugin = LastLoginMethodPlugin(store_in_database=True)
    auth = make_auth()
    ctx = Ctx(auth=auth, request=AuthRequest(method="POST", path="/sign-up/email"))
    result = await plugin._user_create_before({"email": "a@b.com"}, ctx)
    assert result == {"data": {"email": "a@b.com", "lastLoginMethod": "email"}}
