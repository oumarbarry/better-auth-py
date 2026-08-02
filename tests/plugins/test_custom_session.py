"""custom-session plugin — wraps GET /get-session so integrators can shape/augment the
returned session object.

Verified against TS `packages/better-auth/src/plugins/custom-session/index.ts` and
`custom-session.test.ts`.
"""

from __future__ import annotations

from better_auth import AuthResponse, Plugin, SessionOptions
from better_auth.config import CookieCache
from better_auth.plugins import HookSet, PluginHook
from better_auth.plugins_ext.custom_session import CustomSessionPlugin
from better_auth.types import Ctx
from conftest import make_auth, make_client, sign_up


async def _augment(session, ctx):
    return {
        "user": {"firstName": session["user"]["name"].split(" ")[0]},
        "session": session["session"],
        "extra": "hello",
    }


def custom_session_auth(fn=_augment, **kwargs):
    return make_auth(plugins=[CustomSessionPlugin(fn, **kwargs)])


async def test_returns_transformed_session():
    async with make_client(custom_session_auth()) as client:
        await sign_up(client, name="Ada Lovelace")
        response = await client.get("/api/auth/get-session")
        assert response.status_code == 200
        body = response.json()
        assert body["extra"] == "hello"
        assert body["user"]["firstName"] == "Ada"
        assert body["session"]["userId"]


async def test_returns_null_when_no_session():
    async with make_client(custom_session_auth()) as client:
        response = await client.get("/api/auth/get-session")
        assert response.status_code == 200
        assert response.json() is None


async def test_accepts_disable_refresh_query_without_validation_error():
    async with make_client(custom_session_auth()) as client:
        await sign_up(client)
        response = await client.get("/api/auth/get-session", params={"disableRefresh": "true"})
        assert response.status_code == 200
        assert response.json() is not None


async def test_forwards_set_cookie_headers_as_separate_entries_not_comma_joined():
    session_expires_in = 86400
    cache_max_age = 10
    auth = make_auth(
        plugins=[CustomSessionPlugin(_augment)],
        session=SessionOptions(
            expires_in=session_expires_in,
            update_age=0,
            cookie_cache=CookieCache(enabled=True, max_age=cache_max_age),
        ),
    )
    async with make_client(auth) as client:
        await sign_up(client)
        response = await client.get("/api/auth/get-session")
        assert response.status_code == 200
        cookies = response.headers.get_list("set-cookie")
        # each cookie is its own header -- never comma-joined into one entry
        assert len(cookies) >= 2
        token_cookie = next(c for c in cookies if "better-auth.session_token" in c)
        data_cookie = next(c for c in cookies if "better-auth.session_data" in c)
        for cookie in cookies:
            names = [p.strip().split("=")[0].lower() for p in cookie.split(";")]
            assert sum(n.startswith("better-auth.") for n in names) == 1
        # each cookie keeps its OWN Max-Age -- if headers were comma-joined, the
        # browser would merge attributes and session_token could inherit the much
        # shorter cookieCache Max-Age, causing premature session expiry.
        token_max_age = int(token_cookie.split("Max-Age=")[1].split(";")[0])
        data_max_age = int(data_cookie.split("Max-Age=")[1].split(";")[0])
        assert token_max_age > session_expires_in - 10
        assert token_max_age <= session_expires_in
        assert data_max_age == cache_max_age
        assert token_max_age != data_max_age


async def test_refreshed_session_cookie_is_not_double_encoded():
    auth = make_auth(
        plugins=[CustomSessionPlugin(_augment)],
        session=SessionOptions(update_age=0, cookie_cache=CookieCache(enabled=True, max_age=10)),
    )
    async with make_client(auth) as client:
        signed_in_cookie = client.cookies
        await sign_up(client)
        original_token = signed_in_cookie.get("better-auth.session_token")
        assert original_token is not None
        response = await client.get("/api/auth/get-session")
        refreshed = None
        for cookie in response.headers.get_list("set-cookie"):
            if cookie.startswith("better-auth.session_token="):
                refreshed = cookie.split(";")[0].split("=", 1)[1]
        assert refreshed is not None
        assert refreshed == original_token
        assert "%25" not in refreshed  # not re-percent-encoded


async def test_other_plugin_after_hooks_still_apply_on_top_of_custom_session_response():
    class HeaderPlugin(Plugin):
        id = "header-tag"

        async def after(self, ctx, response):
            response.headers.append(("x-tag", "seen"))
            return None

    auth = make_auth(plugins=[CustomSessionPlugin(_augment), HeaderPlugin()])
    async with make_client(auth) as client:
        await sign_up(client)
        response = await client.get("/api/auth/get-session")
        assert response.headers["x-tag"] == "seen"
        assert response.json()["extra"] == "hello"


def test_should_mutate_list_device_sessions_endpoint_default_false():
    plugin = CustomSessionPlugin(_augment)
    assert plugin.should_mutate_list_device_sessions_endpoint is False
    matcher = plugin.hooks().after[0].matcher
    ctx = Ctx(auth=make_auth(), request=_fake_request("/multi-session/list-device-sessions"))
    assert matcher(ctx) is False  # opt-in required


def test_should_mutate_list_device_sessions_endpoint_matcher_scoped_to_path():
    plugin = CustomSessionPlugin(_augment, should_mutate_list_device_sessions_endpoint=True)
    matcher = plugin.hooks().after[0].matcher
    ctx_match = Ctx(auth=make_auth(), request=_fake_request("/multi-session/list-device-sessions"))
    ctx_other = Ctx(auth=make_auth(), request=_fake_request("/get-session"))
    assert matcher(ctx_match) is True
    assert matcher(ctx_other) is False


async def test_list_device_sessions_hook_maps_fn_over_each_entry():
    # ponytail: multi-session isn't ported yet (Wave 4), so this hook's matcher never
    # actually fires through real HTTP dispatch today -- exercised directly here
    # against the handler, matching the shape multi-session's endpoint would produce.
    plugin = CustomSessionPlugin(_augment, should_mutate_list_device_sessions_endpoint=True)
    auth = make_auth()
    ctx = Ctx(auth=auth, request=_fake_request("/multi-session/list-device-sessions"))
    ctx.response = AuthResponse(
        body=[
            {"user": {"name": "Ada Lovelace"}, "session": {"userId": "u1"}},
            {"user": {"name": "Bob Jones"}, "session": {"userId": "u2"}},
        ]
    )
    handler = plugin.hooks().after[0].handler
    await handler(ctx)
    assert ctx.response.body == [
        {"user": {"firstName": "Ada"}, "session": {"userId": "u1"}, "extra": "hello"},
        {"user": {"firstName": "Bob"}, "session": {"userId": "u2"}, "extra": "hello"},
    ]


def _fake_request(path: str):
    from better_auth.types import AuthRequest

    return AuthRequest(method="GET", path=path)


def test_hookset_type_is_reused():
    plugin = CustomSessionPlugin(_augment)
    hooks = plugin.hooks()
    assert isinstance(hooks, HookSet)
    assert isinstance(hooks.after[0], PluginHook)
