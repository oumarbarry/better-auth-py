from better_auth import AuthResponse, Field, Plugin, RateLimit
from better_auth.plugins import HookSet, PluginHook, PluginMiddleware, RateLimitRule
from conftest import make_auth, make_client, sign_up


class TeapotPlugin(Plugin):
    id = "teapot"
    schema = {"teapot": {"id": Field("string", required=True, unique=True)}}

    def routes(self):
        return [("GET", "/teapot", self.teapot), ("GET", "/whoami", self.whoami)]

    async def teapot(self, ctx):
        return {"teapot": True}

    async def whoami(self, ctx):
        result = await ctx.require_session()
        return {"email": result["user"]["email"]}

    async def before(self, ctx):
        if ctx.request.headers.get("x-teapot") == "block":
            return AuthResponse(status=418, body={"message": "I'm a teapot"})
        return None

    async def after(self, ctx, response):
        response.headers.append(("x-teapot", "brewed"))
        return None


def plugin_auth():
    return make_auth(plugins=[TeapotPlugin()])


async def test_plugin_route_and_after_hook():
    async with make_client(plugin_auth()) as client:
        response = await client.get("/api/auth/teapot")
        assert response.json() == {"teapot": True}
        assert response.headers["x-teapot"] == "brewed"


async def test_plugin_route_can_use_session():
    async with make_client(plugin_auth()) as client:
        assert (await client.get("/api/auth/whoami")).status_code == 401
        await sign_up(client)
        assert (await client.get("/api/auth/whoami")).json() == {"email": "ada@example.com"}


async def test_plugin_before_hook_short_circuits():
    async with make_client(plugin_auth()) as client:
        response = await client.get("/api/auth/ok", headers={"x-teapot": "block"})
        assert response.status_code == 418


async def test_plugin_schema_is_merged():
    auth = plugin_auth()
    assert "teapot" in auth.schema
    assert "user" in auth.schema


async def test_database_hooks():
    events: list[str] = []

    async def before(user):
        user["name"] = user["name"].strip()
        events.append("before")

    async def after(user):
        events.append("after")

    auth = make_auth(database_hooks={"user": {"create": {"before": before, "after": after}}})
    async with make_client(auth) as client:
        data = await sign_up(client, name="  Ada Lovelace  ")
        assert data["user"]["name"] == "Ada Lovelace"
        assert events == ["before", "after"]


async def test_session_database_hooks_fire():
    # session writes route through the internal seam, so session databaseHooks fire too
    seen: list[str] = []
    auth = make_auth(
        database_hooks={"session": {"create": {"after": lambda s: seen.append(s["token"])}}}
    )
    async with make_client(auth) as client:
        data = await sign_up(client)
        assert seen == [data["token"]]


# --- TS BetterAuthPlugin contract surface (init/middlewares/onRequest/onResponse/hooks/
#     rateLimit/$ERROR_CODES) -----------------------------------------------------------


class LifecyclePlugin(Plugin):
    id = "lifecycle"
    error_codes = {"CUSTOM_ERROR": "A custom plugin error"}

    def __init__(self) -> None:
        self.events: list[str] = []

    def init(self, auth) -> None:
        self.events.append("init")

    def middlewares(self):
        async def mw(ctx):
            self.events.append(f"mw:{ctx.request.path}")
            return None

        return [PluginMiddleware("/ok", mw)]  # scoped: only fires on /ok

    def hooks(self):
        async def matched_before(ctx):
            self.events.append("matched-before")
            return None

        return HookSet(before=[PluginHook(lambda ctx: ctx.request.path == "/ok", matched_before)])

    def rate_limit(self):
        return [RateLimitRule(window=10, max=1, path_matcher=lambda p: p == "/ok")]

    async def on_request(self, ctx):
        self.events.append("on_request")
        if ctx.request.headers.get("x-block") == "1":
            return AuthResponse(status=403, body={"message": "blocked in onRequest"})
        return None

    async def on_response(self, ctx, response):
        response.headers.append(("x-lifecycle", "seen"))
        return None


async def test_plugin_init_runs_at_construction():
    plugin = LifecyclePlugin()
    make_auth(plugins=[plugin])
    assert "init" in plugin.events


async def test_plugin_error_codes_surface_on_instance():
    auth = make_auth(plugins=[LifecyclePlugin()])
    assert auth.error_codes["CUSTOM_ERROR"] == "A custom plugin error"


async def test_plugin_on_request_can_short_circuit():
    async with make_client(make_auth(plugins=[LifecyclePlugin()])) as client:
        blocked = await client.get("/api/auth/ok", headers={"x-block": "1"})
        assert blocked.status_code == 403
        assert blocked.json() == {"message": "blocked in onRequest"}


async def test_plugin_on_response_and_matched_hooks_and_middleware():
    plugin = LifecyclePlugin()
    async with make_client(make_auth(plugins=[plugin])) as client:
        response = await client.get("/api/auth/ok")
        assert response.headers["x-lifecycle"] == "seen"  # onResponse ran
    # onRequest + path-scoped middleware + matched before-hook all fired for /ok
    assert plugin.events == ["init", "on_request", "mw:/ok", "matched-before"]


async def test_plugin_matched_hook_and_middleware_skip_other_paths():
    plugin = LifecyclePlugin()
    async with make_client(make_auth(plugins=[plugin])) as client:
        await client.get("/api/auth/error")  # a different existing GET route
    # the /ok-scoped middleware and matcher must NOT fire here
    assert "mw:/ok" not in plugin.events
    assert "matched-before" not in plugin.events


async def test_plugin_rate_limit_rule_applies():
    plugin = LifecyclePlugin()
    auth = make_auth(plugins=[plugin], rate_limit=RateLimit(enabled=True))
    async with make_client(auth) as client:
        first = await client.get("/api/auth/ok")
        assert first.status_code == 200
        second = await client.get("/api/auth/ok")  # max=1 -> second is limited
        assert second.status_code == 429
