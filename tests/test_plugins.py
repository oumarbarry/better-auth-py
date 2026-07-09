from better_auth import AuthResponse, Field, Plugin
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

    auth = make_auth(hooks={"user_created_before": before, "user_created_after": after})
    async with make_client(auth) as client:
        data = await sign_up(client, name="  Ada Lovelace  ")
        assert data["user"]["name"] == "Ada Lovelace"
        assert events == ["before", "after"]
