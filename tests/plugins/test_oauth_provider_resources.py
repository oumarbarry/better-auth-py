"""oauth-provider: OAuth protected resources (RFC 8707) end to end.

Anchored to TS v1.7.6 ``packages/oauth-provider/src/resources.ts`` (d2a79bae7), the grant
binding in ``token.ts`` / ``authorize.ts`` (b4b086722) and resource-linked introspection in
``introspect.ts`` (2fd3d5850). Mirrors ``resources-e2e.test.ts`` and ``validation-flow.test.ts``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit

from test_oauth_provider_token import (
    CB,
    ISSUER,
    SECRET,
    VERIFIER,
    authorize_url,
    get_code,
    introspect,
    make_client,
    provider_auth,
    seed,
    token,
    unverified,
)

from better_auth.adapters.base import Where
from better_auth.plugins_ext.oauth_provider.resources import (
    reset_seed_state_for_tests,
    seed_resources,
)
from better_auth.types import AuthRequest, Ctx
from conftest import sign_up

API = "https://api.example.com"
OTHER = "https://other.example.com"
USERINFO = f"{ISSUER}/oauth2/userinfo"


async def link(auth, resource, client_id="client-1"):
    await auth.adapter.create(
        "oauthClientResource",
        {"clientId": client_id, "resourceId": resource, "createdAt": datetime.now(timezone.utc)},
    )


async def code_token(c, *, scope="openid", verifier=None, **authz):
    code = await get_code(c, scope=scope, verifier=verifier, **authz)
    form = {
        "grant_type": "authorization_code",
        "client_id": "client-1",
        "client_secret": SECRET,
        "code": code,
        "redirect_uri": CB,
    }
    if verifier:
        form["code_verifier"] = verifier
    return form


async def test_token_resource_must_be_a_configured_resource():
    # resources.ts:393 "requested resource X is not configured" (invalid_target).
    auth = provider_auth(resources=[API])
    await seed(auth)
    async with make_client(auth) as c:
        await sign_up(c)
        form = await code_token(c)
        res = await token(c, **form, resource=OTHER)
        assert res.status_code == 400
        assert res.json() == {
            "error": "invalid_target",
            "error_description": f"requested resource {OTHER} is not configured",
        }
        assert res.headers["cache-control"] == "no-store"


async def test_token_resource_requires_client_link_by_default():
    # resources.ts:548 enforcePerClientResources defaults to true.
    auth = provider_auth(resources=[API])
    await seed(auth)
    async with make_client(auth) as c:
        await sign_up(c)
        form = await code_token(c)
        res = await token(c, **form, resource=API)
        assert res.status_code == 400
        assert res.json()["error"] == "invalid_target"
        assert res.json()["error_description"] == (
            f"client client-1 is not linked to resource(s) {API}"
        )


async def test_linked_resource_issues_jwt_with_policy():
    # resources.ts:421-510 + token.ts:223: aud, TTL, narrowed scopes, custom claims, jti.
    auth = provider_auth(
        resources=[
            {
                "identifier": API,
                "accessTokenTtl": 120,
                "allowedScopes": ["openid", "profile"],
                "customClaims": {"tier": "gold", "sub": "evil"},
            }
        ]
    )
    await seed(auth)
    async with make_client(auth) as c:
        await sign_up(c)
        await link(auth, API)
        form = await code_token(c, scope="openid profile email")
        res = await token(c, **form, resource=API)
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["expires_in"] == 120
        assert body["scope"] == "openid profile"
        claims = unverified(body["access_token"])
        assert claims["aud"] == [API, USERINFO]
        assert claims["tier"] == "gold"
        assert claims["sub"] != "evil"
        assert len(claims["jti"]) == 32
        assert pyjwt_header(body["access_token"])["typ"] == "at+jwt"


def pyjwt_header(tok):
    import jwt as pyjwt

    return pyjwt.get_unverified_header(tok)


async def test_resource_allowlist_excluding_every_scope_is_invalid_scope():
    auth = provider_auth(resources=[{"identifier": API, "allowedScopes": ["api:read"]}])
    await seed(auth)
    async with make_client(auth) as c:
        await sign_up(c)
        await link(auth, API)
        form = await code_token(c)
        res = await token(c, **form, resource=API)
        assert res.json() == {
            "error": "invalid_scope",
            "error_description": f"none of the requested scopes are allowed for resource {API}",
        }


async def test_disabled_resource_is_invalid_target():
    auth = provider_auth(resources=[{"identifier": API, "disabled": True}])
    await seed(auth)
    async with make_client(auth) as c:
        await sign_up(c)
        await link(auth, API)
        form = await code_token(c)
        res = await token(c, **form, resource=API)
        assert res.json()["error_description"] == f"requested resource {API} is disabled"


async def test_enforce_per_client_resources_false_skips_link_check():
    auth = provider_auth(resources=[API], enforce_per_client_resources=False)
    await seed(auth)
    async with make_client(auth) as c:
        await sign_up(c)
        form = await code_token(c)
        res = await token(c, **form, resource=API)
        assert res.status_code == 200, res.text


async def test_malformed_resource_fails_body_validation():
    # oauth.ts:919 ResourceUriSchema union: invalid_request "resource: Invalid input".
    auth = provider_auth(resources=[API])
    await seed(auth)
    async with make_client(auth) as c:
        res = await token(c, grant_type="client_credentials", client_id="client-1", resource="/api")
        assert res.json() == {
            "error": "invalid_request",
            "error_description": "resource: Invalid input",
        }
        res = await token(
            c, grant_type="client_credentials", client_id="client-1", resource=f"{API}#x"
        )
        assert res.json()["error_description"] == "resource: resource must not contain a fragment"


async def test_authorize_binds_resource_and_token_may_only_narrow():
    # token.ts:1438 "requested resource not authorized" (b4b086722).
    auth = provider_auth(resources=[API, OTHER])
    await seed(auth)
    async with make_client(auth) as c:
        await sign_up(c)
        await link(auth, API)
        await link(auth, OTHER)
        form = await code_token(c, resource=API)
        res = await token(c, **form, resource=OTHER)
        assert res.json() == {
            "error": "invalid_target",
            "error_description": "requested resource not authorized",
        }
        # Without a token-side resource the bound one applies.
        form = await code_token(c, resource=API)
        body = (await token(c, **form)).json()
        assert unverified(body["access_token"])["aud"] == [API, USERINFO]


async def test_authorize_rejects_unknown_resource_with_rp_redirect():
    # authorize.ts:597-623: resource errors go to the registered redirect_uri.
    auth = provider_auth(resources=[API])
    await seed(auth)
    async with make_client(auth) as c:
        await sign_up(c)
        res = await c.get(authorize_url(scope="openid", state="s1", resource=OTHER))
        assert res.status_code == 302
        location = res.headers["location"]
        assert location.startswith(CB + "?")
        q = parse_qs(urlsplit(location).query)
        assert q["error"] == ["invalid_target"]
        assert q["error_description"] == [f"requested resource {OTHER} is not configured"]
        assert q["state"] == ["s1"]
        assert q["iss"] == [ISSUER]


async def test_repeated_form_resources_become_an_audience_list():
    # oauth.ts:1063 extractRepeatedResourceFromForm.
    auth = provider_auth(resources=[API, OTHER])
    await seed(auth, scopes=["api"], clientCredentialsScopes=["api"])
    async with make_client(auth) as c:
        await link(auth, API)
        await link(auth, OTHER)
        res = await c.post(
            "/api/auth/oauth2/token",
            content=(
                "grant_type=client_credentials&client_id=client-1"
                f"&client_secret={SECRET}&resource={API}&resource={OTHER}"
            ),
            headers={"content-type": "application/x-www-form-urlencoded"},
        )
        assert res.status_code == 200, res.text
        assert unverified(res.json()["access_token"])["aud"] == [API, OTHER]


async def test_refresh_keeps_grant_resources_and_rejects_widening():
    # token.ts:1868 "requested resource invalid"; refresh rows carry the resources.
    auth = provider_auth(resources=[API, OTHER])
    await seed(auth)
    async with make_client(auth) as c:
        await sign_up(c)
        await link(auth, API)
        await link(auth, OTHER)
        form = await code_token(c, scope="openid offline_access", verifier=VERIFIER, resource=API)
        body = (await token(c, **form)).json()
        rows = await auth.adapter.find_many("oauthRefreshToken", [])
        assert rows[0]["resources"] == [API]
        res = await token(
            c,
            grant_type="refresh_token",
            client_id="client-1",
            client_secret=SECRET,
            refresh_token=body["refresh_token"],
            resource=OTHER,
        )
        assert res.json() == {
            "error": "invalid_target",
            "error_description": "requested resource invalid",
        }
        res = await token(
            c,
            grant_type="refresh_token",
            client_id="client-1",
            client_secret=SECRET,
            refresh_token=body["refresh_token"],
        )
        assert res.status_code == 200, res.text
        assert unverified(res.json()["access_token"])["aud"] == [API, USERINFO]


async def test_linked_resource_server_may_introspect_another_clients_token():
    # introspect.ts:83 isIntrospectionAuthorized (2fd3d5850).
    auth = provider_auth(resources=[API])
    await seed(auth)
    await seed(auth, client_id="rs", scopes=["openid"], skipConsent=True)
    await seed(auth, client_id="stranger", scopes=["openid"])
    async with make_client(auth) as c:
        await sign_up(c)
        await link(auth, API)
        await link(auth, API, client_id="rs")
        form = await code_token(c)
        access = (await token(c, **form, resource=API)).json()["access_token"]
        body = (await introspect(c, client_id="rs", client_secret=SECRET, token=access)).json()
        assert body["active"] is True
        assert body["client_id"] == "client-1"
        body = (
            await introspect(c, client_id="stranger", client_secret=SECRET, token=access)
        ).json()
        assert body == {"active": False}


async def test_deleting_a_resource_revokes_its_jwt_tokens():
    # introspect.ts:171-193: every aud value must resolve; disabled rows still pass.
    auth = provider_auth(resources=[API])
    await seed(auth)
    async with make_client(auth) as c:
        await sign_up(c)
        await link(auth, API)
        form = await code_token(c)
        access = (await token(c, **form, resource=API)).json()["access_token"]
        await auth.adapter.update("oauthResource", [Where("identifier", API)], {"disabled": True})
        body = (
            await introspect(c, client_id="client-1", client_secret=SECRET, token=access)
        ).json()
        assert body["active"] is True
        await auth.adapter.delete("oauthResource", [Where("identifier", API)])
        body = (
            await introspect(c, client_id="client-1", client_secret=SECRET, token=access)
        ).json()
        assert body == {"active": False}


async def test_consent_records_resources_and_reprompts_for_new_ones():
    # consent.ts:136 + authorize.ts:923: a resource outside stored consent re-prompts.
    auth = provider_auth(resources=[API, OTHER])
    await seed(auth, skipConsent=False)
    async with make_client(auth) as c:
        await sign_up(c)
        await link(auth, API)
        await link(auth, OTHER)
        await auth.adapter.create(
            "oauthConsent",
            {
                "clientId": "client-1",
                "userId": (await auth.adapter.find_many("user", []))[0]["id"],
                "scopes": ["openid"],
                "resources": [API],
            },
        )
        res = await c.get(authorize_url(scope="openid", resource=API))
        assert "code=" in res.headers["location"]
        res = await c.get(authorize_url(scope="openid", resource=OTHER))
        assert res.headers["location"].startswith("https://app.example.com/consent?")


async def test_seed_modes_merge_and_overwrite():
    # resources.ts:771 buildSeedUpdate.
    reset_seed_state_for_tests()
    auth = provider_auth(resources=[{"identifier": API, "name": "Api", "accessTokenTtl": 60}])
    plugin = auth.plugins[-1]

    ctx = Ctx(auth=auth, request=AuthRequest(method="GET", path="/"))
    await seed_resources(ctx, plugin)
    row = await auth.adapter.find_one("oauthResource", [Where("identifier", API)])
    assert row["name"] == "Api" and row["accessTokenTtl"] == 60 and row["policyVersion"] == 1
    await auth.adapter.update("oauthResource", [Where("identifier", API)], {"name": "Edited"})

    plugin.resources = [{"identifier": API, "accessTokenTtl": 30}]
    await seed_resources(ctx, plugin)
    row = await auth.adapter.find_one("oauthResource", [Where("identifier", API)])
    assert row["name"] == "Edited" and row["accessTokenTtl"] == 60  # insertOnly

    plugin.resource_seed_mode = "merge"
    await seed_resources(ctx, plugin)
    row = await auth.adapter.find_one("oauthResource", [Where("identifier", API)])
    assert row["name"] == "Edited" and row["accessTokenTtl"] == 30

    plugin.resource_seed_mode = "overwrite"
    await seed_resources(ctx, plugin)
    row = await auth.adapter.find_one("oauthResource", [Where("identifier", API)])
    assert row["name"] == API and row["accessTokenTtl"] == 30
