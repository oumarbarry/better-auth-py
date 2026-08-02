"""oauth-provider plugin — Phase A (clients + DCR + discovery).

Verified against TS ``packages/oauth-provider/src/`` (register.ts, oauthClient/,
metadata.ts, schema.ts, utils/index.ts) and the corresponding *.test.ts at v1.6.23.
"""

from __future__ import annotations

import pytest

from better_auth.adapters.base import Where
from better_auth.crypto import default_key_hasher
from better_auth.plugins_ext.jwt import JWTPlugin
from better_auth.plugins_ext.oauth_provider import OAuthProviderPlugin
from better_auth.plugins_ext.oauth_provider.utils import (
    basic_to_client_credentials,
    is_safe_url,
    store_client_secret,
    verify_client_secret,
)
from better_auth.types import AuthRequest
from conftest import make_auth, make_client, sign_up


def provider_auth(**kwargs):
    return make_auth(plugins=[JWTPlugin(), OAuthProviderPlugin(**kwargs)])


def provider_client(**kwargs):
    return make_client(provider_auth(**kwargs))


# --- init guards (oauth.ts:71-178) ---------------------------------------------------


def test_disable_jwt_plugin_allowed_default_store_encrypted():
    # disable_jwt_plugin is supported; its default secret storage is "encrypted"
    # (see test_oauth_provider_disable_jwt.py for the HS256 end-to-end flow).
    assert OAuthProviderPlugin(disable_jwt_plugin=True).store_client_secret == "encrypted"


def test_encrypted_secret_storage_rejected_at_init():
    with pytest.raises(ValueError):
        OAuthProviderPlugin(store_client_secret="encrypted")


def test_allowed_scope_outside_scopes_rejected():
    with pytest.raises(ValueError):
        OAuthProviderPlugin(scopes=["openid"], client_registration_allowed_scopes=["email"])


def test_advertised_scope_outside_scopes_rejected():
    with pytest.raises(ValueError):
        OAuthProviderPlugin(scopes=["openid"], advertised_metadata={"scopes_supported": ["email"]})


def test_short_pairwise_secret_rejected():
    with pytest.raises(ValueError):
        OAuthProviderPlugin(pairwise_secret="too-short")


def test_refresh_without_authorization_code_rejected():
    with pytest.raises(ValueError):
        OAuthProviderPlugin(grant_types=["refresh_token"])


def test_non_eddsa_jwt_key_accepted_at_init():
    # TS has no alg gate — the whole JWKOptions union is usable (jwt/types.ts:176-196).
    auth = make_auth(
        plugins=[JWTPlugin(key_pair_config={"alg": "ES256"}), OAuthProviderPlugin()]
    )
    assert auth is not None


def test_schema_registers_all_four_tables():
    auth = provider_auth()
    for model in ("oauthClient", "oauthConsent", "oauthRefreshToken", "oauthAccessToken"):
        assert model in auth.schema
    fields = auth.schema["oauthClient"]
    assert fields["clientId"].unique is True
    assert fields["redirectUris"].type == "string[]"
    assert fields["scopes"].type == "string[]"
    assert fields["metadata"].type == "json"
    assert fields["clientSecret"].returned is False


# --- helpers (client secret storage, basic auth, safe url) ---------------------------


async def test_secret_hashed_and_constant_time_verified():
    opts = OAuthProviderPlugin()
    stored = await store_client_secret(opts, "super-secret")
    assert stored == default_key_hasher("super-secret")
    assert stored != "super-secret"
    assert await verify_client_secret(opts, stored, "super-secret") is True
    assert await verify_client_secret(opts, stored, "wrong") is False


async def test_secret_prefix_stripped_before_verify():
    opts = OAuthProviderPlugin(prefix={"clientSecret": "ba_"})
    stored = await store_client_secret(opts, "raw-secret")
    assert await verify_client_secret(opts, stored, "ba_raw-secret") is True


async def test_secret_wrong_prefix_rejected():
    from better_auth.plugins_ext.oauth_provider.utils import OAuthError

    opts = OAuthProviderPlugin(prefix={"clientSecret": "ba_"})
    stored = await store_client_secret(opts, "raw-secret")
    with pytest.raises(OAuthError):
        await verify_client_secret(opts, stored, "raw-secret")


def test_basic_to_client_credentials_decodes():
    import base64

    header = "Basic " + base64.b64encode(b"cid:csecret").decode()
    assert basic_to_client_credentials(header) == {
        "client_id": "cid",
        "client_secret": "csecret",
    }
    assert basic_to_client_credentials("Bearer x") is None


def test_safe_url_scheme_policy():
    assert is_safe_url("https://example.com/cb") is True
    assert is_safe_url("http://127.0.0.1/cb") is True
    assert is_safe_url("http://localhost:3000/cb") is True
    assert is_safe_url("myapp://callback") is True
    assert is_safe_url("http://example.com/cb") is False
    assert is_safe_url("javascript:alert(1)") is False
    assert is_safe_url("data:text/html,x") is False
    assert is_safe_url("https://example.com/cb#frag") is False


# --- DCR (register.test.ts) ----------------------------------------------------------


async def _register(client, **body):
    return await client.post("/api/auth/oauth2/register", json=body)


async def test_dcr_disabled_by_default():
    async with provider_client() as client:
        await sign_up(client)
        res = await _register(client, redirect_uris=["https://app.example.com/cb"])
        assert res.status_code == 403
        assert res.json()["error"] == "access_denied"


async def test_confidential_registration_preserves_method_and_type():
    async with provider_client(allow_dynamic_client_registration=True) as client:
        await sign_up(client)
        res = await _register(
            client,
            redirect_uris=["https://app.example.com/cb"],
            token_endpoint_auth_method="client_secret_basic",
            type="web",
        )
        assert res.status_code == 201, res.text
        body = res.json()
        assert body["public"] is False
        assert body["token_endpoint_auth_method"] == "client_secret_basic"
        assert body["type"] == "web"
        assert body["client_secret"]  # confidential clients get a secret


async def test_unauthenticated_dcr_forces_none_and_clears_type():
    async with provider_client(
        allow_dynamic_client_registration=True,
        allow_unauthenticated_client_registration=True,
    ) as client:
        res = await _register(
            client,
            redirect_uris=["https://app.example.com/cb"],
            token_endpoint_auth_method="client_secret_basic",
            type="web",
        )
        assert res.status_code == 201, res.text
        body = res.json()
        assert body["public"] is True
        assert body["token_endpoint_auth_method"] == "none"
        assert "type" not in body
        assert "client_secret" not in body


async def test_anonymous_client_credentials_rejected():
    async with provider_client(
        allow_dynamic_client_registration=True,
        allow_unauthenticated_client_registration=True,
    ) as client:
        res = await _register(
            client,
            redirect_uris=["https://app.example.com/cb"],
            grant_types=["authorization_code", "client_credentials"],
        )
        assert res.status_code == 400
        assert res.json()["error"] == "invalid_client_metadata"


def test_wire_schema_round_trip_and_extra_field_collapse():
    # register.ts:302/407 — unknown wire keys collapse into the metadata JSON column and are
    # spread back at the top level on read; the explicit metadata object merges in too.
    from better_auth.plugins_ext.oauth_provider.register import oauth_to_schema, schema_to_oauth

    schema = oauth_to_schema(
        {
            "client_id": "abc",
            "redirect_uris": ["https://app.example.com/cb"],
            "client_name": "My App",
            "scope": "openid email",
            "metadata": {"foo": "bar"},
            "custom_vendor_field": "vendor-value",
        }
    )
    assert isinstance(schema["metadata"], str)  # JSON-stringified on write
    assert schema["scopes"] == ["openid", "email"]
    wire = schema_to_oauth(schema)
    assert wire["client_name"] == "My App"
    assert wire["scope"] == "openid email"
    assert wire["foo"] == "bar"  # explicit metadata spread
    assert wire["custom_vendor_field"] == "vendor-value"  # unknown key collapsed + spread


async def test_dcr_strips_unknown_wire_fields():
    # matches TS zod body stripping: an unknown top-level field never reaches the response.
    async with provider_client(allow_dynamic_client_registration=True) as client:
        await sign_up(client)
        res = await _register(
            client,
            redirect_uris=["https://app.example.com/cb"],
            client_name="My App",
            custom_vendor_field="vendor-value",
        )
        assert res.status_code == 201, res.text
        body = res.json()
        assert body["client_name"] == "My App"
        assert "custom_vendor_field" not in body


# --- clientPrivileges gate (endpoints-privileges.test.ts) ----------------------------


async def test_unauthenticated_public_registration_does_not_invoke_gate():
    calls: list[str] = []

    def privileges(ctx):
        calls.append(ctx["action"])
        return True

    async with provider_client(
        allow_dynamic_client_registration=True,
        allow_unauthenticated_client_registration=True,
        client_privileges=privileges,
    ) as client:
        res = await _register(client, redirect_uris=["https://app.example.com/cb"])
        assert res.status_code == 201, res.text
        assert calls == []  # anonymous public registration skips the gate


async def test_privileges_gate_forbids_every_action():
    async with provider_client(client_privileges=lambda ctx: False) as client:
        await sign_up(client)
        create = await client.post(
            "/api/auth/oauth2/create-client", json={"redirect_uris": ["https://a.example.com/cb"]}
        )
        assert create.status_code == 401
        for path in ("/api/auth/oauth2/get-clients",):
            assert (await client.get(path)).status_code == 401


async def test_privileges_gate_allows_when_hook_true():
    seen: list[str] = []

    def privileges(ctx):
        seen.append(ctx["action"])
        return True

    async with provider_client(client_privileges=privileges) as client:
        await sign_up(client)
        res = await client.post(
            "/api/auth/oauth2/create-client", json={"redirect_uris": ["https://a.example.com/cb"]}
        )
        assert res.status_code == 201, res.text
        assert "create" in seen


# --- CRUD + ownership + immutability -------------------------------------------------


async def _create(client, **body):
    body.setdefault("redirect_uris", ["https://app.example.com/cb"])
    return await client.post("/api/auth/oauth2/create-client", json=body)


async def test_get_and_list_never_return_client_secret():
    async with provider_client() as client:
        await sign_up(client)
        created = (await _create(client)).json()
        cid = created["client_id"]

        got = await client.get(f"/api/auth/oauth2/get-client?client_id={cid}")
        assert got.status_code == 200, got.text
        assert "client_secret" not in got.json()

        listed = await client.get("/api/auth/oauth2/get-clients")
        assert listed.status_code == 200
        assert all("client_secret" not in c for c in listed.json())


async def test_cross_user_cannot_read_client():
    auth = provider_auth()
    async with make_client(auth) as owner:
        await sign_up(owner)
        cid = (await _create(owner)).json()["client_id"]
    async with make_client(auth) as other:
        await sign_up(other, email="mallory@example.com")
        got = await other.get(f"/api/auth/oauth2/get-client?client_id={cid}")
        assert got.status_code == 401


async def test_update_cannot_flip_public_or_change_secret():
    auth = provider_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        created = (await _create(client)).json()
        cid = created["client_id"]
        stored_before = (await auth.adapter.find_one("oauthClient", [Where("clientId", cid)]))[
            "clientSecret"
        ]
        res = await client.post(
            "/api/auth/oauth2/update-client",
            json={
                "client_id": cid,
                "update": {
                    "token_endpoint_auth_method": "none",  # immutable -> stripped
                    "client_secret": "attacker-secret",  # immutable -> stripped
                    "client_name": "Renamed",
                },
            },
        )
        assert res.status_code == 200, res.text
        body = res.json()
        assert body["client_name"] == "Renamed"
        assert body["public"] is False  # not flipped
        assert "client_secret" not in body
        stored_after = (await auth.adapter.find_one("oauthClient", [Where("clientId", cid)]))[
            "clientSecret"
        ]
        assert stored_after == stored_before  # secret unchanged


async def test_confidential_secret_hashed_at_rest():
    auth = provider_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        created = (await _create(client)).json()
        row = await auth.adapter.find_one("oauthClient", [Where("clientId", created["client_id"])])
        assert row["clientSecret"] != created["client_secret"]
        assert row["clientSecret"] == default_key_hasher(created["client_secret"])


async def test_rotate_returns_new_prefixed_secret():
    async with provider_client(prefix={"clientSecret": "sk_"}) as client:
        await sign_up(client)
        cid = (await _create(client)).json()["client_id"]
        res = await client.post("/api/auth/oauth2/client/rotate-secret", json={"client_id": cid})
        assert res.status_code == 200, res.text
        assert res.json()["client_secret"].startswith("sk_")


async def test_rotate_refuses_public_clients():
    async with provider_client() as client:
        await sign_up(client)
        created = (
            await _create(client, token_endpoint_auth_method="none", type="native")
        ).json()
        res = await client.post(
            "/api/auth/oauth2/client/rotate-secret", json={"client_id": created["client_id"]}
        )
        assert res.status_code == 400
        assert res.json()["error"] == "invalid_client"


async def test_trusted_clients_immutable_via_crud():
    async with provider_client(cached_trusted_clients={"trusted-1"}) as client:
        await sign_up(client)
        res = await client.post(
            "/api/auth/oauth2/update-client",
            json={"client_id": "trusted-1", "update": {"client_name": "x"}},
        )
        assert res.status_code == 500
        assert res.json()["error"] == "invalid_client"


# --- discovery metadata (metadata.test.ts) via direct auth.handle --------------------


def discovery_auth(**kwargs):
    # loopback base_url so validateIssuerUrl keeps the issuer as-is (no HTTP->HTTPS upgrade)
    return make_auth(
        base_url="http://localhost:3000",
        plugins=[JWTPlugin(), OAuthProviderPlugin(**kwargs)],
    )


BASE = "http://localhost:3000/api/auth"


async def test_auth_server_metadata_field_exact():
    auth = discovery_auth(allow_dynamic_client_registration=True)
    res = await auth.handle(
        AuthRequest(method="GET", path="/.well-known/oauth-authorization-server")
    )
    assert res.status == 200
    body = res.body
    assert body["issuer"] == BASE
    assert body["authorization_endpoint"] == f"{BASE}/oauth2/authorize"
    assert body["token_endpoint"] == f"{BASE}/oauth2/token"
    assert body["jwks_uri"] == f"{BASE}/jwks"
    assert body["registration_endpoint"] == f"{BASE}/oauth2/register"
    assert body["introspection_endpoint"] == f"{BASE}/oauth2/introspect"
    assert body["revocation_endpoint"] == f"{BASE}/oauth2/revoke"
    assert body["response_types_supported"] == ["code"]
    assert body["code_challenge_methods_supported"] == ["S256"]
    assert body["authorization_response_iss_parameter_supported"] is True


async def test_metadata_served_at_both_well_known_aliases():
    auth = discovery_auth()
    appended = await auth.handle(
        AuthRequest(method="GET", path="/.well-known/oauth-authorization-server")
    )
    insertion = await auth.handle(
        AuthRequest(method="GET", path="/.well-known/oauth-authorization-server/api/auth")
    )
    assert appended.status == 200
    assert insertion.status == 200
    assert appended.body["issuer"] == insertion.body["issuer"] == BASE


async def test_metadata_cache_headers():
    auth = discovery_auth()
    res = await auth.handle(
        AuthRequest(method="GET", path="/.well-known/oauth-authorization-server")
    )
    headers = dict(res.headers)
    assert headers["Cache-Control"] == (
        "public, max-age=15, stale-while-revalidate=15, stale-if-error=86400"
    )


async def test_metadata_restricted_to_get_and_head():
    auth = discovery_auth()
    post = await auth.handle(
        AuthRequest(method="POST", path="/.well-known/oauth-authorization-server")
    )
    assert post.status == 405
    assert dict(post.headers)["Allow"] == "GET, HEAD"
    head = await auth.handle(
        AuthRequest(method="HEAD", path="/.well-known/oauth-authorization-server")
    )
    assert head.status == 200
    assert head.body is None


async def test_openid_configuration_served_when_openid_scope():
    auth = discovery_auth()
    res = await auth.handle(AuthRequest(method="GET", path="/.well-known/openid-configuration"))
    assert res.status == 200
    assert res.body["userinfo_endpoint"] == f"{BASE}/oauth2/userinfo"
    assert res.body["id_token_signing_alg_values_supported"] == ["EdDSA"]


async def test_openid_configuration_advertises_configured_key_pair_alg():
    # TS metadata.ts:99-104 — [keyPairConfig.alg] when configured.
    auth = make_auth(
        base_url="http://localhost:3000",
        plugins=[JWTPlugin(key_pair_config={"alg": "ES256"}), OAuthProviderPlugin()],
    )
    res = await auth.handle(AuthRequest(method="GET", path="/.well-known/openid-configuration"))
    assert res.body["id_token_signing_alg_values_supported"] == ["ES256"]


async def test_no_openid_configuration_without_openid_scope():
    auth = discovery_auth(scopes=["profile", "email"])
    res = await auth.handle(AuthRequest(method="GET", path="/.well-known/openid-configuration"))
    assert res.status == 404


async def test_advertised_metadata_overrides_scopes_supported():
    auth = discovery_auth(advertised_metadata={"scopes_supported": ["openid", "email"]})
    res = await auth.handle(
        AuthRequest(method="GET", path="/.well-known/oauth-authorization-server")
    )
    assert res.body["scopes_supported"] == ["openid", "email"]


async def test_advertised_metadata_overrides_claims_supported():
    auth = discovery_auth(advertised_metadata={"claims_supported": ["sub", "email"]})
    res = await auth.handle(AuthRequest(method="GET", path="/.well-known/openid-configuration"))
    assert res.body["claims_supported"] == ["sub", "email"]


async def test_jwks_uri_reflects_remote_url():
    auth = make_auth(
        base_url="http://localhost:3000",
        plugins=[
            JWTPlugin(remote_url="https://keys.example.com/jwks", key_pair_config={"alg": "EdDSA"}),
            OAuthProviderPlugin(),
        ],
    )
    res = await auth.handle(
        AuthRequest(method="GET", path="/.well-known/oauth-authorization-server")
    )
    assert res.body["jwks_uri"] == "https://keys.example.com/jwks"


# --- admin SERVER_ONLY create (metadata round-trip + extra-field strip) --------------


async def test_admin_create_client_metadata_round_trip_strips_unknown():
    import json as _json

    from better_auth.types import AuthRequest as _AuthRequest
    from better_auth.types import Ctx as _Ctx

    auth = provider_auth()
    plugin = next(p for p in auth.plugins if p.id == "oauth-provider")
    async with make_client(auth) as client:
        await sign_up(client)
        cookie = "; ".join(f"{k}={v}" for k, v in client.cookies.items())

    body = {
        "redirect_uris": ["https://app.example.com/cb"],
        "metadata": {"from_metadata": "value1"},
        "skip_consent": True,  # SERVER_ONLY, admin-allowed
        "custom_field": "value2",  # unknown -> stripped
    }
    request = _AuthRequest(
        method="POST",
        path="/admin/oauth2/create-client",
        headers={"cookie": cookie, "origin": "http://testserver"},
        body=_json.dumps(body).encode(),
    )
    ctx = _Ctx(auth=auth, request=request)
    response = await plugin.admin_create_client(ctx)
    assert response.status == 201, response.body
    assert response.body["from_metadata"] == "value1"
    assert "custom_field" not in response.body
    row = await auth.adapter.find_one(
        "oauthClient", [Where("clientId", response.body["client_id"])]
    )
    assert row["skipConsent"] is True
