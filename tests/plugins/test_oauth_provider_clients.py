"""oauth-provider 1.7 client model: dynamic registration, protected registration, redirect
policy, key metadata, resources and client CRUD.

Anchored to TS ``packages/oauth-provider/src/register.ts``, ``register.test.ts``,
``oauthClient/endpoints.ts`` and ``schema.ts`` at v1.7.6.
"""

from __future__ import annotations

import json

import pytest

from better_auth.adapters.base import Where
from better_auth.plugins_ext.jwt import JWTPlugin
from better_auth.plugins_ext.oauth_provider import OAuthProviderPlugin
from better_auth.types import AuthRequest, Ctx
from conftest import make_auth, make_client, sign_up

RP = "https://rp.example.com/api/auth/callback/test"
RESOURCE = "https://api.example.com/dcr"
RSA_KEY = {"kty": "RSA", "kid": "client-key", "n": "test", "e": "test-exponent"}


def provider_auth(*, jwt: bool = True, **kwargs):
    kwargs.setdefault("allow_dynamic_client_registration", True)
    plugins = [JWTPlugin()] if jwt else []
    extra = {k: kwargs.pop(k) for k in ("trusted_origins",) if k in kwargs}
    return make_auth(plugins=[*plugins, OAuthProviderPlugin(**kwargs)], **extra)


async def register(client, headers=None, **body):
    return await client.post("/api/auth/oauth2/register", json=body, headers=headers or {})


async def row(auth, client_id):
    return await auth.adapter.find_one("oauthClient", [Where("clientId", client_id)])


# --- schema (schema.ts) ---------------------------------------------------------------


def test_oauth_client_model_matches_ts_columns():
    fields = provider_auth().schema["oauthClient"]
    for name in (
        "clientDiscoveryId",
        "backchannelLogoutUri",
        "applicationType",
        "jwks",
        "jwksUri",
        "clientCredentialsScopes",
    ):
        assert fields[name].required is False
    assert fields["backchannelLogoutSessionRequired"].type == "boolean"
    assert fields["dpopBoundAccessTokens"].default is False
    assert "public" not in fields
    assert "type" not in fields


# --- DCR scope policy (register.ts:52, 826) ---------------------------------------------


async def test_dcr_persists_the_operator_scope_set_not_the_request():
    auth = provider_auth(scopes=["openid", "profile", "email", "offline_access", "create:test"])
    async with make_client(auth) as client:
        await sign_up(client)
        res = await register(client, redirect_uris=[RP], scope="openid")
        assert res.status_code == 201, res.text
        body = res.json()
        assert body["scope"] == "openid profile email offline_access create:test"
        assert (await row(auth, body["client_id"]))["scopes"] == body["scope"].split(" ")
        assert body["application_type"] == "web"
        assert res.headers["cache-control"] == "no-store"


async def test_dcr_scope_policy_is_the_default_and_allowed_union():
    auth = provider_auth(
        allow_unauthenticated_client_registration=True,
        scopes=["openid", "read", "write", "admin"],
        client_registration_default_scopes=["openid", "read", "read"],
        client_registration_allowed_scopes=["write", "read"],
    )
    async with make_client(auth) as client:
        ok = await register(
            client, redirect_uris=[RP], token_endpoint_auth_method="none", scope="read"
        )
        assert ok.status_code == 201, ok.text
        assert ok.json()["scope"] == "openid read write"
        bad = await register(
            client, redirect_uris=[RP], token_endpoint_auth_method="none", scope="admin"
        )
        assert bad.status_code == 400
        assert bad.json()["error"] == "invalid_scope"


async def test_public_dcr_client_defaults_to_web_without_legacy_columns():
    auth = provider_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        res = await register(
            client,
            redirect_uris=["https://client.example.com/cb"],
            token_endpoint_auth_method="none",
        )
        body = res.json()
        assert body["application_type"] == "web"
        assert "client_secret" not in body
        stored = await row(auth, body["client_id"])
        assert stored["applicationType"] == "web"
        assert stored["tokenEndpointAuthMethod"] == "none"


async def test_dcr_rejects_skip_consent_and_unsupported_grants():
    auth = provider_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        skip = await register(client, redirect_uris=[RP], skip_consent=True)
        assert skip.status_code == 400
        assert skip.json() == {
            "error": "invalid_client_metadata",
            "error_description": "skip_consent must be a never",
        }
        grant = await register(
            client,
            redirect_uris=[RP],
            grant_types=["authorization_code", "urn:ietf:params:oauth:grant-type:jwt-bearer"],
        )
        assert grant.json()["error_description"] == (
            "unsupported grant_type urn:ietf:params:oauth:grant-type:jwt-bearer"
        )
        empty = await register(client, redirect_uris=[RP], grant_types=[])
        assert empty.json()["error"] == "invalid_client_metadata"


async def test_client_secret_expiration_number_is_an_absolute_exp():
    # toExpJWT: a number is the exp claim itself (register.ts:846).
    auth = provider_auth(client_registration_client_secret_expiration=4102444800)
    async with make_client(auth) as client:
        await sign_up(client)
        body = (await register(client, redirect_uris=[RP])).json()
        assert body["client_secret_expires_at"] == 4102444800


# --- confidential DCR without PKCE (a8200b297) ------------------------------------------


async def test_confidential_dcr_clients_can_opt_out_of_pkce():
    auth = provider_auth(
        allow_unauthenticated_client_registration=True, client_registration_require_pkce=False
    )
    async with make_client(auth) as client:
        confidential = (await register(client, redirect_uris=[RP])).json()
        public = (
            await register(client, redirect_uris=[RP], token_endpoint_auth_method="none")
        ).json()
        assert confidential["require_pkce"] is False
        assert "require_pkce" not in public
        assert (await row(auth, public["client_id"])).get("requirePKCE") is None


# --- redirect URI policy (register.ts:170) ----------------------------------------------


@pytest.mark.parametrize(
    ("application_type", "uri", "ok"),
    [
        ("web", "https://rp.example.com/cb", True),
        ("web", "http://rp.example.com/cb", False),
        ("web", "http://localhost:3000/cb", False),
        ("web", "https://127.0.0.1/cb", False),
        ("native", "http://localhost:3000/cb", True),
        ("native", "http://127.0.0.1/cb", True),
        ("native", "http://[::1]:8080/cb", True),
        ("native", "com.example.app:/oauth", True),
        ("native", "http://rp.example.com/cb", False),
        ("native", "http://127.1/cb", False),
        ("native", "https://localhost/cb", False),
        ("native", "myapp://callback", False),
    ],
)
async def test_redirect_uri_policy_follows_application_type(application_type, uri, ok):
    auth = provider_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        res = await register(client, redirect_uris=[uri], application_type=application_type)
        if ok:
            assert res.status_code == 201, res.text
        else:
            assert res.status_code == 400
            assert res.json()["error"] == "invalid_redirect_uri"


# --- client key metadata (1f8b0282d) ----------------------------------------------------


async def test_inline_jwks_round_trips_with_a_secret_based_method():
    auth = provider_auth(allow_unauthenticated_client_registration=True)
    async with make_client(auth) as client:
        res = await register(
            client,
            redirect_uris=[RP],
            token_endpoint_auth_method="client_secret_basic",
            jwks={"keys": [RSA_KEY]},
        )
        body = res.json()
        assert body["jwks"] == {"keys": [RSA_KEY]}
        assert body["client_secret"]
        assert json.loads((await row(auth, body["client_id"]))["jwks"]) == {"keys": [RSA_KEY]}


@pytest.mark.parametrize(
    ("extra", "description"),
    [
        ({"jwks": [RSA_KEY]}, "jwks must be a object"),
        ({"jwks": {"keys": []}}, "jwks.keys: Too small: expected array to have >=1 items"),
        (
            {"jwks": {"keys": [{**RSA_KEY, "d": "private"}]}},
            "jwks must contain only public asymmetric keys",
        ),
        (
            {"jwks": {"keys": [RSA_KEY]}, "jwks_uri": "https://keys.example.com/jwks"},
            "jwks and jwks_uri are mutually exclusive",
        ),
        ({"jwks_uri": "http://keys.example.com/jwks"}, "jwks_uri must use HTTPS"),
        (
            {"jwks_uri": "https://user:pw@keys.example.com/jwks"},
            "jwks_uri must not contain credentials",
        ),
        (
            {"jwks_uri": "https://keys.example.com/jwks#"},
            "jwks_uri must not include a fragment component",
        ),
        (
            {"jwks_uri": "https://10.0.0.1/jwks"},
            "jwks_uri must not point to a private or reserved address",
        ),
        (
            {"jwks_uri": "https://untrusted.example.org/jwks"},
            "jwks_uri must belong to a trusted origin or the Client ID Metadata Document origin",
        ),
        (
            {"token_endpoint_auth_method": "private_key_jwt"},
            "private_key_jwt requires either jwks or jwks_uri",
        ),
    ],
)
async def test_key_metadata_is_validated(extra, description):
    auth = provider_auth(trusted_origins=["https://keys.example.com"])
    async with make_client(auth) as client:
        await sign_up(client)
        res = await register(client, redirect_uris=[RP], **extra)
        assert res.status_code == 400
        assert res.json() == {"error": "invalid_client_metadata", "error_description": description}


async def test_private_key_jwt_client_with_trusted_jwks_uri_gets_no_secret():
    auth = provider_auth(trusted_origins=["https://keys.example.com"])
    async with make_client(auth) as client:
        await sign_up(client)
        res = await register(
            client,
            redirect_uris=[RP],
            token_endpoint_auth_method="private_key_jwt",
            jwks_uri="https://keys.example.com/jwks",
        )
        assert res.status_code == 201, res.text
        body = res.json()
        assert "client_secret" not in body
        assert body["jwks_uri"] == "https://keys.example.com/jwks"


# --- back-channel logout registration (register.ts:620) ---------------------------------


async def test_backchannel_logout_uri_round_trips():
    auth = provider_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        uri = "https://rp.example.com/logout/backchannel"
        body = (
            await register(
                client,
                redirect_uris=[RP],
                backchannel_logout_uri=uri,
                backchannel_logout_session_required=True,
            )
        ).json()
        assert body["backchannel_logout_uri"] == uri
        assert body["backchannel_logout_session_required"] is True
        stored = await row(auth, body["client_id"])
        assert stored["backchannelLogoutUri"] == uri


@pytest.mark.parametrize(
    "uri",
    [
        "https://rp.example.com/logout#section",
        "https://rp.example.com/logout#",
        "http://rp.example.com/logout",
        "https://user:password@rp.example.com/logout",
        "https://10.0.0.1/logout",
        "https://169.254.169.254/logout",
        "https://[::ffff:169.254.169.254]/logout",
        "https://[64:ff9b::a9fe:a9fe]/logout",
        "https://100.64.0.1/logout",
        "https://metadata.google.internal/logout",
    ],
)
async def test_backchannel_logout_uri_rejects_unsafe_targets(uri):
    auth = provider_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        res = await register(client, redirect_uris=[RP], backchannel_logout_uri=uri)
        assert res.status_code == 400


async def test_backchannel_logout_uri_requires_the_jwt_plugin():
    auth = provider_auth(jwt=False, disable_jwt_plugin=True)
    async with make_client(auth) as client:
        await sign_up(client)
        res = await register(
            client, redirect_uris=[RP], backchannel_logout_uri="https://rp.example.com/logout"
        )
        assert res.json() == {
            "error": "invalid_client_metadata",
            "error_description": (
                "backchannel_logout_uri requires the jwt plugin (disableJwtPlugin must be false)"
            ),
        }


# --- registration resources (register.ts:127) -------------------------------------------


async def test_dcr_links_requested_resources_once():
    auth = provider_auth(resources=[RESOURCE], client_registration_allowed_resources=[RESOURCE])
    async with make_client(auth) as client:
        await sign_up(client)
        res = await register(client, redirect_uris=[RP], resources=[RESOURCE, RESOURCE])
        assert res.status_code == 201, res.text
        body = res.json()
        assert body["resources"] == [RESOURCE]
        links = await auth.adapter.find_many(
            "oauthClientResource", [Where("clientId", body["client_id"])]
        )
        assert len(links) == 1


async def test_dcr_links_default_resources_without_a_request():
    auth = provider_auth(resources=[RESOURCE], client_registration_default_resources=[RESOURCE])
    async with make_client(auth) as client:
        await sign_up(client)
        assert (await register(client, redirect_uris=[RP])).json()["resources"] == [RESOURCE]


async def test_dcr_resource_errors_are_invalid_target():
    auth = provider_auth(resources=[RESOURCE])
    async with make_client(auth) as client:
        await sign_up(client)
        malformed = await register(client, redirect_uris=[RP], resources=["not-a-uri"])
        assert malformed.json()["error"] == "invalid_target"
        refused = await register(client, redirect_uris=[RP], resources=[RESOURCE])
        assert refused.json() == {
            "error": "invalid_target",
            "error_description": (
                f"requested resource {RESOURCE} is not allowed for client registration"
            ),
        }


def test_registration_resources_must_be_configured():
    with pytest.raises(ValueError, match="clientRegistrationDefaultResources resource"):
        OAuthProviderPlugin(client_registration_default_resources=[RESOURCE])


# --- protected DCR (0143d6919, initial-access-token.ts) ---------------------------------

TOKEN = "valid-initial-registration-token"


def validator(calls):
    def validate(context):
        calls.append(context)
        if context["initialAccessToken"] == TOKEN:
            return {"referenceId": "infra-provisioner"}
        return False

    return validate


async def test_initial_access_token_registers_an_owned_confidential_client():
    calls: list = []
    auth = provider_auth(validate_initial_access_token=validator(calls))
    async with make_client(auth) as client:
        res = await register(
            client,
            {"authorization": f"Bearer {TOKEN}"},
            client_name="Machine Client",
            grant_types=["client_credentials"],
        )
        assert res.status_code == 201, res.text
        assert res.headers["cache-control"] == "no-store"
        body = res.json()
        assert body["reference_id"] == "infra-provisioner"
        assert "user_id" not in body
        assert body["redirect_uris"] == []
        assert body["client_secret"]
        assert calls[0]["clientMetadata"]["client_name"] == "Machine Client"
        assert (await row(auth, body["client_id"]))["clientCredentialsScopes"] == []


@pytest.mark.parametrize(
    ("authorization", "configured", "status", "challenge"),
    [
        ("Bearer wrong", True, 401, 'Bearer error="invalid_token"'),
        ("Bearer", True, 400, 'Bearer error="invalid_request"'),
        (f"Bearer {TOKEN}", False, 401, 'Bearer error="invalid_token"'),
    ],
)
async def test_initial_access_token_failures_fail_closed(
    authorization, configured, status, challenge
):
    options = {"validate_initial_access_token": validator([])} if configured else {}
    auth = provider_auth(**options)
    async with make_client(auth) as client:
        res = await register(client, {"authorization": authorization}, redirect_uris=[RP])
        assert res.status_code == status
        assert res.headers["www-authenticate"] == challenge
        assert res.headers["cache-control"] == "no-store"
        assert res.headers["pragma"] == "no-cache"
        assert res.json()["error"] == challenge.split('"')[1]


async def test_no_credentials_get_a_bare_bearer_challenge():
    auth = provider_auth(validate_initial_access_token=validator([]))
    async with make_client(auth) as client:
        res = await register(client, redirect_uris=[RP])
        assert res.status_code == 401
        assert res.headers["www-authenticate"] == "Bearer"
        assert res.json() == {
            "error_description": "Authentication required for client registration"
        }


async def test_validator_errors_are_contained():
    def boom(_context):
        raise RuntimeError("validator failure")

    auth = provider_auth(validate_initial_access_token=boom)
    async with make_client(auth) as client:
        res = await register(client, {"authorization": f"Bearer {TOKEN}"}, redirect_uris=[RP])
        assert res.status_code == 500
        assert res.json() == {
            "error": "server_error",
            "error_description": "Initial access token validation failed",
        }


async def test_validator_may_create_an_unowned_client():
    auth = provider_auth(validate_initial_access_token=lambda _c: {})
    async with make_client(auth) as client:
        res = await register(
            client, {"authorization": f"Bearer {TOKEN}"}, grant_types=["client_credentials"]
        )
        body = res.json()
        assert "reference_id" not in body
        assert "user_id" not in body


async def test_session_registration_does_not_consult_the_validator():
    calls: list = []
    auth = provider_auth(validate_initial_access_token=validator(calls))
    async with make_client(auth) as client:
        await sign_up(client)
        res = await register(client, redirect_uris=[RP])
        assert res.status_code == 201
        assert calls == []
        assert res.json()["user_id"]


async def test_authorization_code_registration_needs_redirect_uris():
    auth = provider_auth(validate_initial_access_token=validator([]))
    async with make_client(auth) as client:
        res = await register(
            client, {"authorization": f"Bearer {TOKEN}"}, grant_types=["authorization_code"]
        )
        assert res.json()["error"] == "invalid_redirect_uri"


# --- client CRUD (oauthClient/endpoints.ts) ---------------------------------------------


async def admin_ctx(auth, client, body, path="/admin/oauth2/create-client"):
    cookie = "; ".join(f"{k}={v}" for k, v in client.cookies.items())
    request = AuthRequest(
        method="POST",
        path=path,
        headers={"cookie": cookie, "origin": "http://testserver"},
        body=json.dumps(body).encode(),
    )
    return Ctx(auth=auth, request=request)


def plugin_of(auth) -> OAuthProviderPlugin:
    return next(p for p in auth.plugins if isinstance(p, OAuthProviderPlugin))


async def test_create_client_responses_are_not_cached():
    auth = provider_auth(allow_dynamic_client_registration=False)
    async with make_client(auth) as client:
        await sign_up(client)
        created = await client.post("/api/auth/oauth2/create-client", json={"redirect_uris": [RP]})
        assert created.status_code == 201
        assert created.headers["cache-control"] == "no-store"
        rotated = await client.post(
            "/api/auth/oauth2/client/rotate-secret", json={"client_id": created.json()["client_id"]}
        )
        assert rotated.headers["cache-control"] == "no-store"
        assert rotated.headers["pragma"] == "no-cache"


async def test_admin_client_credentials_scopes_need_the_privilege_hook():
    auth = provider_auth(scopes=["openid", "admin"])
    async with make_client(auth) as client:
        await sign_up(client)
        body = {
            "grant_types": ["client_credentials"],
            "client_credentials_scopes": ["admin"],
        }
        with pytest.raises(Exception, match="Not authorized"):
            await plugin_of(auth).admin_create_client(await admin_ctx(auth, client, body))


async def test_admin_create_and_update_client_credentials_scopes():
    seen: list[str] = []

    def privileges(context):
        seen.append(context["action"])
        return True

    auth = provider_auth(scopes=["openid", "admin", "audit"], client_privileges=privileges)
    async with make_client(auth) as client:
        await sign_up(client)
        body = {
            "grant_types": ["client_credentials"],
            "client_credentials_scopes": [" admin ", "admin"],
        }
        created = await plugin_of(auth).admin_create_client(await admin_ctx(auth, client, body))
        assert created.status == 201, created.body
        assert created.body["client_credentials_scopes"] == ["admin"]
        assert "configure-client-credentials-scopes" in seen
        client_id = created.body["client_id"]

        bad = await plugin_of(auth).admin_create_client(
            await admin_ctx(auth, client, {**body, "client_credentials_scopes": ["openid"]})
        )
        assert bad.body == {
            "error": "invalid_scope",
            "error_description": "The following client_credentials scopes are invalid: openid",
        }

        update = {"client_id": client_id, "update": {"client_credentials_scopes": ["audit"]}}
        updated = await plugin_of(auth).admin_update_client(
            await admin_ctx(auth, client, update, "/admin/oauth2/update-client")
        )
        assert isinstance(updated, dict)
        assert dict(updated)["client_credentials_scopes"] == ["audit"]
        assert (await row(auth, client_id))["clientCredentialsScopes"] == ["audit"]


async def test_update_applies_the_redirect_policy_of_the_new_application_type():
    auth = provider_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        created = (
            await client.post("/api/auth/oauth2/create-client", json={"redirect_uris": [RP]})
        ).json()
        loopback = {"redirect_uris": ["http://127.0.0.1:8080/cb"]}
        rejected = await client.post(
            "/api/auth/oauth2/update-client",
            json={"client_id": created["client_id"], "update": loopback},
        )
        assert rejected.json()["error"] == "invalid_redirect_uri"
        accepted = await client.post(
            "/api/auth/oauth2/update-client",
            json={
                "client_id": created["client_id"],
                "update": {**loopback, "application_type": "native"},
            },
        )
        assert accepted.status_code == 200, accepted.text
        assert accepted.json()["application_type"] == "native"


async def test_rotation_is_refused_for_clients_without_a_secret():
    auth = provider_auth(trusted_origins=["https://keys.example.com"])
    async with make_client(auth) as client:
        await sign_up(client)
        created = (
            await client.post(
                "/api/auth/oauth2/create-client",
                json={
                    "redirect_uris": [RP],
                    "token_endpoint_auth_method": "private_key_jwt",
                    "jwks_uri": "https://keys.example.com/jwks",
                },
            )
        ).json()
        res = await client.post(
            "/api/auth/oauth2/client/rotate-secret", json={"client_id": created["client_id"]}
        )
        assert res.status_code == 400
        assert res.json() == {
            "error": "invalid_client",
            "error_description": (
                "secret rotation is only available for clients using client_secret authentication"
            ),
        }


async def test_registration_errors_are_not_cached():
    # core api/index.ts:107: noStore endpoints attach the headers to thrown errors too.
    auth = provider_auth()
    async with make_client(auth) as client:
        await sign_up(client)
        res = await register(client, redirect_uris=["http://rp.example.com/cb"])
        assert res.status_code == 400
        assert res.headers["cache-control"] == "no-store"
        assert res.headers["pragma"] == "no-cache"
