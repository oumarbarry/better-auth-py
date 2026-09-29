"""RFC 8628 device authorization grant for the OAuth provider.

Port of TS ``packages/oauth-provider/src/device-code.ts`` at v1.7.6 (f68044dcf, 6782647d7,
3ca2c08dc). :class:`OAuthDeviceAuthorizationPlugin` is the device-authorization plugin with an
OAuth grant: registered OAuth clients request codes at ``/device/code`` (authenticated like at
the token endpoint), and redeem an approved code at ``/oauth2/token`` with
``grant_type=urn:ietf:params:oauth:grant-type:device_code`` for a real OAuth token set.
Codes minted for an OAuth client carry ``oauthClientId`` and ``resources`` and are refused at
the first-party ``/device/token``; other client ids stay in the session flow.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from ...adapters.base import Where
from ...schema import Field, Schema
from ...types import Ctx
from ..device_authorization import (
    DEVICE_AUTHORIZATION_SCHEMA,
    DeviceAuthorizationError,
    DeviceAuthorizationGrant,
    DeviceAuthorizationPlugin,
    redeem_device_code,
)
from .client_crud import get_client
from .resources import (
    extract_repeated_resource_from_form,
    resolve_resource_policy,
    resource_uri_issue,
    to_audience_claim,
    to_resource_list,
)
from .token import authenticate_client, create_user_tokens, validate_client_credentials
from .utils import OAuthError, normalize_client_authentication_parameters

if TYPE_CHECKING:
    from ...auth import BetterAuth

DEVICE_CODE_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"
#: The device authorization endpoint advertised in discovery (device-code.ts:46).
DEVICE_AUTHORIZATION_PATH = "/device/code"
_CLIENT_AUTHENTICATION_FIELDS = ("client_secret", "client_assertion", "client_assertion_type")


def _parse_scopes(scope: Any) -> list[str]:
    return scope.split() if isinstance(scope, str) and scope.strip() else []


def _invalid_resource(value: Any) -> bool:
    """TS ``deviceCodeResourceSchema``: a resource URI, a non-empty list of them, or ``""``."""
    if value == "":
        return False
    if isinstance(value, list):
        return not value or any(not isinstance(v, str) or resource_uri_issue(v) for v in value)
    return not isinstance(value, str) or resource_uri_issue(value) is not None


async def _authenticate(
    ctx: Ctx, opts: Any, body: dict[str, Any], endpoint: str, scopes: list[str] | None
) -> dict[str, Any]:
    """``provider.authenticateClient({requireCredentials: false})`` bound to the device grant
    (token.ts:150): public clients pass with their id, confidential ones must prove it."""
    creds = await authenticate_client(ctx, opts, body, endpoint)
    if not creds["client_id"]:
        raise OAuthError(400, "invalid_request", "Missing required client_id")
    return await validate_client_credentials(
        ctx,
        opts,
        creds["client_id"],
        creds["client_secret"],
        scopes,
        DEVICE_CODE_GRANT_TYPE,
        pre_verified=creds["pre_verified"],
        auth_method=creds["auth_method"],
    )


def _provider(auth: BetterAuth) -> Any:
    return next((p for p in auth.plugins if p.id == "oauth-provider"), None)


async def _authorize_request(ctx: Ctx, request: dict[str, Any]) -> dict[str, Any] | None:
    try:
        return await _authorize_oauth_request(ctx, request)
    except OAuthError as error:
        raise DeviceAuthorizationError(
            error.status, error.error, error.description, error.headers
        ) from None


async def _authorize_oauth_request(ctx: Ctx, request: dict[str, Any]) -> dict[str, Any] | None:
    """TS ``authorizeRequest`` (device-code.ts:253): bind the code to the authenticated OAuth
    client and its resources, or leave an unknown, unauthenticated id to the session flow."""
    for name in _CLIENT_AUTHENTICATION_FIELDS:
        if request.get(name) is not None and not isinstance(request[name], str):
            raise OAuthError(400, "invalid_request", f"{name} must be a string")
    if "resource" in request and _invalid_resource(request["resource"]):
        raise OAuthError(400, "invalid_target", "Invalid resource indicator")
    has_authentication = normalize_client_authentication_parameters(ctx, request)
    form_resources = extract_repeated_resource_from_form(ctx)
    if form_resources:
        value: Any = form_resources[0] if len(form_resources) == 1 else form_resources
        if _invalid_resource(value):
            raise OAuthError(400, "invalid_target", "Invalid resource indicator")
        request["resource"] = value
    provider = _provider(ctx.auth)
    if provider is None:
        return None
    scopes = _parse_scopes(request.get("scope"))
    if request.get("scope") is not None:
        request["scope"] = " ".join(scopes)
    resource = None if request.get("resource") == "" else request.get("resource")
    client_id = request.get("client_id")
    if not client_id and not has_authentication:
        raise OAuthError(400, "invalid_request", "client_id is required")
    known = await get_client(ctx, provider, client_id) if client_id else None
    # Unknown ids stay in the standalone session flow unless OAuth credentials were sent.
    if client_id and not known and not has_authentication:
        return None
    client = await _authenticate(ctx, provider, request, DEVICE_AUTHORIZATION_PATH, scopes)
    if client_id and client["clientId"] != client_id:
        raise OAuthError(400, "invalid_client", "Client ID mismatch")
    await resolve_resource_policy(
        ctx, provider, resource=resource, client_id=client["clientId"], requested_scopes=scopes
    )
    return {
        "clientId": client["clientId"],
        "deviceCodeFields": {
            "oauthClientId": client["clientId"],
            "resources": to_resource_list(resource),
        },
    }


def _assert_session_redemption(_ctx: Ctx, record: dict[str, Any]) -> None:
    if isinstance(record.get("oauthClientId"), str):
        raise DeviceAuthorizationError(
            400,
            "invalid_grant",
            "This device code must be exchanged at the OAuth token endpoint (/oauth2/token).",
        )


def _verification_context(record: dict[str, Any]) -> dict[str, Any] | None:
    resources = record.get("resources")
    if not isinstance(record.get("oauthClientId"), str) or not isinstance(resources, list):
        return None
    if not all(isinstance(r, str) for r in resources):
        return None
    return {"resource": to_audience_claim(resources)}


async def exchange_device_code(ctx: Ctx, opts: Any, body: dict[str, Any]) -> Any:
    """The token endpoint handler for the device grant, TS ``exchangeOAuthDeviceCode``
    (device-code.ts:106): the shared redemption state machine, then provider issuance."""
    device_code = body.get("device_code")
    if not device_code:
        raise OAuthError(400, "invalid_request", "device_code is required")

    async def authorize(record: dict[str, Any]) -> tuple[Where, Any]:
        if not record.get("oauthClientId"):
            raise OAuthError(400, "invalid_grant", "invalid device code")
        # Mismatched body credentials fail before scope validation, so a stolen code cannot
        # disclose the scopes recorded for another client.
        if body.get("client_id") and record["oauthClientId"] != body["client_id"]:
            raise OAuthError(400, "invalid_grant", "Client ID mismatch")
        scopes = _parse_scopes(record.get("scope"))
        client = await _authenticate(ctx, opts, body, "/oauth2/token", None)
        if record["oauthClientId"] != client["clientId"]:
            raise OAuthError(400, "invalid_grant", "Client ID mismatch")
        if client.get("scopes"):
            allowed = set(client["scopes"])
            for scope in scopes:
                if scope not in allowed:
                    raise OAuthError(400, "invalid_scope", f"client does not allow scope {scope}")
        return Where("oauthClientId", client["clientId"]), {"client": client, "scopes": scopes}

    async def prepare(record: dict[str, Any], context: dict[str, Any]) -> list[str] | None:
        requested = to_resource_list(body.get("resource"))
        bound = record.get("resources")
        if requested and (not bound or any(r not in bound for r in requested)):
            raise OAuthError(
                400, "invalid_target", "Requested resource was not authorized by the user"
            )
        resources = requested or bound
        # Validate before the atomic claim so an invalid target keeps the one-time code.
        await resolve_resource_policy(
            ctx,
            opts,
            resource=resources,
            client_id=context["client"]["clientId"],
            requested_scopes=context["scopes"],
        )
        return resources

    try:
        result = await redeem_device_code(ctx, device_code, authorize, prepare)
    except DeviceAuthorizationError as error:
        raise OAuthError(error.status, error.error, error.description) from None
    return await create_user_tokens(
        ctx,
        opts,
        client=result["context"]["client"],
        scopes=result["context"]["scopes"],
        grant_type=DEVICE_CODE_GRANT_TYPE,
        user=result["user"],
        resources=result["redemption"],
    )


class OAuthDeviceAuthorizationPlugin(DeviceAuthorizationPlugin):
    """TS ``oauthDeviceAuthorization()`` (device-code.ts:380): pair with
    :class:`OAuthProviderPlugin`; first-party device login keeps using
    :class:`DeviceAuthorizationPlugin` and ``/device/token``. Takes the same options."""

    #: OAuth-owned columns, added only in composed installations (device-code.ts:241).
    schema: ClassVar[Schema] = {
        "deviceCode": {
            **DEVICE_AUTHORIZATION_SCHEMA["deviceCode"],
            "resources": Field("string[]", required=False),
            "oauthClientId": Field("string", required=False),
        }
    }

    def __init__(self, **options: Any) -> None:
        grant = DeviceAuthorizationGrant(
            request_fields=(*_CLIENT_AUTHENTICATION_FIELDS, "resource"),
            authorize_request=_authorize_request,
            assert_session_redemption=_assert_session_redemption,
            get_verification_context=_verification_context,
        )
        super().__init__(**options, grant=grant)

    def init(self, auth: BetterAuth) -> None:
        # TS device-code.test.ts:53, 72 pin these messages against the TS factory names
        # (oauthDeviceAuthorization(), oauthProvider()); this port is a plain error, not
        # part of the OAuth wire envelope, so it names the Python plugin classes instead.
        if sum(1 for p in auth.plugins if p.id == "device-authorization") > 1:
            raise ValueError(
                "OAuthDeviceAuthorizationPlugin cannot be combined with another Device "
                "Authorization plugin."
            )
        provider = _provider(auth)
        if provider is None:
            raise ValueError("OAuthDeviceAuthorizationPlugin requires OAuthProviderPlugin.")
        provider.extension_grants[DEVICE_CODE_GRANT_TYPE] = exchange_device_code
        if self._metadata not in provider.extension_metadata:
            provider.extension_metadata.append(self._metadata)

    @staticmethod
    def _metadata(auth: BetterAuth) -> dict[str, Any]:
        base = f"{auth.base_url}{auth.base_path}"
        return {"device_authorization_endpoint": f"{base}{DEVICE_AUTHORIZATION_PATH}"}
