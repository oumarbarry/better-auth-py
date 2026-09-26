"""sso plugin: OIDC federation half of ``@better-auth/sso`` (better-auth v1.7.6).

Client/relying-party SSO: register an external OIDC IdP (per-domain/per-org), provider
CRUD, the SSRF-guarded discovery pipeline, sign-in and callback (with the optional
transactional ``resolveUser``), domain verification and organization assignment.

SAML is excluded (see the spec's "Excluded — SAML" boundary): the ``samlConfig``
column is retained (nullable, unused) for cross-runtime DB compat only; a
``providerType:"saml"`` / ``samlConfig`` register body is rejected.

``clientSecret`` is stored in the ``oidcConfig`` JSON in PLAINTEXT — a deliberate
cross-runtime DB-compat contract (the secret is needed cleartext at every token
exchange and there is no symmetric envelope). It is masked only on read
(``sanitize_provider``). Do NOT add at-rest encryption here — it would break a
TS-written row from being usable by Python and vice-versa.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

from ...plugins import HookSet, Plugin, PluginHook, Route
from ...schema import Field, Reference, Schema, parse_input_data
from ...types import APIError, AuthResponse, Ctx
from . import domain_verification as _domain
from . import org_assignment as _org
from . import providers as _providers
from . import routes as _routes

DEFAULT_TOKEN_PREFIX = "better-auth-token"

#: TS v1.7.6 index.ts:168-190: keys an additional field may not reuse
BUILT_IN_FIELD_KEYS = (
    "id",
    "issuer",
    "oidcConfig",
    "samlConfig",
    "userId",
    "providerId",
    "organizationId",
    "domain",
    "domainVerified",
)
RESPONSE_FIELD_KEYS = ("type", "spMetadataUrl", "redirectURI", "domainVerificationToken")


def has_plugin(auth: Any, plugin_id: str) -> bool:
    """Whether a plugin with ``plugin_id`` is registered (TS ``ctx.context.hasPlugin``)."""
    return any(getattr(p, "id", None) == plugin_id for p in auth.plugins)


class SSOPlugin(Plugin):
    id = "sso"

    def __init__(
        self,
        *,
        providers_limit: int | Callable[[dict[str, Any]], int | Awaitable[int]] | None = None,
        default_override_user_info: bool = False,
        default_sso: list[dict[str, Any]] | None = None,
        domain_verification: dict[str, Any] | None = None,
        redirect_uri: str | None = None,
        model_name: str | None = None,
        fields: dict[str, str] | None = None,
        provision_user: Callable[[dict[str, Any]], Any] | None = None,
        provision_user_on_every_login: bool = False,
        organization_provisioning: dict[str, Any] | None = None,
        trust_email_verified: bool = False,
        disable_implicit_sign_up: bool = False,
        resolve_host: Any = None,
        dns_resolver: Any = None,
        resolve_user: Callable[[dict[str, Any], dict[str, Any]], Any] | None = None,
        guard_provider_mutation: Callable[[dict[str, Any], dict[str, Any]], Any] | None = None,
        resolve_private_key: Callable[[dict[str, Any]], Any] | None = None,
        schema: dict[str, Any] | None = None,
        legacy_mapping_id: bool = False,
    ) -> None:
        self.providers_limit = providers_limit
        self.default_override_user_info = default_override_user_info
        self.default_sso = list(default_sso or [])
        self.redirect_uri = redirect_uri
        provider_schema = (schema or {}).get("ssoProvider") or {}
        self.model_name = model_name or provider_schema.get("modelName") or "ssoProvider"
        #: ``schema.ssoProvider.additionalFields`` (TS v1.7.6 48070ada8)
        self.additional_fields: dict[str, Field] = dict(
            provider_schema.get("additionalFields") or {}
        )
        #: ``resolveUser(input, {"database"})`` -> ``{"action": "continue" | "link" |
        #: "reject", ...}``, run inside the account-link transaction (TS v1.7.6 ed61b4798)
        self.resolve_user = resolve_user
        #: ``guardProviderMutation(input, {"database"})``; raise to refuse (59c4c832f)
        self.guard_provider_mutation = guard_provider_mutation
        #: ``resolvePrivateKey({"providerId", "keyId", "issuer"})`` for private_key_jwt
        self.resolve_private_key = resolve_private_key
        #: read the account id from ``oidcConfig.mapping.id`` as before 1.7 (TS now always
        #: uses ``sub``). Only for providers whose accounts were linked under a custom id.
        self.legacy_mapping_id = legacy_mapping_id
        self.provision_user = provision_user
        self.provision_user_on_every_login = provision_user_on_every_login
        self.organization_provisioning = organization_provisioning
        self.trust_email_verified = trust_email_verified
        self.disable_implicit_sign_up = disable_implicit_sign_up
        #: injected A/AAAA resolver for the discovery DNS-rebind check (tests stub it)
        self.resolve_host = resolve_host
        #: injected TXT resolver for domain verification (tests stub it; default: dnspython)
        self.dns_resolver = dns_resolver

        dv = domain_verification or {}
        self.domain_verification_enabled = bool(dv.get("enabled"))
        self.token_prefix = dv.get("tokenPrefix") or DEFAULT_TOKEN_PREFIX

        field_names = {**(provider_schema.get("fields") or {}), **(fields or {})}
        self._assert_no_additional_field_collisions(field_names)
        self.schema: Schema = {self.model_name: self._build_fields(field_names)}

    def _assert_no_additional_field_collisions(self, field_names: dict[str, str]) -> None:
        """TS v1.7.6 index.ts:210-238 ``assertNoAdditionalFieldCollisions``."""
        built_in_names = {field_names.get(key, key) for key in BUILT_IN_FIELD_KEYS}
        for key, spec in self.additional_fields.items():
            if key in BUILT_IN_FIELD_KEYS:
                raise ValueError(
                    f'ssoProvider additional field "{key}" conflicts with a built-in field'
                )
            if key in RESPONSE_FIELD_KEYS:
                raise ValueError(
                    f'ssoProvider additional field "{key}" conflicts with a returned provider field'
                )
            name = spec.field_name or key
            if name in built_in_names:
                raise ValueError(
                    f'ssoProvider additional field "{key}" maps to built-in field "{name}"'
                )

    def parse_additional_fields(self, data: dict[str, Any], action: str) -> dict[str, Any]:
        """TS v1.7.6 schemas.ts:44-67: an ``input: false`` key is refused when present at
        all, then the usual input allowlist applies."""
        for key, spec in self.additional_fields.items():
            if spec.input is False and key in data:
                raise APIError(400, "BAD_REQUEST", f"{key} is not allowed to be set")
        return parse_input_data(data, self.additional_fields, action)

    # --- schema -----------------------------------------------------------------------

    def _build_fields(self, overrides: dict[str, str]) -> dict[str, Field]:
        def name(key: str) -> str:
            return overrides.get(key, key)

        provider_fields: dict[str, Field] = {
            # the row id every model carries (without it the SQL table had no primary key)
            "id": Field("string", required=True, unique=True),
            "issuer": Field("string", required=True, field_name=name("issuer")),
            "oidcConfig": Field("string", field_name=name("oidcConfig")),
            # kept nullable + unused for cross-runtime DB compat (SAML excluded)
            "samlConfig": Field("string", field_name=name("samlConfig")),
            "userId": Field(
                "string", references=Reference("user", "id"), field_name=name("userId")
            ),
            "providerId": Field(
                "string", required=True, unique=True, field_name=name("providerId")
            ),
            "organizationId": Field("string", field_name=name("organizationId")),
            "domain": Field("string", required=True, field_name=name("domain")),
        }
        if self.domain_verification_enabled:
            provider_fields["domainVerified"] = Field(
                "boolean", field_name=overrides.get("domainVerified")
            )
        provider_fields.update(self.additional_fields)
        return provider_fields

    # --- helpers used by the route handlers -------------------------------------------

    def has_plugin(self, ctx: Ctx, plugin_id: str) -> bool:
        return has_plugin(ctx.auth, plugin_id)

    def has_org_plugin(self, ctx: Ctx) -> bool:
        return has_plugin(ctx.auth, "organization")

    def context_base_url(self, ctx: Ctx) -> str:
        """TS ``ctx.context.baseURL`` = base URL + mount path."""
        return f"{ctx.auth.base_url}{ctx.auth.base_path}"

    def verification_identifier(self, provider_id: str) -> str:
        """DNS-TXT identifier ``_{tokenPrefix}-{providerId}`` (domain-verification.ts)."""
        return f"_{self.token_prefix}-{provider_id}"

    # --- routes -----------------------------------------------------------------------

    def routes(self) -> list[Route]:
        routes: list[Route] = [
            ("POST", "/sign-in/sso", self._sign_in),
            ("GET", "/sso/callback/{providerId}", self._callback),
            ("GET", "/sso/callback", self._callback_shared),
            ("POST", "/sso/register", self._register),
            ("GET", "/sso/providers", self._list_providers),
            ("GET", "/sso/get-provider", self._get_provider),
            ("POST", "/sso/update-provider", self._update_provider),
            ("POST", "/sso/delete-provider", self._delete_provider),
        ]
        if self.domain_verification_enabled:
            routes += [
                ("POST", "/sso/request-domain-verification", self._request_domain_verification),
                ("POST", "/sso/verify-domain", self._verify_domain),
            ]
        return routes

    def hooks(self) -> HookSet:
        # after-hook on /callback/* (non-SSO social/generic logins) -> org-by-domain.
        return HookSet(
            after=[
                PluginHook(
                    matcher=lambda ctx: ctx.request.path.startswith("/callback/"),
                    handler=self._after_callback,
                )
            ]
        )

    async def _after_callback(self, ctx: Ctx) -> None:
        new_session = ctx.new_session
        if not new_session or not new_session.get("user"):
            return
        if not self.has_org_plugin(ctx):
            return
        await _org.assign_organization_by_domain(ctx, self, user=new_session["user"])

    async def _sign_in(self, ctx: Ctx) -> AuthResponse:
        return await _routes.sign_in_sso(self, ctx)

    async def _callback(self, ctx: Ctx) -> AuthResponse:
        return await _routes.callback_sso(self, ctx)

    async def _callback_shared(self, ctx: Ctx) -> AuthResponse:
        return await _routes.callback_sso_shared(self, ctx)

    async def _request_domain_verification(self, ctx: Ctx) -> AuthResponse:
        return await _domain.request_domain_verification(self, ctx)

    async def _verify_domain(self, ctx: Ctx) -> AuthResponse:
        return await _domain.verify_domain(self, ctx)

    async def _register(self, ctx: Ctx) -> AuthResponse:
        return await _routes.register(self, ctx)

    async def _list_providers(self, ctx: Ctx) -> AuthResponse:
        return await _providers.list_providers(self, ctx)

    async def _get_provider(self, ctx: Ctx) -> AuthResponse:
        return await _providers.get_provider(self, ctx)

    async def _update_provider(self, ctx: Ctx) -> AuthResponse:
        return await _providers.update_provider(self, ctx)

    async def _delete_provider(self, ctx: Ctx) -> AuthResponse:
        return await _providers.delete_provider(self, ctx)


__all__ = ["SSOPlugin", "has_plugin"]
