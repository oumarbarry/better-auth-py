"""sso plugin — OIDC federation half of ``@better-auth/sso`` (Waves A+B).

Client/relying-party SSO: register an external OIDC IdP (per-domain/per-org),
provider CRUD, and the SSRF-guarded discovery pipeline. Sign-in/callback (Wave C)
and domain verification endpoints / org auto-assignment (Wave D) land in later
dispatches — the ``domainVerified`` column + register-time token seeding are wired
here so the DB shape is stable, but the verify endpoints and login flow are not.

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

from ...plugins import Plugin, Route
from ...schema import Field, Reference, Schema
from ...types import AuthResponse, Ctx
from . import providers as _providers
from . import routes as _routes

DEFAULT_TOKEN_PREFIX = "better-auth-token"


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
    ) -> None:
        self.providers_limit = providers_limit
        self.default_override_user_info = default_override_user_info
        self.default_sso = list(default_sso or [])
        self.redirect_uri = redirect_uri
        self.model_name = model_name or "ssoProvider"

        dv = domain_verification or {}
        self.domain_verification_enabled = bool(dv.get("enabled"))
        self.token_prefix = dv.get("tokenPrefix") or DEFAULT_TOKEN_PREFIX

        self.schema: Schema = {self.model_name: self._build_fields(fields or {})}

    # --- schema -----------------------------------------------------------------------

    def _build_fields(self, overrides: dict[str, str]) -> dict[str, Field]:
        def name(key: str) -> str:
            return overrides.get(key, key)

        provider_fields: dict[str, Field] = {
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
            provider_fields["domainVerified"] = Field("boolean")
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
        return [
            ("POST", "/sso/register", self._register),
            ("GET", "/sso/providers", self._list_providers),
            ("GET", "/sso/get-provider", self._get_provider),
            ("POST", "/sso/update-provider", self._update_provider),
            ("POST", "/sso/delete-provider", self._delete_provider),
        ]

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
