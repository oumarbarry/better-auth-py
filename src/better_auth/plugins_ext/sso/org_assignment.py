"""Organization auto-membership — port of ``packages/sso/src/linking/org-assignment.ts``.

Two seams, both gated on ``has_plugin(auth, "organization")`` and writing ``member``
rows directly through the adapter (exactly as TS — no org-API call):

- :func:`assign_organization_from_provider` — called inline in the OIDC callback when
  the resolved provider carries an ``organizationId``.
- :func:`assign_organization_by_domain` — the after-hook on ``/callback/*`` for non-SSO
  (social/generic) logins whose email domain maps to an org-linked SSO provider.
"""

from __future__ import annotations

import inspect
from typing import TYPE_CHECKING, Any

from ...adapters.base import Where
from ...session import utcnow
from ...types import Ctx
from .utils import domain_matches

if TYPE_CHECKING:
    from . import SSOPlugin


async def _resolve_role(
    provisioning: dict[str, Any],
    *,
    user: dict[str, Any],
    user_info: dict[str, Any],
    token: Any,
    provider: dict[str, Any],
) -> str:
    """``getRole?({user, userInfo, token, provider}) ?? defaultRole ?? "member"``."""
    get_role = provisioning.get("getRole")
    if get_role is not None:
        result = get_role(
            {"user": user, "userInfo": user_info, "token": token, "provider": provider}
        )
        role = await result if inspect.isawaitable(result) else result
        return role
    return provisioning.get("defaultRole") or "member"


async def _create_member_if_absent(
    ctx: Ctx,
    *,
    organization_id: str,
    user: dict[str, Any],
    user_info: dict[str, Any],
    token: Any,
    provider: dict[str, Any],
    provisioning: dict[str, Any],
) -> None:
    already = await ctx.adapter.find_one(
        "member",
        [Where("organizationId", organization_id), Where("userId", user["id"])],
    )
    if already:
        return
    role = await _resolve_role(
        provisioning, user=user, user_info=user_info, token=token, provider=provider
    )
    await ctx.adapter.create(
        "member",
        {
            "organizationId": organization_id,
            "userId": user["id"],
            "role": role,
            "createdAt": utcnow(),
        },
    )


async def assign_organization_from_provider(
    ctx: Ctx,
    plugin: SSOPlugin,
    *,
    user: dict[str, Any],
    profile: dict[str, Any],
    provider: dict[str, Any],
    token: Any = None,
) -> None:
    """Add the user to ``provider.organizationId`` (org-assignment.ts:29). Skipped when
    the provider has no org, provisioning is disabled, the org plugin is absent, or the
    user is already a member."""
    organization_id = provider.get("organizationId")
    if not organization_id:
        return
    provisioning = plugin.organization_provisioning or {}
    if provisioning.get("disabled"):
        return
    if not plugin.has_org_plugin(ctx):
        return
    await _create_member_if_absent(
        ctx,
        organization_id=organization_id,
        user=user,
        user_info=profile.get("rawAttributes") or {},
        token=token,
        provider=provider,
        provisioning=provisioning,
    )


async def assign_organization_by_domain(
    ctx: Ctx, plugin: SSOPlugin, *, user: dict[str, Any]
) -> None:
    """Add a non-SSO login's user to the org of an SSO provider matching their email
    domain (org-assignment.ts:95). Exact-domain fast path, then comma-scan; gated on
    ``domainVerified`` when domain verification is enabled."""
    provisioning = plugin.organization_provisioning or {}
    if provisioning.get("disabled"):
        return
    if not plugin.has_org_plugin(ctx):
        return

    email = user.get("email") or ""
    parts = email.split("@")
    domain = parts[1] if len(parts) > 1 and parts[1] else None
    if not domain:
        return

    where = [Where("domain", domain)]
    if plugin.domain_verification_enabled:
        where.append(Where("domainVerified", True))
    sso_provider = await ctx.adapter.find_one(plugin.model_name, where)

    if sso_provider is None:
        many_where = [Where("domainVerified", True)] if plugin.domain_verification_enabled else None
        all_providers = await ctx.adapter.find_many(plugin.model_name, many_where)
        sso_provider = next(
            (p for p in all_providers if domain_matches(domain, p["domain"])), None
        )

    if not sso_provider or not sso_provider.get("organizationId"):
        return

    await _create_member_if_absent(
        ctx,
        organization_id=sso_provider["organizationId"],
        user=user,
        user_info={},
        token=None,
        provider=sso_provider,
        provisioning=provisioning,
    )
