"""Organization auto-membership — port of ``packages/sso/src/linking/org-assignment.ts``.

Two seams, both gated on ``has_plugin(auth, "organization")`` and writing ``member``
rows directly through the adapter (exactly as TS — no org-API call):

- :func:`assign_organization_from_provider` — called inline in the OIDC callback when
  the resolved provider carries an ``organizationId``. Explicit org-bound provisioning:
  the operator linked that provider to that org, so no domain trust is involved.
- :func:`assign_organization_by_domain` — the after-hook on ``/callback/*`` for non-SSO
  (social/generic) logins. Domain-derived routing is only as trustworthy as the domain
  proof behind it, so since 999acbd41 (GHSA-phx7-w8x2-3xgf) it requires *all* of:
  domain verification enabled, a ``domainVerified`` provider, the canonical stored user
  row with a verified email, and exactly one candidate organization.

Neither seam accepts or cancels a pending invitation: an invited user must complete the
invitation flow, so a pending invite for the target org suppresses automatic membership.
"""

from __future__ import annotations

import inspect
import logging
from typing import TYPE_CHECKING, Any

from ...adapters.base import Where
from ...session import utcnow
from ...types import Ctx
from .utils import domain_matches, parse_provider_domains

if TYPE_CHECKING:
    from . import SSOPlugin

logger = logging.getLogger("better_auth")


def _email_domain(email: str) -> str | None:
    """The single normalized domain an email authorizes, or None if it does not parse to
    exactly one (TS ``getEmailDomain``)."""
    parts = email.strip().lower().split("@")
    if len(parts) != 2 or not parts[0] or not parts[1]:
        return None
    domain = parts[1]
    if any(char in domain for char in ("/", "\\", ":")):
        return None
    domains = parse_provider_domains(domain)
    if not domains or len(domains) != 1:
        return None
    return domains[0]


async def _verified_domain_providers(
    ctx: Ctx, plugin: SSOPlugin, domain: str
) -> list[dict[str, Any]]:
    """Persisted providers whose proven domain set covers ``domain`` (TS
    ``findVerifiedDomainProviders`` — internal, never exposed as a route)."""
    providers = await ctx.adapter.find_many(plugin.model_name, [Where("domainVerified", True)])
    return [p for p in providers if domain_matches(domain, p["domain"])]


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
    pending_invitation = await ctx.adapter.find_one(
        "invitation",
        [
            Where("organizationId", organization_id),
            Where("email", (user.get("email") or "").lower()),
            Where("status", "pending"),
        ],
    )
    if pending_invitation:
        return
    role = await _resolve_role(
        provisioning, user=user, user_info=user_info, token=token, provider=provider
    )
    # FIXME(sso-membership-policy): route automatic SSO membership through the
    # organization plugin's limits, hooks, additional fields, and atomic guard.
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
    """Add the user to ``provider.organizationId`` (org-assignment.ts:217). Skipped when
    provisioning is disabled, the org plugin is absent, the provider has no org, the user
    is already a member, or an invitation to that org is pending."""
    provisioning = plugin.organization_provisioning or {}
    if provisioning.get("disabled"):
        return
    if not plugin.has_org_plugin(ctx):
        return
    organization_id = provider.get("organizationId")
    if not organization_id:
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
    """Add a non-SSO login's user to the organization owning their *verified* email domain
    (org-assignment.ts:230).

    Every gate here is load-bearing: the callback's user copy is re-read from storage so a
    stale/forged ``emailVerified`` cannot carry the assignment, only providers that proved
    the domain are considered, and a domain claimed by two organizations assigns to
    neither."""
    provisioning = plugin.organization_provisioning or {}
    if provisioning.get("disabled"):
        return
    if not plugin.has_org_plugin(ctx):
        return
    if not plugin.domain_verification_enabled:
        return

    # ponytail: TS reads internalAdapter.findUserById; the port's InternalAdapter has no
    # user-by-id read and this is a plain unhooked select either way (routes.py does the same).
    canonical = await ctx.adapter.find_one("user", [Where("id", user["id"])])
    if canonical is None:
        logger.error(
            "Unable to assign SSO organization membership because the canonical user was "
            "not found (userId=%s)",
            user["id"],
        )
        return
    if not canonical.get("emailVerified"):
        return
    domain = _email_domain(canonical.get("email") or "")
    if not domain:
        return

    matching = [
        p for p in await _verified_domain_providers(ctx, plugin, domain) if p.get("organizationId")
    ]
    if len({p["organizationId"] for p in matching}) > 1:
        logger.warning(
            "Skipped SSO organization provisioning because a verified domain maps to "
            "multiple organizations (domain=%s, userId=%s)",
            domain,
            canonical["id"],
        )
        return
    if not matching:
        return
    # ponytail: codepoint order stands in for TS localeCompare — a tie-break among
    # providers that all resolve to the same org, so the pick is never wire-visible.
    selected = min(matching, key=lambda p: p["providerId"])

    await _create_member_if_absent(
        ctx,
        organization_id=selected["organizationId"],
        user=canonical,
        user_info={},
        token=None,
        provider=selected,
        provisioning=provisioning,
    )
