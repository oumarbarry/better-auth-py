"""DNS-TXT domain verification — port of ``packages/sso/src/routes/domain-verification.ts``.

Two session-gated endpoints, only registered when ``domainVerification.enabled``:

- ``POST /sso/request-domain-verification`` — return an active (unexpired) token or mint
  a new one (``generateRandomString(24)``, 7-day expiry); status 201.
- ``POST /sso/verify-domain`` — for every domain in ``parseProviderDomains(provider.domain)``
  resolve the ``{identifier}.{domain}`` TXT record and require a record equal to
  ``{identifier}={value}`` OR the bare ``{value}`` (exact, no substring). Multi-domain is
  all-or-nothing (any miss -> 502). On full success flip ``domainVerified``; status 204.

The DNS TXT resolver is an injected seam (``plugin.dns_resolver``) so tests never touch the
network; the default uses dnspython's async resolver.
"""

from __future__ import annotations

import inspect
from datetime import timedelta
from typing import TYPE_CHECKING

from ...adapters.base import Where
from ...crypto import generate_random_string
from ...session import utcnow
from ...types import APIError, AuthResponse, Ctx
from .providers import check_provider_access
from .utils import parse_provider_domains

if TYPE_CHECKING:
    from . import SSOPlugin

DNS_LABEL_MAX_LENGTH = 63


async def _default_resolve_txt(name: str) -> list[str]:
    """Resolve TXT records for ``name`` via dnspython, each returned as one joined string
    (mirrors TS ``dnsRecords.map((record) => record.join("")))``)."""
    import dns.asyncresolver  # lazy: keep the dep off the import path

    answer = await dns.asyncresolver.resolve(name, "TXT")
    records: list[str] = []
    for rdata in answer:
        chunks = getattr(rdata, "strings", None)
        if chunks is not None:
            records.append(
                "".join(c.decode() if isinstance(c, bytes) else c for c in chunks)
            )
        else:
            records.append(str(rdata).strip('"'))
    return records


async def _resolve_txt(plugin: SSOPlugin, name: str) -> list[str]:
    resolver = plugin.dns_resolver or _default_resolve_txt
    result = resolver(name)
    return await result if inspect.isawaitable(result) else result


async def request_domain_verification(plugin: SSOPlugin, ctx: Ctx) -> AuthResponse:
    session = await ctx.require_session()
    body = ctx.body()
    provider_id = body.get("providerId")
    if not provider_id:
        raise APIError(400, "BAD_REQUEST", "providerId is required")
    provider = await check_provider_access(plugin, ctx, provider_id, session["user"]["id"])

    if provider.get("domainVerified"):
        raise APIError(409, "DOMAIN_VERIFIED", "Domain has already been verified")

    identifier = plugin.verification_identifier(provider["providerId"])
    active = await ctx.internal.find_verification_value(identifier)
    if active and active["expiresAt"] > utcnow():
        return AuthResponse(status=201, body={"domainVerificationToken": active["value"]})

    token = generate_random_string(24)
    await ctx.internal.create_verification_value(
        {
            "identifier": identifier,
            "value": token,
            "expiresAt": utcnow() + timedelta(days=7),
        }
    )
    return AuthResponse(status=201, body={"domainVerificationToken": token})


async def verify_domain(plugin: SSOPlugin, ctx: Ctx) -> AuthResponse:
    session = await ctx.require_session()
    body = ctx.body()
    provider_id = body.get("providerId")
    if not provider_id:
        raise APIError(400, "BAD_REQUEST", "providerId is required")
    provider = await check_provider_access(plugin, ctx, provider_id, session["user"]["id"])

    if provider.get("domainVerified"):
        raise APIError(409, "DOMAIN_VERIFIED", "Domain has already been verified")

    identifier = plugin.verification_identifier(provider["providerId"])
    if len(identifier) > DNS_LABEL_MAX_LENGTH:
        raise APIError(
            400,
            "IDENTIFIER_TOO_LONG",
            f"Verification identifier exceeds the DNS label limit of "
            f"{DNS_LABEL_MAX_LENGTH} characters",
        )

    active = await ctx.internal.find_verification_value(identifier)
    if not active or active["expiresAt"] <= utcnow():
        raise APIError(404, "NO_PENDING_VERIFICATION", "No pending domain verification exists")

    domains = parse_provider_domains(provider["domain"])
    if not domains:
        raise APIError(400, "INVALID_DOMAIN", "Invalid domain")

    verification_value = active["value"]
    verification_record = f"{active['identifier']}={verification_value}"
    for domain in domains:
        try:
            records = await _resolve_txt(plugin, f"{identifier}.{domain}")
        except Exception:
            records = []
        matched = any(
            record.strip() in (verification_record, verification_value) for record in records
        )
        if not matched:
            raise APIError(
                502,
                "DOMAIN_VERIFICATION_FAILED",
                f"Unable to verify domain ownership for {domain}. Try again later",
            )

    await ctx.adapter.update(
        plugin.model_name, [Where("providerId", provider["providerId"])], {"domainVerified": True}
    )
    return AuthResponse(status=204)
