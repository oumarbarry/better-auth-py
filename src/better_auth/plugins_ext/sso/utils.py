"""sso plugin utilities — faithful port of ``packages/sso/src/utils.ts``.

Ports the OIDC-relevant helpers only (``parseCertificate``/``normalizePem`` are
SAML and excluded). ``parseProviderDomains`` uses a minimal hostname normalizer in
place of TS's ``tldts.getHostname`` — sufficient for the domain-matching and
email-domain-gating contracts (no public-suffix behavior is asserted in utils.test.ts).
"""

from __future__ import annotations

import json
import re
from typing import Any

_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")


def safe_json_parse(value: Any) -> Any:
    """Parse a value that may be a JSON string or an already-parsed object
    (ORMs sometimes hand back parsed objects for JSON/TEXT columns).

    Returns None for falsy input; raises ValueError on malformed JSON strings
    (mirrors TS ``safeJsonParse`` which throws)."""
    if not value:
        return None
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except ValueError as error:
            raise ValueError(f"Failed to parse JSON: {error}") from error
    return None


def _get_hostname(entry: str) -> str | None:
    """Minimal ``tldts.getHostname`` analogue: strip scheme/userinfo/path/port,
    lowercase, validate DNS-label shape. Returns None for anything unparseable."""
    host = entry.strip().lower()
    if not host:
        return None
    if "://" in host:
        host = host.split("://", 1)[1]
    for sep in ("/", "?", "#"):
        host = host.split(sep, 1)[0]
    if "@" in host:
        host = host.rsplit("@", 1)[1]
    if ":" in host:
        host = host.split(":", 1)[0]
    if not host:
        return None
    labels = host.split(".")
    if any(not _LABEL_RE.match(label) for label in labels):
        return None
    return host


def parse_provider_domains(domain: str) -> list[str] | None:
    """Normalize a provider ``domain`` value (one or comma-separated) into the
    lowercased, deduped email domains it authorizes. Returns None if empty or if any
    entry fails to parse to a hostname (TS ``parseProviderDomains``)."""
    entries = [entry.strip() for entry in domain.split(",")]
    entries = [entry for entry in entries if entry]
    if not entries:
        return None
    domains: list[str] = []
    seen: set[str] = set()
    for entry in entries:
        parsed = _get_hostname(entry)
        if not parsed:
            return None
        if parsed not in seen:
            seen.add(parsed)
            domains.append(parsed)
    return domains


def domain_matches(search_domain: str, domain_list: str) -> bool:
    """Whether ``search_domain`` matches any domain in the comma-separated
    ``domain_list`` — exact host or ``.``-suffix subdomain, lowercased (TS
    ``domainMatches``)."""
    search = search_domain.strip().lower()
    domains = parse_provider_domains(domain_list)
    if not search or not domains:
        return False
    return any(search == domain or search.endswith(f".{domain}") for domain in domains)


def parse_provider_email_verified(value: Any) -> bool:
    """Strict email-verification claim parse: only boolean ``True`` or the exact
    string ``"true"`` count as verified — everything else (incl. ``"false"``) is
    unverified (TS ``parseProviderEmailVerified``)."""
    return value is True or value == "true"


def validate_email_domain(email: str, domain: str) -> bool:
    """Validate an email's domain against allowed domain(s) (TS ``validateEmailDomain``)."""
    parts = email.split("@")
    email_domain = parts[1].lower() if len(parts) > 1 and parts[1] else None
    if not email_domain or not domain:
        return False
    return domain_matches(email_domain, domain)


def mask_client_id(client_id: str) -> str:
    """Return ``****`` + last four of the client id (or ``****`` if too short) —
    used by ``sanitize_provider`` so a full client id is never returned (TS ``maskClientId``)."""
    if len(client_id) <= 4:
        return "****"
    return f"****{client_id[-4:]}"
