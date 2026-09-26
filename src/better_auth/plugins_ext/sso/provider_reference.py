"""SSO provider reference: port of ``packages/sso/src/provider-reference.ts`` (TS v1.7.6).

The reference is an opaque fence carried through the OIDC flow in the state's
``serverContext.ssoProviderReference``: the provider id, where the configuration lives
(a persisted row or a ``defaultSSO`` entry) and a SHA-256 fingerprint of every
authentication-relevant field (client secrets and private keys excluded, so a rotation
keeps in-flight sign-ins valid). The callback refuses a provider whose reference changed.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from ...crypto import b64url_encode_nopad

SSO_PROVIDER_STATE_KEY = "ssoProviderReference"


def _serialize_canonical(value: Any) -> str:
    """TS ``serializeCanonical``: JSON with object keys sorted, ``undefined`` (an absent
    key here) dropped and array holes written as ``null``."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))  # JSON.stringify(1.0) is "1"
    if isinstance(value, (int, float, str)):
        return json.dumps(value, ensure_ascii=False)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(_serialize_canonical(entry) for entry in value) + "]"
    if isinstance(value, dict):
        entries = sorted(value.items())
        return (
            "{" + ",".join(f"{json.dumps(k)}:{_serialize_canonical(v)}" for k, v in entries) + "}"
        )
    raise TypeError("SSO provider configuration must be JSON-serializable")


def _without_oidc_secret(config: Any) -> Any:
    if not config:
        return None
    return {key: value for key, value in config.items() if key != "clientSecret"}


def _without_saml_private_keys(config: Any) -> Any:
    if not config:
        return None
    secrets = ("privateKey", "privateKeyPass", "encPrivateKey", "encPrivateKeyPass")

    def strip(section: Any) -> dict[str, Any]:
        return {k: v for k, v in (section or {}).items() if k not in secrets}

    result = {k: v for k, v in config.items() if k != "privateKey"}
    result["idpMetadata"] = strip(config.get("idpMetadata"))
    if config.get("spMetadata"):
        result["spMetadata"] = strip(config["spMetadata"])
    else:
        result.pop("spMetadata", None)
    return result


def _provider_source(provider: dict[str, Any]) -> dict[str, str]:
    record_id = provider.get("id")
    if isinstance(record_id, str) and record_id:
        return {"type": "persisted", "recordId": record_id}
    return {"type": "configured"}


def _fingerprint(provider: dict[str, Any]) -> str:
    material: dict[str, Any] = {"domain": provider.get("domain"), "issuer": provider.get("issuer")}
    # keys TS reads as ``undefined`` are left out, a stored null stays null
    for key in ("domainVerified", "organizationId"):
        if key in provider:
            material[key] = provider[key]
    oidc = _without_oidc_secret(provider.get("oidcConfig"))
    if oidc is not None:
        material["oidcConfig"] = oidc
    saml = _without_saml_private_keys(provider.get("samlConfig"))
    if saml is not None:
        material["samlConfig"] = saml
    material = {k: v for k, v in material.items() if k in provider or v is not None}
    digest = hashlib.sha256(_serialize_canonical(material).encode()).digest()
    return b64url_encode_nopad(digest)


def compute_sso_provider_reference(provider: dict[str, Any]) -> dict[str, Any]:
    """``provider`` is the parsed provider view (``oidcConfig`` as a dict)."""
    return {
        "providerId": provider["providerId"],
        "source": _provider_source(provider),
        "authenticationConfigurationFingerprint": _fingerprint(provider),
    }


def parse_sso_provider_reference(value: Any) -> dict[str, Any] | None:
    if not isinstance(value, dict) or not isinstance(value.get("source"), dict):
        return None
    provider_id = value.get("providerId")
    fingerprint = value.get("authenticationConfigurationFingerprint")
    if not isinstance(provider_id, str) or not provider_id:
        return None
    if not isinstance(fingerprint, str) or not fingerprint:
        return None
    source = value["source"]
    if source.get("type") == "configured":
        parsed_source: dict[str, str] = {"type": "configured"}
    elif (
        source.get("type") == "persisted"
        and isinstance(source.get("recordId"), str)
        and source["recordId"]
    ):
        parsed_source = {"type": "persisted", "recordId": source["recordId"]}
    else:
        return None
    return {
        "providerId": provider_id,
        "source": parsed_source,
        "authenticationConfigurationFingerprint": fingerprint,
    }


def is_current_sso_provider_reference(
    provider: dict[str, Any], reference: dict[str, Any] | None
) -> bool:
    if not reference or reference.get("providerId") != provider.get("providerId"):
        return False
    if _provider_source(provider) != reference.get("source"):
        return False
    return reference.get("authenticationConfigurationFingerprint") == _fingerprint(provider)
