"""SSO provider reference (TS v1.7.6 packages/sso/src/provider-reference.ts): the fence the
OIDC flow carries in ``serverContext.ssoProviderReference`` so a provider edited between
sign-in and callback is refused."""

from better_auth.plugins_ext.sso.provider_reference import (
    compute_sso_provider_reference,
    is_current_sso_provider_reference,
    parse_sso_provider_reference,
)

OIDC = {
    "issuer": "https://idp.example.com",
    "clientId": "client-1",
    "clientSecret": "secret",
    "pkce": True,
    "scopes": ["openid", "email"],
    "mapping": {"email": "email", "name": "name"},
    "overrideUserInfo": False,
    "tokenEndpoint": "https://idp.example.com/token",
}

PROVIDER = {
    "id": "row-1",
    "providerId": "corp",
    "issuer": "https://idp.example.com",
    "domain": "corp.example",
    "domainVerified": True,
    "organizationId": None,
    "oidcConfig": OIDC,
    "samlConfig": None,
}


def test_reference_matches_the_ts_fingerprint_vector():
    # Vector from TS serializeCanonical + SHA-256 base64url (client secret excluded).
    assert compute_sso_provider_reference(PROVIDER) == {
        "providerId": "corp",
        "source": {"type": "persisted", "recordId": "row-1"},
        "authenticationConfigurationFingerprint": "bfvbXhr21ayj_Bfu0SwX7DaEiUM1bueOKo9uk8amyZo",
    }


def test_configured_provider_without_row_id():
    reference = compute_sso_provider_reference({**PROVIDER, "id": None})
    assert reference["source"] == {"type": "configured"}


def test_secret_rotation_keeps_the_reference_current():
    reference = compute_sso_provider_reference(PROVIDER)
    rotated = {**PROVIDER, "oidcConfig": {**OIDC, "clientSecret": "rotated"}}
    assert is_current_sso_provider_reference(rotated, reference)


def test_identity_change_invalidates_the_reference():
    reference = compute_sso_provider_reference(PROVIDER)
    moved = {**PROVIDER, "oidcConfig": {**OIDC, "tokenEndpoint": "https://evil.example/token"}}
    assert not is_current_sso_provider_reference(moved, reference)
    assert not is_current_sso_provider_reference({**PROVIDER, "id": "row-2"}, reference)
    assert not is_current_sso_provider_reference(PROVIDER, None)


def test_parse_rejects_malformed_references():
    good = compute_sso_provider_reference(PROVIDER)
    assert parse_sso_provider_reference(good) == good
    assert parse_sso_provider_reference({**good, "providerId": ""}) is None
    assert parse_sso_provider_reference({**good, "source": {"type": "persisted"}}) is None
    assert parse_sso_provider_reference("corp") is None
