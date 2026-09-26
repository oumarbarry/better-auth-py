"""Cross-provider authorize URL parity at TS v1.7.6 (``social-providers/*.ts``): which
providers forward ``loginHint`` and which refuse to build a URL without credentials."""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest

from better_auth.oauth.providers_ext import PROVIDER_REGISTRY, Cognito

#: providers whose TS ``createAuthorizationURL`` passes ``loginHint`` to the builder
FORWARDS_LOGIN_HINT = {
    "facebook",
    "github",
    "gitlab",
    "google",
    "line",
    "linear",
    "linkedin",
    "microsoft",
    "notion",
    "paybin",
}


def make(provider_id: str, **over):
    cls = PROVIDER_REGISTRY[provider_id]
    if cls is Cognito:
        over = {
            "domain": "d.auth.us-east-1.amazoncognito.com",
            "region": "us-east-1",
            "user_pool_id": "pool",
            **over,
        }
    return cls(**{"client_id": "cid", "client_secret": "sec", **over})


def query(provider, **kw) -> dict[str, list[str]]:
    url = provider.authorization_url(
        state="st", redirect_uri="https://app/cb", code_verifier="v" * 64, **kw
    )
    return parse_qs(urlsplit(url).query)


@pytest.mark.parametrize("provider_id", sorted(PROVIDER_REGISTRY))
def test_login_hint_is_forwarded_only_where_ts_forwards_it(provider_id):
    sent = "login_hint" in query(make(provider_id), login_hint="h@example.com")
    assert sent is (provider_id in FORWARDS_LOGIN_HINT)


@pytest.mark.parametrize(
    ("provider_id", "over"),
    [
        # salesforce.ts, figma.ts, atlassian.ts, facebook.ts: client id and secret
        ("salesforce", {"client_secret": None}),
        ("salesforce", {"client_id": ""}),
        ("figma", {"client_secret": None}),
        ("atlassian", {"client_secret": None}),
        ("facebook", {"client_secret": None}),
        # microsoft-entra-id.ts:195, cognito.ts:84: client id only
        ("microsoft", {"client_id": ""}),
        ("cognito", {"client_id": ""}),
    ],
)
def test_authorize_url_requires_credentials(provider_id, over):
    with pytest.raises(ValueError, match="CLIENT_ID_AND_SECRET_REQUIRED"):
        query(make(provider_id, **over))


def test_client_id_only_providers_accept_a_missing_secret():
    assert query(make("microsoft", client_secret=None))["client_id"] == ["cid"]
    assert query(make("cognito", client_secret=None))["client_id"] == ["cid"]
