"""One in-process server (conftest-style make_auth, every client-namespace plugin +
bearer), mounted twice: ASGITransport over the FastAPI app for AsyncAuthClient,
WSGITransport over the Flask app for AuthClient (a Flask instance IS a WSGI app).

Every fixture is parametrized-friendly: test bodies are written once and drive both
shells through the ``res`` awaiter.

Outbound HTTP (Google One Tap JWKS) is stubbed with ``httpx.MockTransport`` via
``BetterAuth(http_client=...)``; the SSO domain-verification TXT lookup goes through
the injected ``dns_resolver`` seam. Nothing leaves the process.
"""

from __future__ import annotations

import inspect
import json
import time
import uuid
from typing import Any

import httpx
import jwt as pyjwt
import pytest
from better_auth_client import AsyncAuthClient, AuthClient
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import FastAPI
from flask import Flask
from httpx import ASGITransport, WSGITransport
from jwt.algorithms import RSAAlgorithm

from better_auth import BetterAuth, EmailAndPassword, Google, MemoryAdapter
from better_auth.integrations.fastapi import BetterAuthFastAPI
from better_auth.integrations.flask import BetterAuthFlask
from better_auth.plugins_ext import (
    AdminPlugin,
    AnonymousPlugin,
    ApiKeyPlugin,
    BearerPlugin,
    DeviceAuthorizationPlugin,
    EmailOTPPlugin,
    GenericOAuthPlugin,
    JWTPlugin,
    MagicLinkPlugin,
    MultiSessionPlugin,
    OAuthPopupPlugin,
    OAuthProviderPlugin,
    OneTapPlugin,
    OneTimeTokenPlugin,
    OrganizationPlugin,
    PasskeyPlugin,
    PhoneNumberPlugin,
    SiwePlugin,
    SSOPlugin,
    TwoFactorPlugin,
    UsernamePlugin,
)
from better_auth.plugins_ext.generic_oauth import GenericOAuthConfig

SECRET = "test-secret-0123456789-abcdefghijklmnop"
BASE_URL = "http://testserver"
IDP = "https://idp.example.com"

# --- siwe: fixed nonce + stub signature check (mirrors tests/plugins/test_siwe.py) -----

SIWE_DOMAIN = "example.com"
SIWE_NONCE = "A1b2C3d4E5f6G7h8J"
SIWE_WALLET = "0x000000000000000000000000000000000000dEaD"


async def _siwe_get_nonce() -> str:
    return SIWE_NONCE


async def _siwe_verify_message(args: dict[str, Any]) -> bool:
    return args["signature"] == "valid_signature"


# --- one-tap: one module-level RSA key signing Google-shaped id tokens -----------------


def _rsa_jwks_and_signer() -> tuple[dict[str, Any], Any]:
    kid = uuid.uuid4().hex
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update({"kid": kid, "alg": "RS256"})

    def sign(payload: dict[str, Any]) -> str:
        return pyjwt.encode(payload, key, algorithm="RS256", headers={"kid": kid})

    return {"keys": [jwk]}, sign


GOOGLE_JWKS, _sign_google = _rsa_jwks_and_signer()
ONE_TAP_CLIENT_ID = "one-tap-client"


def google_id_token(**overrides: Any) -> str:
    now = int(time.time())
    payload = {
        "iss": "https://accounts.google.com",
        "aud": ONE_TAP_CLIENT_ID,
        "sub": "google-sub-1",
        "email": "one-tap@example.com",
        "email_verified": True,
        "name": "One Tap User",
        "iat": now,
        "exp": now + 600,
    }
    payload.update(overrides)
    return _sign_google(payload)


def _mock_http() -> httpx.AsyncClient:
    """Outbound stub: Google JWKS for one-tap; everything else 404 (the client tests
    never complete a third-party OAuth callback in-process)."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/v3/certs"):
            return httpx.Response(200, json=GOOGLE_JWKS)
        return httpx.Response(404, json={"error": "not_found"})

    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


@pytest.fixture(autouse=True)
def _reset_google_jwks_cache() -> Any:
    """The remote-JWKS cache is a module-level singleton keyed by URL (TTL + no-kid-miss
    cooldown); server tests hitting the same Google URL with other kids would otherwise
    rate-limit ours. Mirrors tests/plugins/test_one_tap.py."""
    from better_auth.oauth import verify

    verify._cache._cache.clear()
    verify._cache._last_miss.clear()
    yield


@pytest.fixture
def google_token() -> Any:
    """The Google-shaped id-token signer (test modules can't import conftest by name
    here — the tests dir is a package)."""
    return google_id_token


@pytest.fixture
def outbox() -> dict[str, Any]:
    """Captures what the server "sends": magic-link payloads, email OTPs, SMS codes —
    plus the SSO domain-verification TXT records the stub DNS resolver serves."""
    return {"dns_txt": {}}


@pytest.fixture
def auth(outbox: dict[str, Any]) -> BetterAuth:
    def send_magic_link(data: dict[str, Any]) -> None:
        outbox["magic_link"] = data

    def send_verification_otp(data: dict[str, Any], ctx: Any = None) -> None:
        outbox["otp"] = data

    async def send_sms_otp(data: dict[str, Any], ctx: Any = None) -> None:
        outbox["sms"] = data

    def resolve_txt(name: str) -> list[str]:
        return outbox["dns_txt"].get(name, [])

    return BetterAuth(
        secret=SECRET,
        base_url=BASE_URL,
        adapter=MemoryAdapter(),
        email_and_password=EmailAndPassword(enabled=True),
        social_providers={"google": Google(client_id=ONE_TAP_CLIENT_ID, client_secret="s")},
        http_client=_mock_http(),
        plugins=[
            TwoFactorPlugin(),
            OrganizationPlugin(),
            AdminPlugin(),
            ApiKeyPlugin(),
            MagicLinkPlugin(send_magic_link=send_magic_link),
            EmailOTPPlugin(send_verification_otp=send_verification_otp),
            # interval "0s": poll-driven tests never sleep between polls
            DeviceAuthorizationPlugin(interval="0s"),
            # bearer plugin: emits set-auth-token, which the client captures
            BearerPlugin(),
            UsernamePlugin(),
            PhoneNumberPlugin(
                send_otp=send_sms_otp,
                send_password_reset_otp=send_sms_otp,
                sign_up_on_verification={"get_temp_email": lambda p: f"temp-{p}@example.com"},
            ),
            PasskeyPlugin(),  # rp_id/origin default to the base URL / Origin header
            AnonymousPlugin(),
            SiwePlugin(
                domain=SIWE_DOMAIN,
                get_nonce=_siwe_get_nonce,
                verify_message=_siwe_verify_message,
            ),
            OneTapPlugin(),
            JWTPlugin(),
            OneTimeTokenPlugin(),
            MultiSessionPlugin(),
            GenericOAuthPlugin(
                config=[
                    GenericOAuthConfig(
                        provider_id="acme",
                        client_id="acme-client",
                        client_secret="acme-secret",
                        authorization_url=f"{IDP}/authorize",
                        token_url=f"{IDP}/token",
                        user_info_url=f"{IDP}/userinfo",
                        scopes=["openid", "email"],
                    )
                ]
            ),
            OAuthPopupPlugin(),
            SSOPlugin(domain_verification={"enabled": True}, dns_resolver=resolve_txt),
            OAuthProviderPlugin(
                login_page="https://app.example.com/login",
                consent_page="https://app.example.com/consent",
                allow_dynamic_client_registration=True,
            ),
        ],
    )


def make_fastapi_app(auth: BetterAuth) -> FastAPI:
    app = FastAPI()
    app.include_router(BetterAuthFastAPI(auth).router)
    return app


def make_flask_app(auth: BetterAuth) -> Flask:
    app = Flask(__name__)
    app.register_blueprint(BetterAuthFlask(auth).blueprint)
    return app


@pytest.fixture(params=["sync", "async"])
async def client_factory(request: pytest.FixtureRequest, auth: BetterAuth):
    """Callable minting clients bound to one shared server app (device-flow tests
    need a second, separately-authenticated client)."""
    created: list[AuthClient | AsyncAuthClient] = []

    if request.param == "sync":
        wsgi_app = make_flask_app(auth)

        def make() -> AuthClient | AsyncAuthClient:
            client = AuthClient(BASE_URL, transport=WSGITransport(app=wsgi_app))
            created.append(client)
            return client
    else:
        asgi_app = make_fastapi_app(auth)

        def make() -> AuthClient | AsyncAuthClient:
            client = AsyncAuthClient(BASE_URL, transport=ASGITransport(app=asgi_app))
            created.append(client)
            return client

    yield make

    for client in created:
        if isinstance(client, AuthClient):
            client.close()
        else:
            await client.aclose()


@pytest.fixture
def client(client_factory: Any) -> AuthClient | AsyncAuthClient:
    return client_factory()


@pytest.fixture
def res():
    """Awaits AsyncAuthClient results, passes AuthClient results through — one test
    body drives both shells."""

    async def _res(value: Any) -> Any:
        return await value if inspect.isawaitable(value) else value

    return _res
