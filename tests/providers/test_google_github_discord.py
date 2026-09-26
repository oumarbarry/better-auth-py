"""Provider parity: google, github, discord at TS v1.7.6 (``social-providers/*.ts``)."""

from __future__ import annotations

import json
import time
import uuid
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from better_auth.oauth.machinery import OAuthFetchError
from better_auth.oauth.models import OAuthTokens
from better_auth.oauth.providers import Discord, GitHub, Google


def http_with(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def no_network(request: httpx.Request) -> httpx.Response:
    raise AssertionError(f"unexpected request to {request.url}")


def unsigned_jwt(claims: dict) -> str:
    return jwt.encode(claims, "unused-signing-key-not-verified-by-decoder", algorithm="HS256")


# --- Google: authorize URL ----------------------------------------------------------------


def test_google_authorization_url_exact_shape():
    # google.ts:177-196: default scopes email/profile/openid, include_granted_scopes after
    # the builder params (3a79aff58)
    p = Google(client_id="cid", client_secret="cs")
    url = p.authorization_url(state="st", redirect_uri="http://cb", code_verifier="v" * 43)
    query = parse_qs(urlsplit(url).query)
    assert url.startswith("https://accounts.google.com/o/oauth2/v2/auth?")
    assert list(query) == [
        "response_type",
        "client_id",
        "state",
        "scope",
        "redirect_uri",
        "code_challenge_method",
        "code_challenge",
        "include_granted_scopes",
    ]
    assert query["scope"] == ["email profile openid"]
    assert query["include_granted_scopes"] == ["true"]


def test_google_include_granted_scopes_false_omits_it():
    p = Google(client_id="cid", client_secret="cs", include_granted_scopes=False)
    url = p.authorization_url(state="st", redirect_uri="http://cb", code_verifier="v" * 43)
    assert "include_granted_scopes" not in parse_qs(urlsplit(url).query)


def test_google_request_extras_win_over_include_granted_scopes():
    p = Google(client_id="cid", client_secret="cs")
    url = p.authorization_url(
        state="st",
        redirect_uri="http://cb",
        code_verifier="v" * 43,
        additional_params={"include_granted_scopes": "false", "nonce": "forged"},
    )
    query = parse_qs(urlsplit(url).query)
    assert query["include_granted_scopes"] == ["false"]
    assert "nonce" not in query


def test_google_options_become_authorize_params():
    # google.ts:186-190: prompt, accessType, display, loginHint, hd
    p = Google(
        client_id="cid",
        client_secret="cs",
        prompt="consent",
        access_type="offline",
        display="popup",
        hd="acme.com",
    )
    url = p.authorization_url(
        state="st", redirect_uri="http://cb", code_verifier="v" * 43, login_hint="a@acme.com"
    )
    keys = list(parse_qs(urlsplit(url).query))
    assert keys[5:10] == ["display", "login_hint", "prompt", "hd", "access_type"]
    query = parse_qs(urlsplit(url).query)
    assert query["prompt"] == ["consent"]
    assert query["access_type"] == ["offline"]
    assert query["display"] == ["popup"]
    assert query["hd"] == ["acme.com"]


def test_google_hd_from_authorize_params_is_still_sent_and_enforced():
    p = Google(client_id="cid", client_secret="cs", authorize_params={"hd": "acme.com"})
    url = p.authorization_url(state="st", redirect_uri="http://cb", code_verifier="v" * 43)
    assert parse_qs(urlsplit(url).query)["hd"] == ["acme.com"]
    assert p.hd == "acme.com"


def test_google_requires_client_secret():
    p = Google(client_id="cid")
    with pytest.raises(ValueError, match="CLIENT_ID_AND_SECRET_REQUIRED"):
        p.authorization_url(state="st", redirect_uri="http://cb", code_verifier="v")


def test_google_requires_code_verifier():
    p = Google(client_id="cid", client_secret="cs")
    with pytest.raises(ValueError, match="codeVerifier is required for Google"):
        p.authorization_url(state="st", redirect_uri="http://cb")


# --- Google: callback profile (id token, no userinfo call) ------------------------------


async def test_google_fetch_user_decodes_id_token_without_network():
    # google.ts:236-265: getUserInfo decodes the id token
    claims = {
        "sub": "g-1",
        "email": "a@acme.com",
        "email_verified": True,
        "name": "Ada",
        "picture": "http://img",
    }
    p = Google(client_id="cid", client_secret="cs")
    tokens = OAuthTokens(access_token="at", id_token=unsigned_jwt(claims))
    info = await p.fetch_user(tokens, http_with(no_network))
    assert (info.id, info.email, info.name, info.image) == (
        "g-1",
        "a@acme.com",
        "Ada",
        "http://img",
    )
    assert info.email_verified is True


async def test_google_fetch_user_without_id_token_fails():
    p = Google(client_id="cid", client_secret="cs")
    with pytest.raises(OAuthFetchError):
        await p.fetch_user(OAuthTokens(access_token="at"), http_with(no_network))


@pytest.mark.parametrize(
    ("configured", "token_hd", "allowed"),
    [
        ("acme.com", "acme.com", True),
        ("acme.com", "evil.com", False),
        ("acme.com", None, False),
        ("*", "any.org", True),
        ("*", None, False),
    ],
)
async def test_google_fetch_user_enforces_hosted_domain(configured, token_hd, allowed):
    # google.ts:141-150 isGoogleHostedDomainAllowed, google.ts:246-254
    claims = {"sub": "g-1", "email": "a@x.com"}
    if token_hd:
        claims["hd"] = token_hd
    p = Google(client_id="cid", client_secret="cs", hd=configured)
    tokens = OAuthTokens(access_token="at", id_token=unsigned_jwt(claims))
    if allowed:
        assert (await p.fetch_user(tokens, http_with(no_network))).id == "g-1"
    else:
        with pytest.raises(OAuthFetchError):
            await p.fetch_user(tokens, http_with(no_network))


# --- Google: id token verification --------------------------------------------------------


def _google_signer(**options):
    """A Google provider on its own JWKS URL (the module JWKS cache is keyed by URL and
    rate-limits kid misses, so tests must not share one) plus a token signer."""
    kid = uuid.uuid4().hex
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    jwk["kid"] = kid
    http = http_with(lambda r: httpx.Response(200, json={"keys": [jwk]}))

    def sign(overrides=None, algorithm="RS256", signing_key=None):
        now = int(time.time())
        payload = {
            "iss": "https://accounts.google.com",
            "aud": "cid",
            "sub": "g-1",
            "iat": now,
            "exp": now + 600,
            **(overrides or {}),
        }
        return jwt.encode(payload, signing_key or key, algorithm=algorithm, headers={"kid": kid})

    google = Google(
        client_id="cid",
        client_secret="cs",
        jwks_url=f"https://www.googleapis.com/oauth2/v3/certs?test={kid}",
        **options,
    )
    return http, sign, google


async def test_google_verify_id_token_accepts_fresh_rs256():
    http, sign, p = _google_signer()
    assert (await p.verify_id_token(http, sign()))["sub"] == "g-1"


async def test_google_verify_id_token_pins_rs256():
    # google.ts:72-86: GOOGLE_ID_TOKEN_ALGORITHMS = ["RS256"]
    http, sign, p = _google_signer()
    assert await p.verify_id_token(http, sign(algorithm="HS256", signing_key="x" * 32)) is None


async def test_google_verify_id_token_max_age_one_hour():
    # google.ts:72 GOOGLE_ID_TOKEN_MAX_AGE = "1h"
    http, sign, p = _google_signer()
    old = int(time.time()) - 7200
    assert await p.verify_id_token(http, sign({"iat": old})) is None


async def test_google_verify_id_token_enforces_hd_claim():
    # google.ts:225-233 idToken.verifyClaims
    http, sign, p = _google_signer(hd="acme.com")
    assert await p.verify_id_token(http, sign({"hd": "evil.com"})) is None
    assert await p.verify_id_token(http, sign({"hd": "acme.com"})) is not None


# --- GitHub --------------------------------------------------------------------------------


def test_github_forwards_additional_params():
    # github.ts:90 (e7eb45b06)
    p = GitHub(client_id="cid", client_secret="cs")
    url = p.authorization_url(
        state="st", redirect_uri="http://cb", additional_params={"allow_signup": "false"}
    )
    assert parse_qs(urlsplit(url).query)["allow_signup"] == ["false"]


def test_github_sends_pkce():
    # github.ts:67-91 hands codeVerifier to createAuthorizationURL, which adds S256.
    p = GitHub(client_id="cid", client_secret="cs")
    url = p.authorization_url(state="st", redirect_uri="http://cb", code_verifier="v" * 43)
    query = parse_qs(urlsplit(url).query)
    assert query["code_challenge_method"] == ["S256"]
    assert "code_challenge" in query


async def test_github_exchange_sends_the_code_verifier():
    # github.ts:93-98: authorizationCodeRequest carries codeVerifier.
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update({k: v[0] for k, v in parse_qs(request.content.decode()).items()})
        return httpx.Response(200, json={"access_token": "at", "token_type": "bearer"})

    await GitHub(client_id="c", client_secret="s").exchange(
        http_with(handler), code="code", redirect_uri="http://cb", code_verifier="v" * 43
    )
    assert seen["code_verifier"] == "v" * 43


async def test_github_user_agent_is_better_auth():
    # github.ts:143, 161: "User-Agent": "better-auth" on both profile calls.
    agents: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        agents.append(request.headers["user-agent"])
        if request.url.path == "/user":
            return httpx.Response(200, json={"id": 7, "login": "o", "email": "a@x.com"})
        return httpx.Response(200, json=[])

    await GitHub(client_id="c", client_secret="s").fetch_user(
        OAuthTokens(access_token="at"), http_with(handler)
    )
    assert agents == ["better-auth", "better-auth"]


async def test_github_keeps_public_profile_email_and_its_verification():
    # github.ts:160-165: the emails list only fills a missing profile email, and
    # emailVerified is read from the entry matching the chosen email
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/user":
            return httpx.Response(200, json={"id": 7, "login": "o", "email": "pub@x.com"})
        return httpx.Response(
            200,
            json=[
                {"email": "primary@x.com", "primary": True, "verified": True},
                {"email": "pub@x.com", "primary": False, "verified": False},
            ],
        )

    info = await GitHub(client_id="c", client_secret="s").fetch_user(
        OAuthTokens(access_token="at"), http_with(handler)
    )
    assert info.id == "7"
    assert info.email == "pub@x.com"
    assert info.email_verified is False


# --- Discord -------------------------------------------------------------------------------


def test_discord_authorization_url_shared_builder_shape():
    # discord.ts:92-111: shared builder, prompt defaults to "none", no PKCE
    p = Discord(client_id="cid", client_secret="cs")
    url = p.authorization_url(state="st", redirect_uri="http://cb", code_verifier="v" * 43)
    assert url == (
        "https://discord.com/api/oauth2/authorize?response_type=code&client_id=cid"
        "&state=st&scope=identify+email&redirect_uri=http%3A%2F%2Fcb&prompt=none"
    )


def test_discord_permissions_only_with_bot_scope_and_request_wins():
    p = Discord(client_id="cid", client_secret="cs", permissions=8, prompt="consent")
    no_bot = parse_qs(urlsplit(p.authorization_url(state="s", redirect_uri="http://cb")).query)
    assert "permissions" not in no_bot
    assert no_bot["prompt"] == ["consent"]
    bot = parse_qs(
        urlsplit(
            p.authorization_url(state="s", redirect_uri="http://cb", extra_scopes=["bot"])
        ).query
    )
    assert bot["permissions"] == ["8"]
    overridden = parse_qs(
        urlsplit(
            p.authorization_url(
                state="s",
                redirect_uri="http://cb",
                extra_scopes=["bot"],
                additional_params={"permissions": "0"},
            )
        ).query
    )
    assert overridden["permissions"] == ["0"]


async def test_discord_animated_avatar_uses_gif():
    # discord.ts:148-150
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, json={"id": "1", "username": "u", "avatar": "a_hash", "discriminator": "0"}
        )

    info = await Discord(client_id="c", client_secret="s").fetch_user(
        OAuthTokens(access_token="at"), http_with(handler)
    )
    assert info.image == "https://cdn.discordapp.com/avatars/1/a_hash.gif"
    assert info.raw["image_url"] == info.image
