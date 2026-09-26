"""``handle_oauth_user_info`` resolution options at better-auth v1.7.6
(oauth2/link-account.ts:170-640, ed61b4798): ``selected_user``,
``require_exact_account_binding``, ``defer_non_database_writes`` and the
"unable to update account" refusal."""

from typing import Any

import pytest

from better_auth import EmailVerification, Where
from better_auth.oauth.flow import OAuthLinkError, handle_oauth_user_info
from better_auth.oauth.models import OAuthTokens, OAuthUserInfo
from better_auth.oauth.providers import ProviderConfig
from better_auth.types import APIError, AuthRequest, Ctx
from conftest import make_auth

PROVIDER = ProviderConfig(client_id="cid", provider_id="corp")


def _info(**over: Any) -> OAuthUserInfo:
    data: dict[str, Any] = {
        "id": "sub-1",
        "email": "idp@corp.example",
        "name": "From IdP",
        "email_verified": False,
    }
    data.update(over)
    return OAuthUserInfo(**data)


def _ctx(**auth_kwargs: Any) -> Ctx:
    return Ctx(auth=make_auth(**auth_kwargs), request=AuthRequest(method="GET", path="/x"))


async def _user(ctx: Ctx, email: str, *, verified: bool = True) -> str:
    row = await ctx.internal.create_user(
        {"email": email, "name": "Local", "emailVerified": verified}
    )
    assert row is not None
    return row["id"]


async def test_selected_user_links_without_the_implicit_linking_gate():
    # link-account.ts:283-296: a resolver-selected user skips the trust and email gates.
    ctx = _ctx()
    target = await _user(ctx, "someone.else@corp.example", verified=False)
    user_id, is_register = await handle_oauth_user_info(
        ctx,
        PROVIDER,
        _info(),
        OAuthTokens(access_token="at"),
        selected_user={"userId": target, "profile": "preserve"},
    )
    assert (user_id, is_register) == (target, False)
    account = await ctx.adapter.find_one("account", [Where("providerId", "corp")])
    assert account is not None and account["userId"] == target
    user = await ctx.adapter.find_one("user", [Where("id", target)])
    assert user is not None and user["name"] == "Local"


async def test_selected_user_profile_update_overrides_user_info():
    ctx = _ctx()
    target = await _user(ctx, "someone.else@corp.example")
    await handle_oauth_user_info(
        ctx,
        PROVIDER,
        _info(),
        OAuthTokens(access_token="at"),
        selected_user={"userId": target, "profile": "update"},
    )
    user = await ctx.adapter.find_one("user", [Where("id", target)])
    assert user is not None
    assert (user["name"], user["email"]) == ("From IdP", "idp@corp.example")


async def test_selected_user_must_exist():
    ctx = _ctx()
    with pytest.raises(APIError) as err:
        await handle_oauth_user_info(
            ctx,
            PROVIDER,
            _info(),
            OAuthTokens(access_token="at"),
            selected_user={"userId": "ghost", "profile": "preserve"},
        )
    assert (err.value.status, err.value.code, err.value.message) == (
        404,
        "user_not_found",
        "User not found",
    )


async def test_selected_user_conflicts_with_existing_owner():
    ctx = _ctx()
    owner = await _user(ctx, "owner@corp.example")
    other = await _user(ctx, "other@corp.example")
    await ctx.internal.create_account({"userId": owner, "providerId": "corp", "accountId": "sub-1"})
    with pytest.raises(APIError) as err:
        await handle_oauth_user_info(
            ctx,
            PROVIDER,
            _info(),
            OAuthTokens(access_token="at"),
            selected_user={"userId": other, "profile": "preserve"},
        )
    assert (err.value.status, err.value.code, err.value.message) == (
        409,
        "account_ownership_conflict",
        "Account is already linked to another user",
    )


async def test_exact_binding_rejects_a_hook_that_rewrites_the_account():
    async def rebind(data: dict[str, Any], _ctx: Any) -> dict[str, Any]:
        return {"data": {"accountId": "rewritten"}}

    ctx = _ctx(database_hooks={"account": {"create": {"before": rebind}}})
    with pytest.raises(APIError) as err:
        await handle_oauth_user_info(
            ctx,
            PROVIDER,
            _info(email_verified=True),
            OAuthTokens(access_token="at"),
            require_exact_account_binding=True,
        )
    assert (err.value.status, err.value.code) == (409, "account_hook_binding_conflict")


async def test_sign_in_account_update_refused_reports_unable_to_update_account():
    # link-account.ts:423-433
    async def veto(_data: dict[str, Any], _ctx: Any) -> bool:
        return False

    ctx = _ctx(database_hooks={"account": {"update": {"before": veto}}})
    owner = await _user(ctx, "idp@corp.example")
    await ctx.internal.create_account({"userId": owner, "providerId": "corp", "accountId": "sub-1"})
    with pytest.raises(OAuthLinkError) as err:
        await handle_oauth_user_info(ctx, PROVIDER, _info(), OAuthTokens(access_token="at"))
    assert err.value.code == "unable_to_update_account"


async def test_deferred_verification_email_waits_for_the_transaction():
    sent: list[str] = []

    async def send(user: dict[str, Any], _url: str, _token: str) -> None:
        sent.append(user["email"])

    ctx = _ctx(
        email_verification=EmailVerification(send_verification_email=send, send_on_sign_up=True)
    )

    async def run(_tx: Any) -> None:
        await handle_oauth_user_info(
            ctx, PROVIDER, _info(), OAuthTokens(access_token="at"), defer_non_database_writes=True
        )
        assert sent == []

    await ctx.internal.transaction(run)
    assert sent == ["idp@corp.example"]
