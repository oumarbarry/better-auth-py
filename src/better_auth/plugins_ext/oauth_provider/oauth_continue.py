"""POST /oauth2/continue — resume authorization after selected/created/postLogin steps.

Port of TS ``packages/oauth-provider/src/continue.ts`` (v1.6.23). Named ``oauth_continue``
because ``continue`` is a Python reserved word. Each branch reads the stashed ``oauth_query``,
strips the relevant prompt, and re-enters ``/oauth2/authorize``. The client-submitted
``postLogin: true`` only selects the branch — it is NOT proof the post-login gate completed;
that is trusted only from the server-minted, session-bound ``ba_pl`` marker (continue.ts:87).
"""

from __future__ import annotations

from typing import Any

from ...types import APIError, Ctx
from .authorize import get_oauth_state
from .signed_query import parse_query
from .utils import OAuthError, remove_prompt_from_query, search_params_to_query


def _stashed_query(ctx: Ctx) -> str:
    state = get_oauth_state(ctx)
    stashed = state.get("query") if state else None
    if not stashed:
        raise OAuthError(400, "invalid_request", "missing oauth query")
    return stashed


async def continue_endpoint(ctx: Ctx, opts: Any, authorize: Any) -> Any:
    body = ctx.body()
    if body.get("selected") is True:
        return await _resume(ctx, authorize, "select_account")
    if body.get("created") is True:
        return await _resume(ctx, authorize, "create")
    if body.get("postLogin") is True:
        return await _post_login(ctx, authorize)
    raise OAuthError(400, "invalid_request", "Missing parameters")


async def _resume(ctx: Ctx, authorize: Any, prompt: str) -> Any:
    pairs = parse_query(_stashed_query(ctx))
    ctx.request.headers["accept"] = "application/json"
    return await authorize(ctx, search_params_to_query(remove_prompt_from_query(pairs, prompt)), {})


async def _post_login(ctx: Ctx, authorize: Any) -> Any:
    state = get_oauth_state(ctx)
    pairs = parse_query(_stashed_query(ctx))
    ctx.request.headers["accept"] = "application/json"
    session = await ctx.get_session()
    if session is None:
        raise APIError(401, "UNAUTHORIZED", "Not authenticated")
    post_login_cleared = (
        state is not None
        and state.get("post_login_cleared_for_session") is not None
        and state.get("post_login_cleared_for_session") == session["session"]["id"]
    )
    return await authorize(ctx, search_params_to_query(pairs), {"postLogin": post_login_cleared})
