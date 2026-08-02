"""Flask integration: register the auth blueprint and read sessions in views.

Usage::

    from flask import Flask

    from better_auth import BetterAuth
    from better_auth.integrations.flask import BetterAuthFlask

    auth = BetterAuth(...)
    ba = BetterAuthFlask(auth)

    app = Flask(__name__)
    app.register_blueprint(ba.blueprint)

    @app.get("/me")
    def me():
        result = ba.require_session()
        return result["user"]
"""

from __future__ import annotations

import asyncio
import threading
from typing import Any

try:
    from flask import Blueprint, Response, abort, request
except ModuleNotFoundError as exc:  # pragma: no cover
    raise ModuleNotFoundError(
        "Flask is not installed; install it with `pip install better-auth-server[flask]`"
    ) from exc

from ..auth import BetterAuth
from ..types import AuthRequest, AuthResponse, dump_json


def _to_auth_request(request: Any, path: str, body: bytes) -> AuthRequest:
    headers = {k.lower(): v for k, v in request.headers.items()}
    client_ip = request.remote_addr
    forwarded = headers.get("x-forwarded-for")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()
    return AuthRequest(
        method=request.method,
        path=path,
        headers=headers,
        # last value wins, as with FastAPI's `dict(request.query_params)`
        # (Werkzeug's `args.to_dict()` would keep the first)
        query={key: values[-1] for key, values in request.args.lists()},
        body=body,
        client_ip=client_ip,
    )


def _to_response(result: AuthResponse) -> Response:
    if result.redirect_to is not None:
        # Flask's Response always defaults a content-type, so a redirect carries an
        # (ignored) `text/html` where the FastAPI layer sends none. Body and status match.
        response = Response(status=302)
        response.headers["location"] = result.redirect_to
    else:
        response = Response(
            result.body if result.media_type else dump_json(result.body),
            status=result.status,
            content_type=result.media_type or "application/json",
        )
    for name, value in result.headers:
        response.headers.add(name, value)
    return response


class BetterAuthFlask:
    """Binds a BetterAuth instance to Flask: `.blueprint` plus session helpers.

    Flask is WSGI/sync while the core is async, so the instance owns one event
    loop in a daemon thread and every call crosses it via
    ``run_coroutine_threadsafe``. A fresh loop per request (``asyncio.run``)
    would break the second request: the core caches an ``httpx.AsyncClient``
    on the instance and ``SQLAlchemyAdapter`` holds a loop-bound ``AsyncEngine``
    pool ("attached to a different loop"). One persistent loop reproduces how
    the ASGI integrations run.
    """

    def __init__(self, auth: BetterAuth):
        self.auth = auth
        # ponytail: no close()/shutdown seam — the daemon thread lives with the
        # process; add a close() method if teardown ever matters.
        self._loop = asyncio.new_event_loop()
        threading.Thread(
            target=self._loop.run_forever, name="better-auth-flask", daemon=True
        ).start()

        self.blueprint = Blueprint("better-auth", __name__)
        base = auth.base_path.rstrip("/")

        @self.blueprint.route(base + "/<path:rest>", methods=["GET", "POST"])
        def handle(rest: str) -> Response:
            auth_request = _to_auth_request(request, "/" + rest, request.get_data())
            return _to_response(self._run(auth.handle(auth_request)))

    def _run(self, coro: Any) -> Any:
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result()

    def session(self) -> dict[str, Any] | None:
        """Read the current request's session: ``{"session": ..., "user": ...}`` or None."""
        return self._run(self.auth.load_session(_to_auth_request(request, "/get-session", b"")))

    def require_session(self) -> dict[str, Any]:
        """Like `session` but responds 401 when unauthenticated.

        The 401 is Flask's ``abort(401)``: Werkzeug's HTML error page carrying
        "Not authenticated", not the JSON ``detail`` bodies of the
        FastAPI/Litestar layers.
        """
        result = self.session()
        if result is None:
            abort(401, description="Not authenticated")
        return result
