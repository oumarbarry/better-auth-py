"""Django integration: include the auth URL patterns and read sessions in views.

Usage::

    # urls.py
    from django.http import HttpResponse, JsonResponse
    from django.urls import path

    from better_auth import BetterAuth
    from better_auth.integrations.django import BetterAuthDjango

    auth = BetterAuth(...)
    ba = BetterAuthDjango(auth)

    def me(request):
        result = ba.require_session(request)
        if isinstance(result, HttpResponse):
            return result  # the prepared 401
        return JsonResponse(result["user"])

    urlpatterns = [
        *ba.urls,
        path("me", me),
    ]

The auth view is ``csrf_exempt``: Django's token-based CSRF middleware is foreign
to the protocol (no ``csrftoken`` cookie/form field exists on better-auth clients).
The equivalent protection is built into the core — every state-changing request
passes the Origin/Referer check (``better_auth.origin.check_origin``), which is
how better-auth defends against CSRF on every framework.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Any

try:
    from django.http import HttpRequest, HttpResponse, JsonResponse
    from django.urls import path
    from django.views.decorators.csrf import csrf_exempt
    from django.views.decorators.http import require_http_methods
except ModuleNotFoundError as exc:  # pragma: no cover
    raise ModuleNotFoundError(
        "Django is not installed; install it with `pip install better-auth-server[django]`"
    ) from exc

from ..auth import BetterAuth
from ..types import AuthRequest, AuthResponse, dump_json


def _to_auth_request(request: HttpRequest, path: str, body: bytes) -> AuthRequest:
    headers = {k.lower(): v for k, v in request.headers.items()}
    client_ip = request.META.get("REMOTE_ADDR")
    forwarded = headers.get("x-forwarded-for")
    if forwarded:
        client_ip = forwarded.split(",")[0].strip()
    return AuthRequest(
        method=request.method or "GET",
        path=path,
        headers=headers,
        # last value wins, as with FastAPI's `dict(request.query_params)`
        # (QueryDict[key] agrees, but `.lists()` makes it explicit)
        query={key: values[-1] for key, values in request.GET.lists()},
        body=body,
        client_ip=client_ip,
    )


def _to_response(result: AuthResponse) -> HttpResponse:
    if result.redirect_to is not None:
        # HttpResponse always defaults a content-type, so a redirect carries an
        # (ignored) `text/html` where the FastAPI layer sends none. Body and status match.
        response = HttpResponse(status=302)
        response["location"] = result.redirect_to
    else:
        response = HttpResponse(
            result.body if result.media_type else dump_json(result.body),
            status=result.status,
            content_type=result.media_type or "application/json",
        )
    for name, value in result.headers:
        if name.lower() == "set-cookie":
            # HttpResponse.headers is dict-like and overwrites duplicates; cookies are
            # Django's one repeated-header channel: every handler emits one Set-Cookie
            # line per `response.cookies` morsel (django/core/handlers/wsgi.py). The
            # core's cookie values are percent-encoded (crypto.sign_cookie_value), so
            # the stdlib http.cookies parse behind `load` round-trips them losslessly;
            # attribute order may differ on the wire, semantics do not.
            response.cookies.load(value)
        else:
            response[name] = value
    return response


class BetterAuthDjango:
    """Binds a BetterAuth instance to Django: `.urls` plus session helpers.

    Django views here are sync while the core is async, so the instance owns one
    event loop in a daemon thread and every call crosses it via
    ``run_coroutine_threadsafe``. A fresh loop per request (``asyncio.run``)
    would break the second request: the core caches an ``httpx.AsyncClient``
    on the instance and ``SQLAlchemyAdapter`` holds a loop-bound ``AsyncEngine``
    pool ("attached to a different loop"). One persistent loop reproduces how
    the ASGI integrations run. Sync views also behave identically under WSGI
    and ASGI — Django runs them in a threadpool under ASGI, so the blocking
    ``.result()`` occupies a worker thread, never the server's loop (async
    views would get a per-request asgiref loop under WSGI, hitting the same
    loop-bound breakage).
    """

    def __init__(self, auth: BetterAuth):
        self.auth = auth
        # ponytail: no close()/shutdown seam — the daemon thread lives with the
        # process; add a close() method if teardown ever matters.
        self._loop = asyncio.new_event_loop()
        threading.Thread(
            target=self._loop.run_forever, name="better-auth-django", daemon=True
        ).start()

        base = auth.base_path.strip("/")  # Django route patterns carry no leading slash
        route = f"{base}/<path:rest>" if base else "<path:rest>"

        @csrf_exempt
        @require_http_methods(["GET", "POST"])
        def handle(request: HttpRequest, rest: str) -> HttpResponse:
            auth_request = _to_auth_request(request, "/" + rest, request.body)
            return _to_response(self._run(auth.handle(auth_request)))

        #: splat into ``urlpatterns`` (``urlpatterns = [*ba.urls, ...]``)
        self.urls = [path(route, handle, name="better-auth")]

    def _run(self, coro: Any) -> Any:
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result()

    def session(self, request: HttpRequest) -> dict[str, Any] | None:
        """Read the request's session: ``{"session": ..., "user": ...}`` or None."""
        return self._run(self.auth.load_session(_to_auth_request(request, "/get-session", b"")))

    def require_session(self, request: HttpRequest) -> dict[str, Any] | JsonResponse:
        """Like `session` but hands back a prepared 401 when unauthenticated.

        Django has no exception that maps to a 401 (``PermissionDenied`` is 403),
        so unlike the raising FastAPI/Litestar/Flask layers this returns the
        response for the view to pass through::

            result = ba.require_session(request)
            if isinstance(result, HttpResponse):
                return result

        The 401 body matches the FastAPI layer's ``{"detail": "Not authenticated"}``.
        """
        result = self.session(request)
        if result is None:
            return JsonResponse({"detail": "Not authenticated"}, status=401)
        return result
