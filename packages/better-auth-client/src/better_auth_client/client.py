"""The two client shells: ``AuthClient`` (httpx.Client) / ``AsyncAuthClient``
(httpx.AsyncClient).

Each shell implements a single ``_call``; every endpoint method is generated from
``catalog.CATALOG``, so an endpoint is never written twice. Sessions ride httpx's
cookie jar; bearer mode captures the ``set-auth-token`` response header (server
``bearer`` plugin) or is set explicitly via ``set_bearer``. Every request defaults
``Origin`` to the client's base URL (the server's CSRF check requires it on
state-changing POSTs). Redirects are returned, never followed.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any

import httpx

from .catalog import CATALOG

_GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"


class APIError(Exception):
    """Non-2xx wire error.

    ``code``/``message`` are lifted from the body: ``{code, message}`` (core shape)
    or ``{error, error_description}`` (OAuth-shaped routes, e.g. the device plugin).
    """

    def __init__(self, status: int, code: str, message: str, body: Any = None):
        self.status = status
        self.code = code
        self.message = message
        self.body = body
        super().__init__(f"{status} {code}: {message}")


def _parse(response: httpx.Response) -> Any:
    """2xx JSON -> Python value (``null`` -> None); redirects and non-JSON 2xx ->
    the ``httpx.Response`` itself; 4xx/5xx -> :class:`APIError`."""
    if 300 <= response.status_code < 400:
        return response
    if response.is_success:
        if response.headers.get("content-type", "").startswith("application/json"):
            return response.json() if response.content else None
        return response
    try:
        body = response.json()
    except ValueError:
        body = None
    data = body if isinstance(body, dict) else {}
    code = data.get("code") or data.get("error") or ""
    message = data.get("message") or data.get("error_description") or response.text
    raise APIError(response.status_code, code, message, body)


class _Namespace:
    """Generated attribute bag; callable when its own path is a route (e.g. ``device``
    for ``GET /device``)."""

    def __init__(self, invoke: Any = None):
        self._invoke = invoke

    def __call__(self, **kwargs: Any) -> Any:
        if self._invoke is None:
            raise TypeError("this namespace is not callable")
        return self._invoke(**kwargs)

    def __getattr__(self, name: str) -> Any:
        # Real endpoint methods are set in _build_namespaces; only typos land here.
        raise AttributeError(name)


class _BaseClient:
    """Shared shell: namespace generation, request shaping, bearer state.

    Subclasses implement ``_call(method, path, kwargs)`` (sync or async) and
    ``_device_flow``; everything else is generated from the catalog.
    """

    def __init__(self, base_url: str, *, base_path: str = "/api/auth", **httpx_kwargs: Any):
        self._bearer: str | None = None
        base_url = base_url.rstrip("/")
        # Default Origin to the base URL on every request: the server's CSRF/origin
        # check rejects cookie-carrying POSTs without it (MISSING_OR_NULL_ORIGIN).
        headers = {"origin": base_url, **(httpx_kwargs.pop("headers", None) or {})}
        self._http = self._make_http(base_url + base_path, headers, httpx_kwargs)
        self._build_namespaces()
        self.device.flow = self._device_flow

    def __getattr__(self, name: str) -> Any:
        # Endpoint methods/namespaces are set in _build_namespaces; only typos land
        # here at runtime. Also types the generated surface as Any for checkers.
        raise AttributeError(name)

    def set_bearer(self, token: str | None) -> None:
        """Use ``Authorization: Bearer <token>`` on subsequent requests (e.g. a
        forwarded ``set-auth-token`` value in service-to-service validation)."""
        self._bearer = token

    # --- generation -----------------------------------------------------------------

    def _build_namespaces(self) -> None:
        entries = {name: (method, path) for name, method, path in CATALOG}
        heads = {name.partition(".")[0] for name in entries if "." in name}
        for head in heads:
            invoke = self._method(*entries[head]) if head in entries else None
            setattr(self, head, _Namespace(invoke))
        for name, (method, path) in entries.items():
            head, _, leaf = name.partition(".")
            if leaf:
                setattr(getattr(self, head), leaf, self._method(method, path))
            elif head not in heads:
                setattr(self, head, self._method(method, path))

    def _method(self, method: str, path: str) -> Any:
        def call(**kwargs: Any) -> Any:
            return self._call(method, path, kwargs)

        return call

    # --- request/response plumbing ----------------------------------------------------

    def _request_kwargs(self, method: str, kwargs: dict[str, Any]) -> dict[str, Any]:
        options: dict[str, Any] = {"params": kwargs} if method == "GET" else {"json": kwargs}
        if self._bearer:
            options["headers"] = {"authorization": f"Bearer {self._bearer}"}
        return options

    def _capture(self, response: httpx.Response) -> None:
        """Bearer capture: the server bearer plugin exposes the session token as a
        ``set-auth-token`` response header."""
        token = response.headers.get("set-auth-token")
        if token:
            self._bearer = token


class _FlowState:
    """RFC 8628 code pair: show ``user_code``/``verification_uri`` to the user, then
    poll for the token (``DeviceFlow.poll`` / ``AsyncDeviceFlow.poll``)."""

    def __init__(self, client: Any, client_id: str, grant: dict[str, Any]):
        self._client = client
        self._client_id = client_id
        self.device_code: str = grant["device_code"]
        self.user_code: str = grant["user_code"]
        self.verification_uri: str = grant["verification_uri"]
        self.verification_uri_complete: str = grant["verification_uri_complete"]
        self.expires_in: int = grant["expires_in"]
        self.interval: int = grant["interval"]

    def _token_kwargs(self) -> dict[str, str]:
        return {
            "grant_type": _GRANT_TYPE,
            "device_code": self.device_code,
            "client_id": self._client_id,
        }

    @staticmethod
    def _next_interval(error: APIError, interval: float) -> float:
        """``slow_down`` -> back off +5s (RFC 8628 §3.5); ``authorization_pending`` ->
        keep the current pace; anything else (denial, expiry, ...) propagates."""
        if error.code == "slow_down":
            return interval + 5
        if error.code == "authorization_pending":
            return interval
        raise error

    @staticmethod
    def _expired() -> APIError:
        return APIError(400, "expired_token", "Device code expired before approval", None)


class DeviceFlow(_FlowState):
    def poll(self) -> dict[str, Any]:
        """Block until the grant is approved (token dict), denied, or expired
        (:class:`APIError`)."""
        deadline = time.monotonic() + self.expires_in
        interval = float(self.interval)
        while True:
            try:
                return self._client.device.token(**self._token_kwargs())
            except APIError as error:
                interval = self._next_interval(error, interval)
            if time.monotonic() + interval > deadline:
                raise self._expired()
            time.sleep(interval)


class AsyncDeviceFlow(_FlowState):
    async def poll(self) -> dict[str, Any]:
        """Await until the grant is approved (token dict), denied, or expired
        (:class:`APIError`)."""
        deadline = time.monotonic() + self.expires_in
        interval = float(self.interval)
        while True:
            try:
                return await self._client.device.token(**self._token_kwargs())
            except APIError as error:
                interval = self._next_interval(error, interval)
            if time.monotonic() + interval > deadline:
                raise self._expired()
            await asyncio.sleep(interval)


class AuthClient(_BaseClient):
    """Synchronous better-auth client over ``httpx.Client``."""

    def _make_http(
        self, base_url: str, headers: dict[str, str], kwargs: dict[str, Any]
    ) -> httpx.Client:
        return httpx.Client(base_url=base_url, headers=headers, follow_redirects=False, **kwargs)

    def _call(self, method: str, path: str, kwargs: dict[str, Any]) -> Any:
        response = self._http.request(method, path, **self._request_kwargs(method, kwargs))
        self._capture(response)
        return _parse(response)

    def _device_flow(self, client_id: str, scope: str | None = None) -> DeviceFlow:
        body: dict[str, Any] = {"client_id": client_id}
        if scope is not None:
            body["scope"] = scope
        return DeviceFlow(self, client_id, self._call("POST", "/device/code", body))

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> AuthClient:
        return self

    def __exit__(self, *exc_info: Any) -> None:
        self.close()


class AsyncAuthClient(_BaseClient):
    """Asynchronous better-auth client over ``httpx.AsyncClient``."""

    def _make_http(
        self, base_url: str, headers: dict[str, str], kwargs: dict[str, Any]
    ) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            base_url=base_url, headers=headers, follow_redirects=False, **kwargs
        )

    async def _call(self, method: str, path: str, kwargs: dict[str, Any]) -> Any:
        response = await self._http.request(method, path, **self._request_kwargs(method, kwargs))
        self._capture(response)
        return _parse(response)

    async def _device_flow(self, client_id: str, scope: str | None = None) -> AsyncDeviceFlow:
        body: dict[str, Any] = {"client_id": client_id}
        if scope is not None:
            body["scope"] = scope
        return AsyncDeviceFlow(self, client_id, await self._call("POST", "/device/code", body))

    async def aclose(self) -> None:
        await self._http.aclose()

    async def __aenter__(self) -> AsyncAuthClient:
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        await self.aclose()
