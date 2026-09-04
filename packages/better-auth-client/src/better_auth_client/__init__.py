"""better-auth-client — Python HTTP client for better-auth servers.

Works against `better-auth-server` (this repo) or the TypeScript original — same wire.
"""

from .catalog import CATALOG
from .client import APIError, AsyncAuthClient, AsyncDeviceFlow, AuthClient, DeviceFlow

__all__ = [
    "CATALOG",
    "APIError",
    "AsyncAuthClient",
    "AsyncDeviceFlow",
    "AuthClient",
    "DeviceFlow",
]
