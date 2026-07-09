"""better-auth-py: framework-agnostic authentication for Python.

A port of `better-auth <https://better-auth.com>`_ with a FastAPI integration.
"""

from .adapters import BaseAdapter, MemoryAdapter, Where
from .auth import BetterAuth
from .config import EmailAndPassword, EmailVerification, RateLimit, SessionOptions
from .oauth import Discord, GitHub, Google, OAuthProvider, OAuthTokens, OAuthUserInfo
from .plugins import Plugin
from .schema import CORE_SCHEMA, Field, Schema
from .types import APIError, AuthRequest, AuthResponse, Ctx

__version__ = "0.1.0"

__all__ = [
    "CORE_SCHEMA",
    "APIError",
    "AuthRequest",
    "AuthResponse",
    "BaseAdapter",
    "BetterAuth",
    "Ctx",
    "Discord",
    "EmailAndPassword",
    "EmailVerification",
    "Field",
    "GitHub",
    "Google",
    "MemoryAdapter",
    "OAuthProvider",
    "OAuthTokens",
    "OAuthUserInfo",
    "Plugin",
    "RateLimit",
    "Schema",
    "SessionOptions",
    "Where",
    "__version__",
]
