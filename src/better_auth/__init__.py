"""better-auth-py: framework-agnostic authentication for Python.

A port of `better-auth <https://better-auth.com>`_ with a FastAPI integration.
"""

from .adapters import BaseAdapter, MemoryAdapter, Where
from .auth import BetterAuth
from .config import (
    AdvancedDatabase,
    EmailAndPassword,
    EmailVerification,
    RateLimit,
    SessionOptions,
)
from .internal_adapter import InternalAdapter
from .oauth import Discord, GitHub, Google, OAuthProvider, OAuthTokens, OAuthUserInfo
from .plugins import Plugin
from .schema import CORE_SCHEMA, Field, Reference, Schema, rate_limit_model
from .secondary_storage import MemorySecondaryStorage, SecondaryStorage
from .types import APIError, AuthRequest, AuthResponse, Ctx

__version__ = "0.1.0"

__all__ = [
    "CORE_SCHEMA",
    "APIError",
    "AdvancedDatabase",
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
    "InternalAdapter",
    "MemoryAdapter",
    "MemorySecondaryStorage",
    "OAuthProvider",
    "OAuthTokens",
    "OAuthUserInfo",
    "Plugin",
    "RateLimit",
    "Reference",
    "Schema",
    "SecondaryStorage",
    "SessionOptions",
    "Where",
    "__version__",
    "rate_limit_model",
]
