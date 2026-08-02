"""better-auth-py: framework-agnostic authentication for Python.

A port of `better-auth <https://better-auth.com>`_ with a FastAPI integration.
"""

from .adapters import BaseAdapter, MemoryAdapter, Where
from .auth import BetterAuth
from .config import (
    AccountLinking,
    AccountOptions,
    AdvancedDatabase,
    DynamicBaseURL,
    EmailAndPassword,
    EmailVerification,
    IPAddressOptions,
    RateLimit,
    SessionOptions,
)
from .internal_adapter import InternalAdapter, VerificationOptions
from .oauth import (
    Discord,
    GitHub,
    Google,
    OAuthProvider,
    OAuthTokens,
    OAuthUserInfo,
    ProviderConfig,
)
from .plugins import Plugin
from .schema import CORE_SCHEMA, Field, Reference, Schema, rate_limit_model
from .secondary_storage import MemorySecondaryStorage, SecondaryStorage
from .types import APIError, AuthRequest, AuthResponse, Ctx

__version__ = "0.1.0"

__all__ = [
    "CORE_SCHEMA",
    "APIError",
    "AccountLinking",
    "AccountOptions",
    "AdvancedDatabase",
    "AuthRequest",
    "AuthResponse",
    "BaseAdapter",
    "BetterAuth",
    "Ctx",
    "Discord",
    "DynamicBaseURL",
    "EmailAndPassword",
    "EmailVerification",
    "Field",
    "GitHub",
    "Google",
    "IPAddressOptions",
    "InternalAdapter",
    "MemoryAdapter",
    "MemorySecondaryStorage",
    "OAuthProvider",
    "OAuthTokens",
    "OAuthUserInfo",
    "Plugin",
    "ProviderConfig",
    "RateLimit",
    "Reference",
    "Schema",
    "SecondaryStorage",
    "SessionOptions",
    "VerificationOptions",
    "Where",
    "__version__",
    "rate_limit_model",
]
