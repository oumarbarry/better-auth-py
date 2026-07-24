"""First-party plugins (Wave-3B fan-out).

One module per plugin; this package re-exports every Plugin subclass.
"""

from __future__ import annotations

from .admin import AdminPlugin
from .anonymous import AnonymousPlugin
from .bearer import BearerPlugin
from .captcha import CaptchaPlugin
from .custom_session import CustomSessionPlugin
from .device_authorization import DeviceAuthorizationPlugin
from .email_otp import EmailOTPPlugin
from .generic_oauth import GenericOAuthPlugin
from .haveibeenpwned import HaveIBeenPwnedPlugin
from .jwt import JWTPlugin
from .last_login_method import LastLoginMethodPlugin
from .magic_link import MagicLinkPlugin
from .multi_session import MultiSessionPlugin
from .oauth_popup import OAuthPopupPlugin
from .oauth_proxy import OAuthProxyPlugin
from .one_tap import OneTapPlugin
from .one_time_token import OneTimeTokenPlugin
from .organization import OrganizationPlugin
from .phone_number import PhoneNumberPlugin
from .siwe import SiwePlugin
from .two_factor import TwoFactorPlugin
from .username import UsernamePlugin

__all__ = [
    "AdminPlugin",
    "AnonymousPlugin",
    "BearerPlugin",
    "CaptchaPlugin",
    "CustomSessionPlugin",
    "DeviceAuthorizationPlugin",
    "EmailOTPPlugin",
    "GenericOAuthPlugin",
    "HaveIBeenPwnedPlugin",
    "JWTPlugin",
    "LastLoginMethodPlugin",
    "MagicLinkPlugin",
    "MultiSessionPlugin",
    "OAuthPopupPlugin",
    "OAuthProxyPlugin",
    "OneTapPlugin",
    "OneTimeTokenPlugin",
    "OrganizationPlugin",
    "PhoneNumberPlugin",
    "SiwePlugin",
    "TwoFactorPlugin",
    "UsernamePlugin",
]
