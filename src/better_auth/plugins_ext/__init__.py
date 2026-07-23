"""First-party plugins (Wave-3B fan-out).

One module per plugin; this package re-exports every Plugin subclass.
"""

from __future__ import annotations

from .anonymous import AnonymousPlugin
from .bearer import BearerPlugin
from .captcha import CaptchaPlugin
from .custom_session import CustomSessionPlugin
from .email_otp import EmailOTPPlugin
from .haveibeenpwned import HaveIBeenPwnedPlugin
from .last_login_method import LastLoginMethodPlugin
from .magic_link import MagicLinkPlugin
from .one_time_token import OneTimeTokenPlugin
from .phone_number import PhoneNumberPlugin
from .username import UsernamePlugin

__all__ = [
    "AnonymousPlugin",
    "BearerPlugin",
    "CaptchaPlugin",
    "CustomSessionPlugin",
    "EmailOTPPlugin",
    "HaveIBeenPwnedPlugin",
    "LastLoginMethodPlugin",
    "MagicLinkPlugin",
    "OneTimeTokenPlugin",
    "PhoneNumberPlugin",
    "UsernamePlugin",
]
