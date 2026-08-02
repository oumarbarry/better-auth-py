"""Social provider registry (Wave-2B fan-out).

One module per provider; this package re-exports every ProviderConfig subclass
and a PROVIDER_REGISTRY mapping provider_id -> class for name-based lookup.
"""

from __future__ import annotations

from ..providers import Discord, GitHub, Google
from .apple import Apple
from .atlassian import Atlassian
from .cognito import Cognito
from .dropbox import Dropbox
from .facebook import Facebook
from .figma import Figma
from .gitlab import Gitlab
from .huggingface import Huggingface
from .kakao import Kakao
from .kick import Kick
from .line import Line
from .linear import Linear
from .linkedin import LinkedIn
from .microsoft_entra_id import MicrosoftEntraId
from .naver import Naver
from .notion import Notion
from .paybin import Paybin
from .paypal import Paypal
from .polar import Polar
from .railway import Railway
from .reddit import Reddit
from .roblox import Roblox
from .salesforce import Salesforce
from .slack import Slack
from .spotify import Spotify
from .tiktok import TikTok
from .twitch import Twitch
from .twitter import Twitter
from .vercel import Vercel
from .vk import VK
from .wechat import WeChat
from .zoom import Zoom

PROVIDER_REGISTRY: dict[str, type] = {
    "github": GitHub,
    "google": Google,
    "discord": Discord,
    Apple.provider_id: Apple,
    Atlassian.provider_id: Atlassian,
    Cognito.provider_id: Cognito,
    Dropbox.provider_id: Dropbox,
    Facebook.provider_id: Facebook,
    Figma.provider_id: Figma,
    Gitlab.provider_id: Gitlab,
    Huggingface.provider_id: Huggingface,
    Kakao.provider_id: Kakao,
    Kick.provider_id: Kick,
    Line.provider_id: Line,
    Linear.provider_id: Linear,
    LinkedIn.provider_id: LinkedIn,
    MicrosoftEntraId.provider_id: MicrosoftEntraId,
    Naver.provider_id: Naver,
    Notion.provider_id: Notion,
    Paybin.provider_id: Paybin,
    Paypal.provider_id: Paypal,
    Polar.provider_id: Polar,
    Railway.provider_id: Railway,
    Reddit.provider_id: Reddit,
    Roblox.provider_id: Roblox,
    Salesforce.provider_id: Salesforce,
    Slack.provider_id: Slack,
    Spotify.provider_id: Spotify,
    TikTok.provider_id: TikTok,
    Twitch.provider_id: Twitch,
    Twitter.provider_id: Twitter,
    Vercel.provider_id: Vercel,
    VK.provider_id: VK,
    WeChat.provider_id: WeChat,
    Zoom.provider_id: Zoom,
}

__all__ = [
    "PROVIDER_REGISTRY",
    "VK",
    "Apple",
    "Atlassian",
    "Cognito",
    "Discord",
    "Dropbox",
    "Facebook",
    "Figma",
    "GitHub",
    "Gitlab",
    "Google",
    "Huggingface",
    "Kakao",
    "Kick",
    "Line",
    "Linear",
    "LinkedIn",
    "MicrosoftEntraId",
    "Naver",
    "Notion",
    "Paybin",
    "Paypal",
    "Polar",
    "Railway",
    "Reddit",
    "Roblox",
    "Salesforce",
    "Slack",
    "Spotify",
    "TikTok",
    "Twitch",
    "Twitter",
    "Vercel",
    "WeChat",
    "Zoom",
]
