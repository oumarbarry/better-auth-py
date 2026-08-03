---
title: WeChat
---

# WeChat

WeChat QR-code login (`snsapi_login`). The most non-standard provider: `appid`/`secret` instead of `client_id`/`client_secret` on the wire, GET-based token exchange, comma-joined scopes, no PKCE.

## Configure

```python
from better_auth import BetterAuth
from better_auth.oauth.providers_ext import WeChat

auth = BetterAuth(
    secret=...,
    social_providers={
        "wechat": WeChat(client_id="wx-appid", client_secret="…"),
    },
)
```

Or name-keyed (no import):

```python
auth = BetterAuth(
    secret=...,
    social_providers={
        "wechat": {"client_id": "wx-appid", "client_secret": "…"},
    },
)
```

## Options

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `client_id` | `str \| list[str]` | required | Your WeChat **AppID** — sent as `appid` on every request. |
| `client_secret` | `str` | required | Your **AppSecret** — sent as `secret`. |
| `lang` | `str` | `"cn"` | UI language of the QR login page (`"cn"` or `"en"`). |

All shared [`ProviderConfig` options](/providers/#per-provider-options) apply.

## Notes

- Default scopes: `snsapi_login`, joined with a **comma**.
- Register `{base_url}{base_path}/callback/wechat` as the authorized callback domain/URL on the WeChat Open Platform app.
- The authorize URL is hand-built on `https://open.weixin.qq.com/connect/qrconnect` and ends with the mandatory `#wechat_redirect` fragment.
- Token exchange **and** refresh are `GET` requests with query-string params (`appid`, `secret`, …) against `api.weixin.qq.com/sns/oauth2/*` — not POST bodies.
- The userinfo endpoint needs the `openid` returned alongside the access token; it is kept on the raw token response and read back at fetch time. The stable user id prefers `unionid` over `openid`.
- WeChat never returns an email — a stable `{id}@wechat.invalid` placeholder is synthesized (always unverified) so the email-required callback doesn't reject the sign-in.
