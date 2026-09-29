---
title: Captcha
---

# Captcha

Verifies an `x-captcha-response` header against a CAPTCHA provider before the
protected endpoints run. Supports Cloudflare Turnstile, Google reCAPTCHA,
hCaptcha and CaptchaFox. Vercel BotID is also supported: it checks the request
itself instead of a header. Mirrors the TS `captcha()` plugin.

## Enable

```python
from better_auth import BetterAuth
from better_auth.plugins_ext import CaptchaPlugin

auth = BetterAuth(
    secret="a-strong-32-character-minimum-secret",
    plugins=[
        CaptchaPlugin(provider="cloudflare-turnstile", secret_key="your-secret-key")
    ],
)
```

## Options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `provider` | `str` | required | `"cloudflare-turnstile"`, `"google-recaptcha"`, `"hcaptcha"`, `"captchafox"` or `"vercel-botid"`. |
| `secret_key` | `str` | `""` | The provider's siteverify secret. Required for every provider except `"vercel-botid"`. |
| `endpoints` | `list[str] \| None` | `None` (`["/sign-up/email", "/sign-in/email", "/request-password-reset"]`) | Paths to protect. See [Endpoint rules](#endpoint-rules). |
| `site_verify_url_override` | `str \| None` | `None` | Alternate siteverify endpoint. |
| `min_score` | `float` | `0.5` | Minimum score (score-based providers, e.g. reCAPTCHA v3). |
| `expected_action` | `str \| None` | `None` | Expected action claim. |
| `allowed_hostnames` | `list[str] \| None` | `None` | Accepted hostnames in the provider response. |
| `site_key` | `str \| None` | `None` | Site key (providers that verify it server-side). |
| `check_bot_id` | `async callable \| None` | `None` | Vercel BotID only, required there: `() -> dict`, returns the BotID verdict, such as `{"isBot": False}`. |
| `validate_request` | `callable \| None` | `None` | Vercel BotID only: `({"request", "verification"}) -> bool`, sync or async. Replaces the default rule (allow when `isBot` is `False`). |

## Endpoint rules

Each entry in `endpoints` is compared with the full request path, without the
base path (`/sign-in/email`, not `/api/auth/sign-in/email`). An entry without
wildcards must match exactly. Wildcards:

- `*` matches one path segment: `/sign-in/*` covers `/sign-in/email` but not
  `/sign-in/email/extra`.
- `**` matches across segments: `/sign-up/**` covers every path under
  `/sign-up/`.

`/sign-in/email-otp` is not in the default list, so it is only protected when
a rule matches it.

::: warning Changed in 1.1
In 1.0, a rule matched any path that contained it, so `/sign-up` also covered
`/sign-up/email`. Rules now match full paths: write `/sign-up/email` or
`/sign-up/**`. Check custom `endpoints` before upgrading, or those routes stop
requiring a captcha. The default rules are unaffected. See
[Upgrade from 1.0](/migrate/from-1-0).
:::

## Vercel BotID

```python
async def check_bot_id():
    ...  # call BotID and return its verdict, e.g. {"isBot": False}

CaptchaPlugin(provider="vercel-botid", check_bot_id=check_bot_id)
```

Without `validate_request`, the request is allowed when the verdict has
`isBot: False`. With it, the request is allowed when `validate_request`
returns true. No `x-captcha-response` header is read. The
check and `validate_request` share a 10 second timeout; a timeout or an error
is a 500, and a rejected request is a 403 `VERIFICATION_FAILED`.

## Endpoints

None added. The plugin runs in `on_request`, after core rate limiting and
before route dispatch, so a rejected captcha never reaches the endpoint
handler.

## Notes

- Fails closed: any non-2xx, transport error or malformed body from the
  provider's siteverify endpoint is a 500, never a pass.
- Cloudflare Turnstile rejections are logged as warnings on the
  `better_auth.captcha` logger, with the provider's error codes or the action
  or hostname that did not match. The client still gets the same 403.
- Flattened option set: only the fields relevant to the configured `provider`
  are read (the TS options are a per-provider union).
