---
title: Captcha
---

# Captcha

Verifies an `x-captcha-response` header against a CAPTCHA provider before the
protected endpoints run. Supports Cloudflare Turnstile, Google reCAPTCHA,
hCaptcha and CaptchaFox. Mirrors the TS `captcha()` plugin.

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
| `provider` | `str` | required | `"cloudflare-turnstile"`, `"google-recaptcha"`, `"hcaptcha"` or `"captchafox"`. |
| `secret_key` | `str` | required | The provider's siteverify secret. |
| `endpoints` | `list[str] \| None` | `None` (`["/sign-up/email", "/sign-in/email", "/request-password-reset"]`) | Paths to protect. `/sign-in/email-otp` is exempt unless named explicitly. |
| `site_verify_url_override` | `str \| None` | `None` | Alternate siteverify endpoint. |
| `min_score` | `float` | `0.5` | Minimum score (score-based providers, e.g. reCAPTCHA v3). |
| `expected_action` | `str \| None` | `None` | Expected action claim. |
| `allowed_hostnames` | `list[str] \| None` | `None` | Accepted hostnames in the provider response. |
| `site_key` | `str \| None` | `None` | Site key (providers that verify it server-side). |

## Endpoints

None added — the plugin runs in `on_request`, after core rate limiting and
before route dispatch, so a rejected captcha never reaches the endpoint
handler.

## Notes

- Fails closed: any non-2xx, transport error or malformed body from the
  provider's siteverify endpoint is a 500, never a pass.
- Flattened option set: only the fields relevant to the configured `provider`
  are read (the TS options are a per-provider union).
