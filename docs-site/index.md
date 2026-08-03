---
layout: home

hero:
  name: Better Auth for Python
  text: Authentication for Python, at parity.
  tagline: A server-side port of Better Auth. Same routes, same JSON shapes, same error codes, same database — so a Python service and a TypeScript one are interchangeable on one schema.
  actions:
    - theme: brand
      text: Get started
      link: /guide/getting-started
    - theme: alt
      text: Migrate from Node
      link: /migrate/from-node
    - theme: alt
      text: GitHub
      link: https://github.com/oumarbarry/better-auth-py

features:
  - title: Full parity with Better Auth v1.6.25
    details: Identical paths, success and error bodies, error-code strings, camelCase columns, scrypt hash format and cookie signing scheme. A password created by the TypeScript library verifies in Python, and the reverse.
    link: /migrate/from-node
    linkText: What parity means
  - title: 35 providers, 26 plugins
    details: GitHub, Google, Apple, Microsoft Entra ID, Slack and 30 more built in, plus two-factor, admin, organization, passkeys, JWT, an OAuth 2.1 authorization server, SSO and API keys as first-party plugins.
    link: /plugins/
    linkText: Browse the plugins
  - title: Your database, no service
    details: Users, sessions and accounts live in your own Postgres, MySQL or SQLite. No hosted dependency, no per-user pricing, no vendor to page at 3am.
    link: /guide/concepts
    linkText: How sessions work
---

<div class="ba-quickstart">

## Twenty lines is a working auth server

Sign-up, sign-in, sessions, sign-out, password reset, email verification and social login, mounted under `/api/auth`.

```python
from better_auth import BetterAuth, EmailAndPassword
from better_auth.integrations.fastapi import BetterAuthFastAPI
from fastapi import Depends, FastAPI

auth = BetterAuth(
    secret="...",  # openssl rand -base64 32
    base_url="http://localhost:8000",
    email_and_password=EmailAndPassword(enabled=True),
)

app = FastAPI()
ba = BetterAuthFastAPI(auth)
app.include_router(ba.router)  # mounts /api/auth/*

@app.get("/me")
async def me(result: dict = Depends(ba.require_session)):
    return result["user"]
```

```bash
uv add better-auth-server[fastapi,sqlalchemy]
```

The core is framework-agnostic, and FastAPI, Litestar, Flask and Django
integrations ship in the box — each a thin layer over plain request/response
dataclasses. There is a client too: [better-auth-client](https://pypi.org/project/better-auth-client/)
talks to any Better Auth server from Python, sync or async.
[Start here.](/guide/getting-started)

</div>
