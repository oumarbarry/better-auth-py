# Better Auth for Python

[![CI](https://github.com/oumarbarry/better-auth-py/actions/workflows/ci.yml/badge.svg)](https://github.com/oumarbarry/better-auth-py/actions/workflows/ci.yml)

Authentication for Python, ported from [better-auth](https://better-auth.com). Your users, sessions and accounts live in your own database, with no hosted service and no per-user pricing.

| Package | Description | Links |
|---|---|---|
| **better-auth-server** | The server port. Full parity with better-auth (TypeScript); import name `better_auth`. | [README](src/better_auth/README.md) · [PyPI](https://pypi.org/project/better-auth-server/) |
| **better-auth-client** | Python HTTP client for a better-auth server, 158 endpoints. | [README](packages/better-auth-client/README.md) · [PyPI](https://pypi.org/project/better-auth-client/) |

Docs: **[better-auth-py.oumarbarry.tech](https://better-auth-py.oumarbarry.tech)**

## For AI agents

`npx skills add oumarbarry/better-auth-py` lists the skills in this repository; pick `better-auth-py` to install it for Claude Code and compatible harnesses. It covers setup, plugins, providers and TS-to-Python migration, and every snippet in it has been executed and verified. The [AI agents](docs-site/guide/agents.md) docs page covers the rest: the skill, llms.txt, AGENTS.md.

## License

[MIT](LICENSE). Inspired by and API-compatible with [better-auth](https://github.com/better-auth/better-auth), also MIT.
