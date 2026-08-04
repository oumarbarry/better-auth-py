---
title: AI agents
---

# AI agents

This project ships three things for coding agents: an installable skill, plain-text
mirrors of this site, and in-repo agent instructions. All three describe the same
package — pick the one your setup consumes.

## The skill

```bash
npx skills add oumarbarry/better-auth-py
```

That installs the `better-auth-server` skill — a `SKILL.md` plus four reference
files — for Claude Code and any harness that reads the agent skills format
(the CLI lists the supported ones). It teaches an agent to
stand up a working server (FastAPI, Litestar, Flask or Django), protect routes,
configure any of the 26 plugins and 35 social providers, migrate a Node
Better Auth server onto the same database, and avoid the classic mistakes
(short secrets, the in-memory default adapter, missing `trusted_origins`).
Every code snippet in the skill has been executed and verified against the
released package.

The skill covers *using* `better-auth-server` in your application. It is not a
contribution guide — that is [AGENTS.md](#in-repo) below.

## llms.txt

The site publishes both [llmstxt.org](https://llmstxt.org) endpoints:

| Endpoint | Contents |
|---|---|
| [`/llms.txt`](/llms.txt) | An index — every page with its URL and a one-line description |
| [`/llms-full.txt`](/llms-full.txt) | Every page of this site, concatenated as one Markdown file |

Fetch `/llms.txt` when the agent should pick the pages it needs; fetch
`/llms-full.txt` when you want the whole documentation in context in one
request. Both are regenerated on every deploy, so they never lag the site.

## In-repo

[`AGENTS.md`](https://github.com/oumarbarry/better-auth-py/blob/main/AGENTS.md)
at the repository root governs agents *contributing to* the port: the parity
prime directive (the TypeScript repo is canonical for anything touching wire or
storage), the full test-and-lint gate to run before claiming work done, and the
repo's conventions. `CLAUDE.md` points at it, so Claude Code picks it up
automatically.

In short: install the skill to build *with* `better-auth-server`; read
`AGENTS.md` to work *on* it.
