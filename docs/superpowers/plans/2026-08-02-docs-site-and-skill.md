# Docs Site + Skill Implementation Plan

> **For agentic workers:** executed via the project's ORCHESTRATOR.md model —
> one background agent per task, disjoint file ownership, Fable validates and
> commits. Spec: `docs/superpowers/specs/2026-08-02-docs-site-and-skill-design.md`.

**Goal:** Ship the VitePress space-themed docs site (Option A, ~9 pages) and
the single coherent `better-auth-server` agent skill.

**Architecture:** Site in `docs-site/` (VitePress default theme, deep custom
CSS + canvas starfield hero, user deploys on Vercel). Skill in
`.agents/skills/better-auth-server/` with progressive-disclosure references,
symlinked into `.claude/skills/`.

**Tech Stack:** VitePress (latest stable), native CSS + canvas (no animation
libs), Markdown. Skill = plain Markdown per skills.sh conventions.

## Global Constraints

- Every code sample (site AND skill) must show the REAL API — verified
  against `src/better_auth/` and executed where runnable. Wrong API = reject.
- Package name `better-auth-server`, import `better_auth`, parity v1.6.25,
  2006 tests, 35 providers, 26 plugins — these exact numbers everywhere.
- Site: local search on; `prefers-reduced-motion` honored; AA contrast;
  zero external animation/font-CDN dependencies (self-host or system fonts).
- No agent commits — the orchestrator commits after validation.

---

### Task 1: docs-site (agent SITE)

**Files (create only, owns `docs-site/**` + `.github/workflows/docs.yml`):**
- `docs-site/package.json` (scripts: `docs:dev`, `docs:build`, `docs:preview`)
- `docs-site/.vitepress/config.mts` — nav (Guide/Plugins/Providers/Migrate/
  Deploy + GitHub/PyPI links), sidebar (two groups), local search provider,
  head meta (og tags, favicon 🐍🛰️-style SVG), dark default.
- `docs-site/.vitepress/theme/index.ts` + `custom.css` + `Starfield.vue`
  (canvas ~60 lines, parallax, `prefers-reduced-motion` → static render once)
- Pages: `index.md` (hero + features + quickstart), `guide/getting-started.md`,
  `guide/concepts.md`, `guide/configuration.md`, `migrate/from-node.md`,
  `plugins/index.md` (26 cards), `providers/index.md` (35 + custom example),
  `deploy/production.md`.
- `.github/workflows/docs.yml` — npm ci + docs:build on PRs touching docs-site.

**Content sources (read, do not invent):** README.md, CHANGELOG.md,
`src/better_auth/plugins_ext/__init__.py` (`__all__`, docstrings),
`src/better_auth/oauth/` (`PROVIDER_REGISTRY`), config dataclasses in
`src/better_auth/config.py` / `auth.py` for the Configuration page,
`docs/plans/ACTIVE.md` decision log for the Migrate page's parity claims.

**Steps:** scaffold + build green → theme (invoke a frontend design skill
first) → pages with verified snippets → final `npm run docs:build` (dead
links fail the build) + Lighthouse-minded pass (no layout shift, canvas
idle-scheduled).

**Done when:** `npm run docs:build` exits 0 from a clean `npm ci`; all 9
pages present with real content (no lorem/TBD); starfield + reduced-motion
verified; report lists every snippet and where it was verified.

### Task 2: better-auth-server skill (agent SKILL)

**Files (create only, owns `.agents/skills/better-auth-server/**` and the
symlink `.claude/skills/better-auth-server`):**
- `.agents/skills/better-auth-server/SKILL.md` — frontmatter (name,
  description tuned for agent-trigger phrases: "add auth", "better auth
  python", "fastapi authentication"), then ~150 lines: project detection,
  install (`uv add better-auth-server[fastapi,sqlalchemy]` / pip), minimal
  `BetterAuth` config, FastAPI mount, protecting routes
  (`ba.require_session`), sessions basics, the 5 classic mistakes
  (secret <32 chars, missing base_url, MemoryAdapter in prod, forgetting
  trusted_origins, reading `result["user"]` wrong).
- `references/plugins.md` (all 26: 1-para + config snippet each),
  `references/providers.md` (name-keyed config, all 35 listed, custom
  provider), `references/security.md` (rate limit, ip options, origin/CSRF
  model, secrets rotation), `references/migrate-from-ts.md` (same-DB
  migration, what maps to what).
- Symlink: `ln -s ../../.agents/skills/better-auth-server
  .claude/skills/better-auth-server` (relative, like the Astral skills).

**Method:** invoke superpowers:writing-skills first; mirror the frontmatter
style of `.agents/skills/ruff/SKILL.md`. ACCURACY RULE from Global
Constraints is hard: execute every snippet (scratch venv or `uv run`)
against better-auth-server==0.2.1; paste execution evidence in the report.

**Done when:** all files exist, every snippet executed with evidence,
SKILL.md ≤ ~200 lines with references carrying the depth, symlink resolves.

### Task 3 (orchestrator, after 1+2): validation & integration

- Fable: spot-check snippets, run site build fresh, run a fresh agent
  through the skill on a blank FastAPI project (skill's runnable check),
  wire `.claude/skills` discovery, commit each task atomically, update
  ACTIVE.md, push.
