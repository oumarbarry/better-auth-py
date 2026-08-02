# Design — docs site (VitePress, space theme) + better-auth-server skill

Approved by user 2026-08-02 ("GOOOO") after section-by-section review.

## 1. Architecture

- **Site**: `docs-site/` in this repo. VitePress, deployed by the user on
  Vercel (root directory = `docs-site`, VitePress preset). Docs version with
  the code — single source of truth.
- **Skill**: `.agents/skills/better-auth-server/` (+ relative symlink in
  `.claude/skills/`, same pattern as the Astral skills). Installable via
  `npx skills add oumarbarry/better-auth-py`; mirror to a dedicated repo
  later only if skills.sh indexing requires it.

## 2. Site content (v1 — "Option A", ~9 pages)

- **Home**: space hero + 3 killer facts (full parity v1.6.25 / 35 providers,
  26 plugins / same DB as a TS server) + the 20-line quickstart.
- **Guide**: Getting Started · Core Concepts (sessions, adapters, plugins,
  what "TS parity" means) · Configuration.
- **Migrate**: From Node/TS — the "same database, users keep sessions" angle.
- **Plugins**: ONE index page, 26 cards, each = one sentence + config snippet.
- **Providers**: ONE index page, 35 providers, name-keyed config + custom
  provider example.
- **Deploy**: Production (uvicorn/Vercel, secrets, rate limiting, trusted
  proxy headers, dynamic base_url).

Two sidebar groups, prev/next everywhere, GitHub + PyPI in the navbar.
Full per-plugin/per-provider reference pages are OUT of v1 (iteration 2 if
demand shows).

## 3. Space theme & UX

Default VitePress theme, deeply customized (keeps proven docs UX: local
search, sidebar, mobile). NOT a from-scratch theme.

- Dark-first: near-black blue background, nebula accent gradient
  (indigo→violet→cyan) on links/buttons/active borders. Light mode still
  polished.
- Hero: lightweight canvas starfield (~60 lines, subtle scroll parallax),
  gradient-animated title, quickstart as a floating code block.
- Micro-details: soft glow on plugin cards at hover, custom scrollbar,
  code-block theme consistent with the launch image (quickstart-rayso.png).
- Non-negotiable UX: local search enabled; `prefers-reduced-motion` →
  static starfield; AA contrast; Lighthouse perf ~100 (canvas idle-scheduled,
  zero external animation libs — native CSS + canvas only).

## 4. The skill (one, coherent)

`better-auth-server` — one dense SKILL.md (~150 lines: project detection,
uv/pip install, minimal BetterAuth config, FastAPI mount, protecting routes,
the 5 classic mistakes) + progressive disclosure via `references/`:
`plugins.md`, `providers.md`, `security.md`, `migrate-from-ts.md`.
An agent loads the core; reads a reference only when the task needs it —
deliberately the opposite of better-auth's 8 flat skills, aligned with
Claude-5 context-engineering guidance.

**Accuracy rule**: every code sample in the skill MUST be executed against
the installed package before shipping (wrong API in a skill = mass agent
confusion).

## 5. Verification

- Site: `vitepress build` passes (dead links fail the build) + a docs CI job.
- Skill: exercised by a fresh agent following it on a blank FastAPI project
  (the skill's runnable check is an agent executing it).
