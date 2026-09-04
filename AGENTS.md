# Better Auth for Python: agent instructions

Python port of [better-auth](https://github.com/better-auth/better-auth)
(TypeScript). One uv workspace, two published packages:

- repo root: `better-auth-server` (import name `better_auth`), at full
  parity with better-auth **v1.6.29**;
- `packages/better-auth-client`: the Python HTTP client, with its own
  version, changelog and release tags.

The docs site lives in `docs-site/` (VitePress). `npm run docs:build` there
validates internal anchors and regenerates `llms.txt`/`llms-full.txt`.

## Prime directive: wire & storage parity

The TS repo is canonical (local reference: `../better-auth`, pinned to tag
v1.6.29). Any behavior touching the wire or storage must match it exactly:
same routes, JSON shapes, error-code strings, camelCase DB columns, and
crypto/token encodings. A TS server and this port must stay interchangeable
on the same database. When in doubt, read the TS source and anchor your
change to file:line in the commit or comment.

Cross-runtime crypto vectors in tests (scrypt, XChaCha20-Poly1305, JWK,
HOTP/TOTP) are sacred: never regenerate or "fix" them.

## Rules of work

- Every change goes through a worktree/branch, never directly on main.
  Merging is the user's decision, taken on demonstrated evidence (full
  gate plus proof of behavior).
- Ship a pending patch release before merging the next feature. The server
  and the client are versioned independently (each bumps only when its own
  content changes). Server releases tag `v*`, client releases `client-v*`;
  both publish to PyPI through trusted publishing from GitHub Actions.

## Commands

- Always `cd` into the repo first (the shell cwd can reset to the parent
  directory; symptom: ~300+ pytest collection errors from sibling repos).
- Full gate, required before claiming anything done:
  `uv run pytest -q && uv run ruff check . && uv run ruff format --check . && uv run ty check`
  (CI's lint job runs `ruff format --check` too; omitting it locally is how
  48 files once drifted and broke CI for several commits.)
- ruff and ty must pass on **test files too**, not just `src/`.
- Package management is uv only (`uv add`, `uv run`, `uv lock`). Build:
  `uv build`.
- Optional for contributors' agents: Astral's ruff, ty and uv guides install
  with `npx skills add astral-sh/claude-code-plugins`.

## Non-obvious pointers

- Plugins live in `src/better_auth/plugins_ext/` (not `plugins/`; that
  name is taken by the plugin *framework* module `plugins.py`).
- The client package's tests live in `packages/better-auth-client/tests/`
  and run as part of the root pytest gate.

## Conventions

- TDD: test first against the TS-anchored expectation, then implement.
- Deliberate simplifications carry a `ponytail:` comment naming the ceiling
  and the upgrade path.
- Conventional Commits (`feat:`, `fix:`, `chore:`, `docs(scope):` …).
- No new dependencies without strong justification; stdlib first.
- Deviations from TS behavior must be deliberate, documented where they
  live, and never wire/storage-visible.
- User-facing prose (docs, readmes, error messages) follows the
  `anti-ai-slop` skill (`.agents/skills/anti-ai-slop/`); invoke it before
  writing or editing that text.
