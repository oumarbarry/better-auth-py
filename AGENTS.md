# better-auth-server — agent instructions

Server-side Python port of [better-auth](https://github.com/better-auth/better-auth)
(TypeScript), at full parity with **v1.6.23**. PyPI package: `better-auth-server`;
import name: `better_auth`.

## Prime directive: wire & storage parity

The TS repo is canonical (local reference: `../better-auth`, pinned to tag
v1.6.23). Any behavior touching the wire or storage must match it exactly:
same routes, JSON shapes, error-code strings, camelCase DB columns, and
crypto/token encodings. A TS server and this port must stay interchangeable
on the same database. When in doubt, read the TS source and anchor your
change to file:line in the commit or comment.

Cross-runtime crypto vectors in tests (scrypt, XChaCha20-Poly1305, JWK,
HOTP/TOTP) are sacred — never regenerate or "fix" them.

## Commands

- Always `cd` into the repo first (the shell cwd can reset to the parent
  directory; symptom: ~300+ pytest collection errors from sibling repos).
- Full gate, required before claiming anything done:
  `uv run pytest -q && uv run ruff check . && uv run ty check`
- ruff and ty must pass on **test files too**, not just `src/`.
- Package management is uv only (`uv add`, `uv run`, `uv lock`). Build:
  `uv build`.

## Non-obvious pointers

- Plugins live in `src/better_auth/plugins_ext/` (not `plugins/` — that
  name is taken by the plugin *framework* module `plugins.py`).
- `docs/plans/ACTIVE.md` holds the parity campaign's decision log — check
  it before re-litigating a design choice. Its historical commit hashes
  predate a history rewrite and no longer resolve.

## Conventions

- TDD: test first against the TS-anchored expectation, then implement.
- Deliberate simplifications carry a `ponytail:` comment naming the ceiling
  and the upgrade path.
- Conventional Commits (`feat:`, `fix:`, `chore:`, `docs(scope):` …).
- No new dependencies without strong justification; stdlib first.
- Deviations from TS behavior must be deliberate, documented where they
  live, and never wire/storage-visible.
