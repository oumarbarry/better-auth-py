# Contributing

Thanks for helping build better auth for Python. Here is what you need.

## Setup

The project uses [uv](https://docs.astral.sh/uv/):

```bash
uv sync --all-extras
uv run pre-commit install   # runs ruff before each commit
```

## Checks

CI runs these on every PR (tests on Python 3.10 through 3.14), so run them locally first:

```bash
uv run pytest
uv run ruff check .
uv run ruff format --check .
uv run ty check
```

## Guidelines

- The TypeScript [better-auth](https://github.com/better-auth/better-auth) implementation is the reference. Routes, JSON shapes, error codes and storage formats follow it; if you want to diverge, open an issue first so we can discuss it.
- Bug fixes and features need tests. The suite is end-to-end: it drives a real FastAPI app over ASGI, so test the behavior a user would see.
- Keep dependencies minimal. The core depends on `httpx` only; framework and ORM support lives behind extras.
- Update `CHANGELOG.md` (the Unreleased section) when you change public behavior.

## Commits

Commits follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/):

```
feat(oauth): add GitLab provider
fix(session): skip refresh for dont_remember sessions
docs: clarify the adapter protocol
test(security): cover protocol-relative callback URLs
chore: bump ruff
```

Use `feat!:` or a `BREAKING CHANGE:` footer for breaking changes. PRs target `main`.
