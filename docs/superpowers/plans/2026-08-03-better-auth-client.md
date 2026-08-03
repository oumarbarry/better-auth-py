# better-auth-client — implementation plan

Spec: docs/superpowers/specs/2026-08-03-better-auth-client-design.md.
Orchestration: one implementer agent (files disjoint from everything
else), Fable validates + commits. No code before this plan existed —
honored.

## Phase 1 — workspace + core client (one agent)

Ownership: `packages/better-auth-client/**` (new), root `pyproject.toml`
(workspace table + pytest testpaths + dev-group additions only),
`uv.lock`.

1. Workspace scaffold: member pyproject (PyPI `better-auth-client`,
   import `better_auth_client`, httpx dep, uv_build backend), root
   workspace table, root pytest collects the member's tests.
2. Endpoint catalog + `_call` duo (`AuthClient`/`AsyncAuthClient`),
   sessions (cookie jar, bearer capture/set), Origin default, APIError.
3. Core namespaces (spec list), then the 7 plugin namespaces read from
   `plugin.routes()` — snake_case mirror, nothing invented.
4. Device-flow helper with interval/slow_down handling.
5. Tests: ASGITransport/FastAPI (async) + WSGITransport/Flask (sync)
   against one in-process server fixture; per-namespace e2e, error
   shapes, bearer, device approve/deny.
6. Gate: full repo gate green (pytest incl. new package, ruff,
   format --check, ty — tests included). No commits by the agent.

## Phase 2 — release (Fable, after validation)

CHANGELOG (package-local), version 0.1.0, `client-v*` workflow file,
user registers the PyPI pending publisher, tag, publish, smoke-test
install in a fresh venv against a PyPI-installed better-auth-server.

## Phase 3 — increments (later)

Remaining plugin namespaces batch-wise; docs-site page at first release.
