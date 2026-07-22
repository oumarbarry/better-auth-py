# ACTIVE — Full parity with better-auth v1.6.23

Orchestration per `_plato/framework/ORCHESTRATOR.md`: Fable plans/routes/validates,
Opus/Sonnet/Haiku implement. State lives HERE — on resume, read this file first and
continue from the first unverified task.

**Parity target:** better-auth `v1.6.23` (latest npm stable; local reference repo
`../better-auth` pinned to tag v1.6.23, commit 9dfceee14).
**Prime directive:** wire/storage fidelity — same routes, JSON shapes, error-code
strings, camelCase DB columns, exact crypto/token encodings (cross-runtime compat).
**Baseline (2026-07-22):** 84 tests green, ruff clean, ty clean, v0.1.0.

## Phase 0 — Gap analysis (IN PROGRESS)

6 background agents writing specs to `docs/plans/gap/`:

- [x] 01-core-http.md — DELIVERED (await Fable validation). Wire-compat BUGS in current port: /verify-password shape, /list-accounts scopes[], email-verification must be HS256 JWT (not DB token), sign-up enumeration protection, revoke-session semantics. 8 core endpoints missing. Structural: plugin contract, databaseHooks, cookie cache, rate-limit backends, onAPIError, CSRF/origin hardening. 17 ordered gap items, 5 BLOCKED w/ defaults.
- [x] 02-db-layer.md — DELIVERED (await Fable validation). Headline gaps: adapter contract ~half (missing count/updateMany/delete/transaction/sortBy/limit/select…), no transform/parse layer, no databaseHooks, no secondary storage, no advanced.database opts, schema Field lacks returned/input/onUpdate/onDelete. 2 BLOCKED items recorded in spec.
- [x] 03-social-oauth.md — DELIVERED (await Fable validation). 35 providers in TS vs 3 in Python (32 to port; the 3 existing are incomplete). Machinery gaps: token refresh, JWKS/id-token verify (blocks 9+ providers), account-linking decision tree, per-provider PKCE, stateless-cookie state strategy, SSRF guard on outbound fetches. 16 machinery items + 32 provider ports, no BLOCKED.
- [x] 04-plugins-simple.md — DELIVERED (await Fable validation). All 13 specced. Shared foundation blockers: plugin init()+databaseHooks, atomic consume_verification_value, OTP crypto helpers, schema field attrs, additionalFields core support. Reco: defer open-api (needs route-metadata registry). 8 open questions w/ defaults.
- [ ] 05-plugins-core.md — two-factor, admin, organization+access, multi-session, jwt, generic-oauth, device-authorization (Opus)
- [x] 06-plugins-advanced.md — DELIVERED (await Fable validation). Key finding: oidc-provider & mcp are @deprecated in v1.6.23, successor = standalone `oauth-provider` pkg. Ecosystem reco: IN = api-key, passkey, oauth-provider; PARTIAL = sso (OIDC yes, SAML out); OUT = scim, stripe, expo/electron/cli.

Done-condition: all 6 spec files exist, validated by Fable (spot-check claims
against TS source), gap items consolidated into Phase 1+ waves below.

## Phases 1+ — Implementation waves (TO BE PLANNED after Phase 0)

Provisional wave shape (will be rewritten from the specs):
1. Core upgrades: plugin architecture (TS-shaped), hooks, rate limiting, cookie
   cache, secondary storage, missing account routes (change-email, delete-user,
   link/unlink-social, refresh-token, get-access-token), full options surface.
2. Social providers fan-out (mechanical, per-provider).
3. Simple plugins.
4. Hard plugins (two-factor, admin, organization, jwt, multi-session, generic-oauth, device-authorization).
5. Advanced plugins (oidc-provider, mcp, siwe, one-tap, oauth-proxy/popup).
6. Ecosystem packages per IN/OUT scoping decision.

Each validated task = one atomic Conventional Commit, test gate before commit.

## Decision log

- 2026-07-22: Parity target pinned to v1.6.23 (v1.7.0 is RC-only, not stable).
- 2026-07-22: Server-side parity only; the JS `client` package (browser
  createAuthClient), expo/electron/cli packages are OUT. A Python httpx client
  is a parked question, not in scope now.
- (project, standing) TS repo is canonical; better-auth-rs secondary only.

- 2026-07-22 (Fable ruling, revisitable): skip porting @deprecated oidc-provider &
  mcp plugins; port their successor `oauth-provider` package instead. Rationale:
  porting code upstream is removing = wasted parity. Listed in parked questions
  for user confirmation; work proceeds on this default.

## Parked questions (batch for user)

- Python client library (httpx-based createAuthClient equivalent) — wanted?
- Ecosystem packages (api-key, passkey, sso, scim, stripe, oauth-provider):
  confirm IN/OUT after agent 06's recommendation lands.
