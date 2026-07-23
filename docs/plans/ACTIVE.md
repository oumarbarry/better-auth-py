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
- [x] 05-plugins-core.md — two-factor, admin, organization+access, multi-session, jwt, generic-oauth, device-authorization (Opus) — DELIVERED (checkbox was stale; covered by Phase 0 completion below)
- [x] 06-plugins-advanced.md — DELIVERED (await Fable validation). Key finding: oidc-provider & mcp are @deprecated in v1.6.23, successor = standalone `oauth-provider` pkg. Ecosystem reco: IN = api-key, passkey, oauth-provider; PARTIAL = sso (OIDC yes, SAML out); OUT = scim, stripe, expo/electron/cli.

Done-condition: all 6 spec files exist, validated by Fable (spot-check claims
against TS source), gap items consolidated into Phase 1+ waves below.

## Phase 0 status: COMPLETE — all 6 specs delivered and Fable-validated
(8 wire-critical claims spot-checked against TS source, all confirmed:
verify-password shape, jose JWT email-verification, scopes[], adapter
transaction/updateMany/count, 35 providers, oidc-provider @deprecated,
XChaCha20-Poly1305, exact error-code strings.)

## Wave 1 — Core foundation (branch parity/v1.6.23)

Two parallel tracks (disjoint files), sequential within each track.
Every task: TDD, full test gate (`uv run pytest && uv run ruff check . && uv run ty check`),
one atomic Conventional Commit incl. ACTIVE.md checkbox update.

**Track DB** (spec: gap/02-db-layer.md — task = its gap item numbers):
- [x] W1-A1: DONE, validated, commit 2795c45 (147-test gate green). Accepted
      deviations to carry into A2/E: (a) caller-supplied id kept (strip-unless-
      forceAllowId moves to internal-adapter seam in A2), (b) advanced.database
      passed to adapter ctor, rewire through BetterAuth options in A2/E,
      (c) generate_id="serial" stubbed → returns None (ponytail note in code),
      (d) filter_output_fields/parse_account_output provided but not yet wired
      into endpoints (W1-E), (e) String(255) kept for MySQL unique-index safety.
- [ ] W1-A2 (Opus high, after A1): internal-adapter seam (5) + databaseHooks (4)
      + SecondaryStorage protocol (7) + rateLimit table (9) + shared adapter
      test suite port (11).

**Track HTTP** (spec: gap/01-core-http.md — task = its gap item numbers):
- [x] W1-B (Sonnet medium): DONE, validated, commit 1edbaa7. Interim
      scope-blacklist in /list-accounts to be replaced by parse_account_output
      in W1-E. BODY_MUST_BE_AN_OBJECT unreachable (INVALID_BODY fires earlier
      in types.py) — revisit in W1-E if parity of that code matters.
- [x] W1-C: DONE, validated, commit 98bcfab. Notes: change-email JWT branch
      (updateTo) minted but /verify-email's change-email path lands in W1-D;
      "reuse existing session" refinement for autoSignInAfterVerification
      deliberately skipped (revisit W1-F if parity-relevant).
- [x] W1-A2: DONE, validated, commit 4a3ae2c. Notes: hook signature is
      before(data)/after(payload) single-arg (no ctx object yet — W1-E may
      widen); secondary storage wired in seam only; endpoints not yet routed
      through the seam (W1-E).
- [x] W1-D: DONE, validated, commit 463a919. Fable merge-fix: BetterAuth now
      takes user= (UserOptions) directly; getattr shim removed. Deferred:
      afterEmailVerification hooks + additionalFields allowlist (W1-E/F),
      /account-info data:{} until Wave 2 refresh machinery. Verified against
      TS: delete-user main path cascades sessions only, callback path also
      cascades accounts (update-user.ts:552 vs 649-651).
      /delete-user, /delete-user/callback, /account-info, /update-session
      (item 8 minus link-social/refresh-token/get-access-token → Wave 2).

**Merge point** (both tracks done):
- [x] W1-E: DONE (2 agents — first died at weekly API limit mid-refactor,
      continuation finished it). TS-shaped plugin contract, schema-driven
      output parsing (blacklist deleted), endpoints + session.py + oauth.py
      routed through InternalAdapter seam, options.hooks + databaseHooks
      wired. SECURITY FIX validated: /update-session now enforces
      parse_session_input allowlist; input:false raises FIELD_NOT_ALLOWED
      (verified vs db/schema.ts:155). databaseHook call site adapts to (data)
      or (data, ctx) arity.
- [x] W1-F: DONE (2 agents; continuation after stall), commit f6aabd9.
      243 tests. Origin-check truthiness bypass fixed pre-commit (per-path
      skip tests green). WAVE 1 COMPLETE.
      Deferred leftovers (backlog, fold in later): dynamic base_url
      ({allowedHosts}), secrets rotation, telemetry/logger config groups,
      advanced.ipAddress (ipAddressHeaders/trustedProxies/ipv6Subnet — matters
      for prod rate-limiting; schedule with Wave 3).

## Wave 2 — Social providers (spec: gap/03-social-oauth.md)
- [x] W2-A: DONE (2 agents; continuation after connection-drop crash), commit
      0ba150c, 262 tests. oauth/ package with declarative ProviderConfig.
      Deferred (spec-optional): stateless cookie state strategy,
      storeAccountCookie, oauth-signup verification email (flag for parity
      review). Token encryption is AES-GCM $bap$ (not TS-XChaCha20-compatible —
      revisit in Wave 4 crypto task which ports symmetricEncrypt).
- [x] W2-B: DONE, commit 0d36a03, 406 tests. All 32 providers ported via 6
      parallel group agents (G1-G3 Sonnet, G4-G6 Opus), ZERO merge conflicts
      (disjoint files by design). PROVIDER_REGISTRY exposes all 35.
      Backlog: name-based provider config (socialProviders:{github:{...}})
      ergonomics — BetterAuth takes instances today.
      Security: 2 IDOR in refresh/get-access-token fixed pre-merge (21bc8c7);
      cookie-cache timing side-channel fixed (c541260).

## Wave 3 — Simple plugins (spec: gap/04-plugins-simple.md)

Spec foundation items 1–10 reconciled against post-W1/W2 code (2026-07-23):
init()+databaseHooks, matched hooks, plugin rate-limit rules, field attrs
(input/returned/default/field_name/sortable), additional_fields +
parse_user_input/output, get_session(disable_refresh), verification CRUD
helpers, symmetric_encrypt (AES-GCM interim), fresh_age gate — ALL already
exist. additional-fields plugin: core support done (W1-E); client-only
inference N/A in Python → no port. open-api stays deferred (end of Wave 5).

- [x] W3-A: DONE, validated, 437 tests (31 new). All 10 items landed; Fable
      spot-checked consume vs TS internal-adapter.ts:1254 — TS gates expiry
      (expired row deleted, returns null; dispatch prompt's guess was wrong,
      agent followed TS correctly), per-identifier lock = TS
      withVerificationConsumeLock. Race test proven load-bearing (25 winners
      without lock → 1 with). API names for W3-B: consume_verification_value /
      update_verification_by_identifier / delete_verification_by_identifier /
      revoke_unproven_account_access (internal_adapter), generate_otp /
      generate_random_string(alphabet=) / default_key_hasher (crypto),
      ctx.new_session, add_expose_headers (plugins.py),
      auth.password_checks + hash_password_checked, Field.transform_input,
      build_cookie(http_only=), plugin routes shadow core.
      Backlog (parity edges, later wave): TS verification via secondaryStorage
      when storeInDatabase=false; verification.storeIdentifier hashing —
      Python is DB-backed only for verification.
- [ ] W3-B (after W3-A): 11 plugins via 6 parallel group agents, disjoint
      files only — src/better_auth/plugins_ext/<name>.py +
      tests/plugins/test_<name>.py; plugins_ext/__init__ wiring = orchestrator
      merge commit (W2-B pattern, zero conflicts by design).
      G1 Sonnet: bearer(resp-side) + last-login-method + custom-session;
      G2 Sonnet: anonymous + one-time-token; G3 Opus: username + magic-link;
      G4 Opus: phone-number; G5 Opus: email-otp;
      G6 Sonnet: captcha + haveibeenpwned.

## Wave 4 — Hard plugins (spec: gap/05-plugins-core.md)
- [ ] Crypto primitives first (XChaCha20 symmetricEncrypt `$ba$` envelope,
      TOTP, JWKS EdDSA + exact privateKey storage) — MUST resolve the 2
      BLOCKED cross-runtime items (fetch @better-auth/utils source, byte-parity
      test vs @noble/ciphers) before coding.
- [ ] access-control subsystem → two-factor, admin, organization (XL,
      sub-phased), multi-session, jwt, generic-oauth, device-authorization.

## Wave 5 — Advanced plugins (spec: gap/06-plugins-advanced.md)
- [ ] oauth-popup, siwe, one-tap, oauth-proxy; oauth-provider pkg (subset,
      replaces deprecated oidc-provider/mcp per decision log); open-api.

## Wave 6 — Ecosystem (pending user IN/OUT confirmation; default from spec 06)
- [ ] api-key, passkey (webauthn lib), sso-OIDC. OUT: scim, stripe, SAML.

## Security findings (from background commit review)

- 2026-07-22 CONFIRMED: /update-session (commit 463a919) accepted arbitrary
  non-core session fields — priv-esc vector vs TS's parseSessionInput
  allowlist. Fix folded into W1-E's item-12 scope (message sent to the running
  agent): parse_session_input schema-driven allowlist + tests. Validate before
  W1-E commit.

- 2026-07-23 CONFIRMED (uncommitted code): origin.py truthiness bug —
  disable_origin_check as non-empty list (per-path skip) disabled the origin
  check globally. Fix folded into W1-F-bis (message sent). Gate before commit:
  per-path skip tests must exist and pass.

- 2026-07-23 FIXED c541260: cookie_cache.py compared HMAC signatures with `!=`
  (timing side-channel). Now hmac.compare_digest + type guard. Fixed directly
  by orchestrator (file unowned by any live agent).

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

- 2026-07-22: JWT dependency = `pyjwt` (HS256 now; add `cryptography` only when
  EdDSA/RS256 lands in waves 2/4). Boring, ubiquitous, EdDSA-capable.

- 2026-07-23 (Wave 3 kickoff, spec-04 open questions resolved by defaults):
  Q1 → (b) path-aware overridable password-hash seam (no full ctx.password
  refactor); Q2 → (c) open-api deferred; Q4 → plugin routes shadow core
  (order swap, semantic change flagged for review); Q5 → build_cookie gains
  attribute overrides; Q6 → already done (disable_refresh exists); Q8 →
  sensitive session middleware = existing fresh_age gate, no new variant.

## Parked questions (batch for user)

- Python client library (httpx-based createAuthClient equivalent) — wanted?
- Ecosystem packages (api-key, passkey, sso, scim, stripe, oauth-provider):
  confirm IN/OUT after agent 06's recommendation lands.
