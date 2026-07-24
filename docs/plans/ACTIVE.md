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
- [x] W3-B: DONE, 752 tests (314 plugin tests across 11 plugins), full gate
      green, ZERO merge conflicts (disjoint files by design). All 6 groups
      returned complete, TS line-verified, no hard blockers. Concurrency
      single-winner tests present for magic-link/OTT/phone-number/email-otp.
      Merge-window fixes by orchestrator (files unowned at that point):
      (a) endpoints.py sign-up now hashes/checks BEFORE create_user (G6
          security finding — orphaned user row on rejected password) +
          regression assertion; (b) anonymous delete-anonymous-user gate
      fixed to authoritative get_session(disable_cache=True) per G5's TS
      correction (sensitive ≠ fresh; Fable's G2 dispatch instruction was
      wrong) + stale-session regression test; (c) EmailVerification.
      send_on_sign_in added (G3 soft-blocker, option A); (d) plugins_ext
      __init__ exports all 11. Attempted Plugin.schema ClassVar→instance
      "root fix" REVERTED — subclasses legitimately use ClassVar and G3's
      annotated instance declarations already pass ty; base stays ClassVar.
      Accepted deviations (ponytail-noted in code): sendOTP await-then-
      suppress; phone-number/anonymous schema-remap kwargs dropped;
      OTT plain-message errors as {code:"BAD_REQUEST"}; server-only
      email-otp endpoints unmounted + exposed as methods; require_signature
      strips unsigned bearer header pre-core-read; custom-session drops TS
      type-inference-only ctor arg; magic-link errors always redirect
      (spec's "plain 400" didn't exist in TS).
      BACKLOG (fold into later waves): thread ctx into create_session's
      session databaseHooks (last-login-method works around via after-hook);
      EmailVerification.before/after_email_verification config fields
      (email-otp reads via getattr); encrypted store_otp → TS XChaCha20 in
      Wave 4; TS verification-via-secondaryStorage + storeIdentifier hashing;
      name-based plugin/provider config ergonomics.

## Wave 4 — Hard plugins (spec: gap/05-plugins-core.md)

2 BLOCKED crypto items RESOLVED 2026-07-23 by orchestrator with ground truth:
installed better-auth@1.6.23 + @better-auth/utils + @noble/ciphers via npm in
scratchpad, read published sources, generated cross-runtime vectors by running
the REAL TS implementation (scratchpad/w4-vectors/vectors.json; to be
hardcoded into tests). Facts: symmetricEncrypt key=SHA-256(secret utf8),
managedNonce(xchacha20poly1305) output = 24B nonce || ct || 16B tag, HEX
string; bare hex for string key, `$ba$<version>$<hex>` envelope only for
versioned SecretConfig. createOTP = plain RFC-4226 HOTP: SHA-1 default,
utf8-string HMAC key, 8-byte BE counter, digits 1–8 (default 6), period 30,
verify window ±1, constant-time compare; otpauth URL secret = base32-nopad.
HMAC helper: utf8 key/data, hex + base64url(nopad) encodings.

- [x] W4-A: DONE, validated, 785 tests (+33). XChaCha20-Poly1305 via pynacl
      ($bap$ AES-GCM deleted outright, zero references left), TOTP/HOTP/
      otpauth_url in crypto.py, Ed25519 JWK pair + encode/decode_jwk_private_
      key (privateKey column = JSON.stringify(symmetricEncrypt(JSON JWK)),
      verified jwt/utils.ts:63,73-81). BIDIRECTIONAL parity proven by Fable:
      JS→Python via hardcoded vectors AND Python→node (real better-auth
      1.6.23 symmetricDecrypt, UTF-8 payload) — CROSS-RUNTIME OK.
      One agent connection-drop mid-run; resumed via SendMessage, no rework.
      Accepted deviations: digit-bounds raise ValueError (TS TypeError,
      no wire impact); envelope decrypt surface = optional keys dict
      (port has no SecretConfig yet — secrets-rotation backlog).
Spec-05 "Phase 0" reconciled against landed code (2026-07-24, Fable audit):
consume_one, guarded increment_one, all where ops, HMAC b64urlnopad,
constant-time compare, internal-adapter session/user/verification helpers,
plugin framework, schema attrs — ALL exist (W1–W4-A). Remaining core gap =
4 admin-only internal-adapter helpers (list_users w/ query surface,
count_total_users, update_password, link_account-if-missing) → folded into
the admin agent's ownership (sole consumer, no separate dispatch).

- [x] W4-C/W4-D: DONE — all 7 hard plugins + access-control ported, 1162
      tests total (AC 51, jwt 42, two-factor 41, multi-session 17,
      generic-oauth 50, device-authorization 48, admin 64 + 7 internal-adapter
      helpers, organization-core 54, 3 merge-window regressions), full gate
      green, zero merge conflicts. 3 agent connection drops/stalls, all
      resumed via SendMessage without rework. Agents corrected two Fable
      prompt errors (no TS discovery cache; no organizationCreation option)
      and found 3 core bugs, fixed in the merge window: (e) check_origin now
      parses form-urlencoded bodies (form_post callbacks; malicious form
      callbackURL still validated), (f) memory-adapter in/not_in no longer
      lowercases row values case-sensitively, plus the JS-truthiness
      empty-array divergence caught in AC. internal_adapter gained
      list_users/count_total_users/update_password (admin agent, sole owner).
      Key accepted deviations (ponytail-noted in code): device-auth
      OAuth-shaped wire errors + CAS-hardened lastPolledAt; jwt EdDSA-only,
      custom jwks adapter skipped; two-factor sign-in gate pure-hook (no
      endpoints.py change); impersonation session hand-built (create_session
      lacks overrideAll); org server-only sessionless branch deferred.
      BACKLOG: SQLAlchemyAdapter lacks insensitive mode for "in" op;
      secrets rotation/SecretConfig; server-API surface for sessionless
      create/addMember; flow._create_state requestSignUp slot.
- [x] Organization phase 2 invitations: DONE, 40 new tests (94 org total),
      1202 suite green at its solo gate. CAS-guarded accept
      (updateInvitation fromStatus:pending), verified-email gates, 8
      invitation hooks (types.ts:584-661), sendInvitationEmail payload
      asserted, delete cascade + full-org population. Ponytail: email send
      awaited inline (TS runInBackgroundOrAwait); accept CAS instead of
      transaction+rollback. Seams: teamId/team branches -> phase 3;
      dynamicAccessControl role lookup on invite -> phase 4.
- [x] Organization phases 3+4: DONE — teams committed 6bec82c (40 tests);
      dynamic AC committed (27 tests, org suite 161, full 1371 green).
      organizationRole table (permission singular, JSON-string), 5 role
      endpoints, union-merge precedence (dynamic AUGMENTS same-named static
      role, never shadows — has-permission.ts:65-68), ac instance required
      (MISSING_AC_INSTANCE 501), both unknown-role SEAMs consult dynamic
      roles, 16 DAC error strings byte-exact. ORGANIZATION PLUGIN CLOSED
      vs TS v1.6.23. BACKLOG: missingPermissions[] error-body array (needs
      types.py/auth.py APIError extension); cacheAllRoles optimization.

## Wave 5 — Advanced plugins (spec: gap/06-plugins-advanced.md)

Spec's "runtime items 1–5" ALL exist already (checked 2026-07-24): plugin
system (W1-E), atomic consume (W3-A), crypto incl. PKCE/b64url/charset/
constant-time (W2/W4-A), JWT machinery + jwt plugin (W4), signed cookies +
origin check (W1). Straight to plugins.

- [x] W5-A: DONE — one-tap da779b1 (26 tests, GHSA-9502 regressions,
      maxTokenAge 1h), oauth-popup 5033c71 (15 tests, completion script
      byte-exact, sha256 CSP pin == TS constant), siwe 17628b2 (61 tests,
      ERC-4361 parser verbatim w/ all TS vectors, EIP-55 via pycryptodome
      real Keccak-256, atomic nonce). plugins_ext exports wired (21 plugins).
      Session-limit outage mid-volley: 3 agents died, all resumed to
      completion without rework (oauth-popup was 3 lint items from done).
- [x] W5-B: oauth-proxy DONE+committed (28 tests; suite 1399 whole-tree
      green). Vendor-env URL resolution, x-skip-oauth-proxy, sign-in
      rewrite + state re-encryption under the proxy key, replay-window
      guard, open-redirect guards line-verified (foreign/protocol-relative/
      javascript: all rejected; untrusted request-origin falls back to base
      URL — all 3 TS tests replicated). Ponytail divergences: no per-request
      base_url mutation (shared-instance concurrency hazard; configure
      provider redirect_uri to production instead — upgrade path = per-
      request redirect_uri seam in oauth/flow.py); DB state strategy only.
- [x] W5-C spec: docs/plans/gap/07-oauth-provider.md committed 446e59f
      (747 lines, 20 items, 4 sub-phases A-D). Decision (defaults adopted):
      EdDSA-first, reject disableJwtPlugin + non-EdDSA algs at init; hashed
      client secrets first (encrypted blocked on secrets-rotation backlog);
      client-side helpers (mcpHandler etc.) excluded.
      NEXT: dispatch W5-C phase A (clients + discovery + JWKS) per the spec.
- [ ] W5-C: oauth-provider package subset (XL, replaces deprecated
      oidc-provider/mcp per decision log; sub-phase like organization).
      Phase A (items 1-4,6,7-10: helpers + client schema/CRUD/DCR + discovery)
      DISPATCHED 2026-07-24 (Opus xhigh, background).
- [ ] W5-D: open-api — decide at end of wave (needs route-metadata registry;
      deferred since Wave 3).

## Wave 6 — Ecosystem (USER-CONFIRMED 2026-07-24)
- [ ] W6-specs: gap specs 08-api-key / 09-passkey / 10-sso-oidc (format of 07)
      DISPATCHED 2026-07-24 (3 Opus high agents, parallel, docs-only — no code
      conflict with W5-C-A). 08-api-key DELIVERED+VALIDATED (621 lines; Fable
      spot-checked: defaultKeyHasher=SHA-256→b64url-nopad index.ts:27-35 ==
      port default_key_hasher, 52-char a-zA-Z charset index.ts:129, CAS
      claimUsageInDatabase via guarded incrementOne verify-api-key.ts:244-357,
      verify returns 200 {valid,error,key} never throws — all confirmed).
      Impl-dispatch decisions (defaults adopted): storage:"database" only,
      secondary-storage/customStorage raises NotImplementedError at init;
      deferUpdates → synchronous; legacy double-stringified metadata skip w/
      defensive parse-on-read. Known envelope gap: RATE_LIMITED needs
      details:{tryAgainIn} — port APIError lacks details (same backlog line
      as org missingPermissions[]). One primary agent, single
      plugins_ext/api_key.py. 10-sso-oidc DELIVERED+VALIDATED (580 lines;
      Fable spot-checked: clientSecret PLAINTEXT in JSON oidcConfig blob
      routes/sso.ts:776/802 — hard cross-runtime contract, do NOT encrypt;
      SSRF classifier isPublicRoutableHost/classifyHost oidc/discovery.ts;
      DNS via node:dns discovery.ts:241-251 — all confirmed). Impl decisions
      (defaults adopted): extend shared handle_oauth_user_info w/ trust flags
      (no fork); dnspython dep for TXT + discovery resolve-check; RFC-6890
      host classifier to port; samlConfig column kept nullable-unused for DB
      compat; 12 items / 4 dispatch waves A-D in spec.
      09-passkey DELIVERED+VALIDATED (452 lines; Fable
      spot-checked vs routes.ts: publicKey=padded base64 :686, credentialID=
      base64url credential.id :690, transports join(",") :694, challenge=
      signed cookie + atomic consumeVerificationValue :321-335/578-590 — all
      confirmed). Key findings for impl dispatch: py_webauthn snake_case
      credential_device_type MUST map to camelCase (cross-runtime rows);
      webauthn>=2 dep as [passkey] extra; no freshSessionMiddleware in port
      (default: inline now-createdAt<=fresh_age); rpName default "Better
      Auth"; client-side passkeyClient + authenticator-metadata excluded.
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

- 2026-07-23 FIXED (W3-B merge commit): endpoints.py sign_up_email created
  the user row BEFORE hash_password_checked ran — a rejected password (e.g.
  haveibeenpwned PASSWORD_COMPROMISED) left an orphaned user with no
  credential account; TS hashes first (sign-up.ts:333). Found by G6 during
  TS verification; fixed by orchestrator in the merge window (hash hoisted
  above create_user) + no-orphan-row regression assertion.

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

## Parked questions — ALL RESOLVED (user, 2026-07-24: "applique tes recos")

- Python client library: OUT of scope for this project — server-side parity
  only; a separate httpx client package may exist later.
- Ecosystem Wave 6: IN = api-key, passkey, sso-OIDC; OUT = scim, stripe, SAML.
