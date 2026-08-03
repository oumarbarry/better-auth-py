# ACTIVE — Full parity with better-auth v1.6.23

Orchestration per `_plato/framework/ORCHESTRATOR.md`: Fable plans/routes/validates,
Opus/Sonnet/Haiku implement. State lives HERE — on resume, read this file first and
continue from the first unverified task.

**Parity target:** better-auth `v1.6.25` (latest npm stable; local reference repo
`../better-auth` re-pinned 2026-08-02 to tag v1.6.25, commit 07a646ea1; the
v0.2.0 campaign below was built against v1.6.23 / 9dfceee14).
**Prime directive:** wire/storage fidelity — same routes, JSON shapes, error-code
strings, camelCase DB columns, exact crypto/token encodings (cross-runtime compat).
**Baseline (2026-07-22):** 84 tests green, ruff clean, ty clean, v0.1.0.

## STATUS 2026-07-25: ALL WAVES COMPLETE, BACKLOG FULLY BURNED (B1–B11)

1975 tests, ruff/ty clean, tree clean at 17f6bdd. All planned waves (1–6)
closed and the entire backlog resolved: B1–B10 implemented+validated, B11
(resource param / PAR store / telemetry / logger) closed by Fable ruling —
see the burn-down list and decision log. Spec-07 OQ1 fully resolved (HS256
+ the whole JWKOptions alg union). Release chores v0.2.0 DONE, validated
(version bump + uv.lock, CHANGELOG [0.2.0] themed section, README updated
with verified counts — 26 plugins / 35 providers / 9 adapter methods —,
stale claims removed, broken OAuthProvider sample fixed to real field
names; Fable re-ran full gate 1975/clean/clean and cross-checked every
number). CAMPAIGN COMPLETE — parity with better-auth TS v1.6.23 achieved.
RELEASED 2026-08-02: v0.1.0 AND v0.2.0 live on PyPI as **better-auth-server**
(better-auth-py + better-auth + better-auth-python all taken on PyPI — renamed;
import stays better_auth; future client = better-auth-client, free today).
Trusted publishing via release.yml (tag v* → OIDC, no tokens). parity branch
merged into main at e0a239a, full gate 1975/clean/clean, install-from-PyPI
smoke-tested.

## Catch-up v1.6.23 → v1.6.25 (opened 2026-08-02, user go; EXHAUSTIVE sweep
## of all 60 commits — user instruction: no half-measures)

Triage (Fable, per-commit): 60 commits total. OUT with reasons —
17 docs, 10 chore/deps/release/ci, 3 client pkgs (solid/react lifecycle/
useSession types), 3 cli (drizzle relName, self-import, dup-idx), electron
×2, sveltekit stub, mcp (deprecated, never ported), open-api 4e685eef4
(ruled-out plugin, generator.ts only), cookies d3ce78233 (TS types only),
54fab0844 AsyncLocalStorage dedup (TS runtime; port has no shared-init
race — Ctx is per-request), 29a373eaf sqlite BIGINT (TS migration engine).
VERIFY-ANALOG (agent-checked, not assumed): 750894037 kysely dup unique
indexes → check SQLAlchemy create_tables for the same dup-unique-index
pattern; ef4d27360 Request.clone failures → prove N/A (AuthRequest
dataclass, no clone).

- [x] C1 organization trio + extension: DONE, validated, committed e7326b2
      (170 org tests; Fable re-ran gate + checked hunks vs TS adapter.ts).
      bae71988a = test-only (port's per-id join unbounded by construction;
      regression test PROVEN vs recreated TS pre-fix shape). f59a0ee78
      invitation id deferred to adapter (RED uuid test) — EXTENDED on
      Fable order to member/team/teamMember (same bug class outside the
      diff; org was already correct — agent self-corrected its earlier
      4-site claim). 3bf0e4981 delete hooks get ctx via _call_hook arity
      adapter. Parked follow-up: _users_by_ids N-round-trips perf
      (ponytail-noted in code, upgrade = find_many "in" + limit).
- [x] C2 plugin fixes trio: DONE, validated, committed 33e3069 (149 scoped
      tests green re-run by Fable; hunks checked vs TS anchors). SECURITY:
      email-otp send was origin-bypassable cookieless (RED-proven, OTP
      mailed cross-origin) — now _validate_form_csrf first, == TS
      routes.ts:101 middleware. magic-link needed NO change (port's
      /sign-in prefix rule already covers it — 3 regression tests prove
      it on unmodified source). one-tap reads registered google
      provider's disable_sign_up (index.ts:182; disableImplicitSignUp
      deliberately NOT consulted — matches TS diff). last-login-method
      before_store_cookie ported with TS error-log semantics; cookie-gate
      placement deviation noted (port writes DB+cookie in one _after).
      Note for later: email_otp imports origin._validate_form_csrf
      (module-private) — public alias in origin.py is a 1-liner if wanted.
- [x] C3 core + providers: DONE, validated, committed 5dfb60a (full gate
      2006/clean/clean re-run by Fable; Apple + arity hunks checked vs TS).
      0ffd1fb28 Apple PKCE ported (use_pkce=True + gated verifier; 3 RED
      tests incl. exchange round-trip). c4d1ddaa9 ctx on verify_id_token:
      base + 6 overrides + call_verify_id_token with inspect-arity
      back-compat (existing port precedent; chosen over try/except
      TypeError — a provider-internal TypeError would masquerade as old
      signature). 46d2bf02c ALREADY byte-exact since init (no-store/
      pragma) — pinned by 3 tests; TS's header-leak half N/A. 03dc5a046
      N/A: port has NO modelName remap layer (grep-proven). 750894037
      analog DISPROVEN on emitted DDL (unique+index folds to one Index)
      + non-vacuous regression test. ef4d27360 N/A (buffered dataclass,
      zero clone sites). NEW PARITY GAP LOGGED: TS get-session accepts
      GET+POST, port 405s POST — v1.6.23-era, backlog.
CATCH-UP v1.6.25 COMPLETE (C1-C4 closed): 2006 tests, ruff/ty clean.
RELEASED 2026-08-02: v0.2.1 on PyPI (user "GO" — full sequence: bump +
CHANGELOG + README tagline, gate, tag, trusted-publishing run success,
GitHub release, install-from-PyPI smoke-tested). Backlog: get-session
POST method; _users_by_ids N-round-trips perf; origin.py public
_validate_form_csrf alias. Next big rock: v1.7.0 campaign when stable.
- [x] C4 sso investigation: CLOSED, validated — NO PORT NEEDED. Agent
      classified all 17 hunks of c020a9d6a: every one is SAML-only (new
      idpInitiatedCallbackUrl under samlConfig/saml options, ACS/SLO/
      RelayState redirect pipeline, isSafeSAMLRedirectPath). Fable
      counter-checked: zero OIDC-path additions in shared files; the
      touched routes/sso.ts hunks all sit in SAML branches. sso suite
      170 green on unmodified tree.

Done-condition per item: TS-anchored tests, scoped gate green, ruff/ty
clean incl. tests; Fable validates vs the TS commit diff and commits.
v1.7.0-rc.2 decision: NOT ported now (RC = moving target, decision-log
precedent); 327 files / +45.8k lines — full campaign when 1.7.0 goes
stable. Note: 1.7 deletes oidc-provider & mcp (never ported — ruling
vindicated).

## Docs site + skill (opened 2026-08-02, user "GOOOO" on Option A design)

Spec: docs/superpowers/specs/2026-08-02-docs-site-and-skill-design.md.
Plan: docs/superpowers/plans/2026-08-02-docs-site-and-skill.md.
- [x] SITE: DONE, validated, committed f097ae7 (Fable re-ran clean
      npm ci + build: green, anchors OK across 10 routes). VitePress
      1.6.4, 8 pages (plan's exact list; spec said ~9 — /guide/ index
      possible later), observatory-plate theme under impeccable
      discipline (gradient-text ban honored: solid+size hero; OKLCH
      AA-verified both schemes; card-wall broken into 6 groups),
      zero external deps (Inter bundled, 0 external requests),
      canvas reduced-motion-proven, local search OK, custom
      check-anchors.mjs wired into docs:build. 71 snippets verified
      (live ASGI for quoted JSON). og:url/sitemap conditional on
      VERCEL_PROJECT_PRODUCTION_URL/SITE_URL (no invented hostname).
      Agent found + Fable fixed README's dead hook keys
      (user_created_before/after → hooks {before,after} +
      database_hooks, corrected shape executed).
- [x] SKILL: DONE, validated, committed d561cb2. SKILL.md 199 lines + 4
      references (972 total), 42 blocks / 10 harnesses executed in repo
      AND PyPI-venv, scrypt/HMAC claims proven vs real node crypto.
      BLIND TRIAL PASSED (fresh Sonnet, skill-only docs → working
      per-user auth e2e); its 3 findings folded in (driver callout,
      lifespan/TestClient gotcha reproduced both ways, scoping example).
      Bonus catches committed dbe95ba: __version__ now metadata-derived
      (was 0.1.0 through two releases — published 0.2.1 wheel still has
      the old string, fix ships next release), AGENTS.md → v1.6.25.
- [ ] Validation (Fable): fresh build, snippet spot-checks, fresh-agent
      run-through of the skill on a blank FastAPI project, commits.
User deploys the site on Vercel (root=docs-site) après merge.

## Next-steps wave (opened 2026-08-02, user picked: QW bundle + scout +
## Litestar→Flask→Django; docs-2 + better-auth-client queued after)

- [x] QW: DONE, validated, committed (fix + feat split). Grew beyond
      quick-wins: agent refuted Fable's POST /get-session premise (TS
      405s too, sans deferSessionRefresh) → ported the exact 405, then
      TWO extensions landed defer_session_refresh AND
      disable_session_refresh end-to-end (session-api.test.ts:1835-2107
      mirrored in full, red-green discrimination verified both times).
      _users_by_ids single-query + adapter-spy test; validate_form_csrf
      public seam. Backlog noted: APIError has no header channel (TS
      sets no-store before throwing the 405).
      VERSIONING CORRECTION: the 0.2.2-patch plan died when Litestar
      merged to main first, and defer/disable options are features
      anyway → single v0.3.0 MINOR released instead. Lesson recorded:
      release the patch BEFORE merging the feature.
      RELEASED 2026-08-02: v0.3.0 on PyPI (gate 2031/clean/clean incl.
      format, trusted publishing green, GitHub release, install+import
      smoke-tested with [litestar] extra).
- [x] SCOUT v1.7.0-rc.2: DONE, report committed as
      docs/plans/gap/11-v1.7.0-scout.md. TRUE CORPUS = 169 non-merge
      commits (Fable's 81 was a stale path-filtered count), 968 files,
      +108k/-39k. ~86 IN across 7 work-packages; WP0 = issuer-scoped
      accounts (accountId→providerAccountId + required issuer column,
      the storage migration everything else sits on) MUST go first.
      Campaign-critical flags: (a) TS 1.7 flips trustedProxyHeaders
      default to FALSE on dynamic baseURL — conflicts with shipped B10
      default True, decide flip-vs-documented-deviation at campaign
      time; (b) cimd plugin needs an IN/OUT ruling; (c) WP4 atomics
      may be mostly done already (port's guarded increment_one predates
      TS's hardening) — verify before budgeting XL; (d) granted-scopes
      feature added then REVERTED within the range — net zero, don't
      plan against it. oidc-provider removal upstream = ruling
      vindicated, nothing to delete.
- [x] LITESTAR: DONE, validated, committed (scoped gate re-run by Fable;
      13 tests, ruff/format/ty clean on its files; full-suite green at
      agent time — final full gate rides the v0.3.0 release). 102 lines
      vs FastAPI's 85. Accepted deviations: Litestar 401 body adds
      status_code (framework handler, not wire-visible for auth routes);
      302 carries an ignored content-type; ASGIResponse required for
      repeated Set-Cookie; floor litestar>=2.24 (non-deprecated DI
      spellings); 5-line import guard naming the [litestar] extra
      (no in-repo precedent — new pattern, fine). QW's item-1 premise
      was WRONG (Fable brief error): TS 405s POST /get-session without
      deferSessionRefresh — agent ported the exact TS error instead and
      surfaced the missing defer_session_refresh option; extension
      dispatched (config.py + session.py granted to QW).
      Next in user order: Flask, then Django.
- [x] FLASK: DONE, validated (Fable re-ran FULL gate at CLI: 2046 pass
      = 2031 + 15 new, ruff/format/ty clean — live-IDE ty errors were a
      stale daemon, known precedent). integrations/flask.py 121 lines.
      DESIGN RULING (Fable, pre-dispatch, evidence-based): WSGI→async
      bridge = ONE dedicated event loop in a daemon thread owned by
      BetterAuthFlask, run_coroutine_threadsafe per call. asyncio.run-
      per-request AND asgiref/async_to_sync (what flask[async] uses)
      REJECTED: core caches httpx.AsyncClient (auth.py:286-288) and
      SQLAlchemyAdapter holds a loop-bound AsyncEngine pool — fresh loop
      per call breaks request 2. [flask] extra = flask>=3.0 only, zero
      new deps (stdlib bridge). Agent corrected the dispatch premise:
      aiosqlite is loop-agnostic so the prescribed e2e regression alone
      would NOT catch a bad bridge — test_loop_persists_across_requests
      adds loop-identity asserts, proven failing under asyncio.run.
      Accepted deviations (documented in code/tests): require_session
      401 = Werkzeug HTML page carrying "Not authenticated" (not JSON
      detail); redirect 302 carries Flask default text/html (Litestar-
      class deviation); session helpers are sync reading flask.request
      (no DI in Flask); bare mount path /api/auth/ → framework 404
      (<path:rest> won't match empty; siblings untested there too).
      Ponytail: no close() seam — daemon thread lives with the process.
      RELEASED 2026-08-02: v0.4.0 on PyPI (feat a052e9b, chore(release)
      7865c6f, patch-before-feature rule satisfied — nothing pending on
      main; workflow run green, GitHub release created from CHANGELOG,
      install [flask]==0.4.0 smoke-tested e2e in a fresh venv: sign-up +
      get-session through the wheel, __version__ reports 0.4.0 — the
      metadata-derived fix now live). README updated (extras list +
      framework-agnostic line now names BetterAuthFlask).
- [x] DJANGO: DONE, validated (Fable re-ran FULL gate at CLI: 2063 pass
      = 2046 + 17, ruff/format/ty clean — live-IDE ty errors stale-daemon
      again). integrations/django.py 157 lines, design ruling followed
      (sync views + dedicated-loop bridge, @csrf_exempt with check_origin
      documented as the CSRF layer, [django] extra = django>=5.0, lock
      forks 5.2/6.0 by python version). Set-Cookie repeated-header risk
      RESOLVED cleanly: HttpResponse.headers overwrites dups, so raw
      set-cookie headers go through response.cookies.load() (stdlib
      http.cookies parse — lossless for the core's percent-encoded
      values); Fable verified BOTH installed handlers emit one line per
      morsel (wsgi.py:131, asgi.py:331). Accepted deviations (documented
      in docstrings/tests): require_session RETURNS dict|JsonResponse-401
      instead of raising (Django maps no exception to 401; body ==
      FastAPI's {"detail": ...}); helpers take HttpRequest explicitly;
      .urls list to splat into urlpatterns; Morsel re-sorts cookie
      attribute order (semantics intact); 405 via require_http_methods;
      route pattern strips the leading slash (Django refuses it).
      Agent gotcha finds: Django test client defaults to multipart
      (sign-out test needs content_type json); Morsel stores max-age
      as str. Fable cosmetic fix in merge window: pyproject django
      extra normalized to one line like siblings.
      RELEASED 2026-08-02: v0.5.0 on PyPI (feat 41844f2, chore(release)
      15887c1; patch-before-feature rule satisfied — v0.4.0 was fully
      out before this merge; workflow green, GitHub release created,
      install [django]==0.5.0 smoke-tested e2e in a fresh venv under
      Django 6.0.7 — sign-up + get-session through the wheel; index
      needed one ~15s propagation retry). README updated (extras +
      framework line). FRAMEWORK MATRIX COMPLETE: FastAPI, Litestar,
      Flask, Django. Integration queue empty — next big rocks are the
      user-choice items below (docs-2, better-auth-client brainstorm,
      v1.7.0 campaign when stable).
- [x] DOCS-2: DONE, validated (Fable wired the sidebar in config.mts
      — two collapsed groups — and ran the single docs:build: green,
      anchors OK across 71 pages; agents were forbidden to build, zero
      contention). 26 per-plugin + 35 per-provider pages, both index
      pages rebuilt as hubs, uniform templates, options/routes/schema
      extracted by real introspection (inspect.signature/plugin.routes/
      schema; provider count == PROVIDER_REGISTRY, plugin count ==
      plugins_ext.__all__). 97 snippets executed live (27 plugin Enable
      + 70 provider config forms). Back-compat anchors kept in
      plugins/index.md for #bearer/#oauth-proxy/#generic-oauth (linked
      from guide/deploy/providers pages). Agents fixed 5 stale claims
      in the old indexes (jwt alg union had HS256 — wrong, that's
      oauth-provider's disable_jwt_plugin path only; oauth-provider has
      22 routes not 21; org = 20 core + 9 teams routes; oauth-provider's
      hard JWTPlugin init dependency was undocumented; skill ref
      plugins.md annotates one_time_token expires_in as seconds — it's
      MINUTES (source does *60): skill-ref fix pending, one line).
- [x] Marketing thread aligned (parent dir, out of git): 2063 tests ×3,
      four frameworks ×3 (tweet 2 gained the integrations line).
- Vercel deploy: CONFIRMED WORKING by user 2026-08-03 ("la doc roule
  propre sur vercel"). vercel.json fix ee3c5ea validated in prod.
- better-auth-client: brainstorm CLOSED (user 2026-08-03, 4 answers +
  design approved "let's go"): BOTH usages v0, monorepo uv workspace,
  TS-mirror namespaced surface, sync AND async, device flow IN (Fable
  reco — CLI = RFC 8628's exact audience; server plugin already ported).
  Spec + plan committed 9978b23 (docs/superpowers/specs/2026-08-03-
  better-auth-client-design.md).
- [x] CLIENT PHASE 1: DONE, validated (Fable re-ran FULL gate at CLI:
      2091 pass = 2063 + 28, ruff/format/ty clean — live-IDE ty errors
      stale-daemon again, 3rd occurrence). packages/better-auth-client/
      workspace member: catalog.py (132 lines, pure data, one line per
      endpoint) + client.py (AuthClient/AsyncAuthClient, each implements
      only _call + _device_flow; namespaces generated). 102 entries:
      core 24 + two_factor 8 + organization 34 (incl. teams/dyn-roles,
      conditional server-side) + admin 15 + api_key 5 + magic_link +
      email_otp 9 + device 5 + flow helper. Fable spot-checks: device
      error codes slow_down/authorization_pending/expired_token/
      access_denied match device_authorization.py:300-323 verbatim;
      _next_interval +5s on slow_down == RFC 8628 §3.5. Tests = 14
      scenarios ×2 (ASGITransport/FastAPI async, WSGITransport/Flask
      sync — dogfoods the integrations, in-process, no sockets).
      Workspace frictions solved: tests/__init__.py to avoid conftest
      module-name collision with root tests; [tool.uv.sources]
      workspace=true required for dev-group member. Accepted deviations:
      BearerPlugin added to test fixture (set-auth-token capture needs
      it); device fixture interval="0s" for driven polls.
      NEXT: Phase 2 release client-v0.1.0 — BLOCKED on user action:
      register PyPI pending publisher for better-auth-client (repo
      oumarbarry/better-auth-py, workflow client-release.yml), then
      Fable ships workflow + tag.
- npx skills add oumarbarry/better-auth-py: CONFIRMED working (user).

## Backlog burn-down (started 2026-07-24 on user "continue")

- [x] B1 APIError details wire parity: DONE, validated (Fable pinned TS
      shapes himself: crud-access-control.ts:1201-1205 fromStatus FORBIDDEN
      {message, code, missingPermissions} top-level; verify-api-key.ts:
      293-297 {message, code:"RATE_LIMITED", details:{tryAgainIn}} — port
      diffs match exactly; gate 1642 green on ignore-set + ruff/ty clean).
      APIError gains extra= dict merged top-level, code/message always win.
      Bonus fix: org check now collects ALL missing resource:perm pairs
      (was first-miss-only). Sweep verdict (sub-agent): admin/two-factor
      clean; device-auth + oauth-provider TS {error,error_description}
      already matched by the port's _oauth_error pattern — no action.
- [x] B2 SecretConfig + encrypted client secrets: DONE, validated (30 new
      tests; full gate 1814/clean/clean after Fable merge-window actions:
      applied the auth.py plumbing — secrets=[(version, value)] option →
      resolve_secret_config → self.secret_config, TS create-context.ts:
      169-186 surface — plus 4 ruff fixes + 2 isinstance narrowings in B2's
      test files). Cross-runtime PROVEN both ways: TS-minted $ba$2$ envelope
      decrypts in Python (3 hardcoded vectors: current version, retired-but-
      present version, legacy bare-hex) AND Python-minted envelope decrypted
      live under real TS symmetricDecrypt. Guard truth table == oauth.ts:
      157-178. Ponytail: "encrypted" literal still unreachable end-to-end
      (gated behind disable_jwt_plugin reject) — threading ctx secret_config
      into register/token call sites lands with the HS256 follow-up;
      TS entropy warnings dropped (logging-only). Backlog shrunk: encrypted
      client secrets no longer blocked on secrets rotation — remaining
      blocker for them is the HS256/disableJwtPlugin follow-up alone.
- [x] B3 advanced.ipAddress: DONE, validated (20 tests; Fable verified the
      fail-closed chain semantics line-by-line vs core/src/utils/ip.ts:
      289-340 — right-to-left walk, malformed hop → null, multi-hop without
      trustedProxies → null, all 4 option fields exist in v1.6.23).
      New ip.py (stdlib ipaddress), IPAddressOptions, rate-limit + session
      wired, spoofed non-configured header ignored. Deviations: IPv6 key in
      stdlib-compressed form (grouping identical, keys never cross runtime);
      fallback = request.client_ip instead of TS dev-127.0.0.1.
      Follow-up flagged (minor): plugins admin/api_key/captcha still read
      raw ctx.request.client_ip — verify TS paths before routing them
      through get_request_ip.
- [x] B4 SQLAlchemy insensitive in/not_in: DONE, validated (7-line fix
      mirroring the file's eq/ne insensitive style; +3 tests, 82 adapter
      tests green). Agent verified TS adapters have NO insensitive-in
      precedent — MemoryAdapter semantics (memory.py:24-29) authoritative.
- [x] B5 verification secondaryStorage + storeIdentifier hashing: DONE,
      validated (14 tests; full gate 1851/clean/clean after Fable merge
      window: applied auth.py plumbing — verification=VerificationOptions
      option → InternalAdapter kwargs — + __init__ re-export + 8 ty
      narrowings in B5's test file). TS-verified: processIdentifier/
      getStorageOption verbatim (verification-token-storage.ts:12/28,
      hash = existing default_key_hasher byte-identical), secondaryStorage
      branch map internal-adapter.ts:1119/1148/1217/1288/1511, key prefix
      verification:, hashed find falls back [stored, raw]. Consume on
      secondary = get_and_delete when the store has it, else TS's
      non-atomic locked get→delete replicated faithfully (FIXME
      consume-atomic :1249, ponytail-noted). disableCleanup NOT ported —
      port never had the expired-row sweep it disables (noted).
      DB-default path behaviorally identical (full suite green).
- [x] B6 HS256/disableJwtPlugin mode: DONE, validated (16 new tests, 208
      oauth-provider+jwt green, full suite 1873/clean/clean after Fable's
      1-line ty narrowing; live-IDE _issuer errors were stale — CLI ty
      clean, paths test-covered). Full truth table (encrypted default when
      disabled, hashed rejected), HS256 id_token with decrypted secret
      (token.ts:176-195), opaque-only access (token.ts:519), introspect/
      revoke skip-to-opaque (introspect.ts:44), end-session HS256
      (logout.ts:86-107), secret_config threaded into create/rotate/
      validate call sites (5e0aeda ponytail notes resolved). Agent
      root-cause-fixed revoke.py (sibling caller, unenumerated — correct).
      Spec 07 OQ1 annotated RESOLVED. Remaining deferral: non-EdDSA JWKS
      algs only.
- [x] B8 non-EdDSA JWKS algs: DONE, validated (10 new tests; full gate re-run
      by Fable: 1975 pass — incl. B10's 87 —, ruff/ty clean at CLI). Scope
      CORRECTED by Fable vs TS source: JWKOptions union (jwt/types.ts:176-196)
      is EXACTLY EdDSA/ES256/ES512/PS256/RS256 — NO ES384/RS-PS-384/512 (the
      earlier "ES256/384/512 + RS/PS*" note was wrong). Landed: EC/RSA keygen
      via cryptography (ES256→P-256, ES512→P-521, RSA modulusLength or 2048 /
      e=65537), _export_jwk = pyjwt to_jwk minus key_ops, key_from_jwk decode
      seam (OKP kept on the original byte path — EdDSA sacred, one removed
      test line was only the lifted ceiling's match="EdDSA"), oauth-provider
      init reject lifted, verify sites de-hardcoded to jwt_plugin._alg()
      (utils.py, logout.py; _load_verify_keys now delegates to key_from_jwk),
      metadata.py needed NO change (already matched metadata.ts:99-104 —
      pinned by a new test). Fable live-verified JWK member sets == jose
      exportJWK exactly (EC: kty/crv/x/y[+d]; RSA: kty/n/e[+d,p,q,dp,dq,qi])
      + ES256 sign/verify roundtrip; agent additionally proved interop against
      Node 22 WebCrypto both directions + RFC 7515 A.3 / 7517 A.2 vectors.
      Spec-07 OQ1 deferrals now ALL resolved.
- [x] B10 dynamic base_url ({allowedHosts}): DONE, validated (87 new tests;
      full gate 1975/clean/clean re-run by Fable; security review line-by-line:
      validate_proxy_header denylist+shape regexes == url.ts:91-140,
      _wildcard_to_regex is ^..$-anchored so wildcard hosts can't suffix-match,
      trusted-origins expansion == helpers.ts:108-133). Design as planned:
      contextvars bind in handle()/load_session() + BetterAuth.base_url
      property/setter — zero changes at the 40+ read sites, endpoints.py/
      plugins_ext/oauth untouched. DynamicBaseURL{allowed_hosts,fallback,
      protocol=None} in config.py; trusted_proxy_headers option default True;
      empty allowed_hosts raises at init; direct call w/o request → fallback
      or APIError 500 (to-auth-endpoints.ts:44-51). Accepted deviations
      (ponytail-noted): base_url stays an ORIGIN (base_path composed at call
      sites, TS withPath not replicated); no request-URL host/scheme fallback
      (AuthRequest has no absolute URL); protocol=None ≠ "auto" only for
      origin expansion (faithful to TS runtime undefined); resolution errors
      = ValueError→500; BETTER_AUTH_TRUSTED_ORIGINS env skipped (port is
      explicit-config — separate backlog item if wanted); use_secure_cookies
      for auto/unset dynamic falls back to BETTER_AUTH_ENV/NODE_ENV==
      production (rate_limit.py precedent). Known minor edge (accepted):
      on_api_error/on_error hook runs OUTSIDE the contextvar bind — a hook
      reading auth.base_url on a no-fallback dynamic config degrades to the
      logged-exception path.
- [x] B9 named social-provider config: DONE, validated (5 tests, full gate
      1878/clean/clean re-run by Fable). social_providers now accepts
      {"github": {client_id, ...}} resolved via PROVIDER_REGISTRY, instances
      still pass through, mixed dict fine, unknown name → ValueError listing
      valid keys. Note: only client_id is dataclass-required (client_secret
      defaults ""), so the malformed-config test targets client_id.
- [x] B11 remaining minor items: CLOSED BY FABLE RULING 2026-07-25, no code
      (each verified against TS source):
      (a) multi-resource token param — ALREADY AT PARITY: TS wire schema is
          resource: z.string() single (oauth.ts:753, form-urlencoded only);
          checkResource's string[] branch is defensive typing and the port's
          _check_resource (token.py:396-412) already handles str AND list
          incl. the 1-element→scalar return. Phase C's "single resource
          param only" ponytail note was already stale.
      (b) PAR built-in store — DOES NOT EXIST in TS v1.6.23: no /par
          endpoint, no pushed_authorization_request_endpoint metadata; only
          the requestUriResolver seam (types/index.ts:715-728), which the
          port implements verbatim (authorize.py:217-235, RFC 9126 §4
          client_id carry included). A built-in store would EXCEED parity —
          OUT, revisit if upstream adds one.
      (c) telemetry group — OUT (same rationale as open-api): anonymous
          usage phone-home, zero wire/storage contract, default false.
      (d) logger group — OUT: the port logs via stdlib logging
          ("better_auth" logger); level/sink/format config is the stdlib's
          job, porting TS's Logger{disabled,level,log,colors} shape would
          duplicate it as an anti-idiom. Revisitable on user demand.
      BACKLOG NOW EMPTY except release chores.
- [x] B7 plugin IP call-site audit: DONE, validated (156 tests green incl.
      6 new; Fable re-ran gate + confirmed routing in code). All 3 sites
      were getIp consumers in TS (admin via internal-adapter.ts:349,
      api-key index.ts:248-250, captcha index.ts:68) → all routed through
      get_request_ip with TS-anchor comments. Admin test uses a 3-hop
      chain + disable_ip_tracking to distinguish naive-leftmost from the
      trusted-proxy walk (fastapi client_ip pre-resolution masks 2-hop).

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
- [x] W1-A1: DONE, validated, commit b5926a8 (147-test gate green). Accepted
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
- [x] W1-B (Sonnet medium): DONE, validated, commit 1af422f. Interim
      scope-blacklist in /list-accounts to be replaced by parse_account_output
      in W1-E. BODY_MUST_BE_AN_OBJECT unreachable (INVALID_BODY fires earlier
      in types.py) — revisit in W1-E if parity of that code matters.
- [x] W1-C: DONE, validated, commit 1ba6da2. Notes: change-email JWT branch
      (updateTo) minted but /verify-email's change-email path lands in W1-D;
      "reuse existing session" refinement for autoSignInAfterVerification
      deliberately skipped (revisit W1-F if parity-relevant).
- [x] W1-A2: DONE, validated, commit f032e99. Notes: hook signature is
      before(data)/after(payload) single-arg (no ctx object yet — W1-E may
      widen); secondary storage wired in seam only; endpoints not yet routed
      through the seam (W1-E).
- [x] W1-D: DONE, validated, commit 67a599c. Fable merge-fix: BetterAuth now
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
- [x] W1-F: DONE (2 agents; continuation after stall), commit e0d5e19.
      243 tests. Origin-check truthiness bypass fixed pre-commit (per-path
      skip tests green). WAVE 1 COMPLETE.
      Deferred leftovers (backlog, fold in later): dynamic base_url
      ({allowedHosts}), secrets rotation, telemetry/logger config groups,
      advanced.ipAddress (ipAddressHeaders/trustedProxies/ipv6Subnet — matters
      for prod rate-limiting; schedule with Wave 3).

## Wave 2 — Social providers (spec: gap/03-social-oauth.md)
- [x] W2-A: DONE (2 agents; continuation after connection-drop crash), commit
      77757ce, 262 tests. oauth/ package with declarative ProviderConfig.
      Deferred (spec-optional): stateless cookie state strategy,
      storeAccountCookie, oauth-signup verification email (flag for parity
      review). Token encryption is AES-GCM $bap$ (not TS-XChaCha20-compatible —
      revisit in Wave 4 crypto task which ports symmetricEncrypt).
- [x] W2-B: DONE, commit ec2e504, 406 tests. All 32 providers ported via 6
      parallel group agents (G1-G3 Sonnet, G4-G6 Opus), ZERO merge conflicts
      (disjoint files by design). PROVIDER_REGISTRY exposes all 35.
      Backlog: name-based provider config (socialProviders:{github:{...}})
      ergonomics — BetterAuth takes instances today.
      Security: 2 IDOR in refresh/get-access-token fixed pre-merge (3fc4d38);
      cookie-cache timing side-channel fixed (2d09eab).

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
- [x] Organization phases 3+4: DONE — teams committed 5d2bde0 (40 tests);
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

- [x] W5-A: DONE — one-tap 12caec0 (26 tests, GHSA-9502 regressions,
      maxTokenAge 1h), oauth-popup 3564054 (15 tests, completion script
      byte-exact, sha256 CSP pin == TS constant), siwe d731087 (61 tests,
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
- [x] W5-C spec: docs/plans/gap/07-oauth-provider.md committed ac208da
      (747 lines, 20 items, 4 sub-phases A-D). Decision (defaults adopted):
      EdDSA-first, reject disableJwtPlugin + non-EdDSA algs at init; hashed
      client secrets first (encrypted blocked on secrets-rotation backlog);
      client-side helpers (mcpHandler etc.) excluded.
      NEXT: dispatch W5-C phase A (clients + discovery + JWKS) per the spec.
- [ ] W5-C: oauth-provider package subset (XL, replaces deprecated
      oidc-provider/mcp per decision log; sub-phase like organization).
      Phase A DONE, validated (49 tests; Fable re-ran scoped gate + suite
      minus sibling WIP = 1478 green = 1399 base + 49 + 30 passkey, zero
      regressions; spot-checked: on_request fires before router 404
      auth.py:313-322 — spec note (c) confirmed OK; make_signature =
      arg-flipped crypto._signature; DCR unauthenticated overrides).
      All 4 tables + client CRUD/DCR + privileges gate + discovery/JWKS.
      Init rejects disable_jwt_plugin/non-EdDSA/encrypted-secret per
      decisions. Ponytail deviations: no trusted-client TTL cache;
      _to_exp_seconds int-only (no "30d" strings); SERVER_ONLY endpoints =
      unmounted methods (email-otp precedent); login/consent pages stored
      unused until Phase B.
      Phase B DONE, validated (37 new tests, 116 scoped total; Fable re-ran
      gate green + code-verified the two subtle security gates:
      _session_satisfies_login_prompt >= ba_iat with None→False, and
      post_login_cleared requires signed-query-derived marker == current
      session id — client postLogin:true only selects the branch).
      /oauth2/authorize 10-step flow, consent/continue, consent CRUD,
      signed-query before/after hooks wired, authorize {60,30} rate rule.
      Ponytail deviations: request state on Ctx (no defineRequestState);
      no cross-request oAuthState store (authorize.ts:212 skip, noted);
      after-hook copies login Set-Cookie onto resume redirect (port
      replaces response wholesale).
      Phase C DONE, validated (31 new tests; Fable ran the FULL whole-tree
      gate — first time all agents landed: 1756 pass, ruff clean, ty clean
      after a 1-line assert fix in test_sso_callback seeded by W6; TS
      spot-checks: rotation CAS where revoked=null exact, replay →
      invalidateRefreshFamily + invalid_grant token.ts:1070-1075,
      family teardown = findMany+delete matches agent's delete_many).
      3 grants + createUserTokens + verify_jws_access_token (azp gate,
      WeakKey instance cache) + introspection + pairwise sub. Ponytail:
      family teardown two non-atomic delete_many (== TS TODO); single
      resource param only; concurrent-code loser 401 == TS UNAUTHORIZED.
      Revoke CAS deferred to Phase D per spec option. One connection drop,
      resumed via SendMessage without rework.
      Phase D DONE, validated (25 new tests; Fable re-ran full gate: 1781
      pass, ruff/ty clean). Userinfo + RFC 7009 revoke (opaque delete,
      refresh CAS, already-revoked family teardown, revoke-vs-rotate
      single-winner) + end-session (enableEndSession gate, iss/aud verify,
      sid session delete, exact-match post-logout redirect) + pairwise
      consistency (same sub id_token/userinfo/introspect, distinct across
      hosts, JWT-access sub stays real). Fable merge-window fix: removed
      WWW-Authenticate header on userinfo 401 — Fable's phase-D prompt had
      wrongly required it; TS userinfo.ts:46 sets none (only excluded
      client-side mcp.ts does) — wire parity restored, test asserts
      absence. Kept deviation: SafeUrl belt-and-braces on post-logout
      redirect (additive, registered URIs already validated).
      W5-C OAUTH-PROVIDER PLUGIN CLOSED vs TS v1.6.23 (4 phases, 166
      plugin tests). Backlog carried: encrypted client secrets +
      disableJwtPlugin/HS256 + non-EdDSA JWKS (secrets-rotation
      prerequisite), PAR built-in store, multi-resource param.
- [x] W5-D: open-api — DECIDED 2026-07-24 (Fable ruling, revisitable):
      OUT of parity scope. Rationale: dev-tooling only — zero wire/storage
      contract (the prime directive doesn't bind it); porting requires a
      cross-cutting route-metadata registry touching every endpoint for a
      static docs page. Revisit on user demand as a standalone follow-up.
      WAVE 5 COMPLETE.

## Wave 6 — Ecosystem (USER-CONFIRMED 2026-07-24) — COMPLETE 2026-07-24
(api-key 8b4d13b, passkey 20b80b2, sso-OIDC 6970244+ef94b71. All validated.)
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
- [x] W6 passkey: DONE, validated (Fable re-ran scoped gate: 30 tests green,
      ruff/ty clean; code spot-check: publicKey padded-b64, deviceType
      snake→camel map, real py_webauthn 3.0 verify driven by in-test ES256
      software authenticator, challenge single-winner concurrency). Agent
      documented 9 py_webauthn 3.0-vs-2.x mapping deltas (verify_* raise
      instead of returning {verified}, flat dataclass results, enum
      device_type — spec 09 was 2.x-based). Accepted deviations ponytail-
      noted: freshness inlined reusing SESSION_REQUIRED; delete hides
      existence (PASSKEY_NOT_FOUND 401, == TS notFoundError/forbiddenStatus,
      Fable-verified routes.ts); client-only error codes surfaced but never
      thrown. Export wired by Fable in the W5-C-A merge window (imports
      verified, 79 combined tests green).
      One connection-drop mid-run, resumed via SendMessage without rework.
- [x] W6 api-key: DONE, validated (Fable re-ran scoped gate: 41 tests green,
      ruff/ty clean; spot-checked 52-char alphabet, prefix-inside-hash via
      default_key_hasher(full_key), 4 guarded increment_one CAS sites
      mirroring TS verify-api-key.ts:244-357, cross-runtime hash vector
      SHA-256("hello") asserted byte-exact). CAS single-winner trio present.
      Ponytail deviations: database mode only (secondary storage raises at
      ctor); deferUpdates synchronous; RATE_LIMITED try_again_in surfaced
      only in verify wrapper error object (APIError lacks details —
      backlog); server-only surface = plugin methods (verify_api_key,
      create/update_api_key, delete_all_expired_api_keys), HTTP routes
      client-path only (one-time-token precedent). Export wired by Fable.
- [x] W6 sso-OIDC waves A+B: DONE, validated (Fable re-ran scoped gate: 125
      tests green, ruff/ty clean; near-whole-tree 1595 green = 1478 + 41
      api-key + 125 sso − 49 oauth-provider phase-B-owned excluded).
      Spot-checked vs TS: register DOES echo full parsed oidcConfig incl.
      plaintext clientSecret (routes/sso.ts:913 result spread) — agent's
      deviation faithful; sanitizeProvider masks clientId on reads. SSRF
      classifier on stdlib ipaddress + explicit tunnel/metadata vectors;
      DNS-rebind via injected resolver seam. Seams left for wave C
      (sign-in/callback + handle_oauth_user_info trust flags) and D
      (domain-verification endpoints + org auto-assign): ensure_runtime_
      discovery, verification_identifier, domainVerified column,
      has_org_plugin. Export wired by Fable (+ RUF022 __all__ sort fix).
- [x] W6 sso-OIDC waves C+D: DONE, validated — SSO PLUGIN CLOSED (OIDC half)
      vs TS v1.6.23. 44 new tests (169 sso total); Fable re-ran gates:
      near-whole-tree 1639 = 1595 + 44, shared-caller suites green (flow.py
      extension regression-free). Fable scrutiny of 2 flagged points, both
      sound: (a) trust_provider_by_name defaults True (preserves social/
      generic-oauth callers; SSO callback passes False + is_trusted_provider
      = domainVerified && email-domain match, routes.py:616/641); (b) no
      per-endpoint ensure_trusted_url on sign-in callback URLs == TS
      generateState, AND the port's global check_origin already validates
      callbackURL/errorCallbackURL/redirectTo every request (origin.py:218).
      Ponytail deviations: callback drops dead config.scopes read;
      ssoProviderId/requestSignUp ride state.additionalData (single-runtime
      state, spec-permitted); (user_id, is_register) return convention.
      SAML remains OUT per decision log.
- [ ] W6 impl DISPATCHED 2026-07-24 (3 Opus high agents, parallel, in-tree):
      api-key (plugins_ext/api_key.py), passkey (plugins_ext/passkey.py),
      sso-OIDC waves A+B (plugins_ext/sso/ — schema/CRUD/SSRF/discovery/
      register; waves C+D = later sequential dispatches). Contention
      neutralized: deps webauthn>=2.7 (installed 3.0.0 — agents must adapt
      the spec's 2.x mapping) + dnspython>=2.7 added by orchestrator as
      [passkey]/[sso] extras + dev group; plugins_ext/__init__.py owned by
      W5-C-A agent — W6 agents return their export line, orchestrator wires
      at merge. Agents gate SCOPED (own tests + ruff/ty on own files);
      whole-tree gate = orchestrator at each merge window.
      OUT: scim, stripe, SAML.

## Security findings (from background commit review)

- 2026-07-22 CONFIRMED: /update-session (commit 67a599c) accepted arbitrary
  non-core session fields — priv-esc vector vs TS's parseSessionInput
  allowlist. Fix folded into W1-E's item-12 scope (message sent to the running
  agent): parse_session_input schema-driven allowlist + tests. Validate before
  W1-E commit.

- 2026-07-23 CONFIRMED (uncommitted code): origin.py truthiness bug —
  disable_origin_check as non-empty list (per-path skip) disabled the origin
  check globally. Fix folded into W1-F-bis (message sent). Gate before commit:
  per-path skip tests must exist and pass.

- 2026-07-23 FIXED 2d09eab: cookie_cache.py compared HMAC signatures with `!=`
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

- 2026-07-24: open-api plugin ruled OUT of parity scope (dev tooling, no
  wire/storage contract, needs cross-cutting route-metadata registry).
  Revisitable on user demand. This closed Wave 5.

- 2026-07-25 (Fable rulings, revisitable — evidence in B11): telemetry group
  OUT (open-api rationale); logger group OUT (stdlib logging is the Python
  surface); PAR built-in store OUT (absent from TS v1.6.23, resolver seam
  already ported); multi-resource token param closed as already-at-parity.
  This EMPTIED the backlog — remaining work is release chores only.

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
