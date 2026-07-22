# DB layer — better-auth v1.6.23 → Python parity spec

Scope: the database layer only — schema definition, the adapter contract, the
internal adapter + database hooks, secondary storage, id generation,
`advanced.database` options, transactions, and CLI schema generation. Plugin
*fields* are out of scope (covered by other specs); the plugin *mechanism* for
contributing fields is noted here.

TS paths are relative to `packages/` in the pinned v1.6.23 checkout at
`/Users/oumarbarry/CODESPACE/uzumaki/OPENSOURCE/better-auth-py/better-auth`.
Python paths are relative to `src/` in
`/Users/oumarbarry/CODESPACE/uzumaki/OPENSOURCE/better-auth-py/better-auth-py`.

---

## TS inventory (authoritative)

Field types (`core/src/db/type.ts:164`): `string | number | boolean | date |
json | "string[]" | "number[]" | Array<LiteralString>` (the last is an enum of
allowed string literals). There is **no `text` type** — long-text vs varchar is
controlled by the `sortable` flag, not a distinct type.

### Core schema — every table, every field

Source: `core/src/db/get-tables.ts` (`getAuthTables`). Every field also carries
`fieldName` (defaults to the field key; overridable via
`options.<model>.fields.<field>`). `modelName` per table is overridable via
`options.<model>.modelName`. `id` is **not** listed in `fields`; it is injected
by the adapter factory (`type` string or number, see ID generation). Column
names below are the camelCase defaults.

**user** (order 1, modelName `user`)

| field | type | required | default | unique | input | returned | other |
|-------|------|----------|---------|--------|-------|----------|-------|
| name | string | true | — | — | — | — | `sortable: true` |
| email | string | true | — | true | — | — | `sortable: true` |
| emailVerified | boolean | true | `false` | — | **false** | — | |
| image | string | false | — | — | — | — | |
| createdAt | date | true | `() => new Date()` | — | — | — | |
| updatedAt | date | true | `() => new Date()` | — | — | — | `onUpdate: () => new Date()` |

**session** (order 2, modelName `session`) — *only emitted when there is no
secondaryStorage, or `session.storeSessionInDatabase` is true*
(`get-tables.ts:209`).

| field | type | required | default | unique | references | other |
|-------|------|----------|---------|--------|------------|-------|
| expiresAt | date | true | — | — | — | |
| token | string | true | — | true | — | |
| createdAt | date | true | `() => new Date()` | — | — | |
| updatedAt | date | true | — | — | — | `onUpdate: () => new Date()` |
| ipAddress | string | false | — | — | — | |
| userAgent | string | false | — | — | — | |
| userId | string | true | — | — | `{model:user, field:id, onDelete:"cascade"}` | `index: true` |

**account** (order 3, modelName `account`)

| field | type | required | unique | references | returned |
|-------|------|----------|--------|------------|----------|
| accountId | string | true | — | — | — |
| providerId | string | true | — | — | — |
| userId | string | true | — | `{model:user, field:id, onDelete:"cascade"}`, `index:true` | — |
| accessToken | string | false | — | — | **false** |
| refreshToken | string | false | — | — | **false** |
| idToken | string | false | — | — | **false** |
| accessTokenExpiresAt | date | false | — | — | **false** |
| refreshTokenExpiresAt | date | false | — | — | **false** |
| scope | string | false | — | — | — |
| password | string | false | — | — | **false** |
| createdAt | date | true | — | — | — | default `() => new Date()` |
| updatedAt | date | true | — | — | — | `onUpdate: () => new Date()` |

**verification** (order 4, modelName `verification`) — *only emitted when there
is no secondaryStorage, or `verification.storeInDatabase` is true*
(`get-tables.ts:298`).

| field | type | required | default | other |
|-------|------|----------|---------|-------|
| identifier | string | true | — | `index: true` |
| value | string | true | — | |
| expiresAt | date | true | — | |
| createdAt | date | true | `() => new Date()` | |
| updatedAt | date | true | `() => new Date()` | `onUpdate: () => new Date()` |

**rateLimit** (modelName `rateLimit`, overridable) — *only emitted when
`rateLimit.storage === "database"`* (`get-tables.ts:34`).

| field | type | required | unique | default |
|-------|------|----------|--------|---------|
| key | string | true | true | — |
| count | number | true | — | — |
| lastRequest | number (`bigint: true`) | true | — | `() => Date.now()` |

Plugin fields: `getAuthTables` folds each `plugin.schema[model].fields` into the
matching core table, and any plugin-only model becomes its own table (with
`modelName`, `disableMigrations`, merged `fields`). `options.<model>.additionalFields`
does the same for user/session/account/verification. Field-attribute schema:
`core/src/db/type.ts:184` (`DBFieldAttributeConfig`): `required, returned,
input, defaultValue, onUpdate, transform{input,output}, references{model,field,
onDelete}, unique, bigint, validator{input,output} (StandardSchema), fieldName,
sortable, index`.

### Adapter contract — every method + operators + options

Two layers. Adapters implement **`CustomAdapter`**
(`core/src/db/adapter/index.ts:529`); `createAdapterFactory`
(`core/src/db/adapter/factory.ts:58`) wraps it into the public **`DBAdapter`**
(`index.ts:399`) that core calls. The factory handles id generation, input/output
transforms, where-clause normalization, join planning, and the
`consumeOne`/`incrementOne`/`transaction` fallbacks — so a `CustomAdapter` only
implements raw CRUD, but must honor the *normalized* contract the factory hands it.

**Public `DBAdapter` methods** (what core relies on):

- `create({model, data, select?, forceAllowId?}) → row`. Factory strips a
  caller-supplied `id` unless `forceAllowId` (warns). Applies `transformInput`
  then `transformOutput`.
- `findOne({model, where, select?, join?}) → row | null`.
- `findMany({model, where?, limit?, select?, sortBy?, offset?, join?}) → row[]`.
  `limit` defaults to `advanced.database.defaultFindManyLimit ?? 100`.
  `sortBy = {field, direction: "asc"|"desc"}`.
- `count({model, where?}) → number`.
- `update({model, where, update}) → row | null`. **Empty `where` returns `null`
  (fail-closed)** — factory guard at `factory.ts:972`; bulk writes must use
  `updateMany`.
- `updateMany({model, where, update}) → number` (rows affected).
- `delete({model, where}) → void`.
- `deleteMany({model, where}) → number`.
- `consumeOne({model, where}) → row | null` — atomically delete-and-return a
  single matching row; race-safe single-use credential primitive. Factory
  provides a `transaction(findMany limit 1 + deleteMany)` fallback when the
  CustomAdapter lacks a native one (`factory.ts:1370`).
- `incrementOne({model, where, increment:{field:delta}, set?}) → row | null` —
  atomic `field = field + delta` with `where` as selector **and** guard
  (e.g. `remaining > 0`); optional absolute `set`. Fallback:
  `transaction(findMany + updateMany)` re-applying `where` as compare-and-swap
  (`factory.ts:1529`). Empty increment+set throws.
- `transaction(cb) → cb(trx)`. When `config.transaction` is falsy the factory
  runs the callback against the same adapter (`createAsIsTransaction`,
  `factory.ts:49`) — i.e. sequential, no isolation.
- `createSchema?({file, tables}) → {code, path, append?, overwrite?}` — for CLI
  `generate`.
- `id`, `options` (carries `adapterConfig`).

**Where operators** (`core/src/db/adapter/index.ts:308`, `whereOperators`):
`eq, ne, lt, lte, gt, gte, in, not_in, contains, starts_with, ends_with`.
A `Where` is `{field, value, operator="eq", connector="AND"|"OR", mode="sensitive"|"insensitive"}`.
`connector` mixes AND/OR across clauses; `mode:"insensitive"` makes string
`eq`/`contains`/`starts_with`/`ends_with` case-insensitive (memory adapter uses
`query-builders.ts` helpers; SQL adapters push it down). `in`/`not_in` require an
array value or throw.

**Joins** (`index.ts:352`): `JoinOption = {model: boolean | {limit}}`. The
factory’s `transformJoinClause` resolves the FK direction (forward or backward),
derives `{on:{from,to}, limit, relation:"one-to-one"|"one-to-many"}` from schema
references + `unique`, and either passes it to the adapter (when
`options.experimental.joins`) or performs a **fallback join** with extra
findOne/findMany calls (`factory.ts:751`). Off by default (experimental).

**`AdapterFactoryConfig` capability flags** (`core/src/db/adapter/index.ts:52`,
`DBAdapterFactoryConfig`) — an adapter declares what its DB supports and the
factory does the translation: `supportsNumericIds` (def true), `supportsUUIDs`
(false), `supportsJSON` (false → JSON.stringify), `supportsDates` (true → else
ISO strings), `supportsBooleans` (true → else 0/1), `supportsArrays` (false →
stringify), `transaction` (false | fn), `disableIdGeneration`, `usePlural`,
`mapKeysTransformInput/Output` (e.g. Mongo `id`↔`_id`), `customIdGenerator`,
`customTransformInput/Output`, `disableTransformInput/Output/Join`, `debugLogs`.

**Adapter test suite** — every adapter is validated against a shared suite
(`packages/better-auth/src/adapters/tests`, invoked by kysely/drizzle/prisma/
mongodb/memory packages). The suite is the executable definition of the semantics
above: create-ignores-supplied-id, single `update`/`delete` no-op on empty where,
`sortBy` asc/desc + null ordering, `offset`/`limit`, every where-operator incl.
`not_in`/`starts_with`/`ends_with`, case-insensitive `mode`, `count`, `consumeOne`
exactly-once under concurrency, `incrementOne` guard semantics, and transaction
rollback. A Python port claiming adapter parity should port this suite.

### Internal adapter & database hooks — how core wraps adapters

`packages/better-auth/src/db/internal-adapter.ts` (`createInternalAdapter`) is
the domain layer core actually calls: `createUser`, `createSession`,
`findSession`, `updateSession`, `deleteSession(s)`, `createVerificationValue`,
`findVerificationValue`, `createAccount`, `linkAccount`, `updateAccount`, etc. It
holds the `secondaryStorage` branching and calls the with-hooks wrappers rather
than the adapter directly.

`packages/better-auth/src/db/with-hooks.ts` (`getWithHooks`) wraps every mutating
op — `createWithHooks`, `updateWithHooks`, `updateManyWithHooks`,
`deleteWithHooks`, `deleteManyWithHooks`, `consumeOneWithHooks`. For each it runs,
per registered `databaseHooks` entry, the `<model>.<create|update|delete>.before`
hook (which may return `false` to abort or `{data}` to merge into the payload)
and queues the `.after` hook via `queueAfterTransactionHook` (runs post-commit).
`databaseHooks` is keyed by model (`user|session|account|verification`) →
`{create,update:{before,after}, delete:{before,after}}` and is an
`options.databaseHooks` config plus plugin-contributed entries (each tagged with a
`source`). `delete.before` receives a pre-fetched entity snapshot.

The parse/transform layer around this: `packages/better-auth/src/db/schema.ts`
(`parseInputData`, `parseUserInput`, `parseUserOutput`, `parseAccountOutput`,
etc.) enforces `input:false` (rejects client-set values, errors
`FIELD_NOT_ALLOWED`), runs `validator.input`, applies `transform.input`,
`defaultValue`, `required` checks, and filters `returned:false` fields out of
output (`filterOutputFields`). `parseAccountOutput` additionally strips
tokens+password. Schema results are cached per options in a `WeakMap`.

### Secondary storage — interface + all call sites

Interface `SecondaryStorage` (`core/src/db/type.ts:307`):
`get(key) → unknown`, `set(key, value:string, ttl?:seconds) → void`,
`delete(key) → void`, optional `getAndDelete(key)` (atomic read-and-delete for
single-use credentials), optional `increment(key, ttl) → number` (atomic counter,
ttl applied only on creation). It is a plain KV interface — no schema, no models.

Call sites (all in `packages/better-auth/src`):

1. **Session storage** — `db/internal-adapter.ts`. When `secondaryStorage` is set
   and `session.storeSessionInDatabase` is false, sessions live *only* in the KV
   store, not the DB (the session table is dropped from the schema). Wire format
   (must be stable for cross-impl compat):
   - key = the session `token` → value = `JSON.stringify({session, user})`, TTL =
     seconds until `expiresAt` (`internal-adapter.ts:426`).
   - key = `active-sessions-${userId}` → value = `JSON` array of
     `{token, expiresAt:<epoch ms>}`, TTL = furthest session’s remaining seconds
     (`internal-adapter.ts:406`). `findSession`/`deleteSession`/`listSessions`
     read/prune this list. Session id is generated in app code
     (`internal-adapter.ts:343`) since the DB adapter never runs.
2. **Rate limiting** — `api/rate-limiter/index.ts`. With
   `rateLimit.storage === "secondary-storage"`: uses `increment(key, window)` when
   present (atomic), else `get`/`set` of `JSON {count, lastRequest}`
   (best-effort, non-atomic, logs a warning).
3. **Verification / single-use tokens** — device-authorization plugin routes and
   verification-token consumers prefer `getAndDelete` when present to avoid a
   read-then-delete race.

### ID generation & advanced.database options

`advanced.database` (`core/src/types/init-options.ts:352`):
- `defaultFindManyLimit?: number` (default 100) — applied by the factory to any
  `findMany`/join without an explicit `limit`.
- `generateId?: GenerateIdFn | false | "serial" | "uuid"`.
  - default (unset): `defaultGenerateId()` = 32-char base62 (`a-z A-Z 0-9`) via
    `@better-auth/utils` (`core/src/utils/id.ts`).
  - function: called `({model}) → string` per row.
  - `false`: DB auto-generates (factory returns `undefined` for id).
  - `"serial"`: numeric auto-increment ids (a.k.a. `useNumberId`). Requires
    `supportsNumericIds`; the factory coerces id + all id-referencing FK values to
    `Number`, but always returns `id` as a **string** in output
    (`factory.ts:353`).
  - `"uuid"`: `crypto.randomUUID()` in JS, or native (`gen_random_uuid()`/`uuid()`)
    when `supportsUUIDs`.

Resolution order lives in `core/src/db/adapter/get-id-field.ts`: user
`generateId` fn > `"uuid"` > adapter `customIdGenerator` > default. Applied as the
injected `id` field’s `defaultValue`, plus a `transform.input` that validates/
coerces (UUID regex, number parsing) and a `transform.output` that stringifies.

### Transactions

`DBAdapter.transaction(cb)` is always present. If `config.transaction` is a
function the adapter runs a real DB transaction; if falsy, the factory runs the
callback against the same adapter with **no isolation** (sequential). Core uses
transactions through `context/transaction.ts` (`runWithTransaction`,
`getCurrentAdapter`) so that a caller already inside a transaction keeps using the
active trx adapter, and `queueAfterTransactionHook` defers `.after` hooks until
after commit. The `consumeOne`/`incrementOne` factory fallbacks depend on
`transaction` for their (best-effort) atomicity. The memory adapter implements
transactions via copy-on-write clone + three-way merge on commit
(`packages/memory-adapter/src/memory-adapter.ts:160`).

### CLI schema generation (inventory)

`@better-auth/cli` (`packages/cli`) has `generate` and `migrate`. `generate`
(`commands/generate.ts` → `generators/`) calls the configured adapter’s
`createSchema({tables})` and writes an ORM schema file — Drizzle schema, Prisma
schema, or raw Kysely SQL — from `getAuthTables(options)` (dropping the session
table when secondaryStorage-only). `migrate`
(`packages/better-auth/src/db/get-migration.ts`, `getMigrations`) works **only
with the Kysely adapter**: it introspects the live DB, diffs against the expected
tables/columns, and applies `CREATE TABLE`/`ALTER TABLE ADD COLUMN` directly.
Other adapters print "use `generate`". Both derive everything from the same
`getAuthTables` schema, so field types, `references`+`onDelete`, `unique`, and
`index` flags drive the emitted DDL.

---

## Python current state (file:line precise)

**Schema** — `schema.py`. `Field` dataclass (`schema.py:12`):
`type: str, required=False, unique=False, references: str|None`. Types accepted:
`"string" | "text" | "boolean" | "datetime"` (comment, `schema.py:14`).
`CORE_SCHEMA` (`schema.py:22`) defines user/session/account/verification with
camelCase columns. `merge_schema` (`schema.py:68`) folds plugin schemas (new
models or extra fields). Divergences from TS:
- `id` is a real field in every table (`string, required, unique`), not injected.
- `user.emailVerified` is `boolean, required=True` (`schema.py:27`) — TS has
  `defaultValue false, input:false`.
- `createdAt`/`updatedAt` have no defaults/`onUpdate`; the app sets them by hand
  (`session.py:79`, `endpoints.py:75+`).
- account tokens (`accessToken`, `refreshToken`, `idToken`) use type `"text"`
  (`schema.py:47`) — TS uses `"string"`. `password` is `"string"`.
- `references` is a bare string `"user.id"` (`schema.py:38,46`); no `onDelete`.
- No `returned`/`input`/`defaultValue`/`onUpdate`/`transform`/`bigint`/
  `validator`/`fieldName`/`sortable`/`index` attributes. No `rateLimit` table.
- verification.value uses `"text"` (TS `"string"`); `identifier` has no `index`.

**Adapter contract** — `adapters/base.py`. `Where` (`base.py:14`):
`{field, value, operator="eq"}` — **no `connector`, no `mode`**. `BaseAdapter`
(`base.py:25`) methods: `init(schema)`, `create(model, data)`,
`find_one(model, where)`, `find_many(model, where=None)`, `update(model, where,
data) → row|None`, `delete_many(model, where) → int`. That’s the entire contract.

Operators supported — `adapters/memory.py:11` `_OPS` and
`adapters/sqlalchemy.py:86`: `eq, ne, in, contains, gt, gte, lt, lte`.

`MemoryAdapter` (`adapters/memory.py:27`): list-of-dicts per model, AND-only
matching (`_matches`, `memory.py:24`), single-row `update` returns first match.

`SQLAlchemyAdapter` (`adapters/sqlalchemy.py:41`): builds `Table`s from the schema
in `init` (`sqlalchemy.py:47`), `_TYPES` maps only `string→String(255)`,
`text→Text`, `boolean→Boolean`, `datetime→DateTime` (`sqlalchemy.py:21`).
`primary_key = name=="id"`. Datetimes stored naive-UTC, returned tz-aware UTC
(`sqlalchemy.py:29-38`). Each op opens its own connection/`engine.begin()` —
**no shared transaction**. `create_tables()` (`sqlalchemy.py:68`) is a dev-only
`metadata.create_all`.

**Adapter usage across the port** (`grep`): `create` ×10, `find_one` ×14,
`update` ×6, `delete_many` ×11, `find_many` ×3. `find_many` is always called
with a where-list only — no `limit`/`sortBy`/`offset`/`select`/`join`.

**Internal adapter / hooks** — none. Endpoints/`session.py`/`oauth.py` call
`auth.adapter.*` directly and build row dicts inline. Output filtering is a
manual `SENSITIVE_ACCOUNT_FIELDS` frozenset (`endpoints.py:23`), not a
`returned:false` schema pass. There is a generic `hooks: dict[str, callable]`
(`auth.py:59`, `run_hook` `auth.py:115`) for arbitrary named app callbacks — this
is **not** better-auth’s `databaseHooks` (no per-model before/after
create/update/delete, no abort/merge, no after-transaction queue).

**Secondary storage** — none. No `SecondaryStorage` interface, no KV session
store. Sessions always live in the DB (`session.py:82`).

**ID generation** — `crypto.generate_id` (`crypto.py:30`) = 32-char base62 over
`_ID_ALPHABET` (`crypto.py:26`, `a-z A-Z 0-9`) — byte-compatible with TS default.
Ids generated inline at call sites (`endpoints.py:75,108`, `session.py:74-75`,
`oauth.py:194+`). No `generateId` option, no `false`/`serial`/`uuid`/custom-fn,
no `useNumberId`.

**advanced.database options** — none. No `defaultFindManyLimit`, no `generateId`
config. `find_many` has no default limit (returns all rows).

**Rate limit** — in-memory fixed window in `auth.py` (`_check_rate_limit`,
`auth.py:216`); `RateLimit` config (`config.py:44`) has no `storage` mode. No DB
or secondary-storage backend, no `rateLimit` table.

**CLI / migrations** — none. `SQLAlchemyAdapter.create_tables()` is the only DDL
path; no `generate`, no diff-based `migrate`, no `createSchema`.

**Tests** — `tests/test_sqlalchemy_adapter.py` only; no ported shared adapter
suite.

---

## Gap items — ordered, effort, dependencies

Storage-compat requirements are called out explicitly (**SC**): a DB created/used
by the TS lib must work with the Python lib and vice versa.

1. **Field-attribute model parity** — S. Extend `Field` with `returned`, `input`,
   `default`/`default_factory`, `on_update`, `field_name`, `sortable`, `index`,
   `bigint`, and structured `references={model,field,on_delete}`. Add `number`,
   `json`, `string[]`/`number[]` types; reconcile `text` (Python-only) — keep it
   as a Python alias but ensure it maps the same column type TS’s `string` (no
   `sortable`) produces so a shared DB round-trips. Blocks #2, #6, #9.
   **SC**: column types + nullability + FK `onDelete:cascade` must match TS DDL
   (session.userId / account.userId cascade, email unique, identifier index).

2. **Adapter contract expansion** — L. Add to `BaseAdapter`/impls: `count`,
   `update_many`, single `delete`, `consume_one`, `increment_one`,
   `transaction`; extend `find_many` with `limit`/`sort_by`/`offset`/`select`;
   add `select`/`force_allow_id` to `create`. Add where `connector` (AND/OR) and
   `mode` (insensitive), and operators `not_in`, `starts_with`, `ends_with`.
   Enforce the empty-`where` → no-op/`null` guard on single `update`/`delete`.
   Depends on #1. Largest item; split per method if needed.

3. **Adapter factory / transform layer** — L. Port the input/output transform
   pipeline (defaults, `on_update`, `transform`, id injection+coercion,
   `returned:false` output filtering, where-clause normalization) so adapters
   stay thin and core stops hand-filtering. Depends on #1, #2. This is where
   `parseInputData`/`parseAccountOutput` semantics land.

4. **Database hooks** — M. Add `database_hooks` config keyed by model with
   before/after create/update/delete, abort-on-`False`, `{data}` merge, and a
   with-hooks wrapper core routes mutations through. Depends on an internal-adapter
   seam (#5). Distinct from the existing generic `hooks` dict — keep or rename to
   avoid confusion.

5. **Internal adapter seam** — M. Introduce a domain layer (createUser/
   createSession/findSession/…/createVerificationValue) so hooks (#4), secondary
   storage (#7), and transaction context attach in one place instead of scattered
   `auth.adapter.*` calls. Refactor, low external risk.

6. **advanced.database options** — S/M. Add `default_find_many_limit` (default
   100, applied in factory #3) and `generate_id` (`False | "serial" | "uuid" |
   callable`, plus `useNumberId` coercion). Depends on #3 for id injection.
   **SC**: default id format already matches (base62/32); `"uuid"` and `"serial"`
   change PK type — a Python app must pick the same mode as the TS app sharing the
   DB.

7. **Secondary storage** — M. Define a `SecondaryStorage` protocol (`get`, `set`,
   `delete`, optional `get_and_delete`, optional `increment`) and wire the three
   call sites: session KV store (drop session table when KV-only), rate-limit
   `secondary-storage` mode, single-use token consume. Depends on #5.
   **SC**: exact wire format — session key = token → `{"session":…,"user":…}` JSON
   with TTL=seconds-to-expiry; `active-sessions-<userId>` → JSON `[{token,
   expiresAt:<ms>}]`; rate-limit → `{count,lastRequest}` — must be byte-compatible
   so TS and Python share one Redis/KV.

8. **Transactions** — M. Real transaction support in `SQLAlchemyAdapter` (reuse
   one `AsyncConnection` across the callback) + a transaction context (current-
   adapter var, after-commit hook queue). Prereq for race-safe `consume_one`/
   `increment_one` (#2) and correct hook ordering (#4). Currently every op is its
   own connection, so nothing is atomic.

9. **rateLimit table + DB-backed rate limiting** — S. Add the `rateLimit`
   model (key unique, count number, lastRequest bigint) gated on a `storage:
   "database"` option, using `increment_one`. Depends on #1, #2, #6.
   **SC**: only if a shared DB is expected to carry rate-limit rows.

10. **CLI schema generation / migrations** — L (optional). A `generate`
    equivalent emitting SQLAlchemy models / Alembic migrations from the merged
    schema, and/or a diff-based `migrate`. Lower priority — `create_tables()`
    covers dev; production users bring their own migrations. Depends on #1.

11. **Port the shared adapter test suite** — M. Translate
    `packages/better-auth/src/adapters/tests` to pytest and run it against Memory
    + SQLAlchemy. This is how parity for #2/#3/#8 is proven, not asserted.
    Depends on #2.

---

## Open questions

- **`text` type**: Python invented a `text` type absent in TS (TS uses `string`
  everywhere, `sortable` picks varchar vs text at DDL time). *Options:* (a) keep
  `text` as a Python-only alias mapping to the same SQL column TS emits for a
  non-sortable `string`; (b) drop it, add `sortable` and mirror TS exactly.
  **Default: (a)** — smaller churn, and account tokens genuinely want TEXT; verify
  a TS-generated schema’s token columns are TEXT-compatible before committing.

- **BLOCKED: exact TS column type for `string`** — whether `type:"string"` maps
  to `TEXT` or `VARCHAR(255)` depends on the specific SQL adapter (kysely vs
  drizzle vs prisma), not read here. Python’s `String(255)` for `string` may be
  narrower than a TS deployment’s columns. *Options:* (a) inspect the kysely
  adapter’s type map and match it; (b) use unbounded TEXT for all strings to be
  safe on a shared DB. **Default: (b)** for shared-DB safety, revisit under #1 by
  reading `packages/kysely-adapter`.

- **`emailVerified` default/input**: TS is `defaultValue:false, input:false`;
  Python makes it a plain required boolean the app sets. Aligning requires the
  `input:false` enforcement (#3). Confirm no endpoint depends on clients sending
  `emailVerified`.

- **Generic `hooks` vs `databaseHooks`**: the existing `hooks` dict is a
  different concept. Decide whether #4 replaces it, coexists, or renames it —
  affects the public config surface and any current users.

- **Numeric/serial ids and cross-DB sharing**: `"serial"` and `"uuid"` change PK
  and FK column types. A Python app sharing a DB with a TS app must use the
  identical `generateId` mode. Worth an explicit compat note/validation in #6.
