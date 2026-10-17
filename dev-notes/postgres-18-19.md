# Supporting PostgreSQL 18 and 19

Notes from the `support-latest-postgres` investigation (October 2026). They
cover what broke on PostgreSQL 18 and 19, what this branch changes, how it
was validated, and what is left.

## Summary

* PostgreSQL 18 works as a backend, with no breaking changes, for both
  `--backend-dsn` and the bundled server. PG14 keeps working, so this can
  ship in a 7.x minor release. The rest of this note calls that path
  "the minor".
* PostgreSQL 19 (tested on 19beta4) works except for branch creation.
  That needs PG19 `pg_dump`, which should wait for 19.0.
* The minor bumps the bundled server from 17.4 to 17.11 (the same kind
  of bump Gel shipped in 2.10, 5.7 and 6.5) and keeps pgvector 0.7.4. It
  ships
  newer client tools (`pg_dump`, `pg_restore`, `psql`, `libpq`) built from
  upstream `REL_18_6` (see `PG_CLIENT_COMMIT` in `setup.py`).
* The next major can bundle PG18 and drop 14. The steps are listed under
  "Next major" below.

Gel has no upper bound on the backend version: `MIN_POSTGRES_VERSION` in
`edb/server/defines.py` is the only check.

## Validation

All of these ran in Docker:

| Configuration | Result |
|---|---|
| Bundled 17.11 server (`gel/REL_17_11`) + 18.6 client tools (the minor) | full suite green\* (8727 ran) |
| Bundled 17.4 server + 18.6 client tools | full suite green\* |
| `--backend-dsn` to PG18 (`pgvector/pgvector:0.8.1-pg18`) | full suite green\* |
| `--backend-dsn` to PG14 (`pgvector/pgvector:0.8.1-pg14`) | full suite green\* |
| Bundled PG18 (next major) | every failure from the first full run fixed and re-run |
| `--backend-dsn` to PG19beta4 | boots; catalog probe clean; no full run |
| `edb_stat_statements` regression tests | pass on 17, 18 and 19beta4 |
| Simulated `pg_upgrade` schema restore, 17 → 18 | 0 errors |
| Simulated `pg_upgrade` schema restore, 17 → 19 | only errors from pgvector missing on the target (no pg19 pgvector image) |
| SQL adapter, dump and branch suites on the final branch: bundled 17 + 18 tools, remote 18, remote 14 | pass (623 / 623 / 597 ran) |

\* "Green" excludes failures unrelated to Postgres. These were the GraphQL
tests, whose helpers pass `transaction_options` that the pinned
`gel==3.1.0b1` client doesn't accept, plus clippy and rustfmt missing from
the build image.

Reproducing:

* `edb gen-sql-introspection [DSN...]` needs one running server per
  supported major. The defaults are `localhost:5413` to `5419`, i.e.
  `docker run -p 54NN:5432 -e POSTGRES_PASSWORD=pass postgres:NN`.
* `tests.pg-versions` in CI runs the suite against remote backends 14–18.
  This branch makes 18 the default and the version used by the
  remote-compiler and multi-tenant jobs.
* To run `edb_stat_statements` tests against a different major, build that
  Postgres and run `make installcheck PG_CONFIG=...`. The server needs
  `edb_stat_statements.track=dev` and `max_prepared_transactions > 0`.
* `postgres-18-19/upgrade_sim.sh` approximates the schema step of
  `pg_upgrade`. It dumps every Gel database with the target's `pg_dump`
  and restores it into the target. It is not `--binary-upgrade`, but it
  catches views that reference dropped catalog columns.
* The test `test_sql_query_introspection_07` runs `SELECT *` on every
  emulated catalog table. Most PG18 breakage showed up that way, so run it
  first against any new major.

## The SQL-to-SQL compiler (SQL adapter)

This section covers what happens to SQL that clients send to Gel's
Postgres-protocol port:

```
client SQL
  -> libpg_query (edb/pgsql/parser, geldata fork of 16-5.2.0)  JSON parse tree
  -> edb/pgsql/parser/ast_builder.py                            pgast
  -> edb/pgsql/resolver/*                                       pgast on backend objects
  -> edb/pgsql/codegen.py                                       SQL text
  -> backend (PG 14..19)
```

The resolver rewrites user tables to Gel's storage and maps `pg_catalog`
and `information_schema` to emulated views in `edgedbsql_VER`. It also
evaluates some functions statically (`resolver/static.py`) and forbids most
`pg_*` admin functions.

Gel reports itself to clients as PostgreSQL 13.9
(`PGEXT_POSTGRES_VERSION`, used by `version()` and `server_version`).
Clients therefore stick to 13-era catalog queries and syntax, whatever the
real backend is. Keep it that way in a minor: raising it makes clients such
as psql, pg_dump, ORMs and pgAdmin issue 14+-specific catalog queries. The
emulated views mostly support those, but nobody has tested them.

Each stage depends on the backend version differently.

### 1. Parser: does not depend on the backend; would need work to accept PG17+ syntax

The parser is the PG16 grammar from `libpg_query`
(`edb/pgsql/parser/libpg_query`, geldata fork at `16-5.2.0` plus 4
commits). Those commits add `pg_query_normalize` constant extraction (bool
and NULL constants) and `normalize_query_only`. The backend version doesn't
affect parsing, so this is not needed for PG18 support. Upgrading is only
worth it to accept newer client syntax. Upstream is at `18.1.0` (and
`17-6.2.x`).

If the parser is upgraded, `ast_builder.py` has to change. These are the
parse-tree changes between 16 and 18 in nodes that `ast_builder.py` reads:

* `InsertStmt`, `UpdateStmt` and `DeleteStmt` lost `returningList`. PG18
  replaced it with `returningClause: ReturningClause {options, exprs}`
  (for `RETURNING OLD/NEW`). `ast_builder` reads `returningList` in all
  three, so this is a hard break: `RETURNING` would silently be dropped.
* New fields such as `location`, `list_start`/`list_end` and
  `arg_location` are harmless.
* New node types (JSON_TABLE and the SQL/JSON functions, `MergeSupportFunc`,
  `ReturningExpr`/`ReturningOption`) are not handled, so they fail with
  `PSqlUnsupportedError`. That is the right default, because PG14–16
  backends couldn't run them anyway.
* The 4 fork commits must be rebased onto upstream's normalizer, which
  changed in 17 and 18.
* Anything newly accepted must be rejected or translated in the resolver
  when the backend is older. The resolver can see the backend version
  through `backend_runtime_params`.

### 2. Resolver: emulated catalogs depend on the backend version (fixed here)

Most of the PG18 breakage was here.

**Column metadata (`resolver/sql_introspection.py`).** This file was
generated from a single PG version. Now `edb gen-sql-introspection` queries
every supported major and records each column as
`(name, type, ver_since, ver_until)`. It keeps the union of columns,
including ones removed in later versions. `column_exists_in()` tests a
range.

**View generation (`metaschema._generate_sql_information_schema`).**

* `pg_catalog_columns()` builds column lists that depend on the backend.
  It emits `NULL::type` for columns the backend lacks.
* **Columns that any later PG removes are always `NULL`, even on backends
  that still have them.** Postgres keeps views as parse trees bound to
  column numbers. When `pg_upgrade` restores the views on a newer major,
  any reference to a removed column fails. Examples are
  `pg_attribute.attcacheoff`, gone in 18, and the `pg_stat_wal` columns.
  Without this rule a hosted 17 → 18 `pg_upgrade` fails. The cost is that a
  few deprecated or statistics columns read `NULL` on older backends.
* `empty_pg_view()` creates typed, empty views. It is used for tables the
  backend doesn't have (for example `pg_shmem_allocations_numa` in 18) and
  for tables that are hidden (`pg_subscription`).
* `administer fixup_backend_upgrade()` regenerates these views after a
  backend upgrade.
* The hand-written views (`pg_class`, `pg_attribute`, `pg_constraint`,
  `pg_database`, `pg_index`, `pg_type`, `pg_stats`,
  `pg_statistic_ext_data`) now use these helpers. Before, they used
  `pa.*`-style passthrough, which broke `UNION` arity when PG18 added
  `pg_class.relallfrozen`.
* `pg_constraint` gains the PG18 columns `conenforced` and `conperiod`.
  It also no longer reports foreign keys for computed links (see pg_dump
  18 below).
* New PG18/19 catalog tables are added automatically by `construct_pg_view`.

**Function allowlist (`resolver/static.py`).**
`ALLOWED_ADMIN_FUNCTIONS` assumes every listed function exists on every
backend:

* `pg_timezone_abbrevs()` was removed in PG18. It is now remapped
  (`resolver/expr.py:func_calls_remapping`) to a shim,
  `edgedbsql_VER.pg_timezone_abbrevs()`. The shim reads the
  `pg_timezone_abbrevs` view, which every version has. The column list in
  `range_functions.py` also had a typo (`is_ds`), now fixed. Covered by
  `test_sql_query_timezone_abbrevs`.
* `pg_is_in_backup` does not exist on PG15+. That was already the case
  before this work.
* Re-check this list for each new major with a `pg_proc` lookup.

**Columns of set-returning functions (`resolver/range_functions.py`).**
`FROM func()` gets explicit column aliases from a hard-coded list, so:

* If the backend returns more columns than the list, the extras are
  invisible.
* If it returns fewer, the backend fails with "too many column aliases".
* If the order changes, names attach to the wrong columns.

Of the allowed functions:

* `pg_get_replication_slots` gained columns in 16, 17, 18 and 19; they are
  hidden.
* `pg_get_publication_tables` changed shape in 15 and 16.
* Nothing allowed lost columns in 18 or 19.

The generator query in that file is broken. `ARRAY_AGG` over
`UNNEST`/`GENERATE_SERIES` doesn't keep argument order, and overloads get
merged. Several lists, all for forbidden functions, are in the wrong order.

If this needs fixing, generate the lists per version, like
`sql_introspection`. Use
`unnest(proargnames, proargmodes) WITH ORDINALITY`, filter on modes
`o`/`t`/`b`, and pick one overload. Choose the list at resolve time from
`ctx.options` and the backend version.

**Identifier quoting (`edb/pgsql/keywords.py`, used by
`common.needs_quoting`).** PG18 and 19 add only unreserved keywords. This
branch records them (`enforced`, `objects`, `period`, `virtual`, `ignore`,
`lsn`, `repack`, `respect`, `wait`), so quoting is unchanged.

The list was already out of date before this work. It lacks the reserved
`lateral` and `system_user` (reserved since 16), the type/func-name
keywords `collation` and `tablesample`, and several column-name keywords
(`grouping`, `normalize`, `xmltable`, `xmlexists`, `xmlnamespaces`,
`merge_action`). Codegen can therefore emit those unquoted.

The rule for this list is: **quote if reserved in any supported backend**.
Regenerate it from `pg_get_keywords()` on the newest supported major. When
the categories differ between versions, keep the stricter one.

### 3. Codegen and execution: planner and executor changes

The resolver's output is ordinary SQL, but PG18 changed how some of it
behaves:

* **Statement location.** PG18 sets `stmt_location` to the first token, so
  it no longer includes leading comments. Gel prefixes every query with a
  `-- {json}` comment, which `edb_stat_statements` uses for query info.
  The extension now walks back over leading `--` lines
  (`edbss_include_leading_comments`). Without that fix, PG18 recorded no
  stats for queries from either the SQL adapter or EdgeQL.
* **Normalization.** PG18 query jumbling squashes IN-lists and normalizes
  `SET` values. This only changes what `edb_stat_statements` reports (see
  its expected `*.out.18` and `*.out.19` files).
* `EXPLAIN` statements from SQL clients aren't parsed (`ExplainStmt` isn't
  handled), so PG18's EXPLAIN changes only affect EdgeQL `analyze`. See the
  next section.

## The EdgeQL-to-SQL compiler

Two planner changes in PG18 broke patterns the EdgeQL compiler depended on.
Both mean the same thing: **don't rely on the planner evaluating an
expression just for its side effects or because of how it is marked**.

* **Hash Right Semi Join (PG18) skipped `assert_exists`.** If an access
  policy hides the target of a required link, `select Ptr.tgt` must raise.
  `process_set_as_subquery` (`edb/pgsql/compiler/relgen.py`) deduplicates
  semi-joined paths with `IN (subquery)`. PG18 can run that as a hash right
  semi join that never evaluates the subquery's `assert_exists` for rows
  that don't match. It returned empty results instead of an error, with no
  test failing on PG17.

  The fix uses `DISTINCT` on the identity instead of the semi-join when the
  subquery contains `std::assert_exists`
  (`_contains_existence_assertion`). The policy, scope, select and globals
  suites cover it on PG18. Other assertions, such as
  `assert_single`/cardinality checks and `raise_on_null`, live in similar
  subqueries. They passed the suites on 18, but they are the place to look
  if similar reports come in.
* **Constant folding.** PG18 plans SQL-function bodies with the actual
  argument values, so `IMMUTABLE` functions that raise are folded, and
  raise, at plan time even in branches that never run.
  `edgedb._type_id_to_config_type` (`TypeIDToConfigType`) raised "unknown
  configuration type" at startup; it is now `STABLE`. Any metaschema
  function that can raise should not be `IMMUTABLE`.
* **`EXPLAIN`.**
  * PG18 includes `BUFFERS` by default, so `analyze (buffers := false)`
    now always sends `BUFFERS false` (`edb/server/compiler/compiler.py`).
  * PG18 reports fractional "actual rows" (averaged over loops).
    `test_edgeql_explain` no longer asserts an exact row count for a
    looped node.

## Branching and pg_dump

Branches are created by piping `pg_dump` into `psql`
(`edb/server/pgcluster.py`). Running pg_dump against Gel's emulated
catalogs (`tests/test_pg_dump.py`) is a separate path.

* `pg_dump` refuses to dump a server newer than itself. **With bundled
  17.4 tools, branching fails on a PG18 backend.** Newer tools work with
  older servers, so the minor ships 18.6 client tools
  (`_compile_pg_client_tools` in `setup.py`).
  * They are installed over the server's install tree, so
    `pg_config --bindir` still finds them.
  * The new `libpq.so.5` is ABI-compatible.
  * `pg_config` and `postgres` still report the bundled 17.x version.
* pg_dump from the August 2025 minor releases onward (17.6 and every
  18.x) emits `\restrict`/`\unrestrict` (fix for CVE-2025-8714).
  `dump_database` strips them, because its output is run directly rather
  than through psql. The `psql`-pipe path handles them natively when psql
  is new enough. The bundled server's own 17.11 `pg_dump` emits them
  too.
* pg_dump 18 no longer needs `relhastriggers` to dump foreign keys. It
  dumped FKs for computed links, which aren't real columns (text vs uuid),
  so the dump couldn't be restored. `pg_constraint` now excludes computed
  links. This affects anyone running their own pg_dump 18 against Gel's
  SQL port, not just branching.
* Branching on a PG19 backend needs PG19 tools. Bump `PG_CLIENT_COMMIT` to
  `REL_19_x` once 19.0 is released. pg_dump 19 has not been tested against
  Gel's emulated catalogs.

## edb_stat_statements

Version gates in `edb_stat_statements.c`:

* **PG18:**
  * `ExecutorRun` lost `execute_once`.
  * The normalizer was ported to `StringInfo`, with
    `num_constants_replaced`, `extern_param`, and squashed lists rendered
    as `/*, ... */`.
  * The stmt_location fix above.
* **PG19:**
  * `const JumbleState`.
  * New `ShmemInitHash` signature.
  * The planner hook gained an `ExplainState *es` argument.
  * `QueryDesc.totaltime` became `query_instr`/`query_instr_options`.
    `INSTRUMENT_ALL` is now requested in `ExecutorStart`.
  * `ComputeConstantLengths` is now in core, so the local
    `fill_in_constant_lengths`/`comp_location` are compiled only for <19.
  * `VARSIZE` takes a pointer.
  * Headers that are no longer included transitively are now included
    explicitly.

Expected-output variants are chosen by `pg_variant` in the `Makefile`.
The rules depend on `FORCE`, because stale copies survived switching
majors.

## pgvector

* 0.7.4 doesn't compile against PG18. 0.8.1+ supports 18, and 0.8.7 builds
  on 19.
* `ext::pgvector` accepts `vector >=0.7.4,<0.9.0` and installs the highest
  available version.
* The minor keeps 0.7.4, since it only needs to build against the bundled
  17. Bundling 0.8.x would quietly give new installs 0.8.
* Remote backends use whatever pgvector they have installed.

## The `postgres` fork (`gelstable/postgres`)

The `postgres` submodule now points at `gelstable/postgres`, a GitHub fork
of `geldata/postgres`, which will no longer be updated. Notes on it:

* It has all of `geldata`'s branches, including `gel/REL_16_STABLE`,
  `gel/REL_17_STABLE` and `gel/pkg/REL_17_STABLE`, plus upstream's
  `master`, `REL_*_STABLE` branches and every upstream release tag.
* Every commit the submodule has ever been pinned to can be reached from
  one of its branches or tags. Six old pins weren't on any branch in
  `geldata/postgres`. They are kept alive by `gel/pin/<sha>` tags; one of
  them, `86758c55069d`, was the pin for Gel 6.0–6.4.
* Gel's patches live on one branch per bundled release, made from an
  upstream tag. `gel/REL_17_11` is upstream `REL_17_11` plus the
  domain-rewrite patch, ported onto the code that upstream `d6dd2a02`
  ("Fix broken handling of domains in atthasmissing logic", 17.10)
  restructured. 17.4 carried a second commit, a cherry-picked macOS 15.4
  `strchrnul()` fix, which is upstream since 17.5.
* Syncing is plain git and doesn't use GitHub's "Sync fork" button, which
  would pull from the stale `geldata` parent:

  ```sh
  git remote add upstream https://github.com/postgres/postgres.git
  git fetch upstream --tags
  git push origin upstream/REL_17_STABLE:refs/heads/REL_17_STABLE REL_17_12
  git checkout -b gel/REL_17_12 REL_17_12
  git cherry-pick <patch commit from gel/REL_17_11>
  git push origin gel/REL_17_12
  ```

  The real cost of a bump is a conflict with the patch, which only happens
  when upstream changes the same code (as 17.10 did).

## Backport checklist (7.x minor)

1. Cherry-pick this branch's code changes, minus the CI matrix change if
   the release branch tests differently.
2. Add patches to `edb/pgsql/patches.py`. `master` keeps the list empty and
   relies on the catalog version.
   * `('metaschema-sql', 'TypeIDToConfigType')`. This must be applied
     **before** the backend is upgraded to PG18; otherwise the server
     fails at startup.
   * `('sql-introspection', '')`. It recreates the emulated views and the
     `edgedbsql` helper functions, including the new
     `pg_timezone_abbrevs` shim.
   * Add a patch that runs `edgedb._clear_query_cache()`, probably
     `('sql', ...)`. Persisted compiled queries, including the function
     cache, survive minor upgrades (`dbview.hydrate_cache`), so without it
     cached queries keep the pre-fix SQL from `relgen.py`.
   * Test them with the `tests-patches` workflow.
3. Keep pgvector at `v0.7.4`. Bump the bundled server to 17.11
   (`gelstable/postgres` branch `gel/REL_17_11`, see below). Ship the
   `PG_CLIENT_COMMIT` client tools. The 17.5–17.11 "Migration to
   Version 17.x" notes list post-upgrade steps, and none apply to Gel:
   * BRIN reindexes (17.5, 17.6): Gel creates no BRIN indexes.
   * Self-referential FKs on partitioned tables (17.5): Gel has no
     partitioned tables.
   * `btree_gist`/`ltree` reindexes (17.11): Gel uses neither.
   * The logical-decoding output plugin allowlist (17.11): Gel doesn't
     use logical decoding.
   * pgcrypto PGP cipher failures (17.11): `ext::pgcrypto` doesn't expose
     the `pgp_*` functions.
   * psql's scripted-COPY fix (17.11): branch restores pipe complete
     pg_dump output.

   Re-check these for later bumps.
4. The packaging (gel-pkg) must carry the overwritten `bin/pg_dump`,
   `bin/pg_restore`, `bin/pg_dumpall`, `bin/psql` and `lib/libpq*` from
   the install tree. Check this if it cherry-picks files rather than
   copying the whole tree.
5. For hosted instances, document the order: install the minor (patches
   applied), then run `pg_upgrade`, then
   `administer fixup_backend_upgrade()`.

## Next major (bundle PG18, support 15–18)

1. Create `gel/REL_18_x` in `gelstable/postgres` from upstream
   `REL_18_x` with the ported patch, the same way as `gel/REL_17_11`.
   Ports for 18 and 19 are in `postgres-18-19/`. The 18 port is what the
   bundled-PG18 test runs used; the 19 port has only been built
   against 19beta4. The port:
   * Build `CoerceToDomain(NULL)` only when
     `!defval && has_domain_constraints && DomainIsStrict(atttypid)`.
   * Add `DomainIsStrict()` to `typcache.c/h`.
2. pgvector `v0.8.x` (0.8.7 tested).
3. Drop `PG_CLIENT_COMMIT` and `_compile_pg_client_tools` (or keep them
   one major ahead). Raise `MIN_POSTGRES_VERSION` to 15.
4. PG18's `initdb` enables data checksums by default; decide whether
   that's wanted for bundled instances.
5. Optional: upgrade libpg_query (see "Parser" above), regenerate
   `range_functions.py` per version, and regenerate `keywords.py`.

## Unrelated problems found along the way

* Backend upgrades from PG14 or PG16 to 17+ fail on the schema restore.
  A stdlib function has a parameter named `json`. In PG17 `json` became a
  column-name keyword, which can't be used as a parameter name. The source
  server's `pg_get_function_arguments()` doesn't quote it, because the word
  wasn't a keyword there. This affects `pg_upgrade` of hosted instances.
  The fix is to rename the parameter (a stdlib change).
* `pg_is_in_backup` is allowlisted but doesn't exist on 15+.
* The `range_functions.py` generator and `keywords.py` are stale (see
  above).

## Files in `postgres-18-19/`

* `gel-nullable-domain-pg18.patch`, `gel-nullable-domain-pg19.patch`:
  ports of the fork patch.
* `upgrade_sim.sh`: the `pg_upgrade` schema-restore approximation.
