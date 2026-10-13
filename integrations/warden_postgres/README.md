# warden_postgres

A standalone PostgreSQL adapter for Warden's public `warden/store` contract.
This optional package implements the existing store contract without adding
PostgreSQL to Warden core. It borrows a caller-owned Pog pool and has no
application membership rules, protocol implementation, or new FFI. It is not
yet published or production qualified.

```gleam
let settings = warden_postgres.config(pool_name)
  |> warden_postgres.with_schema("authentication")
  |> warden_postgres.with_timeouts(statement_ms: 1000, lock_ms: 250)
let assert Ok(adapter) = warden_postgres.new(settings)
let assert Ok(Nil) = warden_postgres.initialize(adapter)
let records = warden_postgres.records(adapter)
let settings = oidc_config
  |> config.with_transaction_store(records)
  |> config.with_custody_store(records)
  |> config.with_sealing_key(key_from_secret_storage)
```

`new` validates configuration without I/O. `initialize` serializes initialization
and rejects unknown schema formats; it never imports application data. Configure
the opaque `Config` with `with_schema` and `with_timeouts`; both setters are pure,
and `new` rejects invalid names or limits. Schema names are quoted, checked for
PostgreSQL's byte limit and reserved prefix, and never interpolated as SQL
expressions.

Each callback commits its own transaction. The adapter borrows a named Pog pool,
so it cannot accidentally commit an application's transaction. Reads return
expired records until explicit pruning. Insert does not overwrite expired keys.
The store implements `Absent`, `AtVersion` and `AtVersionBefore`, returning
`Written`, `VersionConflict` or `DeadlineElapsed`. A guarded replacement locks
the row first, checks its version, then samples PostgreSQL `clock_timestamp()`.
The database wall clock is authoritative, at PostgreSQL's microsecond precision;
deadlines are compared as exact numeric nanoseconds without floating-point
conversion. Missing rows and stale versions take precedence over expiry. A
deadline at or before the protected clock sample is refused without mutation.
Validity is independent of the record's retention expiry. A timely decision
can commit or be acknowledged later; an unconfirmed commit remains unknown.
Synchronize the database and Warden host clocks. No local precheck or weaker
legacy write callback substitutes for the database decision.

Versioned replacement is atomic; sealed bytes and nanosecond expiry round-trip
without interpretation. Every callback checks the schema format, including
handles constructed before a format change. No automatic retries or pruning.

Writes with an uncertain result return `StoreOutcomeUnknown`; a database error
is never interpreted as a successful write or a CAS conflict. The mapping is
conservative, including some failures for which PostgreSQL rolled back. Reads
and known pre-write format refusals return `StoreUnavailable`. The store is
uncapped; it does not report `StoreFull` or silently evict sessions.

Server statement and lock limits default to 1000ms and 250ms. Each transaction
sets these locally, plus an idle transaction timeout of twice the statement
limit. They do not persist on the borrowed connection. Pog 4.1 ignores its query
timeout on checked-out connections; this adapter therefore uses PostgreSQL
limits, not that API, to bound database work. Pool checkout, network loss and
initial transaction setup still depend on the driver and Warden's outer store
call deadline. Keep server limits below that deadline. These settings do not
promise immediate cancellation or a hard bound on cleanup.

The application owns the pool and must keep it alive for Warden clients and any
admitted store calls. The adapter starts and stops nothing. Existing Warden
shutdown/drain and security-review release conditions remain unresolved by this
adapter. Persist the same sealing key across restarts and supply old keys during
rotation; Warden owns encryption, identity and session lifecycle.

Run the PostgreSQL consumer from the Warden repository root:

```sh
nix develop --command scripts/postgres-check
```

The script creates and removes its own temporary PostgreSQL cluster. Tests use
this package's public API, Warden's store conformance suite and local HTTPS test
issuer. They cover nanosecond retention, concurrent conditional writes, lock
waits crossing validity deadlines, unknown acknowledgements, session restoration
and rotating refresh. No application-specific queue or identity policy is used.
A lost reply decorator is explicit injected evidence, not a network-loss claim.

Gleam fetches HTTP Gun and Sinal from the immutable Git revisions declared in
`gleam.toml`; no sibling checkouts are required. Warden remains an in-repository
path dependency. HTTP Gun and Sinal provide Warden's transport and observations;
they are not database extension points.
