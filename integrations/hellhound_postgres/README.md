# hellhound_postgres

A PostgreSQL adapter for Hellhound's public `hellhound/store` contract. It borrows a
caller-owned Pog pool, adds no application membership rules or FFI, and keeps
PostgreSQL out of Hellhound core. It is unpublished and not production qualified.

## Installation

Add Hellhound and Pog from Hex and the PostgreSQL adapter from its Git subdirectory:

```toml
[dependencies]
hellhound = ">= 0.1.0 and < 0.3.0"
pog = ">= 4.1.0 and < 4.2.0"
hellhound_postgres = { git = "https://github.com/gleam-dream/hellhound.git", ref = "main", path = "integrations/hellhound_postgres" }
```

Commit `gleam.toml` and `manifest.toml` to retain the resolved versions and Git commit.

## Configure the store

The adapter tests configure a separate schema on a caller-owned pool `name`:

<!-- prettier-ignore-start -->
<!-- snips: test/hellhound_postgres_test.gleam#configure-adapter -->
```gleam
let config = hellhound_postgres.config(name)
let assert Ok(isolated) =
  hellhound_postgres.new(
    config
    |> hellhound_postgres.with_schema("Other\"Hellhound")
    |> hellhound_postgres.with_timeouts(statement_ms: 2000, lock_ms: 250),
  )
let assert Ok(Nil) = hellhound_postgres.initialize(isolated)
let records = hellhound_postgres.records(isolated)
```
<!-- prettier-ignore-end -->

The login integration test supplies the resulting store to Hellhound. Its fixture
provides `db` and a local issuer `provider`; `key` is the sealing key prepared by
the test:

<!-- prettier-ignore-start -->
<!-- snips: test/hellhound_postgres_test.gleam#configure-client -->
```gleam
let records = hellhound_postgres.records(adapter(db))
let config =
  testing.config(provider, "https://app.test/callback")
  |> config.with_custody_store(records)
  |> config.with_transaction_store(records)
  |> config.with_sealing_key(key)
```
<!-- prettier-ignore-end -->

- `new` validates configuration without I/O. `initialize` serializes schema setup and rejects unknown formats.
- The application owns the pool, the sealing keys across restarts and rotation, and the synchronization of database and Hellhound host clocks.
- The adapter prunes nothing and retries nothing. An uncertain write returns `StoreOutcomeUnknown`.
- The design's "Optional PostgreSQL integration" section states the write, clock, timeout and format semantics.

Run the adapter's public consumer from the Hellhound repository root:

```sh
nix develop --command scripts/postgres-check
```

The script creates and removes its own temporary PostgreSQL cluster. Gleam fetches
HTTP Gun and Sinal from Hex, at the versions and checksums locked in `manifest.toml`.
