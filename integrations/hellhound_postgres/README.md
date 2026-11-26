# hellhound_postgres

[![CI](https://github.com/gleam-dream/hellhound/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/gleam-dream/hellhound/actions/workflows/ci.yml)
[![hellhound on Hex](https://img.shields.io/hexpm/v/hellhound?label=Hex%3A%20hellhound)](https://hex.pm/packages/hellhound)
[![Gleam](https://img.shields.io/badge/Gleam-FFAFF3?logo=gleam&logoColor=000000)](https://gleam.run/)

A PostgreSQL adapter for Hellhound's public `hellhound/store` contract. It borrows a
caller-owned Pog pool, adds no application membership rules or FFI, and keeps
PostgreSQL out of Hellhound core. It is unpublished and not production qualified.

## Installation

Add Hellhound and Pog from Hex and the PostgreSQL adapter from its Git subdirectory:

```toml
[dependencies]
hellhound = ">= 0.4.0 and < 0.5.0"
pog = ">= 4.1.0 and < 4.2.0"
hellhound_postgres = { git = "https://github.com/gleam-dream/hellhound.git", ref = "hellhound_postgres-v0.2.1", path = "integrations/hellhound_postgres" }
```

Commit `gleam.toml` and `manifest.toml` to retain the resolved versions and Git commit.

### Upgrading from 0.2.0 to Hellhound 0.4

Release 0.2.0 requires Hellhound 0.3, and release 0.2.1 requires Hellhound 0.4.
Change the `hellhound` and `hellhound_postgres` lines together, to the values in
the block above.

Then delete every call to `config.with_transaction_store`: Hellhound 0.4 keeps
pending logins in sealed browser cookies and writes none to a store. Keep
`config.with_custody_store(records)` and `config.with_sealing_key(key)`. The
schema and the custody record format are unchanged, so installed sessions
survive. Rows of pending logins that 0.3 wrote are no longer read: the session
sweeper deletes them once they expire when the transaction store was the custody
store; when it was a separate table or schema, drop it one login lifetime after
the upgrade. The [Hellhound migration guide](https://github.com/gleam-dream/hellhound/blob/main/docs/MIGRATION.md#postgresql-adapter)
covers the rest of the upgrade.

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

The login integration test supplies the resulting store to Hellhound as its
custody store; pending logins live in sealed browser cookies and need no store.
Its fixture provides `db` and a local issuer `provider`; `key` is the sealing key
prepared by the test:

<!-- prettier-ignore-start -->
<!-- snips: test/hellhound_postgres_test.gleam#configure-client -->
```gleam
let records = hellhound_postgres.records(adapter(db))
let config =
  testing.config(provider, "https://app.test/callback")
  |> config.with_custody_store(records)
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
