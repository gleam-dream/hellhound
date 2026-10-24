//// PostgreSQL implementation of Hellhound's public opaque-record store.
//// Borrows a named Pog pool; starts no processes and performs no retries.

import exception
import gleam/bit_array
import gleam/dynamic/decode
import gleam/erlang/process
import gleam/int
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/time/timestamp
import hellhound/store
import pog

pub opaque type Config {
  Config(
    pool: process.Name(pog.Message),
    schema: String,
    statement_timeout_ms: Int,
    lock_timeout_ms: Int,
  )
}

pub opaque type Adapter {
  Adapter(database: pog.Connection, schema: String, config: Config)
}

pub type Error {
  InvalidSchema
  InvalidLimits
  UnsupportedVersion(Int)
  DatabaseUnavailable
  DatabaseOutcomeUnknown
}

/// Pure defaults, using the database schema `hellhound`.
/// Keep server limits below the caller's Hellhound store deadline.
pub fn config(pool: process.Name(pog.Message)) -> Config {
  Config(pool, "hellhound", 1000, 250)
}

/// Select the caller-owned schema. `new` validates and quotes the name.
pub fn with_schema(config: Config, schema: String) -> Config {
  Config(..config, schema: schema)
}

/// Set PostgreSQL's transaction-local statement and lock limits in milliseconds.
/// `new` requires positive limits, lock <= statement and statement <= 60 seconds.
/// These limits do not replace Hellhound's outer store deadline.
pub fn with_timeouts(
  config: Config,
  statement_ms statement_ms: Int,
  lock_ms lock_ms: Int,
) -> Config {
  Config(..config, statement_timeout_ms: statement_ms, lock_timeout_ms: lock_ms)
}

/// Pure validation. Initialize the schema before supplying `records` to Hellhound.
/// A pool name, rather than a transaction connection, makes the ownership of
/// each store operation's transaction explicit.
pub fn new(config: Config) -> Result(Adapter, Error) {
  use schema <- result.try(quoted_schema(config.schema))
  case
    config.statement_timeout_ms > 0
    && config.statement_timeout_ms <= 60_000
    && config.lock_timeout_ms > 0
    && config.lock_timeout_ms <= config.statement_timeout_ms
  {
    False -> Error(InvalidLimits)
    True -> Ok(Adapter(pog.named_connection(config.pool), schema, config))
  }
}

fn quoted_schema(schema: String) -> Result(String, Error) {
  let bytes = bit_array.byte_size(<<schema:utf8>>)
  case
    bytes > 0
    && bytes <= 63
    && !string.contains(schema, "\u{0000}")
    && !string.starts_with(string.lowercase(schema), "pg_")
  {
    False -> Error(InvalidSchema)
    True -> Ok("\"" <> string.replace(schema, "\"", "\"\"") <> "\"")
  }
}

/// Idempotent, serialized initialization. Unknown formats are refused before
/// touching record data. The caller owns this schema and initialization rights.
pub fn initialize(adapter: Adapter) -> Result(Nil, Error) {
  transaction(adapter, DatabaseOutcomeUnknown, fn(db) {
    use _ <- result.try(
      pog.query(
        "SELECT true FROM (SELECT pg_advisory_xact_lock(hashtextextended($1, 0))) locked",
      )
      |> pog.parameter(pog.text("hellhound_postgres:" <> adapter.config.schema))
      |> execute(db, DatabaseOutcomeUnknown),
    )
    use _ <- result.try(
      pog.query("CREATE SCHEMA IF NOT EXISTS " <> adapter.schema)
      |> execute(db, DatabaseOutcomeUnknown),
    )
    use _ <- result.try(
      pog.query("CREATE TABLE IF NOT EXISTS " <> adapter.schema <> ".format (
        singleton boolean PRIMARY KEY DEFAULT true CHECK(singleton),
        version integer NOT NULL)")
      |> execute(db, DatabaseOutcomeUnknown),
    )
    use _ <- result.try(
      pog.query("INSERT INTO " <> adapter.schema <> ".format(version)
        VALUES (1) ON CONFLICT(singleton) DO NOTHING")
      |> execute(db, DatabaseOutcomeUnknown),
    )
    use Nil <- result.try(check_version(adapter, db))
    list.try_each(
      [
        "CREATE TABLE IF NOT EXISTS " <> adapter.schema <> ".records (
        key text PRIMARY KEY, version bigint NOT NULL,
        expires_seconds bigint NOT NULL,
        expires_nanoseconds integer NOT NULL CHECK (
          expires_nanoseconds >= 0 AND expires_nanoseconds < 1000000000),
        sealed bytea NOT NULL)",
        "CREATE INDEX IF NOT EXISTS records_expiry ON "
          <> adapter.schema
          <> ".records(expires_seconds, expires_nanoseconds)",
      ],
      fn(sql) {
        pog.query(sql)
        |> execute(db, DatabaseOutcomeUnknown)
        |> result.replace(Nil)
      },
    )
  })
}

/// The pool must outlive all Hellhound clients and their admitted store calls.
/// A handle never interprets sealed bytes, rotates keys, prunes automatically,
/// starts a pool, or supplies a fallback store.
pub fn records(adapter: Adapter) -> store.Store {
  store.new(
    get: fn(key) { get(adapter, key) },
    put: fn(record, condition) { put(adapter, record, condition) },
    delete_expired: fn(now) { delete_expired(adapter, now) },
  )
}

fn get(
  adapter: Adapter,
  key: String,
) -> Result(Option(store.Record), store.StoreError) {
  checked(adapter, DatabaseUnavailable, fn(db) {
    use returned <- result.try(
      pog.query(
        "SELECT key, version, expires_seconds, expires_nanoseconds, sealed
        FROM " <> adapter.schema <> ".records WHERE key = $1",
      )
      |> pog.parameter(pog.text(key))
      |> pog.returning(record_decoder())
      |> execute(db, DatabaseUnavailable),
    )
    case returned.rows {
      [] -> Ok(None)
      [record] -> Ok(Some(record))
      _ -> Error(DatabaseUnavailable)
    }
  })
  |> result.replace_error(store.StoreUnavailable)
}

fn put(
  adapter: Adapter,
  record: store.Record,
  condition: store.WriteCondition,
) -> Result(store.WriteOutcome, store.StoreError) {
  checked(adapter, DatabaseOutcomeUnknown, fn(db) {
    case condition {
      store.Absent -> write_record(adapter, db, record, None)
      store.AtVersion(version) ->
        write_record(adapter, db, record, Some(version))
      store.AtVersionBefore(version, deadline) -> {
        // The row lock must precede the clock sample. A time predicate on an
        // UPDATE may have been evaluated before the statement waited for a lock.
        use returned <- result.try(
          pog.query("SELECT version FROM " <> adapter.schema <> ".records
            WHERE key = $1 FOR UPDATE")
          |> pog.parameter(pog.text(record.key))
          |> pog.returning(decode.field(0, decode.int, decode.success))
          |> execute(db, DatabaseOutcomeUnknown),
        )
        case returned.rows {
          [current] if current == version -> {
            use before <- result.try(before_deadline(db, deadline))
            case before {
              False -> Ok(store.DeadlineElapsed)
              True -> write_record(adapter, db, record, Some(version))
            }
          }
          [] | [_] -> Ok(store.VersionConflict)
          _ -> Error(DatabaseOutcomeUnknown)
        }
      }
    }
  })
  |> result.map_error(store_error)
}

fn before_deadline(
  db: pog.Connection,
  deadline: timestamp.Timestamp,
) -> Result(Bool, Error) {
  let #(seconds, nanoseconds) =
    timestamp.to_unix_seconds_and_nanoseconds(deadline)
  use returned <- result.try(
    pog.query(
      "SELECT EXTRACT(EPOCH FROM clock_timestamp()) * 1000000000
      < ($1::bigint::numeric * 1000000000 + $2::bigint::numeric)",
    )
    |> pog.parameter(pog.int(seconds))
    |> pog.parameter(pog.int(nanoseconds))
    |> pog.returning(decode.field(0, decode.bool, decode.success))
    |> execute(db, DatabaseOutcomeUnknown),
  )
  case returned.rows {
    [before] -> Ok(before)
    _ -> Error(DatabaseOutcomeUnknown)
  }
}

fn write_record(
  adapter: Adapter,
  db: pog.Connection,
  record: store.Record,
  expected: Option(Int),
) -> Result(store.WriteOutcome, Error) {
  let #(seconds, nanoseconds) =
    timestamp.to_unix_seconds_and_nanoseconds(record.expires_at)
  let query = case expected {
    None -> pog.query("INSERT INTO " <> adapter.schema <> ".records
      (key, version, expires_seconds, expires_nanoseconds, sealed)
      VALUES ($1, $2, $3, $4, $5) ON CONFLICT(key) DO NOTHING")
    Some(_) -> pog.query("UPDATE " <> adapter.schema <> ".records SET
      version = $2, expires_seconds = $3, expires_nanoseconds = $4, sealed = $5
      WHERE key = $1 AND version = $6")
  }
  let query =
    query
    |> pog.parameter(pog.text(record.key))
    |> pog.parameter(pog.int(record.version))
    |> pog.parameter(pog.int(seconds))
    |> pog.parameter(pog.int(nanoseconds))
    |> pog.parameter(pog.bytea(record.sealed))
  let query = case expected {
    None -> query
    Some(version) -> pog.parameter(query, pog.int(version))
  }
  use returned <- result.try(execute(query, db, DatabaseOutcomeUnknown))
  case returned.count {
    1 -> Ok(store.Written)
    0 -> Ok(store.VersionConflict)
    _ -> Error(DatabaseOutcomeUnknown)
  }
}

fn delete_expired(
  adapter: Adapter,
  now: timestamp.Timestamp,
) -> Result(Int, store.StoreError) {
  checked(adapter, DatabaseOutcomeUnknown, fn(db) {
    let #(seconds, nanoseconds) = timestamp.to_unix_seconds_and_nanoseconds(now)
    pog.query("DELETE FROM " <> adapter.schema <> ".records
      WHERE (expires_seconds, expires_nanoseconds) <= ($1, $2)")
    |> pog.parameter(pog.int(seconds))
    |> pog.parameter(pog.int(nanoseconds))
    |> execute(db, DatabaseOutcomeUnknown)
    |> result.map(fn(returned) { returned.count })
  })
  |> result.map_error(store_error)
}

fn record_decoder() -> decode.Decoder(store.Record) {
  use key <- decode.field(0, decode.string)
  use version <- decode.field(1, decode.int)
  use seconds <- decode.field(2, decode.int)
  use nanoseconds <- decode.field(3, decode.int)
  use sealed <- decode.field(4, decode.bit_array)
  decode.success(store.Record(
    key,
    version,
    timestamp.from_unix_seconds_and_nanoseconds(seconds, nanoseconds),
    sealed,
  ))
}

fn check_version(adapter: Adapter, db: pog.Connection) -> Result(Nil, Error) {
  use returned <- result.try(
    pog.query(
      "SELECT version FROM "
      <> adapter.schema
      <> ".format WHERE singleton FOR SHARE",
    )
    |> pog.returning(decode.field(0, decode.int, decode.success))
    |> execute(db, DatabaseUnavailable),
  )
  case returned.rows {
    [1] -> Ok(Nil)
    [version] -> Error(UnsupportedVersion(version))
    _ -> Error(DatabaseUnavailable)
  }
}

fn checked(
  adapter: Adapter,
  failure: Error,
  run: fn(pog.Connection) -> Result(a, Error),
) -> Result(a, Error) {
  transaction(adapter, failure, fn(db) {
    use Nil <- result.try(check_version(adapter, db))
    run(db)
  })
}

fn transaction(
  adapter: Adapter,
  failure: Error,
  run: fn(pog.Connection) -> Result(a, Error),
) -> Result(a, Error) {
  // Pog's query timeout does not bound checked-out connections. Enforce work
  // limits in PostgreSQL; Hellhound still owns the outer store-call deadline.
  case
    exception.rescue(fn() {
      pog.transaction(adapter.database, fn(db) {
        use _ <- result.try(
          pog.query(
            "SELECT set_config('statement_timeout', $1, true),
          set_config('lock_timeout', $2, true),
          set_config('idle_in_transaction_session_timeout', $3, true)",
          )
          |> pog.parameter(
            pog.text(int.to_string(adapter.config.statement_timeout_ms)),
          )
          |> pog.parameter(
            pog.text(int.to_string(adapter.config.lock_timeout_ms)),
          )
          |> pog.parameter(
            pog.text(int.to_string(adapter.config.statement_timeout_ms * 2)),
          )
          |> execute(db, DatabaseUnavailable),
        )
        run(db)
      })
    })
  {
    Ok(Ok(value)) -> Ok(value)
    Ok(Error(pog.TransactionRolledBack(error))) -> Error(error)
    Ok(Error(pog.TransactionQueryError(_))) | Error(_) -> Error(failure)
  }
}

fn execute(
  query: pog.Query(a),
  db: pog.Connection,
  failure: Error,
) -> Result(pog.Returned(a), Error) {
  pog.execute(query, db) |> result.replace_error(failure)
}

fn store_error(error: Error) -> store.StoreError {
  case error {
    DatabaseOutcomeUnknown -> store.StoreOutcomeUnknown
    InvalidSchema
    | InvalidLimits
    | UnsupportedVersion(_)
    | DatabaseUnavailable -> store.StoreUnavailable
  }
}
