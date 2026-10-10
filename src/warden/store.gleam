//// A storage port for Warden's opaque login and custody records.
////
//// Stores provide three operations: `get`, conditional `put`, and
//// `delete_expired`. Warden owns protocol transitions and seals every record;
//// adapters own atomic write admission and report effect knowledge honestly.
//// Captured database pools remain application-owned. Warden bounds adapter
//// calls in isolated workers; timing out a write cannot prove it did not act.
////
//// `Absent` inserts only a missing key. `AtVersion` replaces only the expected
//// version. `AtVersionBefore` also requires the adapter's wall clock to be
//// strictly before the supplied deadline. Check version first, then sample
//// time under exclusive write authority, after any lock or queue wait.
//// Missing rows and stale versions return `VersionConflict` even if expired.
//// Refusals change no record. Only `AtVersionBefore` returns `DeadlineElapsed`.
////
//// The deadline governs the protected decision, not commit acknowledgement
//// or request completion. `Written` requires confirmation that the write
//// succeeded. Lost acknowledgement remains `StoreOutcomeUnknown`.
//// `Record.expires_at` governs retention and must not stand in for validity.
//// The built-in store samples its configured Unix-second wall clock; durable
//// adapters document their clock and precision. Hosts must synchronize clocks.
////
//// In PostgreSQL a guarded replacement can lock the row in a transaction,
//// check its version, sample `clock_timestamp()`, and conditionally update.
//// Transaction-start time and an UPDATE time predicate evaluated before a
//// lock wait do not establish the required boundary. Test actual lock waits.
////
//// ```gleam
//// let records = store.new(
////   get: fn(key) { db.get(pool, key) },
////   put: fn(record, condition) { db.put(pool, record, condition) },
////   delete_expired: fn(now) { db.delete_expired(pool, now) },
//// )
//// config.new(issuer:, client_id:, redirect_uri:, authentication:)
//// |> config.with_custody_store(records)
//// |> config.with_sealing_key(sealing_key)
//// ```
////
//// `warden/testing.check_store` checks observable contract outcomes. Adapters
//// also need queue/lock-wait and uncertain-commit tests for their own runtime.
//// There is no legacy adapter fallback with a weaker expiry guarantee.

import gleam/option.{type Option}
import gleam/time/timestamp.{type Timestamp}

/// One stored record. `sealed` is opaque to the store.
pub type Record {
  Record(key: String, version: Int, expires_at: Timestamp, sealed: BitArray)
}

/// The complete set of supported atomic write conditions.
pub type WriteCondition {
  Absent
  AtVersion(version: Int)
  AtVersionBefore(version: Int, deadline: Timestamp)
}

/// A confirmed write or a confirmed refusal. Neither refusal changes the row.
pub type WriteOutcome {
  Written
  /// The key already exists for Absent, or the expected version is absent.
  VersionConflict
  /// The version matched, but the protected clock sample reached the deadline.
  DeadlineElapsed
}

pub type StoreError {
  /// The store did not act: nothing was read or written.
  StoreUnavailable
  /// The store may or may not have written (a timeout or a lost reply).
  StoreOutcomeUnknown
  /// The store refuses new records because it is at capacity. Nothing was
  /// written.
  StoreFull
}

/// A record store. Build one with `new`.
pub opaque type Store {
  Store(
    get: fn(String) -> Result(Option(Record), StoreError),
    put: fn(Record, WriteCondition) -> Result(WriteOutcome, StoreError),
    delete_expired: fn(Timestamp) -> Result(Int, StoreError),
  )
}

/// A store from its three operations (see the module documentation).
pub fn new(
  get get: fn(String) -> Result(Option(Record), StoreError),
  put put: fn(Record, WriteCondition) -> Result(WriteOutcome, StoreError),
  delete_expired delete_expired: fn(Timestamp) -> Result(Int, StoreError),
) -> Store {
  Store(get:, put:, delete_expired:)
}

/// Read the record with this key.
pub fn get(store: Store, key: String) -> Result(Option(Record), StoreError) {
  store.get(key)
}

/// Atomically write if the condition holds. See WriteCondition and the module
/// contract for clock authority, refusal precedence and acknowledgement.
pub fn put(
  store: Store,
  record: Record,
  condition: WriteCondition,
) -> Result(WriteOutcome, StoreError) {
  store.put(record, condition)
}

/// Delete the records that expired at or before `now`.
pub fn delete_expired(store: Store, now: Timestamp) -> Result(Int, StoreError) {
  store.delete_expired(now)
}

/// Describe a store error for logs.
pub fn describe_error(error: StoreError) -> String {
  case error {
    StoreUnavailable -> "the store did not act"
    StoreOutcomeUnknown -> "the store may or may not have written"
    StoreFull -> "the store is at capacity"
  }
}
