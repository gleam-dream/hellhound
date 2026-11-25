//// The record store port: the in-memory store meets the contract, a
//// broken adapter is caught by `testing.check_store`, the login store is
//// bounded, and a slow store fails one call without leaking its reply.

import exception
import gleam/erlang/process
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleam/time/timestamp
import hellhound/internal/memory_store
import hellhound/internal/port
import hellhound/store
import hellhound/testing
import hellhound_test_support as support

pub fn the_memory_store_meets_the_contract_test() {
  assert testing.check_store(testing.memory_store()) == Ok(Nil)
}

/// An adapter without compare-and-set fails the conformance check.
pub fn a_store_without_compare_and_set_fails_the_check_test() {
  let inner = testing.memory_store()
  let careless =
    store.new(
      get: fn(key) { store.get(inner, key) },
      // Ignores the condition: last write wins.
      put: fn(record, _expected) {
        let current = store.get(inner, record.key)
        let expected = case current {
          Ok(Some(existing)) -> store.AtVersion(existing.version)
          _ -> store.Absent
        }
        store.put(inner, record, expected)
      },
      delete_expired: fn(now) { store.delete_expired(inner, now) },
    )
  let assert Error(failures) = testing.check_store(careless)
  assert list.contains(failures, "insert of a present key is refused")
  assert list.contains(failures, "replace at a stale version is refused")
  assert list.all(failures, fn(f) { !string.is_empty(f) })
}

fn record(key: String, expires: Int) -> store.Record {
  store.Record(
    key:,
    version: 1,
    expires_at: timestamp.from_unix_seconds(expires),
    sealed: <<1>>,
  )
}

/// A store call that outlives the store timeout fails typed, and its late
/// reply never reaches the caller's mailbox.
pub fn slow_store_calls_fail_typed_without_late_replies_test() {
  let slow =
    store.new(
      get: fn(_) {
        process.sleep(200)
        Ok(None)
      },
      put: fn(_, _) {
        process.sleep(200)
        Ok(store.Written)
      },
      delete_expired: fn(_) { Ok(0) },
    )
  let impatient = port.Port(store: slow, timeout_ms: 50)
  let before = support.mailbox_size()
  assert port.get(impatient, "k") == Error(store.StoreUnavailable)
  assert port.put(impatient, record("k", 1), store.Absent)
    == Error(store.StoreOutcomeUnknown)
  assert port.put(
      impatient,
      record("k", 1),
      store.AtVersionBefore(1, timestamp.from_unix_seconds(100)),
    )
    == Error(store.StoreOutcomeUnknown)
  process.sleep(300)
  assert support.mailbox_size() == before
}

/// An adapter that raises fails typed instead of crashing the caller.
pub fn a_crashing_adapter_fails_typed_test() {
  let crashing =
    store.new(
      get: fn(_) { panic as "adapter bug" },
      put: fn(_, _) { panic as "adapter bug" },
      delete_expired: fn(_) { Ok(0) },
    )
  let p = port.Port(store: crashing, timeout_ms: 1000)
  assert port.get(p, "k") == Error(store.StoreUnavailable)
  assert port.put(p, record("k", 1), store.Absent)
    == Error(store.StoreOutcomeUnknown)
}

/// The public checker must reject adapters that silently ignore the deadline.
pub fn an_adapter_without_deadline_admission_fails_conformance_test() {
  let inner = testing.memory_store()
  let careless =
    store.new(
      get: store.get(inner, _),
      put: fn(record, condition) {
        let condition = case condition {
          store.AtVersionBefore(version, _) -> store.AtVersion(version)
          other -> other
        }
        store.put(inner, record, condition)
      },
      delete_expired: store.delete_expired(inner, _),
    )
  let assert Error(failures) = testing.check_store(careless)
  assert list.contains(
    failures,
    "expired guard refuses without changing bytes, version or retention",
  )
}

/// Admission samples time after the actor obtains exclusive write authority.
pub fn a_queued_guard_refuses_at_exact_expiry_test() {
  let clock = support.clock_new(99)
  let name = process.new_name("queued_guard")
  let assert Ok(started) =
    memory_store.start(name, fn() { support.clock_read(clock) })
  use <- exception.defer(fn() {
    process.unlink(started.pid)
    process.kill(started.pid)
  })
  let records = memory_store.store(started.data, 5000)
  let pending = record("pending", 500)
  let assert Ok(store.Written) = store.put(records, pending, store.Absent)
  suspend(started.pid)
  let reply = process.new_subject()
  process.spawn(fn() {
    process.send(
      reply,
      store.put(
        records,
        store.Record(..pending, version: 2, sealed: <<9>>),
        store.AtVersionBefore(1, timestamp.from_unix_seconds(100)),
      ),
    )
  })
  await_queued(started.pid, 1000)
  assert support.clock_read(clock) == 99
  support.clock_set(clock, 100)
  resume(started.pid)
  let assert Ok(outcome) = process.receive(reply, 5000)
  assert outcome == Ok(store.DeadlineElapsed)
  assert store.get(records, "pending") == Ok(Some(pending))
  // The refusal does not consume the version or shorten retention.
  assert store.put(
      records,
      store.Record(..pending, version: 2),
      store.AtVersionBefore(1, timestamp.from_unix_seconds(101)),
    )
    == Ok(store.Written)
  assert store.delete_expired(records, timestamp.from_unix_seconds(101))
    == Ok(0)
}

@external(erlang, "hellhound_store_barrier_ffi", "suspend")
fn suspend(pid: process.Pid) -> Nil

@external(erlang, "hellhound_store_barrier_ffi", "resume")
fn resume(pid: process.Pid) -> Nil

@external(erlang, "hellhound_store_barrier_ffi", "queue_length")
fn queue_length(pid: process.Pid) -> Int

fn await_queued(pid: process.Pid, attempts: Int) -> Nil {
  case queue_length(pid) > 0, attempts {
    True, _ -> Nil
    False, 0 -> panic as "guarded write never entered the actor mailbox"
    False, _ -> {
      process.sleep(1)
      await_queued(pid, attempts - 1)
    }
  }
}
