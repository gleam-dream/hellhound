//// The built-in in-memory record store: one actor holding a dictionary,
//// implementing the `hellhound/store` contract (compare-and-set `put`,
//// `delete_expired`). Records do not survive a restart of the actor; each
//// start draws a new random epoch, which lets custody tell a session lost on
//// restart from one that never existed. It has no capacity bound: sessions
//// per identity are deliberately unbounded, and expired records leave with
//// the sweeper's `delete_expired`.

import gleam/dict.{type Dict}
import gleam/erlang/process.{type Subject}
import gleam/list
import gleam/option.{type Option}
import gleam/order
import gleam/otp/actor
import gleam/result
import gleam/time/timestamp.{type Timestamp}
import hellhound/internal/call
import hellhound/internal/secure
import hellhound/store.{type Record, type Store, type StoreError}

pub opaque type Message {
  Get(key: String, reply: Subject(Option(Record)))
  Put(
    record: Record,
    condition: store.WriteCondition,
    reply: Subject(Result(store.WriteOutcome, StoreError)),
  )
  DeleteExpired(now: Timestamp, reply: Subject(Int))
  Epoch(reply: Subject(String))
  Size(reply: Subject(Int))
}

type State {
  State(records: Dict(String, Record), clock: fn() -> Int, epoch: String)
}

pub fn start(
  name: process.Name(Message),
  clock: fn() -> Int,
) -> actor.StartResult(Subject(Message)) {
  actor.new(State(records: dict.new(), clock:, epoch: secure.random_token(9)))
  |> actor.named(name)
  |> actor.on_message(handle)
  |> actor.start
}

/// An unnamed, unsupervised store linked to the caller (`hellhound/testing`).
pub fn start_linked() -> Result(Subject(Message), actor.StartError) {
  actor.new(State(
    records: dict.new(),
    clock: secure.now_seconds,
    epoch: secure.random_token(9),
  ))
  |> actor.on_message(handle)
  |> actor.start
  |> result.map(fn(started) { started.data })
}

fn handle(state: State, message: Message) -> actor.Next(State, Message) {
  case message {
    Get(key, reply) -> {
      process.send(reply, option.from_result(dict.get(state.records, key)))
      actor.continue(state)
    }
    Put(record, condition, reply) -> {
      case check_condition(state, record.key, condition) {
        Error(refusal) -> {
          process.send(reply, Ok(refusal))
          actor.continue(state)
        }
        Ok(Nil) -> {
          let records = dict.insert(state.records, record.key, record)
          process.send(reply, Ok(store.Written))
          actor.continue(State(..state, records:))
        }
      }
    }
    DeleteExpired(now, reply) -> {
      let #(expired, kept) =
        dict.to_list(state.records)
        |> list.partition(fn(entry) { not_after(entry.1.expires_at, now) })
      process.send(reply, list.length(expired))
      actor.continue(State(..state, records: dict.from_list(kept)))
    }
    Epoch(reply) -> {
      process.send(reply, state.epoch)
      actor.continue(state)
    }
    Size(reply) -> {
      process.send(reply, dict.size(state.records))
      actor.continue(state)
    }
  }
}

// Actor ownership protects both the version check and the clock sample.
fn check_condition(
  state: State,
  key: String,
  condition: store.WriteCondition,
) -> Result(Nil, store.WriteOutcome) {
  case dict.get(state.records, key), condition {
    Error(Nil), store.Absent -> Ok(Nil)
    Ok(existing), store.AtVersion(version) if existing.version == version ->
      Ok(Nil)
    Ok(existing), store.AtVersionBefore(version, deadline)
      if existing.version == version
    -> {
      let now = timestamp.from_unix_seconds(state.clock())
      case timestamp.compare(now, deadline) {
        order.Lt -> Ok(Nil)
        order.Eq | order.Gt -> Error(store.DeadlineElapsed)
      }
    }
    _, _ -> Error(store.VersionConflict)
  }
}

fn not_after(a: Timestamp, b: Timestamp) -> Bool {
  timestamp.compare(a, b) != order.Gt
}

/// The store over a running actor, each call bounded by `timeout_ms`.
pub fn store(subject: Subject(Message), timeout_ms: Int) -> Store {
  let unavailable = fn(_) { store.StoreUnavailable }
  store.new(
    get: fn(key) {
      call.call(subject, timeout_ms, Get(key, _))
      |> result.map_error(unavailable)
    },
    put: fn(record, condition) {
      case call.call(subject, timeout_ms, Put(record, condition, _)) {
        Ok(outcome) -> outcome
        Error(_) -> Error(store.StoreOutcomeUnknown)
      }
    },
    delete_expired: fn(now) {
      call.call(subject, timeout_ms, DeleteExpired(now, _))
      |> result.map_error(fn(_) { store.StoreOutcomeUnknown })
    },
  )
}

/// The store's current epoch.
pub fn epoch(
  subject: Subject(Message),
  timeout_ms: Int,
) -> Result(String, StoreError) {
  call.call(subject, timeout_ms, Epoch)
  |> result.replace_error(store.StoreUnavailable)
}

/// The number of records held (tests).
pub fn size(
  subject: Subject(Message),
  timeout_ms: Int,
) -> Result(Int, StoreError) {
  call.call(subject, timeout_ms, Size)
  |> result.replace_error(store.StoreUnavailable)
}
