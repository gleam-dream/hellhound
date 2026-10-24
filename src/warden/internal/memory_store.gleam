//// The built-in in-memory record store: one actor holding a dictionary,
//// implementing the `warden/store` contract (compare-and-set `put`,
//// `delete_expired`). Records do not survive a restart of the actor; each
//// start draws a new random epoch, which lets custody tell a session lost on
//// restart from one that never existed.
////
//// With a capacity, an insert into a full store first drops expired records
//// (oldest first, in constant amortised time) and then refuses with
//// `StoreFull`.

import gleam/dict.{type Dict}
import gleam/erlang/process.{type Subject}
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/order
import gleam/otp/actor
import gleam/result
import gleam/time/timestamp.{type Timestamp}
import warden/internal/call
import warden/internal/fifo.{type Fifo}
import warden/internal/secure
import warden/store.{type Record, type Store, type StoreError}

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
  State(
    records: Dict(String, Record),
    order: Fifo(#(Timestamp, String)),
    capacity: Option(Int),
    clock: fn() -> Int,
    epoch: String,
  )
}

pub fn start(
  name: process.Name(Message),
  capacity: Option(Int),
  clock: fn() -> Int,
) -> actor.StartResult(Subject(Message)) {
  actor.new(State(
    records: dict.new(),
    order: fifo.new(),
    capacity:,
    clock:,
    epoch: secure.random_token(9),
  ))
  |> actor.named(name)
  |> actor.on_message(handle)
  |> actor.start
}

/// An unnamed, unsupervised store linked to the caller (`warden/testing`).
pub fn start_linked(
  capacity: Option(Int),
) -> Result(Subject(Message), actor.StartError) {
  actor.new(State(
    records: dict.new(),
    order: fifo.new(),
    capacity:,
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
          let state = case condition {
            store.Absent -> make_room(state)
            store.AtVersion(_) | store.AtVersionBefore(_, _) -> state
          }
          case condition, full(state) {
            store.Absent, True -> {
              process.send(reply, Error(store.StoreFull))
              actor.continue(state)
            }
            _, _ -> {
              let state =
                State(
                  ..state,
                  records: dict.insert(state.records, record.key, record),
                  order: fifo.push(state.order, #(record.expires_at, record.key)),
                )
              process.send(reply, Ok(store.Written))
              actor.continue(state)
            }
          }
        }
      }
    }
    DeleteExpired(now, reply) -> {
      let #(expired, kept) =
        dict.to_list(state.records)
        |> list.partition(fn(entry) { not_after(entry.1.expires_at, now) })
      let records = dict.from_list(kept)
      let order =
        kept
        |> list.map(fn(entry) { #(entry.1.expires_at, entry.0) })
        |> list.sort(fn(a, b) { timestamp.compare(a.0, b.0) })
        |> list.fold(fifo.new(), fifo.push)
      process.send(reply, list.length(expired))
      actor.continue(State(..state, records:, order:))
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

fn full(state: State) -> Bool {
  case state.capacity {
    Some(capacity) -> dict.size(state.records) >= capacity
    None -> False
  }
}

/// Drop expired records from the oldest end until the store has room.
fn make_room(state: State) -> State {
  let now = timestamp.from_unix_seconds(state.clock())
  case full(state) {
    False -> state
    True ->
      case fifo.pop(state.order) {
        Ok(#(#(expires_at, key), rest)) ->
          case not_after(expires_at, now) {
            False -> state
            True -> {
              // Delete only if the record was not rewritten with a later expiry.
              let records = case dict.get(state.records, key) {
                Ok(record) ->
                  case not_after(record.expires_at, now) {
                    True -> dict.delete(state.records, key)
                    False -> state.records
                  }
                Error(Nil) -> state.records
              }
              make_room(State(..state, records:, order: rest))
            }
          }
        Error(Nil) -> state
      }
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
