//// The login validity deadline is enforced by the storage decision.

import exception
import gleam/crypto
import gleam/erlang/process
import gleam/http/request
import gleam/time/duration
import gleam/time/timestamp
import hellhound
import hellhound/config
import hellhound/store
import hellhound/testing

fn seconds() -> Int {
  let #(seconds, _) =
    timestamp.system_time() |> timestamp.to_unix_seconds_and_nanoseconds
  seconds
}

type Delay {
  BeforeWrite
  AfterWrite
  LostReply
}

pub fn delayed_write_cannot_consume_an_expired_login_test() {
  complete(BeforeWrite)
}

pub fn timely_write_can_be_acknowledged_after_expiry_test() {
  complete(AfterWrite)
}

pub fn lost_consumption_reply_never_authorizes_exchange_test() {
  complete(LostReply)
}

fn complete(delay: Delay) -> Nil {
  let assert Ok(provider) = testing.start_provider(testing.provider_options())
  use <- exception.defer(fn() { testing.stop_provider(provider) })
  let memory = testing.memory_store()
  let observed = process.new_subject()
  let records =
    store.new(
      get: store.get(memory, _),
      put: fn(record, condition) {
        case condition {
          store.Absent | store.AtVersion(_) ->
            store.put(memory, record, condition)
          store.AtVersionBefore(_, _) -> {
            let entered = seconds()
            case delay {
              BeforeWrite -> process.sleep(2500)
              AfterWrite | LostReply -> Nil
            }
            let decision = seconds()
            let outcome = store.put(memory, record, condition)
            case delay {
              AfterWrite -> process.sleep(2500)
              BeforeWrite | LostReply -> Nil
            }
            process.send(observed, #(entered, decision, seconds()))
            case delay {
              LostReply -> Error(store.StoreOutcomeUnknown)
              BeforeWrite | AfterWrite -> outcome
            }
          }
        }
      },
      delete_expired: store.delete_expired(memory, _),
    )
  let assert Ok(key) = config.sealing_key(crypto.strong_random_bytes(32))
  let assert Ok(client) =
    testing.config(provider, "https://deadline.test/callback")
    |> config.with_transaction_store(records)
    |> config.with_sealing_key(key)
    |> config.with_login_lifetime(duration.seconds(2))
    |> config.with_store_timeout(duration.seconds(10))
    |> hellhound.new
  use <- exception.defer(fn() { hellhound.stop(client) })
  let assert Ok(Nil) = hellhound.start(client)
  let before = seconds()
  let assert Ok(redirect) =
    hellhound.begin_login(client, request.new(), hellhound.default_login())
  let after = seconds()
  let assert Ok(callback) =
    testing.authorize(provider, redirect, subject: "ada")
  let completed = hellhound.complete_login(client, callback)
  let assert Ok(#(entered, decision, returned)) = process.receive(observed, 100)
  assert entered < before + 2
  case delay {
    BeforeWrite -> {
      assert decision >= after + 2
      assert completed == Error(hellhound.LoginExpired)
      assert testing.requests(provider).code_grants == 0
    }
    AfterWrite -> {
      assert decision < before + 2
      assert returned >= after + 2
      let assert Ok(_) = completed
      assert testing.requests(provider).code_grants == 1
      assert hellhound.complete_login(client, callback)
        == Error(hellhound.LoginReplayed)
    }
    LostReply -> {
      assert completed == Error(hellhound.TransactionStoreUnavailable)
      assert hellhound.login_error_action(hellhound.TransactionStoreUnavailable)
        == hellhound.Reauthenticate
      assert testing.requests(provider).code_grants == 0
      assert hellhound.complete_login(client, callback)
        == Error(hellhound.LoginReplayed)
      assert testing.requests(provider).code_grants == 0
    }
  }
}

/// Ordinary custody writes remain recoverable without another code exchange.
pub fn uncertain_custody_recovers_idempotently_after_guarded_consumption_test() {
  let assert Ok(provider) = testing.start_provider(testing.provider_options())
  use <- exception.defer(fn() { testing.stop_provider(provider) })
  let memory = testing.memory_store()
  let records =
    store.new(
      get: store.get(memory, _),
      put: fn(record, condition) {
        let outcome = store.put(memory, record, condition)
        case condition, outcome {
          store.Absent, Ok(store.Written) -> Error(store.StoreOutcomeUnknown)
          _, _ -> outcome
        }
      },
      delete_expired: store.delete_expired(memory, _),
    )
  let assert Ok(key) = config.sealing_key(crypto.strong_random_bytes(32))
  let assert Ok(client) =
    testing.config(provider, "https://recovery.test/callback")
    |> config.with_custody_store(records)
    |> config.with_sealing_key(key)
    |> hellhound.new
  use <- exception.defer(fn() { hellhound.stop(client) })
  let assert Ok(Nil) = hellhound.start(client)
  let assert Ok(redirect) =
    hellhound.begin_login(client, request.new(), hellhound.default_login())
  let assert Ok(callback) =
    testing.authorize(provider, redirect, subject: "ada")
  let assert Error(hellhound.CustodyUnconfirmed(recovery)) =
    hellhound.complete_login(client, callback)
  let assert Ok(session) = hellhound.recover_custody(client, recovery)
  let assert Ok(again) = hellhound.recover_custody(client, recovery)
  assert hellhound.session_reference(session)
    == hellhound.session_reference(again)
  assert testing.requests(provider).code_grants == 1
  let assert Ok(_) =
    hellhound.logout(client, session, hellhound.default_logout())
  assert hellhound.recover_custody(client, recovery)
    == Error(hellhound.RecoveryEnded)
}
