//// An uncertain custody write recovers without another code exchange.

import exception
import gleam/crypto
import hellhound
import hellhound/config
import hellhound/store
import hellhound/testing

/// Ordinary custody writes remain recoverable without another code exchange.
pub fn uncertain_custody_recovers_idempotently_test() {
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
    hellhound.begin_login(client, hellhound.default_login())
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
