//// Usage: run a client under an application supervisor.
////
//// `hellhound.new` allocates stable names once, so the `client` handle stays
//// valid after process replacement. A supervised client discovers the
//// provider in the background; operations answer a provider-unavailable
//// failure until fresh compatible metadata and keys arrive. `run` starts
//// the tree against the local test provider and waits for readiness.

import gleam/erlang/process
import gleam/http/request
import gleam/otp/actor
import gleam/otp/static_supervisor as supervisor
import gleam/result
import gleam/time/duration
import hellhound
import hellhound/config
import hellhound/testing

// snips-start: supervision
pub fn under_supervision(
  configuration: config.Config,
) -> Result(#(hellhound.Client, actor.Started(supervisor.Supervisor)), String) {
  let assert Ok(client) = hellhound.new(configuration)
  supervisor.new(supervisor.OneForOne)
  |> supervisor.add(hellhound.supervised(client))
  |> supervisor.start
  |> result.map(fn(started) { #(client, started) })
  |> result.replace_error("the supervision tree did not start")
}

// snips-end: supervision

/// The Erlang exit reason `shutdown`.
type ExitReason {
  Shutdown
}

/// Starts the tree, waits until discovery has succeeded, signs a user in,
/// and stops the client through its parent.
pub fn run() -> Nil {
  let assert Ok(provider) = testing.start_provider(testing.provider_options())
  let configuration =
    testing.config(provider, "https://app.test/callback")
    |> config.with_startup_timeout(duration.seconds(5))
  let assert Ok(#(client, started)) = under_supervision(configuration)
  // Background discovery: operations fail until the provider is ready.
  assert wait_until_ready(client, 100) == Ok(Nil)
  let assert Ok(redirect) =
    hellhound.begin_login(client, request.new(), hellhound.default_login())
  let assert Ok(callback) =
    testing.authorize(provider, redirect, subject: "ada")
  let assert Ok(session) = hellhound.complete_login(client, callback)
  assert hellhound.subject(hellhound.session_identity(session)) == "ada"
  // Stop a supervised client through its parent. `hellhound.stop` would be
  // undone by the supervisor's restart.
  process.unlink(started.pid)
  process.send_abnormal_exit(started.pid, Shutdown)
  testing.stop_provider(provider)
}

fn wait_until_ready(
  client: hellhound.Client,
  attempts: Int,
) -> Result(Nil, Nil) {
  case hellhound.begin_login(client, request.new(), hellhound.default_login()) {
    Ok(_) -> Ok(Nil)
    Error(hellhound.LoginProviderUnavailable(hellhound.ProviderNotReady)) ->
      case attempts {
        0 -> Error(Nil)
        _ -> {
          process.sleep(50)
          wait_until_ready(client, attempts - 1)
        }
      }
    Error(_) -> Error(Nil)
  }
}
