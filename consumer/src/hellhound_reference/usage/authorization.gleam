//// Usage: decide a permission from claims no older than a bound.
////
//// `session_identity` returns the claims custody holds and is not for
//// authorization: they may be as old as the session. A permission check
//// calls `current_identity` with the application's own `ClaimsAge`. The
//// claims come back only when the provider issued them within that bound;
//// otherwise Hellhound renews them with one refresh, shared by concurrent
//// requests, and the error's `Action` names the next step.
////
//// The bound limits the age of the last ID token. A removed role is denied
//// within it only when the provider evaluates claims again on refresh, which
//// each application verifies for its own provider.

import gleam/dynamic/decode
import gleam/http/request
import gleam/json
import gleam/list
import gleam/option
import gleam/time/duration
import hellhound
import hellhound/testing

// snips-start: authorization
/// Built once at startup. The bound is the application's policy; Hellhound
/// has no default. `claims_age` refuses less than 60 s.
pub fn role_claims_age() -> hellhound.ClaimsAge {
  let assert Ok(age) = hellhound.claims_age(duration.minutes(15))
  age
}

pub type Decision {
  Allowed
  /// The person lacks the role.
  Denied
  /// Nothing was decided: deny this request and keep the session.
  TryAgainLater
  /// The session was ended: send the person to sign in.
  SignInAgain
  /// An operator must act: deny, and alert.
  Misconfigured
}

/// Authorization helpers take a `Current`, never a `VerifiedIdentity`, so
/// the type shows that the age of the claims was checked. A missing roles
/// claim means no roles.
pub fn has_role(current: hellhound.Current, role: String) -> Bool {
  hellhound.decode_claims(
    hellhound.current_claims(current),
    decode.at(["https://example.test/roles"], decode.list(decode.string)),
  )
  |> option.from_result
  |> option.unwrap([])
  |> list.contains(role)
}

/// One call per role check, on every protected request.
pub fn require_role(
  client: hellhound.Client,
  session: hellhound.Session,
  claims_age: hellhound.ClaimsAge,
  role: String,
) -> Decision {
  case hellhound.current_identity(client, session, claims_age) {
    Ok(current) ->
      case has_role(current, role) {
        True -> Allowed
        False -> Denied
      }
    Error(error) -> denied(client, session, error)
  }
}

fn denied(
  client: hellhound.Client,
  session: hellhound.Session,
  error: hellhound.SessionError,
) -> Decision {
  case hellhound.session_error_action(error), error {
    // Publication was not confirmed. Recover it, without another provider
    // call; the next request reads the renewed claims.
    hellhound.Recover, hellhound.RefreshUnconfirmed(recovery) -> {
      let _ = hellhound.recover_refresh(client, recovery)
      TryAgainLater
    }
    hellhound.Recover, _ | hellhound.RetryLater, _ -> TryAgainLater
    // End the session before redirecting, so a renewal that cannot succeed
    // is not sent again on every request.
    hellhound.Reauthenticate, _ -> {
      let _ = hellhound.logout(client, session, hellhound.default_logout())
      SignInAgain
    }
    hellhound.FixConfiguration, _ | hellhound.RejectRequest, _ -> Misconfigured
  }
}

// snips-end: authorization

fn roles(names: List(String)) -> List(testing.ExtraClaim) {
  let assert Ok(claim) =
    testing.extra_claim(
      "https://example.test/roles",
      json.array(names, json.string),
    )
  [claim]
}

/// Runs the decision against the local test provider: a role removed at
/// the provider is denied once the claims are past the bound.
pub fn run() -> Nil {
  let assert Ok(provider) =
    testing.start_provider(
      testing.provider_options()
      |> testing.with_extra_claims("ada", roles(["operator", "approver"]))
      |> testing.with_refresh_answer(testing.RefreshWithIdToken),
    )
  let assert Ok(client) =
    hellhound.new(testing.config(provider, "https://app.test/callback"))
  let assert Ok(Nil) = hellhound.start(client)
  let sign_in = fn() {
    let assert Ok(redirect) =
      hellhound.begin_login(client, request.new(), hellhound.default_login())
    let assert Ok(callback) =
      testing.authorize(provider, redirect, subject: "ada")
    let assert Ok(session) = hellhound.complete_login(client, callback)
    session
  }
  let age = role_claims_age()
  assert hellhound.claims_age(duration.seconds(59)) == Error(Nil)

  // Two sign-ins. The provider's clock ran 8 minutes behind for the first,
  // so its claims are 8 minutes old.
  testing.set_clock_skew(provider, duration.minutes(-8))
  let old = sign_in()
  testing.set_clock_skew(provider, duration.seconds(0))
  let session = sign_in()

  // Claims within the bound: the check calls nobody.
  assert require_role(client, session, age, "approver") == Allowed
  assert require_role(client, session, age, "auditor") == Denied
  // The role is removed at the provider. Within the bound the held claims
  // still carry it; that window is the bound the application chose.
  testing.set_extra_claims(provider, "ada", roles(["operator"]))
  assert require_role(client, old, age, "approver") == Allowed
  assert testing.requests(provider).refresh_grants == 0

  // A stricter bound for a sensitive route; bounds compose per call. The
  // older claims are past it: the check renews them once, and the removed
  // role is denied.
  let assert Ok(strict) = hellhound.claims_age(duration.minutes(5))
  assert require_role(client, old, strict, "approver") == Denied
  assert require_role(client, old, strict, "operator") == Allowed
  assert testing.requests(provider).refresh_grants == 1

  // A provider that returns no ID token on refresh cannot renew claims: the
  // person signs in again, and the session is gone.
  testing.set_refresh_answer(provider, testing.RefreshWithoutIdToken)
  testing.set_clock_skew(provider, duration.minutes(-8))
  let stale = sign_in()
  testing.set_clock_skew(provider, duration.seconds(0))
  assert require_role(client, stale, strict, "operator") == SignInAgain
  assert hellhound.restore_session(client, hellhound.session_reference(stale))
    == Error(hellhound.SessionNotFound)
  hellhound.stop(client)
  testing.stop_provider(provider)
}
