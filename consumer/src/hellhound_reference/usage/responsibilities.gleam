//// Usage: the decisions an application makes around Hellhound's evidence.
////
//// Hellhound owns checked OIDC and OAuth evidence and user-token custody. The
//// application chooses how those facts authorize its requests. Each function
//// below is one such decision, in the application's own types; the routes,
//// session cookie, CSRF and origin policy are in `hellhound_reference/web` and
//// `hellhound_reference/protect`. The design's "Application responsibilities"
//// section states every obligation.

import gleam/http/request
import gleam/option.{None, Some}
import gleam/result
import gleam/time/timestamp.{type Timestamp}
import hellhound
import hellhound/testing

/// `(issuer, subject)` is the authentication key. An email claim is neither
/// a stable identity key nor proof of permission.
pub fn identity_key(session: hellhound.Session) -> #(String, String) {
  let identity = hellhound.session_identity(session)
  #(hellhound.issuer(identity), hellhound.subject(identity))
}

/// What the application does about a failure. Hellhound's `Action` is closed,
/// so every case is handled.
pub type Handling {
  SendThroughLoginAgain
  TryTheSameOperationLater
  RunTheCarriedRecovery
  AlertAnOperator
  AnswerBadRequest
}

pub fn handle(action: hellhound.Action) -> Handling {
  case action {
    hellhound.Reauthenticate -> SendThroughLoginAgain
    hellhound.RetryLater -> TryTheSameOperationLater
    hellhound.Recover -> RunTheCarriedRecovery
    hellhound.FixConfiguration -> AlertAnOperator
    hellhound.RejectRequest -> AnswerBadRequest
  }
}

/// A forced `refresh` fits only where the application holds retry authority
/// for its own request. It does not make a resource-side effect idempotent.
pub fn call_resource(
  client: hellhound.Client,
  session: hellhound.Session,
  send: fn(String) -> Int,
  repeatable repeatable: Bool,
) -> Result(Int, hellhound.SessionError) {
  use access <- result.try(hellhound.access_token(client, session))
  let status = send(hellhound.access_token_value(access.token))
  case status, repeatable {
    401, True -> {
      use fresh <- result.map(hellhound.refresh(client, access.session))
      send(hellhound.access_token_value(fresh.token))
    }
    _, _ -> Ok(status)
  }
}

/// `client_credentials` grants one token per call and creates no session.
/// The application owns the cache policy, including an absent expiry.
pub type ServiceTokenCache {
  CacheUntil(Timestamp)
  DoNotCache
}

pub fn service_token_cache(token: hellhound.ClientToken) -> ServiceTokenCache {
  case token.expires_at {
    Some(expires_at) -> CacheUntil(expires_at)
    None -> DoNotCache
  }
}

/// Logout removes custody first. The application ends its own session
/// whatever happens, and reads revocation separately from custody removal.
pub type SignOut {
  SignOut(custody_removed: Bool, token_revoked: Bool)
}

pub fn end_session(
  client: hellhound.Client,
  session: hellhound.Session,
) -> SignOut {
  case hellhound.logout(client, session, hellhound.default_logout()) {
    Ok(hellhound.LoggedOut(revocation:, ..)) ->
      SignOut(
        custody_removed: True,
        token_revoked: revocation == hellhound.Revoked,
      )
    Error(_) -> SignOut(custody_removed: False, token_revoked: False)
  }
}

/// Runs each decision against the local test provider.
pub fn run() -> Nil {
  let assert Ok(provider) = testing.start_provider(testing.provider_options())
  let assert Ok(client) =
    hellhound.new(testing.config(provider, "https://app.test/callback"))
  let assert Ok(Nil) = hellhound.start(client)
  let assert Ok(redirect) =
    hellhound.begin_login(client, request.new(), hellhound.default_login())
  let assert Ok(callback) =
    testing.authorize(provider, redirect, subject: "ada")
  let assert Ok(session) = hellhound.complete_login(client, callback)
  // The key names the user, whatever the email claims say.
  assert identity_key(session) == #(testing.issuer(provider), "ada")
  // Every action has a handling; failures map through the closed projections.
  assert handle(hellhound.login_error_action(hellhound.LoginReplayed))
    == SendThroughLoginAgain
  assert handle(hellhound.session_error_action(hellhound.SessionNotFound))
    == SendThroughLoginAgain
  assert handle(hellhound.RejectRequest) == AnswerBadRequest
  // A repeatable request refreshes once after a 401 and resends; a request
  // the application cannot repeat is answered as it came back.
  let assert Ok(access) = hellhound.access_token(client, session)
  let first = hellhound.access_token_value(access.token)
  let send = fn(token) {
    case token == first {
      True -> 401
      False -> 200
    }
  }
  assert call_resource(client, session, send, repeatable: True) == Ok(200)
  assert call_resource(client, session, fn(_) { 401 }, repeatable: False)
    == Ok(401)
  // A service grant carries its own expiry, and the application decides how
  // long to keep it.
  let assert Ok(service) = hellhound.new(testing.service_config(provider))
  let assert Ok(Nil) = hellhound.start(service)
  let assert Ok(granted) = hellhound.client_credentials(service, ["reports"])
  let assert CacheUntil(_) = service_token_cache(granted)
  assert service_token_cache(hellhound.ClientToken(..granted, expires_at: None))
    == DoNotCache
  // Logout removes custody, then revokes the refresh token.
  let assert Ok(current) =
    hellhound.restore_session(client, hellhound.session_reference(session))
  assert end_session(client, current)
    == SignOut(custody_removed: True, token_revoked: True)
  hellhound.stop(service)
  hellhound.stop(client)
  testing.stop_provider(provider)
}
