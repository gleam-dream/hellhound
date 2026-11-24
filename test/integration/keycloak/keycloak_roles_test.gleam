//// A realm role removed at the pinned Keycloak, read through the bounded
//// claims read. Observed with Keycloak 26.7.5: the refresh succeeds and
//// returns a new ID token whose claims are evaluated again, so the removed
//// role is gone from it (the realm-role mapper then emits no `roles` claim
//// at all); the refreshed token has no `nonce` and keeps `acr`, `auth_time`
//// and `sid`.
////
//// The fixture realm gives `carol` the realm role `approver` and maps realm
//// roles into the ID token as `roles`. The test grants the role first and
//// again at the end, so it can be repeated.

import exception
import gleam/dynamic/decode
import gleam/erlang/process
import gleam/http/request
import gleam/option.{Some}
import gleam/time/duration
import gleam/time/timestamp
import hellhound
import hellhound/config
import hellhound/telemetry
import hellhound_login_test.{with_clock}
import hellhound_test_support as support
import sinal

fn start(clock: support.Clock) -> hellhound.Client {
  config.new(
    issuer: "https://localhost:18443/realms/hellhound",
    client_id: "hellhound-rp",
    redirect_uri: "https://localhost:1/callback",
    authentication: config.ClientSecretBasic(config.secret(
      "hellhound-rp-disposable-secret",
    )),
  )
  |> config.with_scopes(["profile", "email"])
  |> config.with_trust(config.TrustAnchorsPem(support.ca_pem()))
  |> config.with_destinations(config.AllowLoopbackForTesting)
  |> with_clock(clock)
  |> support.start_client
}

fn sign_in(client: hellhound.Client) -> hellhound.Session {
  let assert Ok(redirect) =
    hellhound.begin_login(client, request.new(), hellhound.default_login())
  let assert Ok(support.Query(query)) =
    support.keycloak_login(
      hellhound.login_url(redirect),
      "carol",
      "carol-disposable",
    )
  let assert Ok(session) =
    hellhound.complete_login(client, support.query_callback(redirect, query))
  session
}

/// A missing roles claim means no roles.
fn roles(identity: hellhound.VerifiedIdentity) -> List(String) {
  hellhound.decode_claims(
    identity,
    decode.at(["roles"], decode.list(decode.string)),
  )
  |> option.from_result
  |> option.unwrap([])
}

pub fn a_removed_realm_role_is_gone_after_the_claims_renew_test() {
  support.keycloak_realm_role("carol", "approver", support.Grant)
  let clock = support.clock_new(support.now_seconds())
  let client = start(clock)
  // The realm is shared by the suite: give the role back and stop the
  // client even when an assertion below fails.
  use <- exception.defer(fn() {
    support.keycloak_realm_role("carol", "approver", support.Grant)
    hellhound.stop(client)
  })
  let session = sign_in(client)
  // The smallest bound the constructor accepts.
  let assert Ok(age) = hellhound.claims_age(client, duration.seconds(60))
  let login = hellhound.session_identity(session)
  assert roles(login) == ["approver"]
  assert hellhound.acr(login) == Some("1")

  // Within the bound the read calls nobody and shows the role.
  support.count_reset()
  let assert Ok(current) = hellhound.current_identity(client, session, age)
  assert roles(hellhound.current_claims(current)) == ["approver"]
  assert support.count("/protocol/openid-connect/token") == 0
  let #(issued_at, _) =
    hellhound.current_issued_at(current)
    |> timestamp.to_unix_seconds_and_nanoseconds

  // An administrator removes the role. Keycloak stamps `iat` in whole
  // seconds, so let its clock pass the login's second, then move this
  // node's clock just past the bound.
  support.keycloak_realm_role("carol", "approver", support.Revoke)
  process.sleep(2000)
  support.clock_set(clock, issued_at + 61)

  let events = process.new_subject()
  let plan =
    sinal.subscriptions([
      sinal.subscription(telemetry.refresh(), fn(_, refresh) {
        process.send(events, #(refresh.outcome, refresh.claims))
      }),
    ])
  let assert Ok(sinal.SubscriptionCompletion(work_result: renewed, ..)) =
    sinal.with_subscriptions(plan, fn() {
      hellhound.current_identity(client, session, age)
    })
  // One refresh; Keycloak returned an ID token evaluated after the removal.
  let assert Ok(renewed) = renewed
  assert support.count("/protocol/openid-connect/token") == 1
  assert process.receive(events, 1000)
    == Ok(#(telemetry.Refreshed, telemetry.Replaced))
  let claims = hellhound.current_claims(renewed)
  assert roles(claims) == []
  let #(renewed_at, _) =
    hellhound.current_issued_at(renewed)
    |> timestamp.to_unix_seconds_and_nanoseconds
  assert renewed_at > issued_at
  // The unchecked reads show the replaced claims too.
  let held = hellhound.current_session(renewed)
  assert roles(hellhound.session_identity(held)) == []
  let assert Ok(restored) =
    hellhound.restore_session(client, hellhound.session_reference(session))
  assert roles(hellhound.session_identity(restored)) == []
  // Authentication evidence stays the login's.
  assert hellhound.acr(claims) == hellhound.acr(login)
  assert hellhound.amr(claims) == hellhound.amr(login)
  assert hellhound.authentication_time(claims)
    == hellhound.authentication_time(login)
  assert hellhound.subject(claims) == hellhound.subject(login)
  // The rest of the profile survived the replacement.
  assert hellhound.email(claims) == Some("carol@example.test")
}
