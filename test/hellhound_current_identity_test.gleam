//// Current claims and the bounded claims read, against the scripted
//// provider: replacement on every refresh path, the zero-call read, one
//// shared renewal, the two not-renewed reasons, the renewal circuit, and
//// the login-pinned authentication accessors.

import gleam/dict
import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode
import gleam/erlang/process
import gleam/list
import gleam/option.{Some}
import gleam/time/duration
import gleam/time/timestamp
import hellhound
import hellhound/config
import hellhound/telemetry
import hellhound_login_test.{
  authorize, browser, logged_in, settings, start, with_clock,
}
import hellhound_store_support as faults
import hellhound_test_support as support
import sinal

const quarter_hour = 900

fn bound() -> hellhound.ClaimsAge {
  let assert Ok(age) = hellhound.claims_age(duration.seconds(quarter_hour))
  age
}

fn roles(identity: hellhound.VerifiedIdentity) -> List(String) {
  hellhound.decode_claims(
    identity,
    decode.at(["roles"], decode.list(decode.string)),
  )
  // A missing roles claim means no roles.
  |> option.from_result
  |> option.unwrap([])
}

fn role_claims(names: List(String)) -> List(#(String, Dynamic)) {
  [#("roles", dynamic.list(list.map(names, dynamic.string)))]
}

/// Script the claims of every ID token issued from now on.
fn claims(
  provider: support.Provider,
  entries: List(#(String, Dynamic)),
) -> Nil {
  support.set_json_claims(provider, dict.from_list(entries))
}

/// An `iat` claim `seconds` in the past: past the quarter-hour bound when
/// `seconds` is above it.
fn issued_ago(seconds: Int) -> #(String, Dynamic) {
  #("iat", dynamic.int(support.now_seconds() - seconds))
}

fn script_refreshes(
  provider: support.Provider,
  behaviour: support.Behaviour,
) -> Nil {
  list.each(support.refresh_tokens(provider), fn(token) {
    support.script(provider, support.Refresh(token), behaviour)
  })
}

fn current_roles(
  client: hellhound.Client,
  session: hellhound.Session,
) -> List(String) {
  let assert Ok(current) = hellhound.current_identity(client, session, bound())
  roles(hellhound.current_claims(current))
}

// --- claims_age ------------------------------------------------------------

pub fn claims_age_refuses_less_than_a_minute_test() {
  assert hellhound.claims_age(duration.seconds(59)) == Error(Nil)
  // The default clock tolerance.
  assert hellhound.claims_age(duration.seconds(5)) == Error(Nil)
  assert hellhound.claims_age(duration.seconds(0)) == Error(Nil)
  assert hellhound.claims_age(duration.seconds(-900)) == Error(Nil)
  let assert Ok(_) = hellhound.claims_age(duration.seconds(60))
  let assert Ok(_) = hellhound.claims_age(duration.minutes(15))
}

// --- Current claims follow every refresh path --------------------------------

/// A role change is shown by `session_identity` and `current_identity` on a
/// session read after `refresh`, `access_token` and `restore_session`.
pub fn a_role_change_is_read_after_each_refresh_path_test() {
  let provider = support.provider_start(support.Standard)
  claims(provider, role_claims(["admin", "operator"]))
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  assert roles(hellhound.session_identity(session)) == ["admin", "operator"]
  assert current_roles(client, session) == ["admin", "operator"]

  // refresh: the next token lives 10 s, inside the refresh margin.
  claims(provider, role_claims(["operator"]))
  script_refreshes(provider, support.TokenIntField("expires_in", 10))
  let assert Ok(refreshed) = hellhound.refresh(client, session)
  assert roles(hellhound.session_identity(refreshed.session)) == ["operator"]
  assert current_roles(client, refreshed.session) == ["operator"]
  // The earlier value is a view of what custody held when it was read; the
  // bounded read goes to custody.
  assert roles(hellhound.session_identity(session)) == ["admin", "operator"]
  assert current_roles(client, session) == ["operator"]

  // restore_session reads the replaced claims.
  let assert Ok(restored) =
    hellhound.restore_session(client, hellhound.session_reference(session))
  assert roles(hellhound.session_identity(restored)) == ["operator"]

  // access_token: the margin refresh returns a token without a roles claim.
  // Replacement is whole, so no role survives.
  claims(provider, [])
  let requests = support.token_requests(provider)
  let assert Ok(access) = hellhound.access_token(client, restored)
  assert support.token_requests(provider) == requests + 1
  assert roles(hellhound.session_identity(access.session)) == []
  assert current_roles(client, access.session) == []
  let assert Ok(restored) =
    hellhound.restore_session(client, hellhound.session_reference(session))
  assert roles(hellhound.session_identity(restored)) == []
  hellhound.stop(client)
  support.provider_stop(provider)
}

fn durable_client(
  provider: support.Provider,
) -> #(hellhound.Client, faults.Control) {
  let #(custody, control) = faults.memory()
  let client =
    start(
      settings(provider)
      |> config.with_store_timeout(duration.milliseconds(200))
      |> config.with_custody_store(custody)
      |> config.with_sealing_key(faults.sealing_key()),
    )
  #(client, control)
}

/// An unconfirmed publication is returned as it is; after `recover_refresh`
/// the role change is read and no second provider call is made.
pub fn an_unconfirmed_renewal_recovers_without_a_second_call_test() {
  let provider = support.provider_start(support.Standard)
  claims(provider, [issued_ago(1000), ..role_claims(["admin"])])
  let #(client, control) = durable_client(provider)
  let session = logged_in(provider, client)
  claims(provider, role_claims(["operator"]))
  // Writes during the renewal: the reservation, then the publication.
  faults.lose_ack_of(control, 2)
  let assert Error(hellhound.RefreshUnconfirmed(recovery) as error) =
    hellhound.current_identity(client, session, bound())
  assert hellhound.session_error_action(error) == hellhound.Recover
  let requests = support.token_requests(provider)
  let assert Ok(recovered) = hellhound.recover_refresh(client, recovery)
  assert roles(hellhound.session_identity(recovered.session)) == ["operator"]
  assert current_roles(client, session) == ["operator"]
  assert current_roles(client, recovered.session) == ["operator"]
  assert support.token_requests(provider) == requests
  hellhound.stop(client)
  support.provider_stop(provider)
}

// --- The bounded read ----------------------------------------------------------

pub fn claims_within_the_bound_make_no_provider_call_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  let requests = support.token_requests(provider)
  let before = support.now_seconds()
  let assert Ok(current) = hellhound.current_identity(client, session, bound())
  let assert Ok(_) = hellhound.current_identity(client, session, bound())
  assert support.token_requests(provider) == requests
  assert hellhound.subject(hellhound.current_claims(current)) == "subject-1"
  assert hellhound.session_reference(hellhound.current_session(current))
    == hellhound.session_reference(session)
  let #(issued_at, _) =
    hellhound.current_issued_at(current)
    |> timestamp.to_unix_seconds_and_nanoseconds
  assert issued_at >= before - 5 && issued_at <= support.now_seconds()
  hellhound.stop(client)
  support.provider_stop(provider)
}

pub fn concurrent_reads_past_the_bound_share_one_renewal_test() {
  let provider = support.provider_start(support.Standard)
  claims(provider, [issued_ago(1000), ..role_claims(["admin"])])
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  claims(provider, role_claims(["operator"]))
  script_refreshes(provider, support.Delay(300))
  let requests = support.token_requests(provider)
  let attempt = fn() { current_roles(client, session) }
  let results = support.spawn_collect(list.repeat(attempt, 3), 30_000)
  assert results == [["operator"], ["operator"], ["operator"]]
  assert support.token_requests(provider) == requests + 1
  hellhound.stop(client)
  support.provider_stop(provider)
}

/// A session value older than custody, whose custody record is newer but
/// also past the bound, renews from the current revision with one call.
pub fn an_old_session_value_renews_from_the_current_revision_test() {
  let provider = support.provider_start(support.Standard)
  claims(provider, [issued_ago(2000), ..role_claims(["admin"])])
  let client = start(settings(provider))
  let old = logged_in(provider, client)
  claims(provider, [issued_ago(1000), ..role_claims(["admin", "operator"])])
  let assert Ok(_) = hellhound.refresh(client, old)
  claims(provider, role_claims(["operator"]))
  let requests = support.token_requests(provider)
  assert current_roles(client, old) == ["operator"]
  assert support.token_requests(provider) == requests + 1
  // Now within the bound: the old value costs nothing more.
  assert current_roles(client, old) == ["operator"]
  assert support.token_requests(provider) == requests + 1
  hellhound.stop(client)
  support.provider_stop(provider)
}

pub fn an_omitted_id_token_is_not_returned_test() {
  let provider = support.provider_start(support.Standard)
  claims(provider, [issued_ago(1000), ..role_claims(["admin"])])
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  script_refreshes(provider, support.OmitIdToken)
  let error = hellhound.ClaimsNotRenewed(hellhound.NotReturned)
  assert hellhound.current_identity(client, session, bound()) == Error(error)
  assert hellhound.session_error_action(error) == hellhound.Reauthenticate
  // The refresh itself succeeded; the unchecked read still shows the old
  // claims, which is why it decides no permission.
  let assert Ok(restored) =
    hellhound.restore_session(client, hellhound.session_reference(session))
  assert roles(hellhound.session_identity(restored)) == ["admin"]
  // The application ends the session; further reads send nothing.
  let assert Ok(_) =
    hellhound.logout(client, session, hellhound.default_logout())
  let requests = support.token_requests(provider)
  list.each([session, restored, session], fn(held) {
    assert hellhound.current_identity(client, held, bound())
      == Error(hellhound.SessionNotFound)
  })
  assert support.token_requests(provider) == requests
  hellhound.stop(client)
  support.provider_stop(provider)
}

/// A provider clock behind by more than the bound: the token just issued
/// is already too old. An operator must act.
pub fn a_provider_clock_behind_the_bound_is_issued_too_long_ago_test() {
  let provider = support.provider_start(support.Standard)
  claims(provider, [issued_ago(1000)])
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  claims(provider, [issued_ago(950)])
  let error = hellhound.ClaimsNotRenewed(hellhound.IssuedTooLongAgo)
  assert hellhound.current_identity(client, session, bound()) == Error(error)
  assert hellhound.session_error_action(error) == hellhound.FixConfiguration
  hellhound.stop(client)
  support.provider_stop(provider)
}

/// A stored `iat` later than now plus the clock tolerance is not within any
/// bound: the read renews.
pub fn a_stored_issue_time_in_the_future_renews_test() {
  let provider = support.provider_start(support.Standard)
  let now = support.now_seconds()
  let clock = support.clock_new(now)
  let client = start(settings(provider) |> with_clock(clock))
  let session = logged_in(provider, client)
  // This node's clock steps back: the stored token now reads 100 s ahead.
  support.clock_set(clock, now - 100)
  claims(provider, [#("iat", dynamic.int(now - 100))])
  let requests = support.token_requests(provider)
  let assert Ok(current) = hellhound.current_identity(client, session, bound())
  assert support.token_requests(provider) == requests + 1
  assert hellhound.current_issued_at(current)
    == timestamp.from_unix_seconds(now - 100)
  hellhound.stop(client)
  support.provider_stop(provider)
}

pub fn a_logged_out_session_fails_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  let assert Ok(_) =
    hellhound.logout(client, session, hellhound.default_logout())
  assert hellhound.current_identity(client, session, bound())
    == Error(hellhound.SessionNotFound)
  hellhound.stop(client)
  support.provider_stop(provider)
}

/// Past the bound, a session that was never given a refresh token cannot
/// renew: the person signs in again, and nothing is sent.
pub fn a_session_without_a_refresh_token_must_reauthenticate_test() {
  let provider = support.provider_start(support.Standard)
  claims(provider, [issued_ago(1000)])
  let client = start(settings(provider))
  let assert Ok(redirect) =
    hellhound.begin_login(client, browser(), hellhound.default_login())
  support.script(provider, support.Code("code-1"), support.DropRefreshToken)
  let assert Ok(session) =
    hellhound.complete_login(client, authorize(provider, redirect, "code-1"))
  let requests = support.token_requests(provider)
  let error = hellhound.RefreshTokenUnavailable
  assert hellhound.current_identity(client, session, bound()) == Error(error)
  assert hellhound.session_error_action(error) == hellhound.Reauthenticate
  assert support.token_requests(provider) == requests
  hellhound.stop(client)
  support.provider_stop(provider)
}

// --- Login-pinned accessors ------------------------------------------------------

/// A refreshed ID token with another `acr` and `amr` replaces the current
/// claims; the accessors keep the login's values.
pub fn a_refreshed_acr_does_not_change_the_login_acr_test() {
  let provider = support.provider_start(support.Standard)
  claims(provider, [
    #("acr", dynamic.string("urn:example:mfa")),
    #("amr", dynamic.list([dynamic.string("pwd"), dynamic.string("otp")])),
  ])
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  let login_time =
    hellhound.authentication_time(hellhound.session_identity(session))
  claims(provider, [
    #("acr", dynamic.string("urn:example:password")),
    #("amr", dynamic.list([dynamic.string("pwd")])),
    #("department", dynamic.string("finance")),
  ])
  let assert Ok(access) = hellhound.refresh(client, session)
  let identity = hellhound.session_identity(access.session)
  assert hellhound.acr(identity) == Some("urn:example:mfa")
  assert hellhound.amr(identity) == ["pwd", "otp"]
  assert hellhound.authentication_time(identity) == login_time
  assert option.is_some(login_time)
  // Every other read is the current claims, raw `acr` included.
  let text = fn(name) {
    hellhound.decode_claims(identity, decode.at([name], decode.string))
  }
  assert text("department") == Ok("finance")
  assert text("acr") == Ok("urn:example:password")
  let assert Ok(current) =
    hellhound.current_identity(client, access.session, bound())
  assert hellhound.acr(hellhound.current_claims(current))
    == Some("urn:example:mfa")
  hellhound.stop(client)
  support.provider_stop(provider)
}

// --- The renewal circuit -----------------------------------------------------------

fn circuit(status: Int, code: String) -> Nil {
  let provider = support.provider_start(support.Standard)
  claims(provider, [issued_ago(1000)])
  let monotonic = support.clock_new(0)
  let client =
    start(settings(provider) |> support.with_monotonic_clock(monotonic))
  let sessions = list.map([1, 2, 3, 4], fn(_) { logged_in(provider, client) })
  let assert [first, second, third, fourth] = sessions
  script_refreshes(provider, support.Status(status, code))
  let requests = support.token_requests(provider)
  // The first renewal reaches the provider, which answers with the error:
  // the outcome is unknown, so that session is quarantined.
  let quarantined =
    Error(hellhound.RefreshQuarantined(hellhound.ProviderOutcomeUnknown))
  assert hellhound.current_identity(client, first, bound()) == quarantined
  assert support.token_requests(provider) == requests + 1
  // For 60 s this node starts no renewal: the others keep their sessions.
  let paused = hellhound.RefreshNotSent(hellhound.RenewalPaused)
  list.each([second, third, second], fn(session) {
    assert hellhound.current_identity(client, session, bound()) == Error(paused)
  })
  assert hellhound.session_error_action(paused) == hellhound.RetryLater
  assert support.token_requests(provider) == requests + 1
  support.clock_set(monotonic, 59_999)
  assert hellhound.current_identity(client, third, bound()) == Error(paused)
  // After the window, a session found already quarantined is reported as
  // such, sends nothing and does not open the circuit again.
  support.clock_set(monotonic, 60_000)
  assert hellhound.current_identity(client, first, bound()) == quarantined
  assert support.token_requests(provider) == requests + 1
  // After the window one renewal is admitted. The provider still answers
  // the error, so one more session is quarantined and the circuit reopens.
  assert hellhound.current_identity(client, second, bound()) == quarantined
  assert support.token_requests(provider) == requests + 2
  assert hellhound.current_identity(client, third, bound()) == Error(paused)
  // The circuit guards only the bounded read: a forced refresh still goes
  // to the provider while it is open.
  let assert Error(hellhound.RefreshQuarantined(_)) =
    hellhound.refresh(client, fourth)
  assert support.token_requests(provider) == requests + 3
  hellhound.stop(client)
  support.provider_stop(provider)
}

pub fn a_503_quarantines_one_session_and_pauses_the_rest_test() {
  circuit(503, "temporarily_unavailable")
}

pub fn a_429_quarantines_one_session_and_pauses_the_rest_test() {
  circuit(429, "slow_down")
}

/// The provider recovers within the window: paused sessions renew once the
/// window ends, and a session within the bound is never paused.
pub fn the_circuit_closes_after_its_window_test() {
  let provider = support.provider_start(support.Standard)
  claims(provider, [issued_ago(1000)])
  let monotonic = support.clock_new(0)
  let client =
    start(settings(provider) |> support.with_monotonic_clock(monotonic))
  let first = logged_in(provider, client)
  let second = logged_in(provider, client)
  claims(provider, [])
  let within = logged_in(provider, client)
  script_refreshes(provider, support.Status(503, "temporarily_unavailable"))
  let assert Error(hellhound.RefreshQuarantined(_)) =
    hellhound.current_identity(client, first, bound())
  // The provider is healthy again; scripts are cleared by being replaced.
  script_refreshes(provider, support.Delay(0))
  assert hellhound.current_identity(client, second, bound())
    == Error(hellhound.RefreshNotSent(hellhound.RenewalPaused))
  let assert Ok(_) = hellhound.current_identity(client, within, bound())
  support.clock_set(monotonic, 60_000)
  let assert Ok(_) = hellhound.current_identity(client, second, bound())
  hellhound.stop(client)
  support.provider_stop(provider)
}

// --- Telemetry ---------------------------------------------------------------------

pub fn the_refresh_event_reports_whether_claims_were_replaced_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  let events = process.new_subject()
  let plan =
    sinal.subscriptions([
      sinal.subscription(telemetry.refresh(), fn(_, refresh) {
        process.send(events, #(refresh.outcome, refresh.claims))
      }),
    ])
  let assert Ok(_) =
    sinal.with_subscriptions(plan, fn() {
      let assert Ok(access) = hellhound.refresh(client, session)
      script_refreshes(provider, support.OmitIdToken)
      let assert Ok(access) = hellhound.refresh(client, access.session)
      script_refreshes(provider, support.Status(503, "temporarily_unavailable"))
      let assert Error(_) = hellhound.refresh(client, access.session)
      Nil
    })
  assert process.receive(events, 1000)
    == Ok(#(telemetry.Refreshed, telemetry.Replaced))
  assert process.receive(events, 1000)
    == Ok(#(telemetry.Refreshed, telemetry.NotReturned))
  assert process.receive(events, 1000)
    == Ok(#(telemetry.RefreshQuarantined, telemetry.NotReturned))
  assert process.receive(events, 0) == Error(Nil)
  hellhound.stop(client)
  support.provider_stop(provider)
}
