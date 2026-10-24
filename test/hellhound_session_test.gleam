//// Session operations against the scripted provider: access with the
//// refresh margin, one refresh shared by concurrent requests, rotation,
//// retention, continuity, quarantine and publication recovery; userinfo,
//// client credentials, introspection and logout.

import gleam/dynamic/decode
import gleam/erlang/process
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleam/time/duration
import gleam/time/timestamp
import hellhound
import hellhound/config
import hellhound_login_test.{browser, logged_in, settings, start, with_clock}
import hellhound_store_support as faults
import hellhound_test_support as support

fn refresh_token_of(provider: support.Provider) -> String {
  let assert [token] = support.refresh_tokens(provider)
  token
}

fn token(access: hellhound.Access) -> String {
  hellhound.access_token_value(access.token)
}

pub fn refresh_rotates_and_reports_the_new_token_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  let first = refresh_token_of(provider)
  let assert Ok(before) = hellhound.access_token(client, session)
  let assert Ok(after) = hellhound.refresh(client, session)
  assert hellhound.session_reference(after.session)
    == hellhound.session_reference(session)
  assert hellhound.identity_key(hellhound.session_identity(after.session))
    == hellhound.identity_key(hellhound.session_identity(session))
  // The provider rotated; custody holds the successor.
  assert refresh_token_of(provider) != first
  assert token(before) != token(after)
  // The superseded session value is not stale: it reads the current token,
  // and a forced refresh with it sends nothing, because the session was
  // already refreshed since that value was read.
  let requests = support.token_requests(provider)
  let assert Ok(current) = hellhound.access_token(client, session)
  assert token(current) == token(after)
  let assert Ok(again) = hellhound.refresh(client, session)
  assert token(again) == token(after)
  assert support.token_requests(provider) == requests
  hellhound.stop(client)
  support.provider_stop(provider)
}

/// Concurrent requests share one refresh; the losers wait for it
/// and receive its token instead of an error.
pub fn concurrent_refresh_sends_one_request_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  support.script(
    provider,
    support.Refresh(refresh_token_of(provider)),
    support.Delay(300),
  )
  let attempt = fn() { hellhound.refresh(client, session) }
  let results = support.spawn_collect(list.repeat(attempt, 8), 30_000)
  let tokens =
    list.map(results, fn(r) {
      let assert Ok(access) = r
      token(access)
    })
    |> list.unique
  assert list.length(tokens) == 1
  // One authorization-code request plus one refresh request.
  assert support.token_requests(provider) == 2
  hellhound.stop(client)
  support.provider_stop(provider)
}

/// A token within the refresh margin is refreshed by `access_token`; one
/// outside it is returned as is.
pub fn access_token_refreshes_within_the_margin_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  let assert Ok(fresh) = hellhound.access_token(client, session)
  assert option.is_some(fresh.expires_at)
  assert support.token_requests(provider) == 1
  // The next token lives 10 s: inside the default 30 s margin.
  support.script(
    provider,
    support.Refresh(refresh_token_of(provider)),
    support.TokenIntField("expires_in", 10),
  )
  let assert Ok(short) = hellhound.refresh(client, session)
  assert support.token_requests(provider) == 2
  let assert Ok(renewed) = hellhound.access_token(client, short.session)
  assert token(renewed) != token(short)
  assert support.token_requests(provider) == 3
  // With a zero margin the same short token is used as is.
  hellhound.stop(client)
  let relaxed =
    start(settings(provider) |> config.with_refresh_margin(duration.seconds(0)))
  let session = logged_in(provider, relaxed)
  support.script(
    provider,
    support.Refresh(refresh_token_of_latest(provider)),
    support.TokenIntField("expires_in", 10),
  )
  let assert Ok(short) = hellhound.refresh(relaxed, session)
  let requests = support.token_requests(provider)
  let assert Ok(same) = hellhound.access_token(relaxed, short.session)
  assert token(same) == token(short)
  assert support.token_requests(provider) == requests
  hellhound.stop(relaxed)
  support.provider_stop(provider)
}

fn refresh_token_of_latest(provider: support.Provider) -> String {
  let assert Ok(token) = list.last(support.refresh_tokens(provider))
  token
}

/// A request that finds another's refresh in flight waits at most the
/// refresh wait, then answers `RefreshWaitTimedOut` without sending.
pub fn refresh_wait_is_bounded_test() {
  let provider = support.provider_start(support.Standard)
  let client =
    start(
      settings(provider)
      |> config.with_refresh_wait(duration.milliseconds(200)),
    )
  let session = logged_in(provider, client)
  support.script(
    provider,
    support.Refresh(refresh_token_of(provider)),
    support.Delay(1500),
  )
  let winner = process.new_subject()
  process.spawn(fn() {
    process.send(winner, hellhound.refresh(client, session))
  })
  process.sleep(100)
  assert hellhound.refresh(client, session)
    == Error(hellhound.RefreshWaitTimedOut)
  assert hellhound.session_error_action(hellhound.RefreshWaitTimedOut)
    == hellhound.RetryLater
  let assert Ok(Ok(_)) = process.receive(winner, 5000)
  assert support.token_requests(provider) == 2
  hellhound.stop(client)
  support.provider_stop(provider)
}

pub fn omitted_refresh_token_is_retained_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  let original = refresh_token_of(provider)
  support.script(provider, support.Refresh(original), support.DropRefreshToken)
  let assert Ok(refreshed) = hellhound.refresh(client, session)
  // Custody retained the original token, which the provider still accepts.
  let assert Ok(_) = hellhound.refresh(client, refreshed.session)
  assert support.token_requests(provider) == 3
  hellhound.stop(client)
  support.provider_stop(provider)
}

fn refresh_with(
  behaviour: support.Behaviour,
) -> #(
  Result(hellhound.Access, hellhound.SessionError),
  Result(hellhound.Access, hellhound.SessionError),
) {
  let provider = support.provider_start(support.Standard)
  let client =
    start(
      settings(provider)
      |> config.with_request_timeout(duration.milliseconds(400)),
    )
  let session = logged_in(provider, client)
  support.script(
    provider,
    support.Refresh(refresh_token_of(provider)),
    behaviour,
  )
  let first = hellhound.refresh(client, session)
  let second = hellhound.refresh(client, session)
  hellhound.stop(client)
  support.provider_stop(provider)
  #(first, second)
}

pub fn uncertain_and_invalid_refresh_outcomes_quarantine_test() {
  let quarantined = fn(result) {
    case result {
      Error(hellhound.RefreshQuarantined(hellhound.ProviderOutcomeUnknown)) ->
        "provider"
      Error(hellhound.RefreshQuarantined(hellhound.ResponseRejected(problem))) ->
        string.inspect(problem)
      other -> "unexpected " <> string.inspect(other)
    }
  }
  let cases = [
    #(support.Delay(1500), "provider"),
    #(support.Status(503, "temporarily_unavailable"), "provider"),
    #(support.Close, "provider"),
    #(support.MalformedJson, "RefreshResponseMalformed"),
    // Tokens Hellhound cannot use as Bearer tokens, or a negative lifetime.
    #(support.TokenField("token_type", "DPoP"), "RefreshResponseMalformed"),
    #(support.TokenIntField("expires_in", -5), "RefreshResponseMalformed"),
    // An error code Hellhound does not recognise may follow processing of the
    // grant; the token it sent is never sent again.
    #(support.Status(400, "unrecognised_error"), "provider"),
    #(support.IdToken("changed_sub"), "RefreshedSubjectMismatch"),
    #(support.IdToken("changed_nonce"), "RefreshedNonceMismatch"),
    #(
      support.IdToken("changed_auth_time"),
      "RefreshedAuthenticationTimeMismatch",
    ),
    #(
      support.IdToken("wrong_aud"),
      "RefreshedIdTokenInvalid(IdTokenAudienceMismatch)",
    ),
  ]
  list.each(cases, fn(c) {
    let #(first, second) = refresh_with(c.0)
    assert #(c.0, quarantined(first)) == #(c.0, c.1)
    // A quarantined generation never dispatches again, and its reason is
    // kept in custody.
    assert #(c.0, quarantined(second)) == #(c.0, c.1)
    let assert Error(error) = second
    assert hellhound.session_error_action(error) == hellhound.Reauthenticate
  })
}

pub fn definite_rejection_revokes_or_releases_test() {
  let #(first, second) = refresh_with(support.Status(400, "invalid_grant"))
  assert first == Error(hellhound.RefreshRevoked)
  assert second == Error(hellhound.RefreshRevoked)
  // A rejection that does not concern the grant releases the generation.
  let #(first, second) = refresh_with(support.Status(401, "invalid_client"))
  assert first == Error(hellhound.RefreshRejected(hellhound.InvalidClient))
  let assert Ok(_) = second
}

pub fn bearer_token_type_is_case_insensitive_test() {
  let #(first, _) = refresh_with(support.TokenField("token_type", "bearer"))
  let assert Ok(_) = first
}

pub fn proven_no_send_releases_the_generation_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  support.provider_stop(provider)
  let not_sent =
    Error(
      hellhound.RefreshNotSent(hellhound.TransportFailure(
        evidence: hellhound.NotSent,
        reason: hellhound.ConnectionRefused,
      )),
    )
  assert hellhound.refresh(client, session) == not_sent
  // Released, not quarantined: another attempt is admitted.
  assert hellhound.refresh(client, session) == not_sent
  hellhound.stop(client)
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

pub fn lost_publication_acknowledgement_recovers_without_provider_test() {
  let provider = support.provider_start(support.Standard)
  let #(client, control) = durable_client(provider)
  let session = logged_in(provider, client)
  // Writes during the refresh: the reservation, then the publication.
  faults.lose_ack_of(control, 2)
  let assert Error(hellhound.RefreshUnconfirmed(recovery) as error) =
    hellhound.refresh(client, session)
  assert hellhound.session_error_action(error) == hellhound.Recover
  let requests = support.token_requests(provider)
  let assert Ok(recovered) = hellhound.recover_refresh(client, recovery)
  let assert Ok(again) = hellhound.recover_refresh(client, recovery)
  assert token(recovered) == token(again)
  assert support.token_requests(provider) == requests
  hellhound.stop(client)
  support.provider_stop(provider)
}

pub fn foreign_sessions_are_rejected_before_any_call_test() {
  let provider_a = support.provider_start(support.Standard)
  let provider_b = support.provider_start(support.Standard)
  let a = start(settings(provider_a))
  let b = start(settings(provider_b))
  let session = logged_in(provider_a, a)
  let requests = support.token_requests(provider_b)
  assert hellhound.refresh(b, session) == Error(hellhound.SessionForeign)
  assert hellhound.access_token(b, session) == Error(hellhound.SessionForeign)
  let assert Error(hellhound.UserinfoSession(hellhound.SessionForeign)) =
    hellhound.userinfo(b, session)
  assert support.token_requests(provider_b) == requests
  hellhound.stop(a)
  hellhound.stop(b)
  support.provider_stop(provider_a)
  support.provider_stop(provider_b)
}

pub fn userinfo_requires_subject_continuity_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  let assert Ok(info) = hellhound.userinfo(client, session)
  assert hellhound.userinfo_subject(info) == "subject-1"
  assert hellhound.decode_userinfo(info, decode.at(["email"], decode.string))
    == Ok("user@example.test")
  support.script(provider, support.Userinfo, support.Sub("someone-else"))
  let assert Error(hellhound.UserinfoSubjectMismatch) =
    hellhound.userinfo(client, session)
  support.script(
    provider,
    support.Userinfo,
    support.Status(401, "invalid_token"),
  )
  let assert Error(hellhound.UserinfoFailed(hellhound.ProviderStatus(
    status: 401,
    error: hellhound.InvalidToken,
  ))) = hellhound.userinfo(client, session)
  hellhound.stop(client)
  support.provider_stop(provider)
}

pub fn client_credentials_returns_typed_token_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let now = support.now_seconds()
  let assert Ok(token) = hellhound.client_credentials(client, ["api"])
  assert hellhound.access_token_value(token.access_token) != ""
  let assert Some(expires_at) = token.expires_at
  let #(expires, _) = timestamp.to_unix_seconds_and_nanoseconds(expires_at)
  assert expires >= now + 59 && expires <= now + 61
  let assert Error(hellhound.ClientCredentialsInvalidScope(_)) =
    hellhound.client_credentials(client, ["a b"])
  hellhound.stop(client)
  let public =
    start(
      config.new(
        issuer: support.provider_issuer(provider),
        client_id: "hellhound-rp",
        redirect_uri: "https://app.example/callback",
        authentication: config.PublicClient,
      )
      |> config.with_trust(config.TrustAnchorsPem(support.ca_pem()))
      |> config.with_destinations(config.AllowLoopbackForTesting)
      |> config.with_signing_algorithms([config.Rs256]),
    )
  let assert Error(hellhound.ClientCredentialsNeedConfidentialClient) =
    hellhound.client_credentials(public, [])
  hellhound.stop(public)
  support.provider_stop(provider)
}

pub fn introspection_distinguishes_inactive_from_failure_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let assert Ok(hellhound.ActiveToken(info)) =
    hellhound.introspect(client, "active-token")
  assert info.client_id == Some("hellhound-rp")
  assert info.subject == Some("subject-1")
  assert info.scopes == ["openid", "email"]
  assert hellhound.decode_token_claims(
      info,
      decode.at(["department"], decode.string),
    )
    == Ok("platform")
  let assert Ok(hellhound.InactiveToken) =
    hellhound.introspect(client, "unknown")
  // An oversized token is refused locally.
  assert hellhound.introspect(client, string.repeat("t", 8193))
    == Error(hellhound.IntrospectionTokenTooLarge)
  support.provider_stop(provider)
  let assert Error(hellhound.IntrospectionFailed(hellhound.TransportFailure(
    evidence: hellhound.NotSent,
    ..,
  ))) = hellhound.introspect(client, "active-token")
  hellhound.stop(client)
}

/// An active answer whose `exp` has passed is inactive, with no
/// clock tolerance. Both sides use one fixed expiry, independent of
/// startup latency and the wall-clock second in which a request arrives.
pub fn introspection_checks_exp_strictly_test() {
  let provider = support.provider_start(support.Standard)
  let expires_at = 2_000_000_000
  support.set_introspection_expiry(provider, expires_at)
  let clock = support.clock_new(expires_at)
  let client = start(settings(provider) |> with_clock(clock))
  assert hellhound.introspect(client, "active-token")
    == Ok(hellhound.InactiveToken)
  support.clock_set(clock, expires_at - 1)
  let assert Ok(hellhound.ActiveToken(_)) =
    hellhound.introspect(client, "active-token")
  hellhound.stop(client)
  support.provider_stop(provider)
}

pub fn logout_removes_custody_then_redirects_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  let assert Ok(hellhound.LoggedOut(
    provider_logout: hellhound.RedirectToProvider(redirect) as provider_logout,
    // The scripted provider advertises no revocation endpoint.
    revocation: hellhound.RevocationUnsupported,
  )) =
    hellhound.logout(
      client,
      session,
      hellhound.LogoutOptions(
        ..hellhound.default_logout(),
        post_logout_redirect_uri: Some("https://app.example/logged-out"),
        state: Some("logout-state"),
      ),
    )
  let url = hellhound.logout_url(redirect)
  assert string.starts_with(
    url,
    support.provider_issuer(provider) <> "/logout?",
  )
  assert string.contains(url, "id_token_hint=")
  assert string.contains(url, "post_logout_redirect_uri=")
  assert string.contains(url, "state=logout-state")
  // The redirect carries the ID token, so it does not print.
  assert !string.contains(string.inspect(provider_logout), "id_token_hint")
  assert hellhound.restore_session(client, hellhound.session_reference(session))
    == Error(hellhound.SessionNotFound)
  assert hellhound.refresh(client, session) == Error(hellhound.SessionNotFound)
  let assert Error(hellhound.InvalidPostLogoutRedirect) =
    hellhound.logout(
      client,
      logged_in(provider, client),
      hellhound.LogoutOptions(
        ..hellhound.default_logout(),
        post_logout_redirect_uri: Some("javascript:alert(1)"),
      ),
    )
  hellhound.stop(client)
  support.provider_stop(provider)
}

/// Request A holds the session value from before request B refreshed
/// it. A's logout still ends the session; a second logout reports that no
/// session existed.
pub fn logout_with_an_older_session_value_ends_the_session_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  let assert Ok(refreshed) = hellhound.refresh(client, session)
  let assert Ok(hellhound.LoggedOut(
    provider_logout: hellhound.RedirectToProvider(redirect),
    ..,
  )) = hellhound.logout(client, session, hellhound.default_logout())
  assert string.contains(hellhound.logout_url(redirect), "id_token_hint=")
  assert hellhound.restore_session(client, hellhound.session_reference(session))
    == Error(hellhound.SessionNotFound)
  assert hellhound.refresh(client, refreshed.session)
    == Error(hellhound.SessionNotFound)
  assert hellhound.logout(client, refreshed.session, hellhound.default_logout())
    == Error(hellhound.LogoutSession(hellhound.SessionNotFound))
  hellhound.stop(client)
  support.provider_stop(provider)
}

pub fn logout_without_end_session_endpoint_is_explicit_test() {
  let provider = support.provider_start(support.NoEndSession)
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  let assert Ok(hellhound.LoggedOut(
    provider_logout: hellhound.NoEndSessionEndpoint,
    revocation: hellhound.RevocationSkipped,
  )) =
    hellhound.logout(
      client,
      session,
      hellhound.LogoutOptions(
        ..hellhound.default_logout(),
        revocation: hellhound.SkipRevocation,
      ),
    )
  assert hellhound.restore_session(client, hellhound.session_reference(session))
    == Error(hellhound.SessionNotFound)
  hellhound.stop(client)
  support.provider_stop(provider)
}

/// The in-memory custody restarts empty: the session is reported lost (not
/// merely missing), and refresh never reaches the provider.
pub fn custody_loss_is_reported_as_lost_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  let requests = support.token_requests(provider)
  let assert Some(name) = client.names.memory_custody
  let assert Ok(pid) = process.named(name)
  process.kill(pid)
  process.sleep(100)
  assert hellhound.refresh(client, session) == Error(hellhound.SessionLost)
  assert hellhound.restore_session(client, hellhound.session_reference(session))
    == Error(hellhound.SessionLost)
  assert hellhound.restore_session(client, "never-issued")
    == Error(hellhound.SessionNotFound)
  assert support.token_requests(provider) == requests
  hellhound.stop(client)
  support.provider_stop(provider)
}

/// OIDC Core §12.2 permits a refresh response without an ID token; the
/// established identity is kept.
pub fn refresh_without_id_token_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  support.script(
    provider,
    support.Refresh(refresh_token_of(provider)),
    support.OmitIdToken,
  )
  let assert Ok(refreshed) = hellhound.refresh(client, session)
  assert hellhound.identity_key(hellhound.session_identity(refreshed.session))
    == hellhound.identity_key(hellhound.session_identity(session))
  let assert Ok(_) = hellhound.refresh(client, refreshed.session)
  hellhound.stop(client)
  support.provider_stop(provider)
}

/// A refresher that dies mid-request may already have reached the provider.
/// Its lease runs out and the generation is quarantined, never released.
pub fn an_expired_refresh_lease_quarantines_the_generation_test() {
  let provider = support.provider_start(support.Standard)
  let base = support.now_seconds()
  let clock = support.clock_new(base)
  let client =
    start(
      settings(provider)
      |> config.with_request_timeout(duration.milliseconds(500))
      |> config.with_store_timeout(duration.milliseconds(200))
      |> config.with_refresh_wait(duration.milliseconds(100))
      |> with_clock(clock),
    )
  let session = logged_in(provider, client)
  support.script(
    provider,
    support.Refresh(refresh_token_of(provider)),
    support.Delay(3000),
  )
  let dispatcher =
    process.spawn_unlinked(fn() { hellhound.refresh(client, session) })
  process.sleep(200)
  process.kill(dispatcher)
  // Within the lease, another request waits and gives up.
  assert hellhound.refresh(client, session)
    == Error(hellhound.RefreshWaitTimedOut)
  // Past the lease (request + 2 store timeouts + 1 s), it is quarantined.
  support.clock_set(clock, base + 3)
  assert hellhound.refresh(client, session)
    == Error(hellhound.RefreshQuarantined(hellhound.RefresherLost))
  assert hellhound.refresh(client, session)
    == Error(hellhound.RefreshQuarantined(hellhound.RefresherLost))
  hellhound.stop(client)
  support.provider_stop(provider)
}

/// A request may return `RefreshUnconfirmed` and exit; another process
/// recovers the publication with the value it handed over.
pub fn publication_recovery_survives_the_dispatcher_test() {
  let provider = support.provider_start(support.Standard)
  let #(client, control) = durable_client(provider)
  let session = logged_in(provider, client)
  faults.lose_ack_of(control, 2)
  let handed_over = process.new_subject()
  process.spawn_unlinked(fn() {
    let assert Error(hellhound.RefreshUnconfirmed(recovery)) =
      hellhound.refresh(client, session)
    process.send(handed_over, recovery)
  })
  let assert Ok(recovery) = process.receive(handed_over, 2000)
  let assert Ok(_) = hellhound.recover_refresh(client, recovery)
  hellhound.stop(client)
  support.provider_stop(provider)
}

/// An idle session ends in custody: it can no longer be restored, and its
/// tokens are gone.
pub fn idle_sessions_end_test() {
  let provider = support.provider_start(support.Standard)
  let clock = support.clock_new(support.now_seconds())
  let client =
    start(
      settings(provider)
      |> config.with_session_lifetime(
        absolute: duration.minutes(10),
        idle: duration.seconds(60),
      )
      |> with_clock(clock),
    )
  let session = logged_in(provider, client)
  let reference = hellhound.session_reference(session)
  let assert Ok(_) = hellhound.restore_session(client, reference)
  support.clock_set(clock, support.clock_read(clock) + 61)
  assert hellhound.restore_session(client, reference)
    == Error(hellhound.SessionNotFound)
  hellhound.stop(client)
  support.provider_stop(provider)
}

/// Use restarts the idle period.
pub fn use_restarts_the_idle_period_test() {
  let provider = support.provider_start(support.Standard)
  let base = support.now_seconds()
  let clock = support.clock_new(base)
  let client =
    start(
      settings(provider)
      |> config.with_session_lifetime(
        absolute: duration.minutes(10),
        idle: duration.seconds(60),
      )
      |> with_clock(clock),
    )
  let session = logged_in(provider, client)
  let reference = hellhound.session_reference(session)
  list.each([40, 80, 120, 160], fn(t) {
    support.clock_set(clock, base + t)
    let assert Ok(_) = hellhound.restore_session(client, reference)
  })
  support.clock_set(clock, base + 230)
  assert hellhound.restore_session(client, reference)
    == Error(hellhound.SessionNotFound)
  hellhound.stop(client)
  support.provider_stop(provider)
}

/// A provider that closes the connection without answering: the request may
/// have been sent, and the public reason is `ReceiveFailed`.
pub fn a_closed_connection_reports_receive_failed_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  support.script(provider, support.Userinfo, support.Close)
  assert hellhound.userinfo(client, session)
    == Error(
      hellhound.UserinfoFailed(hellhound.TransportFailure(
        evidence: hellhound.MaybeSent,
        reason: hellhound.ReceiveFailed,
      )),
    )
  let _ = browser
  let _ = None
  hellhound.stop(client)
  support.provider_stop(provider)
}

/// A refresh that decides nothing leaves an unexpired token in use: the
/// provider is down, the token expires in 10 s (inside the margin), and
/// `access_token` still returns it; `refresh` reports the failure.
pub fn an_undecided_refresh_keeps_the_unexpired_token_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  support.script(
    provider,
    support.Refresh(refresh_token_of(provider)),
    support.TokenIntField("expires_in", 10),
  )
  let assert Ok(short) = hellhound.refresh(client, session)
  support.provider_stop(provider)
  let assert Ok(same) = hellhound.access_token(client, short.session)
  assert token(same) == token(short)
  let assert Error(hellhound.RefreshNotSent(_)) =
    hellhound.refresh(client, short.session)
  hellhound.stop(client)
}
