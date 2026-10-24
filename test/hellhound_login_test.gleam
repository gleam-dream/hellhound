//// Login orchestration against the scripted in-process provider: atomic
//// consumption under contention, the clock sampled at consumption, store
//// loss, exchange outcomes, identity rejection, custody recovery and the
//// login bound. Every provider request crosses Hellhound's real TLS transport.

import gleam/dict
import gleam/dynamic/decode
import gleam/erlang/process
import gleam/http
import gleam/http/request.{type Request}
import gleam/list
import gleam/option.{None, Some}
import gleam/string
import gleam/time/duration
import gleam/uri
import hellhound
import hellhound/config
import hellhound/internal/secure
import hellhound/internal/settings
import hellhound/testing
import hellhound_store_support as faults
import hellhound_test_support as support

pub fn settings(provider: support.Provider) -> config.Config {
  config.new(
    issuer: support.provider_issuer(provider),
    client_id: "hellhound-rp",
    redirect_uri: "https://app.example/callback",
    authentication: config.ClientSecretBasic(config.secret("sentinel-secret")),
  )
  |> config.with_scopes(["email"])
  |> config.with_trust(config.TrustAnchorsPem(support.ca_pem()))
  |> config.with_destinations(config.AllowLoopbackForTesting)
  |> config.with_signing_algorithms([config.Rs256])
}

pub fn start(config: config.Config) -> hellhound.Client {
  let assert Ok(client) = hellhound.new(config)
  let assert Ok(Nil) = hellhound.start(client)
  client
}

/// The configuration reading Unix time from a test clock.
pub fn with_clock(
  config: config.Config,
  clock: support.Clock,
) -> config.Config {
  settings.Settings(..config, clock: fn() { support.clock_read(clock) })
}

pub fn param(url: String, name: String) -> String {
  let assert Ok(#(_, query)) = string.split_once(url, "?")
  let assert Ok(params) = uri.parse_query(query)
  let assert Ok(value) = list.key_find(params, name)
  value
}

/// A request from a browser without a binding cookie.
pub fn browser() -> Request(String) {
  request.new()
}

/// Act as the browser and provider front channel: register a code for the
/// login's nonce and build the callback request with the binding cookie.
pub fn authorize(
  provider: support.Provider,
  redirect: hellhound.LoginRedirect,
  code: String,
) -> Request(String) {
  let url = hellhound.login_url(redirect)
  support.issue_code(provider, code, param(url, "nonce"))
  callback(redirect, [
    #("code", code),
    #("state", param(url, "state")),
    #("iss", support.provider_issuer(provider)),
  ])
}

/// A GET callback with these parameters and the redirect's binding cookie.
pub fn callback(
  redirect: hellhound.LoginRedirect,
  params: List(#(String, String)),
) -> Request(String) {
  request.Request(
    ..testing.browser_request(redirect),
    query: Some(uri.query_to_string(params)),
  )
}

pub fn logged_in(
  provider: support.Provider,
  client: hellhound.Client,
) -> hellhound.Session {
  let assert Ok(redirect) =
    hellhound.begin_login(client, browser(), hellhound.default_login())
  let code = "code-" <> param(hellhound.login_url(redirect), "state")
  let assert Ok(session) =
    hellhound.complete_login(client, authorize(provider, redirect, code))
  session
}

type Department {
  Department(name: String)
}

pub fn login_issues_identity_with_custom_claims_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let session = logged_in(provider, client)
  let identity = hellhound.session_identity(session)
  assert hellhound.subject(identity) == "subject-1"
  assert hellhound.issuer(identity) == support.provider_issuer(provider)
  let decoder = {
    use name <- decode.field("department", decode.string)
    decode.success(Department(name))
  }
  assert hellhound.decode_claims(identity, decoder)
    == Ok(Department("platform"))
  assert option.is_some(hellhound.authentication_time(identity))
  assert support.token_requests(provider) == 1
  hellhound.stop(client)
  support.provider_stop(provider)
}

pub fn authorization_url_carries_s256_and_fresh_material_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let assert Ok(a) =
    hellhound.begin_login(client, browser(), hellhound.default_login())
  let assert Ok(b) =
    hellhound.begin_login(client, browser(), hellhound.default_login())
  let a_url = hellhound.login_url(a)
  let b_url = hellhound.login_url(b)
  assert param(a_url, "code_challenge_method") == "S256"
  assert string.length(param(a_url, "code_challenge")) == 43
  assert string.length(param(a_url, "state")) == 43
  assert string.length(param(a_url, "nonce")) == 43
  assert param(a_url, "state") != param(b_url, "state")
  assert param(a_url, "nonce") != param(b_url, "nonce")
  assert param(a_url, "code_challenge") != param(b_url, "code_challenge")
  assert param(a_url, "scope") == "openid email"
  // Two browsers, two bindings.
  assert testing.browser_request(a).headers
    != testing.browser_request(b).headers
  // The verifier never appears in the URL.
  assert !string.contains(a_url, "code_verifier")
  hellhound.stop(client)
  support.provider_stop(provider)
}

/// One browser keeps one binding across tabs: a second login from a browser
/// that holds the cookie reuses it, and both callbacks complete.
pub fn one_binding_covers_concurrent_tabs_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let assert Ok(first) =
    hellhound.begin_login(client, browser(), hellhound.default_login())
  let assert Ok(second) =
    hellhound.begin_login(
      client,
      testing.browser_request(first),
      hellhound.default_login(),
    )
  assert testing.browser_request(first).headers
    == testing.browser_request(second).headers
  let assert Ok(_) =
    hellhound.complete_login(client, authorize(provider, second, "tab-2"))
  let assert Ok(_) =
    hellhound.complete_login(client, authorize(provider, first, "tab-1"))
  hellhound.stop(client)
  support.provider_stop(provider)
}

pub fn racing_callbacks_consume_once_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let assert Ok(redirect) =
    hellhound.begin_login(client, browser(), hellhound.default_login())
  let request = authorize(provider, redirect, "race-code")
  let attempt = fn() { hellhound.complete_login(client, request) }
  let results = support.spawn_collect(list.repeat(attempt, 16), 30_000)
  let completed = list.count(results, fn(r) { result_is_ok(r) })
  assert completed == 1
  assert list.count(results, fn(r) { r == Error(hellhound.LoginReplayed) })
    == 15
  assert support.token_requests(provider) == 1
  hellhound.stop(client)
  support.provider_stop(provider)
}

fn result_is_ok(r: Result(a, b)) -> Bool {
  case r {
    Ok(_) -> True
    Error(_) -> False
  }
}

/// The clock moves to exactly `expires_at` between the lookup and the
/// consumption; consumption samples the clock itself, so the login expires
/// and no token request is sent.
pub fn clock_is_sampled_at_consumption_test() {
  let provider = support.provider_start(support.Standard)
  let base = support.now_seconds()
  let clock = support.clock_new(base)
  let #(logins, control) = faults.memory()
  let client =
    start(
      settings(provider)
      |> config.with_login_lifetime(duration.seconds(60))
      |> config.with_transaction_store(logins)
      |> config.with_sealing_key(faults.sealing_key())
      |> with_clock(clock),
    )
  let assert Ok(redirect) =
    hellhound.begin_login(client, browser(), hellhound.default_login())
  let request = authorize(provider, redirect, "held-code")
  support.clock_set(clock, base + 59)
  faults.set(control, fn(f) {
    faults.Faults(..f, after_get: fn() { support.clock_set(clock, base + 60) })
  })
  assert hellhound.complete_login(client, request)
    == Error(hellhound.LoginExpired)
  assert support.token_requests(provider) == 0
  hellhound.stop(client)
  support.provider_stop(provider)
}

pub fn one_second_before_expiry_completes_test() {
  let provider = support.provider_start(support.Standard)
  let base = support.now_seconds()
  let clock = support.clock_new(base)
  let client =
    start(
      settings(provider)
      |> config.with_login_lifetime(duration.seconds(60))
      |> with_clock(clock),
    )
  let assert Ok(redirect) =
    hellhound.begin_login(client, browser(), hellhound.default_login())
  let request = authorize(provider, redirect, "edge-code")
  support.clock_set(clock, base + 59)
  let assert Ok(_) = hellhound.complete_login(client, request)
  hellhound.stop(client)
  support.provider_stop(provider)
}

pub fn store_loss_never_authorises_exchange_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let assert Ok(redirect) =
    hellhound.begin_login(client, browser(), hellhound.default_login())
  let request = authorize(provider, redirect, "lost-code")
  // The in-memory login store restarts empty under supervision.
  let assert Some(name) = client.names.memory_logins
  let assert Ok(pid) = process.named(name)
  process.kill(pid)
  process.sleep(50)
  let assert Error(hellhound.CallbackRejected(hellhound.UnknownState)) =
    hellhound.complete_login(client, request)
  assert support.token_requests(provider) == 0
  hellhound.stop(client)
  support.provider_stop(provider)
}

pub fn store_timeout_is_typed_and_sends_nothing_test() {
  let provider = support.provider_start(support.Standard)
  let #(logins, control) = faults.memory()
  let client =
    start(
      settings(provider)
      |> config.with_store_timeout(duration.milliseconds(200))
      |> config.with_transaction_store(logins)
      |> config.with_sealing_key(faults.sealing_key()),
    )
  let assert Ok(redirect) =
    hellhound.begin_login(client, browser(), hellhound.default_login())
  let request = authorize(provider, redirect, "slow-code")
  faults.set(control, fn(f) { faults.Faults(..f, get_delay_ms: 500) })
  let assert Error(hellhound.TransactionStoreUnavailable) =
    hellhound.complete_login(client, request)
  assert support.token_requests(provider) == 0
  hellhound.stop(client)
  support.provider_stop(provider)
}

fn exchange_outcome(
  behaviour: support.Behaviour,
  configure: fn(config.Config) -> config.Config,
) -> #(Result(hellhound.Session, hellhound.LoginError), Int) {
  let provider = support.provider_start(support.Standard)
  let client = start(configure(settings(provider)))
  let assert Ok(redirect) =
    hellhound.begin_login(client, browser(), hellhound.default_login())
  let code = "code-" <> param(hellhound.login_url(redirect), "state")
  let request = authorize(provider, redirect, code)
  support.script(provider, support.Code(code), behaviour)
  let result = hellhound.complete_login(client, request)
  // The login is consumed whatever the outcome: a retry is a replay and
  // sends nothing.
  let assert Error(hellhound.LoginReplayed) =
    hellhound.complete_login(client, request)
  let requests = support.token_requests(provider)
  hellhound.stop(client)
  support.provider_stop(provider)
  #(result, requests)
}

fn same(config: config.Config) -> config.Config {
  config
}

pub fn exchange_outcomes_are_classified_test() {
  let short = fn(c) {
    config.with_request_timeout(c, duration.milliseconds(400))
  }
  let cases = [
    #(
      support.Status(400, "invalid_grant"),
      same,
      Error(hellhound.ExchangeRejected(hellhound.InvalidGrant)),
    ),
    #(
      support.Status(401, "invalid_client"),
      same,
      Error(hellhound.ExchangeRejected(hellhound.InvalidClient)),
    ),
    #(
      support.Status(500, "server_error"),
      same,
      Error(hellhound.ExchangeOutcomeUnknown),
    ),
    #(
      support.Status(400, "not-a-known-code"),
      same,
      Error(hellhound.ExchangeRejected(hellhound.OtherOAuthError)),
    ),
    #(support.Delay(1500), short, Error(hellhound.ExchangeOutcomeUnknown)),
    #(support.Close, same, Error(hellhound.ExchangeOutcomeUnknown)),
    #(support.MalformedJson, same, Error(hellhound.ExchangeOutcomeUnknown)),
    #(
      support.OmitIdToken,
      same,
      Error(hellhound.IdentityRejected(hellhound.MissingIdToken)),
    ),
    #(
      support.IdToken("wrong_aud"),
      same,
      Error(hellhound.IdentityRejected(hellhound.IdTokenAudienceMismatch)),
    ),
    #(
      support.IdToken("extra_aud"),
      same,
      Error(hellhound.IdentityRejected(hellhound.IdTokenAudienceMismatch)),
    ),
    #(
      support.IdToken("wrong_azp"),
      same,
      Error(hellhound.IdentityRejected(hellhound.AuthorizedPartyMismatch)),
    ),
    #(
      support.IdToken("wrong_nonce"),
      same,
      Error(hellhound.IdentityRejected(hellhound.NonceMismatch)),
    ),
    #(
      support.IdToken("expired"),
      same,
      Error(hellhound.IdentityRejected(hellhound.IdTokenExpired)),
    ),
    #(
      support.IdToken("unknown_kid"),
      same,
      Error(hellhound.IdentityRejected(hellhound.UnknownSigningKey)),
    ),
  ]
  list.each(cases, fn(c) {
    let #(result, requests) = exchange_outcome(c.0, c.1)
    assert #(c.0, result) == #(c.0, c.2)
    assert requests == 1
  })
}

/// `complete_login` has one bound (default 30 s): a slow token endpoint is
/// cut at what the bound leaves, not at the full request timeout.
pub fn complete_login_has_one_bound_test() {
  let configure = fn(c) {
    c
    |> config.with_request_timeout(duration.seconds(10))
    |> config.with_login_timeout(duration.milliseconds(500))
  }
  let started = secure.monotonic_ms()
  let #(result, _) = exchange_outcome(support.Delay(3000), configure)
  assert result == Error(hellhound.ExchangeOutcomeUnknown)
  assert secure.monotonic_ms() - started < 2500
}

/// A login store slow enough to use up the bound: the code is never sent.
pub fn exhausted_login_bound_sends_nothing_test() {
  let provider = support.provider_start(support.Standard)
  let #(logins, control) = faults.memory()
  let client =
    start(
      settings(provider)
      |> config.with_login_timeout(duration.milliseconds(300))
      |> config.with_transaction_store(logins)
      |> config.with_sealing_key(faults.sealing_key()),
    )
  let assert Ok(redirect) =
    hellhound.begin_login(client, browser(), hellhound.default_login())
  let request = authorize(provider, redirect, "bounded-code")
  faults.set(control, fn(f) { faults.Faults(..f, get_delay_ms: 400) })
  let result = hellhound.complete_login(client, request)
  assert result == Error(hellhound.LoginTimedOut)
    || result == Error(hellhound.TransactionStoreUnavailable)
  assert support.token_requests(provider) == 0
  hellhound.stop(client)
  support.provider_stop(provider)
}

pub fn provider_down_before_exchange_is_proven_not_sent_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let assert Ok(redirect) =
    hellhound.begin_login(client, browser(), hellhound.default_login())
  let request = authorize(provider, redirect, "down-code")
  support.provider_stop(provider)
  let assert Error(hellhound.ProviderUnavailableBeforeExchange(hellhound.TransportFailure(
    evidence: hellhound.NotSent,
    reason: hellhound.ConnectionRefused,
  ))) = hellhound.complete_login(client, request)
  // Consumed all the same: a new login is needed.
  let assert Error(hellhound.LoginReplayed) =
    hellhound.complete_login(client, request)
  hellhound.stop(client)
}

pub fn lost_custody_acknowledgement_recovers_without_exchange_test() {
  let provider = support.provider_start(support.Standard)
  let #(custody, control) = faults.memory()
  let client =
    start(
      settings(provider)
      |> config.with_store_timeout(duration.milliseconds(200))
      |> config.with_custody_store(custody)
      |> config.with_sealing_key(faults.sealing_key()),
    )
  let assert Ok(redirect) =
    hellhound.begin_login(client, browser(), hellhound.default_login())
  let request = authorize(provider, redirect, "custody-code")
  faults.lose_ack_of(control, 1)
  let assert Error(hellhound.CustodyUnconfirmed(recovery) as error) =
    hellhound.complete_login(client, request)
  assert hellhound.login_error_action(error) == hellhound.Recover
  let assert Ok(session) = hellhound.recover_custody(client, recovery)
  // Idempotent: the same command yields the same installed session.
  let assert Ok(again) = hellhound.recover_custody(client, recovery)
  assert hellhound.session_reference(session)
    == hellhound.session_reference(again)
  assert support.token_requests(provider) == 1
  // After logout the recovery cannot resurrect the session.
  let assert Ok(_) =
    hellhound.logout(client, session, hellhound.default_logout())
  assert hellhound.recover_custody(client, recovery)
    == Error(hellhound.RecoveryEnded)
  // A different client configuration cannot use the recovery.
  let other_provider = support.provider_start(support.Standard)
  let other = start(settings(other_provider))
  assert hellhound.recover_custody(other, recovery)
    == Error(hellhound.RecoveryForeign)
  hellhound.stop(other)
  support.provider_stop(other_provider)
  hellhound.stop(client)
  support.provider_stop(provider)
}

/// A recovery older than the login lifetime is refused, so a stale value
/// cannot re-install a session whose record has expired.
pub fn old_custody_recovery_expires_test() {
  let provider = support.provider_start(support.Standard)
  let base = support.now_seconds()
  let clock = support.clock_new(base)
  let #(custody, control) = faults.memory()
  let client =
    start(
      settings(provider)
      |> config.with_store_timeout(duration.milliseconds(200))
      |> config.with_custody_store(custody)
      |> config.with_sealing_key(faults.sealing_key())
      |> with_clock(clock),
    )
  let assert Ok(redirect) =
    hellhound.begin_login(client, browser(), hellhound.default_login())
  let request = authorize(provider, redirect, "old-code")
  faults.lose_ack_of(control, 1)
  let assert Error(hellhound.CustodyUnconfirmed(recovery)) =
    hellhound.complete_login(client, request)
  support.clock_set(clock, base + 601)
  assert hellhound.recover_custody(client, recovery)
    == Error(hellhound.RecoveryExpired)
  hellhound.stop(client)
  support.provider_stop(provider)
}

pub fn max_age_requires_recent_authentication_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let options = fn(age) {
    hellhound.LoginOptions(
      ..hellhound.default_login(),
      max_age: Some(duration.seconds(age)),
    )
  }
  let assert Ok(strict) = hellhound.begin_login(client, browser(), options(1))
  assert param(hellhound.login_url(strict), "max_age") == "1"
  let assert Error(hellhound.IdentityRejected(hellhound.AuthenticationTooOld)) =
    hellhound.complete_login(client, authorize(provider, strict, "strict-code"))
  let assert Ok(relaxed) =
    hellhound.begin_login(client, browser(), options(300))
  let assert Ok(_) =
    hellhound.complete_login(
      client,
      authorize(provider, relaxed, "relaxed-code"),
    )
  hellhound.stop(client)
  support.provider_stop(provider)
}

/// An `auth_time` in the future is not a recent authentication.
pub fn future_authentication_time_fails_max_age_test() {
  let provider = support.provider_start(support.Standard)
  support.set_int_claims(
    provider,
    dict.from_list([#("auth_time", support.now_seconds() + 3600)]),
  )
  let client = start(settings(provider))
  let assert Ok(redirect) =
    hellhound.begin_login(
      client,
      browser(),
      hellhound.LoginOptions(
        ..hellhound.default_login(),
        max_age: Some(duration.seconds(300)),
      ),
    )
  let assert Error(hellhound.IdentityRejected(hellhound.AuthenticationTooOld)) =
    hellhound.complete_login(
      client,
      authorize(provider, redirect, "future-code"),
    )
  hellhound.stop(client)
  support.provider_stop(provider)
}

/// Pending-login lifetimes are wall-clock Unix time, so a durable login
/// store shared by several nodes agrees on them.
pub fn login_lifetime_follows_the_wall_clock_test() {
  let provider = support.provider_start(support.Standard)
  let base = support.now_seconds()
  let clock = support.clock_new(base)
  let client = start(settings(provider) |> with_clock(clock))
  let assert Ok(redirect) =
    hellhound.begin_login(client, browser(), hellhound.default_login())
  let request = authorize(provider, redirect, "wall-code")
  support.clock_set(clock, base + 601)
  assert hellhound.complete_login(client, request)
    == Error(hellhound.LoginExpired)
  hellhound.stop(client)
  support.provider_stop(provider)
}

/// An `auth_time` a few seconds ahead (provider clock) is within the clock
/// tolerance.
pub fn slightly_future_authentication_time_is_tolerated_test() {
  let provider = support.provider_start(support.Standard)
  support.set_int_claims(
    provider,
    dict.from_list([#("auth_time", support.now_seconds() + 3)]),
  )
  let client = start(settings(provider))
  let assert Ok(redirect) =
    hellhound.begin_login(
      client,
      browser(),
      hellhound.LoginOptions(
        ..hellhound.default_login(),
        max_age: Some(duration.seconds(300)),
      ),
    )
  let assert Ok(_) =
    hellhound.complete_login(
      client,
      authorize(provider, redirect, "tolerated-code"),
    )
  hellhound.stop(client)
  support.provider_stop(provider)
}

pub fn login_options_are_validated_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let with = fn(extra) {
    hellhound.begin_login(
      client,
      browser(),
      hellhound.LoginOptions(
        ..hellhound.default_login(),
        extra_parameters: extra,
      ),
    )
  }
  let assert Error(hellhound.InvalidLoginOption(hellhound.ReservedParameter(
    "state",
  ))) = with([#("state", "x")])
  let assert Error(hellhound.InvalidLoginOption(hellhound.ReservedParameter(
    "Redirect_URI",
  ))) = with([#("Redirect_URI", "https://evil.example")])
  let assert Error(hellhound.InvalidLoginOption(hellhound.InvalidParameterValue(
    _,
  ))) = with([#("x", "a\nb")])
  // Login option values are bounded (2 KiB each).
  let assert Error(hellhound.InvalidLoginOption(hellhound.OptionTooLong("big"))) =
    with([#("big", string.repeat("a", 2049))])
  let assert Error(hellhound.InvalidLoginOption(hellhound.OptionTooLong(
    "login_hint",
  ))) =
    hellhound.begin_login(
      client,
      browser(),
      hellhound.LoginOptions(
        ..hellhound.default_login(),
        login_hint: Some(string.repeat("h", 2049)),
      ),
    )
  let assert Ok(redirect) = with([#("resource", "https://api.example")])
  assert param(hellhound.login_url(redirect), "resource")
    == "https://api.example"
  let assert Error(hellhound.InvalidLoginOption(hellhound.InvalidOptionScope(_))) =
    hellhound.begin_login(
      client,
      browser(),
      hellhound.LoginOptions(..hellhound.default_login(), scopes: ["bad scope"]),
    )
  hellhound.stop(client)
  support.provider_stop(provider)
}

fn start_result(config: config.Config) -> Result(Nil, hellhound.StartError) {
  let assert Ok(client) = hellhound.new(config)
  case hellhound.start(client) {
    Ok(Nil) -> {
      hellhound.stop(client)
      Ok(Nil)
    }
    Error(error) -> Error(error)
  }
}

pub fn incompatible_providers_are_rejected_at_startup_test() {
  let cases = [
    #(support.NoS256, Error(hellhound.ProviderIncompatible([hellhound.NoS256]))),
    #(
      support.RequiresPar,
      Error(
        hellhound.ProviderIncompatible([hellhound.RequiresPushedAuthorization]),
      ),
    ),
    #(
      support.Hs256Only,
      Error(
        hellhound.ProviderIncompatible([hellhound.NoCommonSigningAlgorithm]),
      ),
    ),
    #(
      support.WrongIssuer,
      Error(hellhound.DiscoveryFailed(hellhound.IssuerMismatch)),
    ),
  ]
  list.each(cases, fn(c) {
    let provider = support.provider_start(c.0)
    assert start_result(settings(provider)) == c.1
    support.provider_stop(provider)
  })
}

/// `AssumeS256WhenUnadvertised` accepts only a provider that omits
/// `code_challenge_methods_supported`; Hellhound still sends its S256 challenge.
pub fn unadvertised_pkce_is_accepted_only_by_explicit_policy_test() {
  let assume = fn(provider) {
    settings(provider)
    |> config.with_pkce_advertisement(config.AssumeS256WhenUnadvertised)
  }
  let provider = support.provider_start(support.UnadvertisedPkce)
  assert start_result(settings(provider))
    == Error(hellhound.ProviderIncompatible([hellhound.NoS256]))
  let client = start(assume(provider))
  let assert Ok(redirect) =
    hellhound.begin_login(client, browser(), hellhound.default_login())
  assert param(hellhound.login_url(redirect), "code_challenge_method") == "S256"
  assert string.length(param(hellhound.login_url(redirect), "code_challenge"))
    == 43
  hellhound.stop(client)
  support.provider_stop(provider)

  // Advertising methods without S256 is refused under either policy, and
  // so is an explicit empty list: only an omitted field is "unadvertised".
  list.each([support.NoS256, support.EmptyPkceMethods], fn(variant) {
    let provider = support.provider_start(variant)
    assert start_result(assume(provider))
      == Error(hellhound.ProviderIncompatible([hellhound.NoS256]))
    support.provider_stop(provider)
  })
}

/// An authorization endpoint may carry its own query, as Azure AD B2C's
/// policy parameter does.
pub fn authorization_endpoint_query_is_preserved_test() {
  let provider = support.provider_start(support.QueryInAuthorizationEndpoint)
  let client = start(settings(provider))
  let assert Ok(redirect) =
    hellhound.begin_login(client, browser(), hellhound.default_login())
  assert param(hellhound.login_url(redirect), "p") == "b2c_1_signin"
  assert string.length(param(hellhound.login_url(redirect), "code_challenge"))
    == 43
  hellhound.stop(client)
  support.provider_stop(provider)
}

/// The browser is sent to the end-session endpoint with an ID-token hint,
/// so it must be HTTPS like the authorization endpoint.
pub fn insecure_end_session_endpoint_is_refused_test() {
  let provider = support.provider_start(support.InsecureEndSession)
  assert start_result(settings(provider))
    == Error(
      hellhound.ProviderIncompatible([hellhound.InsecureEndSessionEndpoint]),
    )
  support.provider_stop(provider)
}

/// The startup timeout bounds discovery and the first key load together.
pub fn startup_is_bounded_by_startup_timeout_test() {
  // Answers every request after 3 s.
  let server = support.server_start("localhost", support.Slow)
  let config =
    config.new(
      issuer: support.server_url(server, ""),
      client_id: "hellhound-rp",
      redirect_uri: "https://app.example/callback",
      authentication: config.ClientSecretBasic(config.secret("sentinel-secret")),
    )
    |> config.with_trust(config.TrustAnchorsPem(support.ca_pem()))
    |> config.with_destinations(config.AllowLoopbackForTesting)
    |> config.with_startup_timeout(duration.milliseconds(300))
  let started = secure.monotonic_ms()
  assert start_result(config) == Error(hellhound.StartupTimedOut)
  assert secure.monotonic_ms() - started < 2000
  support.server_stop(server)
}

pub fn loopback_provider_is_rejected_by_default_policy_test() {
  let provider = support.provider_start(support.Standard)
  assert start_result(
      settings(provider) |> config.with_destinations(config.PublicInternetOnly),
    )
    == Error(
      hellhound.DiscoveryFailed(hellhound.TransportFailure(
        evidence: hellhound.NotSent,
        reason: hellhound.DestinationRejected,
      )),
    )
  support.provider_stop(provider)
}

pub fn missing_issuer_parameter_follows_policy_test() {
  // The provider does not advertise RFC 9207: absence is accepted by the
  // default policy and rejected by AlwaysRequireIssuer.
  let provider = support.provider_start(support.NoIssParameter)
  let client = start(settings(provider))
  let assert Ok(redirect) =
    hellhound.begin_login(client, browser(), hellhound.default_login())
  let url = hellhound.login_url(redirect)
  support.issue_code(provider, "no-iss", param(url, "nonce"))
  let assert Ok(_) =
    hellhound.complete_login(
      client,
      callback(redirect, [#("code", "no-iss"), #("state", param(url, "state"))]),
    )
  hellhound.stop(client)
  let strict =
    start(
      settings(provider)
      |> config.with_issuer_parameter(config.AlwaysRequireIssuer),
    )
  let assert Ok(redirect) =
    hellhound.begin_login(strict, browser(), hellhound.default_login())
  let url = hellhound.login_url(redirect)
  let assert Error(hellhound.CallbackRejected(hellhound.CallbackIssuerMissing)) =
    hellhound.complete_login(
      strict,
      callback(redirect, [#("code", "x"), #("state", param(url, "state"))]),
    )
  hellhound.stop(strict)
  support.provider_stop(provider)
}

pub fn denial_codes_are_closed_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let deny = fn(code) {
    let assert Ok(redirect) =
      hellhound.begin_login(client, browser(), hellhound.default_login())
    hellhound.complete_login(
      client,
      callback(redirect, [
        #("error", code),
        #("error_description", "secret-looking description"),
        #("state", param(hellhound.login_url(redirect), "state")),
        #("iss", support.provider_issuer(provider)),
      ]),
    )
  }
  assert deny("access_denied")
    == Error(hellhound.ProviderDenied(hellhound.AccessDenied))
  assert deny("consent_required")
    == Error(hellhound.ProviderDenied(hellhound.ConsentRequired))
  assert deny("made_up")
    == Error(hellhound.ProviderDenied(hellhound.OtherDenial))
  assert support.token_requests(provider) == 0
  hellhound.stop(client)
  support.provider_stop(provider)
}

pub fn form_post_mode_rejects_query_callbacks_test() {
  let provider = support.provider_start(support.Standard)
  let client =
    start(settings(provider) |> config.with_response_mode(config.FormPost))
  let assert Ok(redirect) =
    hellhound.begin_login(client, browser(), hellhound.default_login())
  assert param(hellhound.login_url(redirect), "response_mode") == "form_post"
  let query = authorize(provider, redirect, "form-code")
  let assert Error(hellhound.CallbackMalformed(hellhound.UnexpectedResponseMode)) =
    hellhound.complete_login(client, query)
  let body = option.unwrap(query.query, "") |> string.replace("%20", "+")
  let post = request.Request(..query, method: http.Post, query: None, body:)
  // A form post must declare its content type.
  let assert Error(hellhound.CallbackMalformed(
    hellhound.CallbackEncodingInvalid,
  )) = hellhound.complete_login(client, post)
  let assert Ok(_) =
    hellhound.complete_login(
      client,
      request.set_header(
        post,
        "content-type",
        "application/x-www-form-urlencoded",
      ),
    )
  hellhound.stop(client)
  support.provider_stop(provider)
}

/// The binding cookie is the browser's, and only its digest is stored: a
/// callback without it, or with another browser's, is refused without
/// consuming the login.
pub fn callbacks_must_carry_this_browsers_binding_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let assert Ok(redirect) =
    hellhound.begin_login(client, browser(), hellhound.default_login())
  let assert Ok(other) =
    hellhound.begin_login(client, browser(), hellhound.default_login())
  let request = authorize(provider, redirect, "bound-code")
  let bare = request.Request(..request, headers: [])
  assert hellhound.complete_login(client, bare)
    == Error(hellhound.CallbackRejected(hellhound.BrowserBindingMissing))
  let foreign =
    request.Request(..request, headers: testing.browser_request(other).headers)
  assert hellhound.complete_login(client, foreign)
    == Error(hellhound.CallbackRejected(hellhound.BrowserBindingMismatch))
  let assert Ok(_) = hellhound.complete_login(client, request)
  hellhound.stop(client)
  support.provider_stop(provider)
}
