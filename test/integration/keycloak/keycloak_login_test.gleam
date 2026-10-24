//// MVP acceptance: real logins through Hellhound's public API against the
//// pinned Keycloak (`scripts/keycloak up`), over verified TLS with an
//// explicit test trust anchor.

import gleam/http/request
import gleam/list
import gleam/option.{Some}
import gleam/string
import gleam/time/duration
import gleam/uri
import hellhound
import hellhound/config
import hellhound/testing
import hellhound_test_support as support

const issuer = "https://localhost:18443/realms/hellhound"

fn settings() -> config.Config {
  config.new(
    issuer:,
    client_id: "hellhound-rp",
    redirect_uri: "https://localhost:1/callback",
    authentication: config.ClientSecretBasic(config.secret(
      "hellhound-rp-disposable-secret",
    )),
  )
  |> config.with_scopes(["profile", "email"])
  |> config.with_trust(config.TrustAnchorsPem(support.ca_pem()))
  |> config.with_destinations(config.AllowLoopbackForTesting)
}

fn start(config: config.Config) -> hellhound.Client {
  support.start_client(config)
}

fn login(
  client: hellhound.Client,
  user: String,
) -> #(String, hellhound.LoginRedirect) {
  let assert Ok(redirect) =
    hellhound.begin_login(client, request.new(), hellhound.default_login())
  let assert Ok(support.Query(query)) =
    support.keycloak_login(
      hellhound.login_url(redirect),
      user,
      user <> "-disposable",
    )
  #(query, redirect)
}

fn param(query: String, name: String) -> String {
  let assert Ok(params) = uri.parse_query(query)
  let assert Ok(value) = list.key_find(params, name)
  value
}

fn replace_param(query: String, name: String, value: String) -> String {
  let assert Ok(params) = uri.parse_query(query)
  params
  |> list.map(fn(p) {
    case p.0 == name {
      True -> #(name, value)
      False -> p
    }
  })
  |> uri.query_to_string
}

pub fn login_verifies_identity_and_confirms_custody_test() {
  let client = start(settings())
  let #(query, binding) = login(client, "alice")
  let assert Ok(session) =
    hellhound.complete_login(client, support.query_callback(binding, query))
  let identity = hellhound.session_identity(session)
  assert hellhound.issuer(identity) == issuer
  assert hellhound.subject(identity) != ""
  assert hellhound.email(identity) == Some("alice@example.test")
  assert hellhound.email_verified(identity) == Some(True)
  assert hellhound.identity_key(identity)
    == hellhound.IdentityKey(issuer:, subject: hellhound.subject(identity))
  // The session is restorable from its custody reference.
  let assert Ok(restored) =
    hellhound.restore_session(client, hellhound.session_reference(session))
  assert hellhound.subject(hellhound.session_identity(restored))
    == hellhound.subject(identity)
  let assert Ok(hellhound.Access(token:, ..)) =
    hellhound.access_token(client, session)
  assert hellhound.access_token_value(token) != ""
  // No token value is visible through generic inspection.
  assert !string.contains(
    string.inspect(token),
    hellhound.access_token_value(token),
  )
  hellhound.stop(client)
}

pub fn replayed_callback_is_rejected_test() {
  let client = start(settings())
  let #(query, binding) = login(client, "alice")
  let assert Ok(_) =
    hellhound.complete_login(client, support.query_callback(binding, query))
  let assert Error(hellhound.LoginReplayed) =
    hellhound.complete_login(client, support.query_callback(binding, query))
  hellhound.stop(client)
}

pub fn invalid_binding_or_issuer_does_not_consume_the_login_test() {
  let client = start(settings())
  let #(query, binding) = login(client, "alice")
  let assert Ok(other) =
    hellhound.begin_login(client, request.new(), hellhound.default_login())
  // Another browser's binding.
  let assert Error(hellhound.CallbackRejected(hellhound.BrowserBindingMismatch)) =
    hellhound.complete_login(client, support.query_callback(other, query))
  // No binding cookie.
  let assert Error(hellhound.CallbackRejected(hellhound.BrowserBindingMissing)) =
    hellhound.complete_login(
      client,
      support.without_binding(support.query_callback(binding, query)),
    )
  // Mix-up: a different issuer in the response.
  let assert Error(hellhound.CallbackRejected(hellhound.CallbackIssuerMismatch)) =
    hellhound.complete_login(
      client,
      support.query_callback(
        binding,
        replace_param(query, "iss", "https://evil.example"),
      ),
    )
  // Keycloak advertises RFC 9207 support, so a missing iss is rejected.
  let without_iss =
    uri.parse_query(query)
    |> fn(r) {
      let assert Ok(p) = r
      p
    }
    |> list.filter(fn(p) { p.0 != "iss" })
    |> uri.query_to_string
  let assert Error(hellhound.CallbackRejected(hellhound.CallbackIssuerMissing)) =
    hellhound.complete_login(
      client,
      support.query_callback(binding, without_iss),
    )
  // A forged state finds no login.
  let assert Error(hellhound.CallbackRejected(hellhound.UnknownState)) =
    hellhound.complete_login(
      client,
      support.query_callback(binding, replace_param(query, "state", "forged")),
    )
  // The legitimate callback still completes.
  let assert Ok(_) =
    hellhound.complete_login(client, support.query_callback(binding, query))
  hellhound.stop(client)
}

pub fn malformed_callbacks_are_rejected_before_lookup_test() {
  let client = start(settings())
  let #(query, binding) = login(client, "alice")
  let code = param(query, "code")
  let cases = [
    #(query <> "&code=" <> code, hellhound.DuplicateCallbackParameter),
    #(query <> "&error=access_denied", hellhound.AmbiguousCallback),
    #(replace_param(query, "code", ""), hellhound.EmptyCode),
    #("state=" <> param(query, "state"), hellhound.MissingCode),
    #("code=abc", hellhound.MissingState),
    #("state=%zz&code=1", hellhound.CallbackEncodingInvalid),
    #(string.repeat("a", 20_000), hellhound.CallbackTooLarge),
  ]
  list.each(cases, fn(c) {
    let assert Error(hellhound.CallbackMalformed(problem)) =
      hellhound.complete_login(client, support.query_callback(binding, c.0))
    assert problem == c.1
  })
  // A form-post body is refused while query mode is configured.
  let assert Error(hellhound.CallbackMalformed(hellhound.UnexpectedResponseMode)) =
    hellhound.complete_login(client, support.form_callback(binding, query))
  let assert Ok(_) =
    hellhound.complete_login(client, support.query_callback(binding, query))
  hellhound.stop(client)
}

/// Two concurrent callbacks for one login: exactly one token request and one
/// session; the other callback observes replay.
pub fn concurrent_callbacks_send_one_token_request_test() {
  let client = start(settings())
  let #(query, binding) = login(client, "alice")
  support.count_reset()
  let attempt = fn() {
    hellhound.complete_login(client, support.query_callback(binding, query))
  }
  let results = support.spawn_collect(list.repeat(attempt, 8), 30_000)
  let completed =
    list.count(results, fn(r) {
      case r {
        Ok(_) -> True
        _ -> False
      }
    })
  let replayed =
    list.count(results, fn(r) { r == Error(hellhound.LoginReplayed) })
  assert completed == 1
  assert replayed == 7
  assert support.count("/protocol/openid-connect/token") == 1
  hellhound.stop(client)
}

pub fn form_post_login_test() {
  let client = start(settings() |> config.with_response_mode(config.FormPost))
  let assert Ok(redirect) =
    hellhound.begin_login(client, request.new(), hellhound.default_login())
  assert string.contains(
    hellhound.login_url(redirect),
    "response_mode=form_post",
  )
  let assert Ok(support.FormPost(body)) =
    support.keycloak_login(
      hellhound.login_url(redirect),
      "alice",
      "alice-disposable",
    )
  let assert Error(hellhound.CallbackMalformed(hellhound.UnexpectedResponseMode)) =
    hellhound.complete_login(client, support.query_callback(redirect, body))
  let assert Ok(session) =
    hellhound.complete_login(client, support.form_callback(redirect, body))
  assert hellhound.email(hellhound.session_identity(session))
    == Some("alice@example.test")
  hellhound.stop(client)
}

pub fn provider_denial_consumes_without_exchange_test() {
  let client = start(settings())
  let options =
    hellhound.LoginOptions(..hellhound.default_login(), prompt: [
      hellhound.PromptNone,
    ])
  let assert Ok(redirect) =
    hellhound.begin_login(client, request.new(), options)
  let assert Ok(support.Query(query)) =
    support.visit(hellhound.login_url(redirect))
  support.count_reset()
  let assert Error(hellhound.ProviderDenied(hellhound.LoginRequired)) =
    hellhound.complete_login(client, support.query_callback(redirect, query))
  assert support.count("/protocol/openid-connect/token") == 0
  let assert Error(hellhound.LoginReplayed) =
    hellhound.complete_login(client, support.query_callback(redirect, query))
  hellhound.stop(client)
}

pub fn concurrent_tabs_share_a_binding_test() {
  let client = start(settings())
  let assert Ok(first) =
    hellhound.begin_login(client, request.new(), hellhound.default_login())
  let binding = first
  let assert Ok(second) =
    hellhound.begin_login(
      client,
      testing.browser_request(first),
      hellhound.default_login(),
    )
  assert testing.browser_request(second).headers
    == testing.browser_request(first).headers
  assert hellhound.login_url(first) != hellhound.login_url(second)
  let assert Ok(support.Query(q1)) =
    support.keycloak_login(
      hellhound.login_url(first),
      "alice",
      "alice-disposable",
    )
  let assert Ok(support.Query(q2)) =
    support.keycloak_login(hellhound.login_url(second), "bob", "bob-disposable")
  // Complete in reverse order.
  let assert Ok(s2) =
    hellhound.complete_login(client, support.query_callback(binding, q2))
  let assert Ok(s1) =
    hellhound.complete_login(client, support.query_callback(binding, q1))
  assert hellhound.email(hellhound.session_identity(s1))
    == Some("alice@example.test")
  assert hellhound.email(hellhound.session_identity(s2))
    == Some("bob@example.test")
  hellhound.stop(client)
}

pub fn expired_login_is_rejected_test() {
  let client =
    start(settings() |> config.with_login_lifetime(duration.seconds(1)))
  let #(query, binding) = login(client, "alice")
  let _ = support.sleep(1100)
  support.count_reset()
  let assert Error(hellhound.LoginExpired) =
    hellhound.complete_login(client, support.query_callback(binding, query))
  assert support.count("/protocol/openid-connect/token") == 0
  hellhound.stop(client)
}

/// RFC 9700 §4.5 code injection: an attacker's authorization code presented
/// with the victim's own state, binding and issuer. Hellhound sends the victim
/// transaction's PKCE verifier, which does not match the attacker's
/// challenge, so the provider rejects the exchange.
pub fn injected_code_is_rejected_by_pkce_test() {
  let client = start(settings())
  let #(attacker_query, _) = login(client, "bob")
  let assert Ok(victim) =
    hellhound.begin_login(client, request.new(), hellhound.default_login())
  let assert Ok(#(_, victim_query)) =
    string.split_once(hellhound.login_url(victim), "?")
  let injected =
    uri.query_to_string([
      #("code", param(attacker_query, "code")),
      #("state", param(victim_query, "state")),
      #("iss", issuer),
    ])
  let assert Error(hellhound.ExchangeRejected(hellhound.InvalidGrant)) =
    hellhound.complete_login(client, support.query_callback(victim, injected))
  hellhound.stop(client)
}
