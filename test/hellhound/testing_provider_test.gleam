//// The public test provider end to end: login, access, refresh, logout
//// with revocation, introspection and client credentials.

import gleam/bit_array
import gleam/erlang/process
import gleam/http/request
import gleam/list
import gleam/option
import gleam/string
import gleam/time/duration
import hellhound
import hellhound/config
import hellhound/resource
import hellhound/testing

fn started(
  options: testing.ProviderOptions,
) -> #(testing.Provider, hellhound.Client) {
  let assert Ok(provider) = testing.start_provider(options)
  let assert Ok(client) =
    hellhound.new(testing.config(provider, "https://app.test/callback"))
  let assert Ok(Nil) = hellhound.start(client)
  #(provider, client)
}

fn login(
  provider: testing.Provider,
  client: hellhound.Client,
) -> hellhound.Session {
  let assert Ok(redirect) =
    hellhound.begin_login(client, request.new(), hellhound.default_login())
  let assert Ok(callback) =
    testing.authorize(provider, redirect, subject: "ada")
  let assert Ok(session) = hellhound.complete_login(client, callback)
  session
}

pub fn login_access_refresh_logout_test() {
  let #(provider, client) = started(testing.provider_options())
  let session = login(provider, client)
  assert hellhound.subject(hellhound.session_identity(session)) == "ada"
  let assert Ok(access) = hellhound.access_token(client, session)
  let assert Ok(refreshed) = hellhound.refresh(client, access.session)
  assert hellhound.access_token_value(refreshed.token)
    != hellhound.access_token_value(access.token)
  assert testing.requests(provider).refresh_grants == 1
  let assert Ok(hellhound.LoggedOut(
    provider_logout: hellhound.RedirectToProvider(_),
    revocation: hellhound.Revoked,
  )) = hellhound.logout(client, refreshed.session, hellhound.default_logout())
  assert testing.requests(provider).active_refresh_tokens == 0
  assert hellhound.restore_session(client, hellhound.session_reference(session))
    == Error(hellhound.SessionNotFound)
  hellhound.stop(client)
  testing.stop_provider(provider)
}

pub fn introspection_and_client_credentials_test() {
  let #(provider, client) = started(testing.provider_options())
  let assert Ok(token) = hellhound.client_credentials(client, ["reports"])
  assert option.is_some(token.expires_at)
  let assert Ok(hellhound.ActiveToken(info)) =
    hellhound.introspect(
      client,
      hellhound.access_token_value(token.access_token),
    )
  assert info.audiences == [testing.client_id(provider)]
  assert info.scopes == ["reports"]
  assert hellhound.introspect(client, "unknown") == Ok(hellhound.InactiveToken)
  hellhound.stop(client)
  testing.stop_provider(provider)
}

/// The provider's controls: a revoked grant answers `invalid_grant`, which
/// Hellhound reports as `RefreshRevoked`; a provider clock running ahead is
/// refused beyond the clock tolerance and accepted within it.
pub fn revocation_and_clock_skew_controls_test() {
  let #(provider, client) = started(testing.provider_options())
  let session = login(provider, client)
  testing.revoke_refresh_tokens(provider, "ada")
  assert hellhound.refresh(client, session) == Error(hellhound.RefreshRevoked)
  assert testing.requests(provider).rejected_refresh_grants == 1
  testing.set_clock_skew(provider, duration.seconds(20))
  let assert Ok(redirect) =
    hellhound.begin_login(client, request.new(), hellhound.default_login())
  let assert Ok(callback) =
    testing.authorize(provider, redirect, subject: "ada")
  assert hellhound.complete_login(client, callback)
    == Error(hellhound.IdentityRejected(hellhound.IdTokenNotYetValid))
  hellhound.stop(client)
  let assert Ok(tolerant) =
    hellhound.new(
      testing.config(provider, "https://app.test/callback")
      |> config.with_clock_tolerance(duration.seconds(60)),
    )
  let assert Ok(Nil) = hellhound.start(tolerant)
  let _ = login(provider, tolerant)
  hellhound.stop(tolerant)
  testing.stop_provider(provider)
}

/// The access tokens the provider issues are RFC 9068 JWTs a resource
/// server can verify locally; the refresh delay widens races.
pub fn issued_tokens_verify_locally_and_races_share_one_refresh_test() {
  let #(provider, client) =
    started(
      testing.provider_options()
      |> testing.with_access_token_audiences(["https://api.test"])
      |> testing.with_refresh_delay(duration.milliseconds(200)),
    )
  let session = login(provider, client)
  let assert Ok(access) = hellhound.access_token(client, session)
  let validator = resource.new(client, audience: "https://api.test")
  let assert Ok(claims) =
    resource.verify(validator, hellhound.access_token_value(access.token))
  assert resource.subject(claims) == "ada"
  let racers =
    list.repeat(fn() { hellhound.refresh(client, session) }, 4)
    |> list.map(fn(run) {
      let reply = process.new_subject()
      process.spawn(fn() { process.send(reply, run()) })
      reply
    })
    |> list.map(fn(reply) {
      let assert Ok(Ok(access)) = process.receive(reply, 5000)
      hellhound.access_token_value(access.token)
    })
  assert list.length(list.unique(racers)) == 1
  assert testing.requests(provider).refresh_grants == 1
  hellhound.stop(client)
  testing.stop_provider(provider)
}

/// `trust_anchor_der` is the certificate of `trust_anchor_pem` in the form
/// HTTP Gun's `Anchors` takes.
pub fn trust_anchor_der_matches_the_pem_test() {
  let assert Ok(provider) = testing.start_provider(testing.provider_options())
  let body =
    testing.trust_anchor_pem(provider)
    |> string.split("\n")
    |> list.filter(fn(line) { !string.starts_with(line, "-----") })
    |> string.concat
  assert bit_array.base64_encode(testing.trust_anchor_der(provider), True)
    == body
  testing.stop_provider(provider)
}
