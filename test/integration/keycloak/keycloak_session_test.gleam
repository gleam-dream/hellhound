//// Session operations against the pinned Keycloak through Hellhound's API.

import gleam/dynamic/decode
import gleam/http/request
import gleam/list
import gleam/option.{Some}
import gleam/string
import gleam/uri
import hellhound
import hellhound/config
import hellhound_test_support as support

const issuer = "https://localhost:18443/realms/hellhound"

fn start() -> hellhound.Client {
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
  |> support.start_client
}

fn session(client: hellhound.Client) -> hellhound.Session {
  let assert Ok(redirect) =
    hellhound.begin_login(client, request.new(), hellhound.default_login())
  let assert Ok(support.Query(query)) =
    support.keycloak_login(
      hellhound.login_url(redirect),
      "alice",
      "alice-disposable",
    )
  let assert Ok(session) =
    hellhound.complete_login(client, support.query_callback(redirect, query))
  session
}

fn token(access: hellhound.Access) -> String {
  hellhound.access_token_value(access.token)
}

pub fn refresh_rotates_and_keeps_identity_test() {
  let client = start()
  let s0 = session(client)
  let assert Ok(a1) = hellhound.refresh(client, s0)
  assert hellhound.identity_key(hellhound.session_identity(a1.session))
    == hellhound.identity_key(hellhound.session_identity(s0))
  let assert Ok(a2) = hellhound.refresh(client, a1.session)
  assert token(a2) != token(a1)
  // The older session value reads the current token; it cannot dispatch the
  // rotated-out refresh token.
  support.count_reset()
  let assert Ok(current) = hellhound.refresh(client, s0)
  assert token(current) == token(a2)
  assert support.count("/protocol/openid-connect/token") == 0
  let assert Ok(info) = hellhound.userinfo(client, a2.session)
  assert hellhound.userinfo_subject(info)
    == hellhound.subject(hellhound.session_identity(a2.session))
  hellhound.stop(client)
}

pub fn concurrent_refresh_dispatches_once_test() {
  let client = start()
  let s0 = session(client)
  support.count_reset()
  let results =
    support.spawn_collect(
      list.repeat(fn() { hellhound.refresh(client, s0) }, 6),
      30_000,
    )
  let tokens =
    list.map(results, fn(r) {
      let assert Ok(access) = r
      token(access)
    })
  assert list.length(list.unique(tokens)) == 1
  assert support.count("/protocol/openid-connect/token") == 1
  hellhound.stop(client)
}

pub fn userinfo_introspection_and_client_credentials_test() {
  let client = start()
  let s = session(client)
  let assert Ok(info) = hellhound.userinfo(client, s)
  assert hellhound.decode_userinfo(info, decode.at(["email"], decode.string))
    == Ok("alice@example.test")
  let assert Ok(access) = hellhound.access_token(client, s)
  let assert Ok(hellhound.ActiveToken(details)) =
    hellhound.introspect(client, token(access))
  assert details.subject
    == Some(hellhound.subject(hellhound.session_identity(s)))
  let assert Ok(hellhound.InactiveToken) =
    hellhound.introspect(client, "not-a-token")
  let assert Ok(cc) = hellhound.client_credentials(client, ["profile"])
  assert hellhound.access_token_value(cc.access_token) != ""
  assert option.is_some(cc.expires_at)
  hellhound.stop(client)
}

pub fn logout_revokes_and_ends_the_provider_session_test() {
  let client = start()
  let s = session(client)
  let assert Ok(hellhound.LoggedOut(
    provider_logout: hellhound.RedirectToProvider(redirect),
    revocation: hellhound.Revoked,
  )) =
    hellhound.logout(
      client,
      s,
      hellhound.LogoutOptions(
        ..hellhound.default_logout(),
        post_logout_redirect_uri: Some("https://localhost:1/logged-out"),
        state: Some("bye"),
      ),
    )
  let url = hellhound.logout_url(redirect)
  assert string.starts_with(url, issuer <> "/protocol/openid-connect/logout?")
  let assert Error(hellhound.SessionNotFound) =
    hellhound.restore_session(client, hellhound.session_reference(s))
  // Following the logout URL with the provider session cookie ends it and
  // returns to the post-logout URI with the state.
  let assert Ok(support.Query(query)) = support.keycloak_logout(url)
  let assert Ok(params) = uri.parse_query(query)
  assert list.key_find(params, "state") == Ok("bye")
  hellhound.stop(client)
}
