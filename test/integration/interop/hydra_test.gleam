//// Interoperability with Ory Hydra v26.2.0 (`scripts/interop up`).
//// Hydra advertises S256, an end-session endpoint, a revocation endpoint
//// and no introspection endpoint in discovery (introspection is an admin
//// API there).

import gleam/http/request
import gleam/option.{Some}
import gleam/string
import hellhound
import hellhound/config
import hellhound_test_support as support

const issuer = "https://localhost:14444"

fn client() -> hellhound.Client {
  config.new(
    issuer:,
    client_id: "hellhound-rp",
    redirect_uri: "https://localhost:1/callback",
    authentication: config.ClientSecretBasic(config.secret(
      "hellhound-hydra-disposable-secret-0123456789",
    )),
  )
  |> config.with_scopes(["email", "offline_access"])
  |> config.with_trust(config.TrustAnchorsPem(support.ca_pem()))
  |> config.with_destinations(config.AllowLoopbackForTesting)
  |> support.start_client
}

fn login(client: hellhound.Client) -> hellhound.Session {
  let assert Ok(redirect) =
    hellhound.begin_login(client, request.new(), hellhound.default_login())
  // The consent app lives on another port of the same host.
  let assert Ok(support.Query(query)) =
    support.authorize(hellhound.login_url(redirect), "https://localhost:1444")
  let assert Ok(session) =
    hellhound.complete_login(client, support.query_callback(redirect, query))
  session
}

pub fn hydra_login_refresh_client_credentials_and_logout_test() {
  let client = client()
  let session = login(client)
  let identity = hellhound.session_identity(session)
  assert hellhound.issuer(identity) == issuer
  assert hellhound.subject(identity) == "alice-subject"
  assert hellhound.email(identity) == Some("alice@example.test")
  let assert Ok(info) = hellhound.userinfo(client, session)
  assert hellhound.userinfo_subject(info) == "alice-subject"
  let assert Ok(refreshed) = hellhound.refresh(client, session)
  let assert Ok(again) = hellhound.refresh(client, refreshed.session)
  // The first session value reads the current token instead of refreshing.
  let assert Ok(current) = hellhound.refresh(client, session)
  assert hellhound.access_token_value(current.token)
    == hellhound.access_token_value(again.token)
  let assert Ok(token) = hellhound.client_credentials(client, [])
  assert hellhound.access_token_value(token.access_token) != ""
  let assert Error(hellhound.IntrospectionNotSupported) =
    hellhound.introspect(
      client,
      hellhound.access_token_value(token.access_token),
    )
  let assert Ok(hellhound.LoggedOut(
    provider_logout: hellhound.RedirectToProvider(redirect),
    revocation: hellhound.Revoked,
  )) =
    hellhound.logout(
      client,
      login(client),
      hellhound.LogoutOptions(
        ..hellhound.default_logout(),
        post_logout_redirect_uri: Some("https://localhost:1/logged-out"),
        state: Some("bye"),
      ),
    )
  assert string.starts_with(
    hellhound.logout_url(redirect),
    issuer <> "/oauth2/sessions/logout?",
  )
  hellhound.stop(client)
}
