//// Interoperability with Dex v2.45.1 (`scripts/interop up`).
//// Dex advertises S256 PKCE, no RFC 9207 `iss` and no end-session endpoint.

import gleam/http/request
import gleam/option.{Some}
import hellhound
import hellhound/config
import hellhound_test_support as support

const issuer = "https://localhost:15556/dex"

fn client() -> hellhound.Client {
  config.new(
    issuer:,
    client_id: "hellhound-rp",
    redirect_uri: "https://localhost:1/callback",
    authentication: config.ClientSecretBasic(config.secret(
      "hellhound-dex-disposable-secret",
    )),
  )
  |> config.with_scopes(["email", "profile", "offline_access"])
  |> config.with_trust(config.TrustAnchorsPem(support.ca_pem()))
  |> config.with_destinations(config.AllowLoopbackForTesting)
  |> support.start_client
}

fn login(client: hellhound.Client) -> hellhound.Session {
  let assert Ok(redirect) =
    hellhound.begin_login(client, request.new(), hellhound.default_login())
  let assert Ok(support.Query(query)) =
    support.form_login(hellhound.login_url(redirect), issuer, [
      #("login", "alice@example.test"),
      #("password", "alice-disposable"),
    ])
  let assert Ok(session) =
    hellhound.complete_login(client, support.query_callback(redirect, query))
  session
}

pub fn dex_login_refresh_userinfo_and_logout_test() {
  let client = client()
  let session = login(client)
  let identity = hellhound.session_identity(session)
  assert hellhound.issuer(identity) == issuer
  assert hellhound.email(identity) == Some("alice@example.test")
  let assert Ok(info) = hellhound.userinfo(client, session)
  assert hellhound.userinfo_subject(info) == hellhound.subject(identity)
  let assert Ok(refreshed) = hellhound.refresh(client, session)
  let assert Ok(_) = hellhound.refresh(client, refreshed.session)
  let assert Ok(hellhound.LoggedOut(
    provider_logout: hellhound.NoEndSessionEndpoint,
    ..,
  )) = hellhound.logout(client, login(client), hellhound.default_logout())
  hellhound.stop(client)
}
