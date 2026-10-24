//// Usage: test an application's Hellhound integration with a local provider.
////
//// `hellhound/testing` runs a scripted provider over HTTPS on loopback with its
//// own PKI. A test browser follows the application's own `/login` redirect,
//// trusting `testing.trust_anchor_pem`, and returns to `/callback` with no
//// test hook in the application. Unit tests that hold a `LoginRedirect` call
//// `testing.authorize` and skip HTTP. The provider also mints and revokes
//// tokens, skews its clock, rotates its key and counts requests.

import gleam/http/request
import gleam/option.{None, Some}
import hellhound
import hellhound/testing

// snips-start: test-provider
pub fn sign_in_then_refuse() -> Nil {
  let assert Ok(provider) =
    testing.start_provider(
      testing.provider_options() |> testing.with_login(testing.SignIn("ada")),
    )
  let assert Ok(client) =
    hellhound.new(testing.config(provider, "https://app.test/callback"))
  let assert Ok(Nil) = hellhound.start(client)
  // /login -> provider /authorize (signs "ada" in) -> /callback?code=...
  let assert Ok(redirect) =
    hellhound.begin_login(client, request.new(), hellhound.default_login())
  let assert Ok(callback) =
    testing.authorize(provider, redirect, subject: "ada")
  let assert Ok(session) = hellhound.complete_login(client, callback)
  assert hellhound.subject(hellhound.session_identity(session)) == "ada"
  // The next login at the provider's page is cancelled.
  testing.set_login(provider, testing.Refuse("access_denied"))
  hellhound.stop(client)
  testing.stop_provider(provider)
}

// snips-end: test-provider

/// A request's `login_hint` picks the user per login. `with_granted_scopes`
/// replaces the scopes a login is granted, so a test can sign in a user who
/// lacks a scope; the scopes appear in the access token and at introspection.
/// Email claims are provider assertions: each is independently optional.
pub fn run() -> Nil {
  sign_in_then_refuse()
  let assert Ok(provider) =
    testing.start_provider(
      testing.provider_options()
      |> testing.with_granted_scopes("ada", ["openid", "approve:refund"])
      |> testing.with_granted_scopes("mallory", ["openid"])
      |> testing.with_email_claims(
        "ada",
        testing.EmailClaims(Some("ada@example.test"), Some(False)),
      ),
    )
  let assert Ok(client) =
    hellhound.new(testing.config(provider, "https://app.test/callback"))
  let assert Ok(Nil) = hellhound.start(client)
  // Unit tests that hold the `LoginRedirect` skip HTTP.
  let sign_in = fn(subject) {
    let assert Ok(redirect) =
      hellhound.begin_login(client, request.new(), hellhound.default_login())
    let assert Ok(callback) = testing.authorize(provider, redirect, subject:)
    let assert Ok(session) = hellhound.complete_login(client, callback)
    session
  }
  let ada = sign_in("ada")
  let mallory = sign_in("mallory")
  assert hellhound.subject(hellhound.session_identity(ada)) == "ada"
  // Scripted grants reach the access token.
  let assert Ok(access) = hellhound.access_token(client, mallory)
  assert access.scopes == ["openid"]
  // The provider's counters and token minting are scriptable.
  assert testing.requests(provider).authorizations >= 2
  let minted = testing.issue_access_token(provider, testing.access_token("ada"))
  assert minted != ""
  // Email claims can be changed for later evidence without touching a held
  // identity.
  testing.set_email_claims(provider, "ada", testing.EmailClaims(None, None))
  assert hellhound.subject(hellhound.session_identity(ada)) == "ada"
  hellhound.stop(client)
  testing.stop_provider(provider)
}
