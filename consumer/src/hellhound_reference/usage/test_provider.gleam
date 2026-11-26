//// Usage: test an application's Hellhound integration with a local provider.
////
//// `hellhound/testing` runs a scripted provider over HTTPS on loopback with its
//// own PKI. A test browser follows the application's own `/login` redirect,
//// trusting `testing.trust_anchor_pem`, and returns to `/callback` with no
//// test hook in the application. Unit tests that hold a `LoginRedirect` call
//// `testing.authorize` and skip HTTP. The provider also mints and revokes
//// tokens, skews its clock, rotates its key and counts requests. Per subject,
//// it scripts granted scopes, email claims and extra ID-token claims such as
//// a namespaced roles claim, so a test signs in as production does. Refresh
//// answers are scripted too (`usage/authorization` uses them).

import gleam/dynamic/decode
import gleam/int
import gleam/json
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
    hellhound.begin_login(client, hellhound.default_login())
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
/// Extra claims carry what a real provider adds, such as roles in a namespaced
/// claim or `name`; `extra_claim` refuses protocol claims such as `iss`.
pub fn run() -> Nil {
  sign_in_then_refuse()
  let assert Ok(roles) =
    testing.extra_claim(
      "https://example.test/roles",
      json.array(["operator"], json.string),
    )
  let assert Ok(name) = testing.extra_claim("name", json.string("Ada"))
  let assert Error(testing.ReservedClaim("iss")) =
    testing.extra_claim("iss", json.string("https://elsewhere.test"))
  let assert Ok(provider) =
    testing.start_provider(
      testing.provider_options()
      |> testing.with_granted_scopes("ada", ["openid", "approve:refund"])
      |> testing.with_granted_scopes("mallory", ["openid"])
      |> testing.with_email_claims(
        "ada",
        testing.EmailClaims(Some("ada@example.test"), Some(False)),
      )
      |> testing.with_extra_claims("ada", [roles, name]),
    )
  let assert Ok(client) =
    hellhound.new(testing.config(provider, "https://app.test/callback"))
  let assert Ok(Nil) = hellhound.start(client)
  // Unit tests that hold the `LoginRedirect` skip HTTP.
  let sign_in = fn(subject) {
    let assert Ok(redirect) =
      hellhound.begin_login(client, hellhound.default_login())
    let assert Ok(callback) = testing.authorize(provider, redirect, subject:)
    let assert Ok(session) = hellhound.complete_login(client, callback)
    session
  }
  let ada = sign_in("ada")
  let mallory = sign_in("mallory")
  assert hellhound.subject(hellhound.session_identity(ada)) == "ada"
  // Extra claims are read from the verified identity like any other claim.
  assert hellhound.decode_claims(
      hellhound.session_identity(ada),
      decode.at(["https://example.test/roles"], decode.list(decode.string)),
    )
    == Ok(["operator"])
  assert hellhound.name(hellhound.session_identity(ada)) == Some("Ada")
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
  testing.set_extra_claims(provider, "ada", [])
  assert hellhound.subject(hellhound.session_identity(ada)) == "ada"
  hellhound.stop(client)
  testing.stop_provider(provider)
}

/// A local run with a real browser: a fixed port keeps the issuer, and a
/// root kept in a directory the application chooses is trusted once by the
/// developer (`testing.trust_anchor_file`). For local development only.
/// `start` reports why it could not start, such as a taken port or a broken
/// anchor, which it never replaces silently.
pub fn local_run(directory: String, port: Int) -> testing.Provider {
  let options =
    testing.provider_options()
    |> testing.with_port(port)
    |> testing.with_trust_anchor(directory)
  case testing.start(options) {
    Ok(provider) -> provider
    Error(testing.PortInUse(port)) ->
      panic as { "port " <> int.to_string(port) <> " is taken" }
    Error(testing.TrustAnchorFailed(directory, _)) ->
      panic as {
        "fix or replace the anchor in "
        <> directory
        <> " (testing.replace_trust_anchor), then trust "
        <> testing.trust_anchor_file(directory)
      }
    Error(_) -> panic as "the local provider did not start"
  }
}
