//// Public fixture behavior: extra claims for one subject pass through real
//// HTTPS login and userinfo, never replace protocol claims and never construct
//// application identity or permission.

import exception
import gleam/dict
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option.{Some}
import gleam/string
import gleeunit/should
import hellhound
import hellhound/testing

const roles = "https://example.test/roles"

pub fn roles_claim_reaches_the_verified_identity_and_userinfo_test() -> Nil {
  use provider, client <- with_provider(
    testing.provider_options()
    |> testing.with_extra_claims("ada", [
      extra(roles, json.array(["operator"], json.string)),
    ]),
  )
  let session = login(provider, client, "ada")
  let identity = hellhound.session_identity(session)
  hellhound.subject(identity) |> should.equal("ada")
  identity_roles(identity) |> should.equal(Ok(["operator"]))
  userinfo_roles(client, session) |> should.equal(Ok(["operator"]))
  // Email defaults are kept beside the extra claim.
  hellhound.email(identity) |> should.equal(Some("ada@example.test"))
  hellhound.email_verified(identity) |> should.equal(Some(True))
}

pub fn subject_without_extra_claims_is_unchanged_test() -> Nil {
  use provider, client <- with_provider(
    testing.provider_options()
    |> testing.with_extra_claims("ada", [
      extra(roles, json.array(["operator"], json.string)),
    ]),
  )
  let bob = login(provider, client, "bob")
  let identity = hellhound.session_identity(bob)
  hellhound.subject(identity) |> should.equal("bob")
  claim_names(identity)
  |> should.equal([
    "aud", "auth_time", "email", "email_verified", "exp", "iat", "iss", "nonce",
    "sub",
  ])
  let assert Ok(info) = hellhound.userinfo(client, bob)
  let assert Ok(fields) =
    hellhound.decode_userinfo(info, decode.dict(decode.string, decode.dynamic))
  dict.keys(fields)
  |> list.sort(by: string.compare)
  |> should.equal(["email", "sub"])
}

pub fn run_time_change_affects_only_later_logins_test() -> Nil {
  use provider, client <- with_provider(testing.provider_options())
  let before = login(provider, client, "ada")
  identity_roles(hellhound.session_identity(before))
  |> should.equal(Error(Nil))
  testing.set_extra_claims(provider, "ada", [
    extra(roles, json.array(["operator", "admin"], json.string)),
  ])
  // The identity verified earlier keeps the claims it was issued with.
  identity_roles(hellhound.session_identity(before))
  |> should.equal(Error(Nil))
  let after = login(provider, client, "ada")
  identity_roles(hellhound.session_identity(after))
  |> should.equal(Ok(["operator", "admin"]))
  hellhound.session_identity(after)
  |> hellhound.identity_key
  |> should.equal(hellhound.session_identity(before) |> hellhound.identity_key)
  // An empty list removes the subject's extra claims for later logins.
  testing.set_extra_claims(provider, "ada", [])
  identity_roles(hellhound.session_identity(login(provider, client, "ada")))
  |> should.equal(Error(Nil))
}

pub fn reserved_protocol_claims_are_refused_test() -> Nil {
  [
    "iss", "sub", "aud", "exp", "iat", "nbf", "jti", "nonce", "azp", "at_hash",
    "c_hash", "s_hash", "auth_time", "sid", "cnf", "_claim_names",
    "_claim_sources", "email", "email_verified",
  ]
  |> list.each(fn(name) {
    testing.extra_claim(name, json.string("forged"))
    |> should.equal(Error(testing.ReservedClaim(name)))
  })
}

pub fn profile_claims_can_be_set_test() -> Nil {
  use provider, client <- with_provider(
    testing.provider_options()
    |> testing.with_extra_claims("ada", [
      extra("name", json.string("Ada Lovelace")),
      extra("preferred_username", json.string("ada.l")),
      extra("https://example.test/staff", json.bool(True)),
    ]),
  )
  let identity = hellhound.session_identity(login(provider, client, "ada"))
  hellhound.name(identity) |> should.equal(Some("Ada Lovelace"))
  hellhound.preferred_username(identity) |> should.equal(Some("ada.l"))
  hellhound.decode_claims(
    identity,
    decode.at(["https://example.test/staff"], decode.bool),
  )
  |> should.equal(Ok(True))
}

pub fn a_repeated_name_keeps_the_last_value_test() -> Nil {
  use provider, client <- with_provider(
    testing.provider_options()
    |> testing.with_extra_claims("ada", [
      extra("name", json.string("first")),
      extra("name", json.string("last")),
    ]),
  )
  let identity = hellhound.session_identity(login(provider, client, "ada"))
  hellhound.name(identity) |> should.equal(Some("last"))
}

fn extra(name: String, value: json.Json) -> testing.ExtraClaim {
  let assert Ok(claim) = testing.extra_claim(name, value)
  claim
}

fn identity_roles(
  identity: hellhound.VerifiedIdentity,
) -> Result(List(String), Nil) {
  hellhound.decode_claims(
    identity,
    decode.at([roles], decode.list(decode.string)),
  )
  |> nil_error
}

fn userinfo_roles(
  client: hellhound.Client,
  session: hellhound.Session,
) -> Result(List(String), Nil) {
  let assert Ok(info) = hellhound.userinfo(client, session)
  hellhound.decode_userinfo(
    info,
    decode.at([roles], decode.list(decode.string)),
  )
  |> nil_error
}

fn nil_error(result: Result(a, b)) -> Result(a, Nil) {
  case result {
    Ok(value) -> Ok(value)
    Error(_) -> Error(Nil)
  }
}

fn claim_names(identity: hellhound.VerifiedIdentity) -> List(String) {
  let assert Ok(fields) =
    hellhound.decode_claims(
      identity,
      decode.dict(decode.string, decode.dynamic),
    )
  dict.keys(fields) |> list.sort(by: string.compare)
}

fn login(
  provider: testing.Provider,
  client: hellhound.Client,
  subject: String,
) -> hellhound.Session {
  let assert Ok(redirect) =
    hellhound.begin_login(client, hellhound.default_login())
  let assert Ok(callback) = testing.authorize(provider, redirect, subject:)
  let assert Ok(session) = hellhound.complete_login(client, callback)
  session
}

fn with_provider(
  options: testing.ProviderOptions,
  run: fn(testing.Provider, hellhound.Client) -> Nil,
) -> Nil {
  let assert Ok(provider) = testing.start_provider(options)
  use <- exception.defer(fn() { testing.stop_provider(provider) })
  let assert Ok(client) =
    hellhound.new(testing.config(provider, "https://app.test/callback"))
  use <- exception.defer(fn() { hellhound.stop(client) })
  let assert Ok(Nil) = hellhound.start(client)
  run(provider, client)
}
