//// Public fixture behavior: standard email assertions pass through real
//// HTTPS login/userinfo and never construct application identity or permission.

import exception
import gleam/dict
import gleam/dynamic/decode
import gleam/http/request
import gleam/list
import gleam/option.{type Option, None, Some}
import gleeunit/should
import hellhound
import hellhound/testing

pub fn defaults_preserve_existing_id_token_and_userinfo_claims_test() -> Nil {
  use provider, client <- with_provider(testing.provider_options())
  let session = login(provider, client, "ada")
  assert_identity(session, "ada", Some("ada@example.test"), Some(True))
  assert_userinfo(client, session, Some("ada@example.test"), None)
}

pub fn typed_fields_preserve_omission_false_and_string_contents_test() -> Nil {
  let samples = [
    testing.EmailClaims(None, None),
    testing.EmailClaims(None, Some(True)),
    testing.EmailClaims(None, Some(False)),
    testing.EmailClaims(Some(""), Some(True)),
    testing.EmailClaims(Some("ada@example.test"), None),
    testing.EmailClaims(Some("ada@example.test"), Some(False)),
    testing.EmailClaims(Some("new@example.test"), Some(True)),
    testing.EmailClaims(Some("quoted\"name@example.test"), Some(True)),
  ]
  list.each(samples, fn(claims) {
    use provider, client <- with_provider(
      testing.provider_options() |> testing.with_email_claims("ada", claims),
    )
    let session = login(provider, client, "ada")
    assert_identity(session, "ada", claims.email, claims.verified)
    assert_userinfo(client, session, claims.email, claims.verified)
  })
}

pub fn per_subject_override_does_not_change_another_identity_test() -> Nil {
  use provider, client <- with_provider(
    testing.provider_options()
    |> testing.with_email_claims("ada", testing.EmailClaims(None, None)),
  )
  let ada = login(provider, client, "ada")
  let bob = login(provider, client, "bob")
  assert_identity(ada, "ada", None, None)
  assert_identity(bob, "bob", Some("bob@example.test"), Some(True))
  assert_userinfo(client, bob, Some("bob@example.test"), None)
}

pub fn changed_claims_affect_new_evidence_not_existing_identity_test() -> Nil {
  use provider, client <- with_provider(testing.provider_options())
  let original = login(provider, client, "ada")
  let original_key =
    hellhound.session_identity(original) |> hellhound.identity_key
  testing.set_email_claims(
    provider,
    "ada",
    testing.EmailClaims(Some("changed@example.test"), Some(False)),
  )
  assert_userinfo(client, original, Some("changed@example.test"), Some(False))
  assert_identity(original, "ada", Some("ada@example.test"), Some(True))
  let changed = login(provider, client, "ada")
  assert_identity(changed, "ada", Some("changed@example.test"), Some(False))
  hellhound.session_identity(changed)
  |> hellhound.identity_key
  |> should.equal(original_key)
}

fn assert_identity(
  session: hellhound.Session,
  subject: String,
  email: Option(String),
  verified: Option(Bool),
) -> Nil {
  let identity = hellhound.session_identity(session)
  hellhound.subject(identity) |> should.equal(subject)
  hellhound.email(identity) |> should.equal(email)
  hellhound.email_verified(identity) |> should.equal(verified)
  let assert Ok(fields) =
    hellhound.decode_claims(
      identity,
      decode.dict(decode.string, decode.dynamic),
    )
  dict.has_key(fields, "email") |> should.equal(email != None)
  dict.has_key(fields, "email_verified") |> should.equal(verified != None)
}

fn assert_userinfo(
  client: hellhound.Client,
  session: hellhound.Session,
  email: Option(String),
  verified: Option(Bool),
) -> Nil {
  let assert Ok(info) = hellhound.userinfo(client, session)
  let decoder = {
    use email <- decode.optional_field(
      "email",
      None,
      decode.optional(decode.string),
    )
    use verified <- decode.optional_field(
      "email_verified",
      None,
      decode.optional(decode.bool),
    )
    decode.success(testing.EmailClaims(email, verified))
  }
  hellhound.decode_userinfo(info, decoder)
  |> should.equal(Ok(testing.EmailClaims(email, verified)))
  // Check absence, not merely a decoder treating JSON null as None.
  let assert Ok(fields) =
    hellhound.decode_userinfo(info, decode.dict(decode.string, decode.dynamic))
  dict.has_key(fields, "email") |> should.equal(email != None)
  dict.has_key(fields, "email_verified") |> should.equal(verified != None)
  hellhound.userinfo_subject(info)
  |> should.equal(hellhound.subject(hellhound.session_identity(session)))
}

fn login(
  provider: testing.Provider,
  client: hellhound.Client,
  subject: String,
) -> hellhound.Session {
  let assert Ok(redirect) =
    hellhound.begin_login(client, request.new(), hellhound.default_login())
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
