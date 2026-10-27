//// Public signing contract; erlang-jose independently verifies the output.

import gleam/bit_array
import gleam/dynamic/decode
import gleam/json
import gleam/option.{None, Some}
import gleam/string
import gleam/time/timestamp
import hellhound/assertion
import hellhound/config
import hellhound/internal/signing_key
import hellhound_test_support as support

@external(erlang, "hellhound_assertion_oracle", "key")
pub fn key(kind: String) -> String

@external(erlang, "hellhound_assertion_oracle", "verify")
pub fn verify(
  token: String,
  key: String,
  algorithm: String,
) -> Result(String, Nil)

@external(erlang, "hellhound_assertion_oracle", "pem")
fn pem(key: String, format: String) -> String

@external(erlang, "hellhound_assertion_oracle", "malformed_rsa_pem")
fn malformed_rsa_pem(key: String, field: Int) -> String

@external(erlang, "hellhound_assertion_oracle", "rfc_vector")
fn rfc_vector() -> #(String, String, String)

@external(erlang, "hellhound_assertion_oracle", "emit")
fn emit(token: String, key: String) -> Nil

pub fn rs256_preserves_exact_claims_without_profile_defaults_test() {
  let raw_key = key("RSA")
  let assert Ok(key) = config.signing_key_from_jwk(raw_key)
  let claims =
    assertion.claims()
    |> assertion.with_issuer("application-client")
    |> assertion.with_issued_at(timestamp.from_unix_seconds(100))
    |> assertion.with_expiration(timestamp.from_unix_seconds(700))
    |> assertion.with_claim(
      "tenant",
      json.object([
        #(
          "roles",
          json.array([json.string("reader"), json.string("writer")], fn(x) { x }),
        ),
        #("enabled", json.bool(False)),
      ]),
    )
  let assert Ok(signed) = assertion.sign(claims, key, config.Rs256)
  let assert Ok(verified) =
    verify(assertion.to_string(signed), raw_key, "RS256")
  let assert Ok(fields) =
    json.parse(verified, decode.dict(decode.string, decode.dynamic))
  assert dict_keys(fields) == ["exp", "iat", "iss", "tenant"]
  let assert Ok(False) =
    json.parse(verified, decode.at(["tenant", "enabled"], decode.bool))
  assert !string.contains(
    string.inspect(#(claims, signed, key)),
    "application-client",
  )
  emit(assertion.to_string(signed), raw_key)
}

import gleam/dict
import gleam/list

fn dict_keys(fields: dict.Dict(String, decode.Dynamic)) -> List(String) {
  dict.keys(fields) |> list.sort(string.compare)
}

pub fn rfc7520_rs256_known_answer_test() {
  let #(raw_key, payload, expected) = rfc_vector()
  let assert Ok(key) = signing_key.from_jwk(raw_key)
  assert signing_key.sign(
      key,
      "RS256",
      bit_array.from_string(payload),
      signing_key.key_id(key),
      None,
    )
    == Ok(expected)
}

pub fn standard_claim_setters_replace_and_preserve_types_test() {
  let raw = key("EC")
  let assert Ok(key) = config.signing_key_from_jwk(raw)
  let claims =
    assertion.claims()
    |> assertion.with_issuer("old")
    |> assertion.with_issuer("new")
    |> assertion.with_subject("subject")
    |> assertion.with_audiences(["first", "second"])
    |> assertion.with_jwt_id("id")
    |> assertion.with_not_before(timestamp.from_unix_seconds(-10))
  let assert Ok(signed) = assertion.sign(claims, key, config.Es256)
  let assert Ok(payload) = verify(assertion.to_string(signed), raw, "ES256")
  assert json.parse(payload, decode.at(["iss"], decode.string)) == Ok("new")
  assert json.parse(payload, decode.at(["nbf"], decode.int)) == Ok(-10)
  assert json.parse(payload, decode.at(["aud"], decode.list(decode.string)))
    == Ok(["first", "second"])
}

pub fn claims_remain_optional_and_audience_string_shape_is_preserved_test() {
  let raw = key("EC")
  let assert Ok(key) = config.signing_key_from_jwk(raw)
  let assert Ok(empty) = assertion.sign(assertion.claims(), key, config.Es256)
  assert verify(assertion.to_string(empty), raw, "ES256") == Ok("{}")
  let assert Ok(signed) =
    assertion.claims()
    |> assertion.with_audience("one")
    |> assertion.sign(key, config.Es256)
  let assert Ok(payload) = verify(assertion.to_string(signed), raw, "ES256")
  assert json.parse(payload, decode.at(["aud"], decode.string)) == Ok("one")
}

pub fn claim_collisions_are_sticky_and_sanitized_test() {
  let assert Ok(key) = config.signing_key_from_jwk(key("EC"))
  let reserved =
    assertion.claims()
    |> assertion.with_claim("iss", json.string("SECRET"))
    |> assertion.with_issuer("valid")
  assert assertion.sign(reserved, key, config.Es256)
    == Error(assertion.ReservedClaim)
  let duplicate =
    assertion.claims()
    |> assertion.with_claim("SECRET", json.int(1))
    |> assertion.with_claim("SECRET", json.int(2))
    |> assertion.with_subject("subject")
  assert assertion.sign(duplicate, key, config.Es256)
    == Error(assertion.DuplicateClaim)
  let audience =
    assertion.claims()
    |> assertion.with_audiences([])
    |> assertion.with_audience("later")
  assert assertion.sign(audience, key, config.Es256)
    == Error(assertion.InvalidAudience)
  assert !string.contains(string.inspect(#(reserved, duplicate)), "SECRET")
}

pub fn explicit_algorithm_and_key_metadata_are_enforced_test() {
  let raw = key("RSA")
  let assert Ok(rsa) = config.signing_key_from_jwk(raw)
  assert assertion.sign(assertion.claims(), rsa, config.Es256)
    == Error(assertion.UnsupportedAlgorithm)
  let assert Ok(restricted) =
    config.signing_key_from_jwk(support.jwk_with(raw, "alg", "\"RS256\""))
  assert assertion.sign(assertion.claims(), restricted, config.Ps256)
    == Error(assertion.UnsupportedAlgorithm)
  assert config.signing_key_from_jwk(support.jwk_with(raw, "use", "\"enc\""))
    == Error(config.NotForSigning)
  assert config.signing_key_from_jwk(support.jwk_with(
      raw,
      "key_ops",
      "[\"verify\"]",
    ))
    == Error(config.NotForSigning)
  assert config.signing_key_from_jwk(key("weak")) == Error(config.WeakRsaKey)
}

pub fn malformed_present_key_metadata_is_not_an_omitted_restriction_test() {
  let raw = key("RSA")
  list.each(["alg", "kid"], fn(name) {
    list.each(["null", "true", "0", "[]", "{}"], fn(value) {
      assert config.signing_key_from_jwk(support.jwk_with(raw, name, value))
        == Error(config.NotAPrivateSigningJwk)
    })
  })
}

pub fn malformed_private_pem_integers_return_a_sanitized_refusal_test() {
  let raw = key("RSA")
  // DER INTEGER values are signed. Parsing the container is not proof that
  // each RSA integer is admissible for conversion and signing.
  list.each([3, 4, 5, 6, 7, 8, 9, 10], fn(field) {
    assert config.signing_key_from_pem(malformed_rsa_pem(raw, field))
      == Error(config.NotAPrivateSigningPem)
  })
}

pub fn supported_families_verify_independently_test() {
  list.each(
    [
      #("RSA", config.Ps256, "PS256"),
      #("EC", config.Es256, "ES256"),
      #("Ed25519", config.EdDsa, "EdDSA"),
    ],
    fn(pair) {
      let #(kind, algorithm, name) = pair
      let raw = key(kind)
      let assert Ok(key) = config.signing_key_from_jwk(raw)
      let assert Ok(signed) = assertion.sign(assertion.claims(), key, algorithm)
      assert verify(assertion.to_string(signed), raw, name) == Ok("{}")
    },
  )
}

pub fn pem_formats_share_admission_and_do_not_inspect_private_material_test() {
  let raw = key("RSA")
  list.each(["pkcs1", "pkcs8"], fn(format) {
    let text = pem(raw, format)
    let assert Ok(key) = config.signing_key_from_pem(text)
    let assert Ok(signed) =
      assertion.sign(assertion.claims(), key, config.Rs256)
    assert verify(assertion.to_string(signed), raw, "RS256") == Ok("{}")
    assert !string.contains(string.inspect(key), "PRIVATE KEY")
  })
  assert config.signing_key_from_pem(pem(raw, "public"))
    == Error(config.NotAPrivateSigningPem)
  assert config.signing_key_from_pem("SENTINEL-MALFORMED")
    == Error(config.NotAPrivateSigningPem)
  assert config.signing_key_from_pem(pem(key("weak"), "pkcs8"))
    == Error(config.WeakRsaKey)
}

pub fn protected_headers_can_be_selected_or_omitted_test() {
  let raw = support.jwk_with(key("EC"), "kid", "\"key-1\"")
  let assert Ok(key) = config.signing_key_from_jwk(raw)
  let assert Ok(default) = assertion.sign(assertion.claims(), key, config.Es256)
  assert header(default, "kid") == Ok("key-1")
  let assert Ok(plain) =
    assertion.sign_with_options(
      assertion.claims(),
      key,
      assertion.Options(config.Es256, None, None),
    )
  assert header(plain, "typ") == Error(Nil)
  assert header(plain, "kid") == Error(Nil)
  let assert Ok(custom) =
    assertion.sign_with_options(
      assertion.claims(),
      key,
      assertion.Options(config.Es256, Some("other"), Some("custom+jwt")),
    )
  assert header(custom, "kid") == Ok("other")
  assert header(custom, "typ") == Ok("custom+jwt")
  assert assertion.sign_with_options(
      assertion.claims(),
      key,
      assertion.Options(config.Es256, Some("bad\nheader"), None),
    )
    == Error(assertion.InvalidHeader)
}

fn header(assertion: assertion.Assertion, name: String) -> Result(String, Nil) {
  let assert Ok(#(encoded, _)) =
    string.split_once(assertion.to_string(assertion), ".")
  let assert Ok(bytes) = bit_array.base64_url_decode(encoded)
  let assert Ok(text) = bit_array.to_string(bytes)
  case json.parse(text, decode.at([name], decode.string)) {
    Ok(value) -> Ok(value)
    Error(_) -> Error(Nil)
  }
}

pub fn oversized_assertion_is_refused_test() {
  let assert Ok(key) = config.signing_key_from_jwk(key("EC"))
  let claims =
    assertion.claims()
    |> assertion.with_claim("large", json.string(string.repeat("x", 65_537)))
  assert assertion.sign(claims, key, config.Es256)
    == Error(assertion.PayloadTooLarge)
  let claims =
    assertion.claims()
    |> assertion.with_claim("large", json.string(string.repeat("x", 50_000)))
  assert assertion.sign(claims, key, config.Es256)
    == Error(assertion.PayloadTooLarge)
}
