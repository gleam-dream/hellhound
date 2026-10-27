//// Standalone signed JWT assertions. No discovery, network or implicit clock.
//// Registered claims are optional here; the caller's protocol profile decides
//// which are required. Custom JSON claims cannot replace registered claims.
//// Material is redacted during ordinary inspection; `to_string` exposes the
//// compact credential deliberately. This module does not issue checked identity.

import exception
import gleam/bit_array
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import gleam/time/timestamp.{type Timestamp}
import hellhound/config.{type SigningAlgorithm, type SigningKey}
import hellhound/internal/redacted.{type Redacted}
import hellhound/internal/signing_key

pub opaque type Claims {
  Claims(
    material: Redacted(List(#(String, json.Json))),
    error: Option(SignError),
  )
}

pub opaque type Assertion {
  Assertion(material: Redacted(String))
}

pub type SignError {
  ReservedClaim
  DuplicateClaim
  InvalidAudience
  InvalidHeader
  UnsupportedAlgorithm
  PayloadTooLarge
  SigningFailed
}

/// Protected header options. None omits kid/typ, including a JWK's own kid.
/// `alg` is always derived from the explicit compatible algorithm.
pub type Options {
  Options(
    algorithm: SigningAlgorithm,
    key_id: Option(String),
    token_type: Option(String),
  )
}

pub fn options(algorithm: SigningAlgorithm) -> Options {
  Options(algorithm, None, Some("JWT"))
}

pub fn claims() -> Claims {
  Claims(redacted.new([]), None)
}

pub fn with_issuer(claims: Claims, issuer: String) -> Claims {
  put(claims, "iss", json.string(issuer))
}

pub fn with_subject(claims: Claims, subject: String) -> Claims {
  put(claims, "sub", json.string(subject))
}

pub fn with_audience(claims: Claims, audience: String) -> Claims {
  put(claims, "aud", json.string(audience))
}

pub fn with_audiences(claims: Claims, audiences: List(String)) -> Claims {
  case audiences {
    [] -> refuse(claims, InvalidAudience)
    _ -> put(claims, "aud", json.array(audiences, json.string))
  }
}

/// NumericDates use whole Unix seconds. No system clock is read.
pub fn with_expiration(claims: Claims, expires_at: Timestamp) -> Claims {
  put(
    claims,
    "exp",
    json.int(timestamp.to_unix_seconds_and_nanoseconds(expires_at).0),
  )
}

pub fn with_issued_at(claims: Claims, issued_at: Timestamp) -> Claims {
  put(
    claims,
    "iat",
    json.int(timestamp.to_unix_seconds_and_nanoseconds(issued_at).0),
  )
}

pub fn with_not_before(claims: Claims, not_before: Timestamp) -> Claims {
  put(
    claims,
    "nbf",
    json.int(timestamp.to_unix_seconds_and_nanoseconds(not_before).0),
  )
}

pub fn with_jwt_id(claims: Claims, id: String) -> Claims {
  put(claims, "jti", json.string(id))
}

/// Add a custom JSON claim. Registered names and duplicate custom names make
/// this Claims value invalid; `sign` returns the first construction error.
pub fn with_claim(claims: Claims, name: String, value: json.Json) -> Claims {
  case list.contains(["iss", "sub", "aud", "exp", "nbf", "iat", "jti"], name) {
    True -> refuse(claims, ReservedClaim)
    False ->
      case
        list.any(redacted.reveal(claims.material), fn(pair) { pair.0 == name })
      {
        True -> refuse(claims, DuplicateClaim)
        False -> put(claims, name, value)
      }
  }
}

fn put(claims: Claims, name: String, value: json.Json) -> Claims {
  let material =
    redacted.reveal(claims.material)
    |> list.filter(fn(pair) { pair.0 != name })
    |> list.append([#(name, value)])
  Claims(..claims, material: redacted.new(material))
}

fn refuse(claims: Claims, error: SignError) -> Claims {
  case claims.error {
    Some(_) -> claims
    None -> Claims(..claims, error: Some(error))
  }
}

/// Sign with typ JWT and the key's identifier, when present.
pub fn sign(
  claims: Claims,
  key: SigningKey,
  algorithm: SigningAlgorithm,
) -> Result(Assertion, SignError) {
  sign_with_options(
    claims,
    key,
    Options(..options(algorithm), key_id: signing_key.key_id(key)),
  )
}

pub fn sign_with_options(
  claims: Claims,
  key: SigningKey,
  options: Options,
) -> Result(Assertion, SignError) {
  use _ <- result.try(case claims.error {
    Some(error) -> Error(error)
    None -> Ok(Nil)
  })
  let algorithm = algorithm_name(options.algorithm)
  use _ <- result.try(
    case list.contains(signing_key.algorithms(key), algorithm) {
      True -> Ok(Nil)
      False -> Error(UnsupportedAlgorithm)
    },
  )
  use _ <- result.try(
    case
      list.all(
        option.values([options.key_id, options.token_type]),
        valid_header,
      )
    {
      True -> Ok(Nil)
      False -> Error(InvalidHeader)
    },
  )
  // Serialization and foreign signing failures cannot retain input material in
  // errors. In particular a hostile/custom JSON encoder cannot leak a term.
  use signed <- result.try(
    exception.rescue(fn() { serialize(claims, key, options, algorithm) })
    |> result.replace_error(SigningFailed),
  )
  signed |> result.map(fn(value) { Assertion(redacted.new(value)) })
}

fn serialize(
  claims: Claims,
  key: SigningKey,
  options: Options,
  algorithm: String,
) -> Result(String, SignError) {
  let payload =
    redacted.reveal(claims.material) |> json.object |> json.to_string
  use _ <- result.try(within_limit(payload))
  use compact <- result.try(
    signing_key.sign(
      key,
      algorithm,
      bit_array.from_string(payload),
      options.key_id,
      options.token_type,
    )
    |> result.replace_error(SigningFailed),
  )
  use _ <- result.map(within_limit(compact))
  compact
}

fn within_limit(value: String) -> Result(Nil, SignError) {
  case string.byte_size(value) <= 65_536 {
    True -> Ok(Nil)
    False -> Error(PayloadTooLarge)
  }
}

fn valid_header(value: String) -> Bool {
  string.byte_size(value) <= 1024
  && !string.contains(value, "\r")
  && !string.contains(value, "\n")
  && !string.contains(value, "\u{0}")
}

fn algorithm_name(algorithm: SigningAlgorithm) -> String {
  case algorithm {
    config.Rs256 -> "RS256"
    config.Rs384 -> "RS384"
    config.Rs512 -> "RS512"
    config.Ps256 -> "PS256"
    config.Ps384 -> "PS384"
    config.Ps512 -> "PS512"
    config.Es256 -> "ES256"
    config.Es384 -> "ES384"
    config.Es512 -> "ES512"
    config.EdDsa -> "EdDSA"
  }
}

/// Expose the compact credential for deliberate transmission. Do not log it.
pub fn to_string(assertion: Assertion) -> String {
  redacted.reveal(assertion.material)
}
