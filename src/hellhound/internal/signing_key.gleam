//// Shared private-key admission for OAuth client authentication and assertions.

import exception
import gleam/dict
import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode
import gleam/json
import gleam/list
import gleam/option.{type Option}
import gleam/result
import gose
import gose/jose/jwk
import gose/jose/jws
import hellhound/internal/key_policy
import hellhound/internal/redacted.{type Redacted}
import kryptos/ec
import kryptos/eddsa

pub opaque type Key {
  Key(
    material: Redacted(gose.Key(String)),
    credential: Redacted(String),
    key_id: Option(String),
    algorithms: List(String),
  )
}

pub type KeyError {
  NotAPrivateSigningJwk
  NotAPrivateSigningPem
  WeakRsaKey
  NotForSigning
}

pub fn from_jwk(json: String) -> Result(Key, KeyError) {
  case jwk.from_json(json) {
    Ok(key) ->
      case gose.is_private_key(key), jwk_fields(json) {
        False, _ -> Error(NotAPrivateSigningJwk)
        True, fields -> {
          // gose's optional metadata decoders treat explicit null as absent.
          // A present JWK algorithm or identifier must still be a string.
          use _ <- result.try(
            case list.all(["alg", "kid"], valid_optional_string(fields, _)) {
              True -> Ok(Nil)
              False -> Error(NotAPrivateSigningJwk)
            },
          )
          use _ <- result.try(case key_policy.strong_enough(fields) {
            True -> Ok(Nil)
            False -> Error(WeakRsaKey)
          })
          use _ <- result.try(case key_policy.for_signing(fields) {
            True -> Ok(Nil)
            False -> Error(NotForSigning)
          })
          let algorithms = case gose.key_type(key) {
            gose.RsaKeyType -> ["RS256", "PS256"]
            gose.EcKeyType ->
              case gose.ec_curve(key) {
                Ok(ec.P256) -> ["ES256"]
                Ok(ec.P384) -> ["ES384"]
                Ok(ec.P521) -> ["ES512"]
                _ -> []
              }
            gose.OkpKeyType ->
              case gose.eddsa_curve(key) {
                Ok(eddsa.Ed25519) -> ["EdDSA"]
                _ -> []
              }
            gose.OctKeyType -> []
          }
          // A JWK `alg` member restricts the key to that algorithm.
          let algorithms = case gose.alg(key) {
            Ok(alg) ->
              list.filter(algorithms, fn(a) { a == jwk.alg_to_string(alg) })
            Error(Nil) -> algorithms
          }
          Ok(Key(
            material: redacted.new(key),
            credential: redacted.new(json),
            key_id: option.from_result(gose.kid(key)),
            algorithms:,
          ))
        }
      }
    Error(_) -> Error(NotAPrivateSigningJwk)
  }
}

fn jwk_fields(text: String) -> dict.Dict(String, Dynamic) {
  json.parse(text, decode.dict(decode.string, decode.dynamic))
  |> result.unwrap(dict.new())
}

fn valid_optional_string(
  fields: dict.Dict(String, Dynamic),
  name: String,
) -> Bool {
  case dict.get(fields, name) {
    Error(Nil) -> True
    Ok(value) -> decode.run(value, decode.string) |> result.is_ok
  }
}

pub fn from_pem(pem: String) -> Result(Key, KeyError) {
  // A parsed ASN.1 container can still contain invalid RSA integers whose
  // conversion raises. Normalize the entire foreign operation, not only parse.
  exception.rescue(fn() {
    use parsed <- result.try(
      gose.from_pem(pem) |> result.replace_error(NotAPrivateSigningPem),
    )
    from_jwk(jwk.to_json(parsed) |> json.to_string)
    |> result.map_error(fn(error) {
      case error {
        NotAPrivateSigningJwk -> NotAPrivateSigningPem
        other -> other
      }
    })
  })
  |> result.replace_error(NotAPrivateSigningPem)
  |> result.try(fn(value) { value })
}

pub fn credential(key: Key) -> Redacted(String) {
  key.credential
}

pub fn key_id(key: Key) -> Option(String) {
  key.key_id
}

pub fn algorithms(key: Key) -> List(String) {
  key.algorithms
}

pub fn sign(
  key: Key,
  algorithm: String,
  payload: BitArray,
  key_id: Option(String),
  token_type: Option(String),
) -> Result(String, Nil) {
  use alg <- result.try(case jwk.alg_from_string(algorithm) {
    Ok(gose.SigningAlg(alg)) -> Ok(alg)
    _ -> Error(Nil)
  })
  let unsigned = jws.new(alg)
  let unsigned = case key_id {
    option.Some(id) -> jws.with_kid(unsigned, id)
    option.None -> unsigned
  }
  let unsigned = case token_type {
    option.Some(kind) -> jws.with_typ(unsigned, kind)
    option.None -> unsigned
  }
  jws.sign(unsigned, redacted.reveal(key.material), payload)
  |> result.try(jws.serialize_compact)
  |> result.replace_error(Nil)
}
