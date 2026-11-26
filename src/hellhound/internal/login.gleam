//// A pending login sealed into a cookie that the browser which started it
//// holds until the callback.
////
//// The server keeps no record of a pending login. The cookie name carries a
//// digest of the login's `state`, so parallel logins in one browser keep
//// separate cookies. The sealing additional data binds the record kind and
//// the `state`, so a cookie renamed to another login's name does not open.
//// The sealed material names the issuer and client id that started the
//// login; the callback compares them with its own client.
////
//// Nothing here enforces single use. The provider accepts an authorization
//// code once, and only the browser holding this cookie has the PKCE
//// verifier that the code exchange needs (docs/adr/0026).

import gleam/bit_array
import gleam/dynamic/decode
import gleam/json
import gleam/option.{type Option}
import gleam/result
import gleam/string
import hellhound/internal/sealed.{type Keys}
import hellhound/internal/secure

const kind = "hellhound.login.v2"

const cookie_prefix = "__Host-hellhound_login_"

/// Immutable material for one login. Secret-bearing; it leaves Hellhound
/// only sealed.
pub type Material {
  Material(
    state: String,
    nonce: String,
    verifier: String,
    redirect_uri: String,
    /// The scopes the authorization request asked for. A token response
    /// that omits `scope` grants exactly these (RFC 6749 §5.1).
    scopes: List(String),
    max_age: Option(Int),
    issuer: String,
    client_id: String,
    expires_at: Int,
  )
}

/// The cookie name for the login with this `state`: a fixed prefix and 64
/// bits of its digest.
pub fn cookie_name(state: String) -> String {
  cookie_prefix <> string.slice(secure.sha256_hex(state), 0, 16)
}

/// The sealed material as a cookie value (base64url, no padding).
pub fn seal(keys: Keys, material: Material) -> String {
  let body =
    json.object([
      #("state", json.string(material.state)),
      #("nonce", json.string(material.nonce)),
      #("verifier", json.string(material.verifier)),
      #("redirect_uri", json.string(material.redirect_uri)),
      #("scopes", json.array(material.scopes, json.string)),
      #("max_age", json.nullable(material.max_age, json.int)),
      #("issuer", json.string(material.issuer)),
      #("client_id", json.string(material.client_id)),
      #("expires_at", json.int(material.expires_at)),
    ])
  sealed.seal(
    keys,
    kind:,
    key: material.state,
    version: 0,
    plaintext: bit_array.from_string(json.to_string(body)),
  )
  |> bit_array.base64_url_encode(False)
}

/// Open the cookie value of the login with this `state`. Fails for a value
/// that was not sealed by this key ring for this `state`.
pub fn open(keys: Keys, state: String, value: String) -> Result(Material, Nil) {
  use bits <- result.try(bit_array.base64_url_decode(value))
  use plain <- result.try(sealed.open(
    keys,
    kind:,
    key: state,
    version: 0,
    sealed: bits,
  ))
  use text <- result.try(bit_array.to_string(plain))
  json.parse(text, decoder()) |> result.replace_error(Nil)
}

fn decoder() -> decode.Decoder(Material) {
  use state <- decode.field("state", decode.string)
  use nonce <- decode.field("nonce", decode.string)
  use verifier <- decode.field("verifier", decode.string)
  use redirect_uri <- decode.field("redirect_uri", decode.string)
  use scopes <- decode.field("scopes", decode.list(decode.string))
  use max_age <- decode.field("max_age", decode.optional(decode.int))
  use issuer <- decode.field("issuer", decode.string)
  use client_id <- decode.field("client_id", decode.string)
  use expires_at <- decode.field("expires_at", decode.int)
  decode.success(Material(
    state:,
    nonce:,
    verifier:,
    redirect_uri:,
    scopes:,
    max_age:,
    issuer:,
    client_id:,
    expires_at:,
  ))
}
