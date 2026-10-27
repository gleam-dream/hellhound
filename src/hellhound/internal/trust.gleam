//// Shared TLS trust-anchor admission; never accepts private-key PEM blocks.

import exception
import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode
import gleam/erlang/atom
import gleam/list
import gleam/result

/// DER certificates from PEM text. Every block must be an X.509
/// certificate that decodes; any other block (a private key, a corrupt
/// certificate) rejects the whole input, as does an input with none.
pub fn pem_certificates(pem: String) -> Result(List(BitArray), Nil) {
  let entry = {
    use kind <- decode.field(0, atom.decoder())
    use der <- decode.field(1, decode.bit_array)
    decode.success(#(atom.to_string(kind), der))
  }
  use entries <- result.try(
    exception.rescue(fn() { pem_decode(<<pem:utf8>>) })
    |> result.replace_error(Nil),
  )
  use entries <- result.try(
    decode.run(entries, decode.list(entry)) |> result.replace_error(Nil),
  )
  use ders <- result.try(
    list.try_map(entries, fn(entry) {
      case entry {
        #("Certificate", der) ->
          case
            exception.rescue(fn() { pkix_decode_cert(der, atom.create("otp")) })
          {
            Ok(_) -> Ok(der)
            Error(_) -> Error(Nil)
          }
        _ -> Error(Nil)
      }
    }),
  )
  case ders {
    [] -> Error(Nil)
    _ -> Ok(ders)
  }
}

@external(erlang, "public_key", "pem_decode")
fn pem_decode(pem: BitArray) -> Dynamic

@external(erlang, "public_key", "pkix_decode_cert")
fn pkix_decode_cert(der: BitArray, form: atom.Atom) -> Dynamic
