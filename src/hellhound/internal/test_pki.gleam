//// Disposable test PKI for `hellhound/testing`: a P-256 root and a leaf for
//// `localhost` and `127.0.0.1` it signed, from OTP's own
//// `public_key:pkix_test_data/1`. OTP refuses a self-signed peer even when
//// it is the configured anchor, so the leaf must be CA-issued. Nothing is
//// written to disk.
////
//// `anchored` instead keeps a root constrained to loopback names in a
//// caller-chosen directory, reuses it on later starts and signs a fresh leaf
//// per start (`hellhound_test_anchor_ffi.erl`).

import gleam/dict
import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode
import gleam/erlang/atom
import gleam/erlang/charlist
import gleam/list
import gleam/result

pub type Pki {
  Pki(
    /// PEM text of the root: the trust anchor.
    ca_pem: String,
    ca_der: BitArray,
    /// The leaf certificate (DER) and its key term for `ssl:listen`.
    certificate: BitArray,
    key: Dynamic,
  )
}

/// Why a kept root cannot be used. Never answered by minting a new root.
pub type AnchorError {
  AnchorUnreadable(path: String)
  AnchorCorrupt(path: String)
  AnchorIncomplete(missing: String)
  AnchorMismatch
  AnchorExpired
  AnchorKeyExposed(path: String)
  AnchorWriteFailed(path: String)
}

/// The root kept in `directory`, created there on first use, and a leaf for
/// `localhost` and `127.0.0.1` it signs now.
pub fn anchored(directory: String) -> Result(Pki, AnchorError) {
  use #(root, root_key) <- result.try(load_or_create(directory))
  let #(certificate, key) = mint_leaf(root, root_key)
  let a = atom.create
  let ca_pem = pem_encode([#(a("Certificate"), root, a("not_encrypted"))])
  Ok(Pki(ca_pem:, ca_der: root, certificate:, key:))
}

/// Mint a new root in `directory`, replacing the one kept there.
@external(erlang, "hellhound_test_anchor_ffi", "replace")
pub fn replace(directory: String) -> Result(Nil, AnchorError)

/// Path of the root certificate a developer trusts.
@external(erlang, "hellhound_test_anchor_ffi", "certificate_file")
pub fn certificate_file(directory: String) -> String

@external(erlang, "hellhound_test_anchor_ffi", "load_or_create")
fn load_or_create(
  directory: String,
) -> Result(#(BitArray, Dynamic), AnchorError)

@external(erlang, "hellhound_test_anchor_ffi", "leaf")
fn mint_leaf(root: BitArray, root_key: Dynamic) -> #(BitArray, Dynamic)

pub fn generate() -> Result(Pki, Nil) {
  let a = atom.create
  let key = to_dynamic(#(a("key"), #(a("namedCurve"), a("secp256r1"))))
  let digest = to_dynamic(#(a("digest"), a("sha256")))
  let san = #(
    a("Extension"),
    // id-ce-subjectAltName
    #(2, 5, 29, 17),
    False,
    [
      to_dynamic(#(a("dNSName"), charlist.from_string("localhost"))),
      to_dynamic(#(a("iPAddress"), <<127, 0, 0, 1>>)),
    ],
  )
  let conf =
    dict.from_list([
      #(a("root"), to_dynamic([key, digest])),
      #(
        a("peer"),
        to_dynamic([key, digest, to_dynamic(#(a("extensions"), [san]))]),
      ),
    ])
  use options <- result.try(
    decode.run(pkix_test_data(conf), decode.list(decode.dynamic))
    |> result.replace_error(Nil),
  )
  let find = fn(name: String) {
    list.find_map(options, fn(option) {
      let tagged = {
        use tag <- decode.field(0, atom.decoder())
        use value <- decode.field(1, decode.dynamic)
        case atom.to_string(tag) == name {
          True -> decode.success(value)
          False -> decode.failure(value, name)
        }
      }
      decode.run(option, tagged) |> result.replace_error(Nil)
    })
  }
  use certificate <- result.try(
    find("cert")
    |> result.try(fn(v) {
      decode.run(v, decode.bit_array) |> result.replace_error(Nil)
    }),
  )
  use key <- result.try(find("key"))
  use ca_der <- result.try(
    find("cacerts")
    |> result.try(fn(v) {
      decode.run(v, decode.list(decode.bit_array)) |> result.replace_error(Nil)
    })
    |> result.try(list.first),
  )
  let pem = pem_encode([#(a("Certificate"), ca_der, a("not_encrypted"))])
  Ok(Pki(ca_pem: pem, ca_der:, certificate:, key:))
}

@external(erlang, "public_key", "pkix_test_data")
fn pkix_test_data(conf: dict.Dict(atom.Atom, Dynamic)) -> Dynamic

@external(erlang, "public_key", "pem_encode")
fn pem_encode(entries: List(#(atom.Atom, BitArray, atom.Atom))) -> String

@external(erlang, "gleam_stdlib", "identity")
fn to_dynamic(value: a) -> Dynamic
