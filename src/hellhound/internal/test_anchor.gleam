//// The reusable local trust anchor behind `testing.with_trust_anchor`: a P-256
//// root constrained to loopback names, kept in a caller-chosen directory, and
//// a leaf it signs per start. Locating, locking, creating or loading,
//// replacing, the load-time profile check and every refusal are decided here.
//// Nothing here touches a system trust store.
////
//// Libraries: kryptos generates, stores (PKCS#8 PEM) and imports the keys
//// and derives the public point from the private scalar; simplifile does the
//// file work, and its `create_directory` (`mkdir`, exclusive across OS
//// processes) is the lock; gleam_crypto gives the serials and key identifier.
////
//// Remaining FFI, each a direct call on OTP `public_key`, no Erlang source:
////
//// - `pkix_sign` mints the root and the leaf. kryptos (1.5.0, and 1.6.0)
////   builds only self-signed certificates and has no name-constraints or
////   custom extension, so it can mint neither. The certificates are OTP
////   records built from Gleam values; OTP encodes them.
//// - `pkix_decode_cert` and `pkix_verify` inspect and verify a kept root.
////   kryptos refuses to parse any certificate with a critical extension it
////   does not know (`UnrecognizedCriticalExtension`), and RFC 5280 requires
////   name constraints to be critical.
//// - `pem_decode` and `pem_encode` read and write the certificate PEM.
////   kryptos exposes certificate PEM only through `certificate.from_pem` and
////   `to_pem`, which need a certificate it can parse or build.
////
//// `gleam_stdlib:identity` (also used by `test_pki`) only views a Gleam
//// value as `Dynamic` to pass OTP its records; it is not a boundary.
////
//// Two kryptos additions would remove the `public_key` calls: a builder that signs with an
//// issuer's key and certificate (not only self-signed), and name constraints
//// on the builder and parser (recognized as a critical extension, with a
//// typed or raw value). The profile check could then run on kryptos's parsed
//// certificate and raw extension bytes.

import exception
import gleam/bit_array
import gleam/bool
import gleam/crypto
import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode
import gleam/erlang/atom.{type Atom}
import gleam/erlang/charlist
import gleam/erlang/process
import gleam/int
import gleam/list
import gleam/order
import gleam/result
import gleam/string
import gleam/time/calendar
import gleam/time/duration
import gleam/time/timestamp.{type Timestamp}
import hellhound/internal/secure
import kryptos/ec
import simplifile

/// Why a kept root cannot be used. Never answered by minting a new root.
pub type AnchorError {
  AnchorUnreadable(path: String)
  AnchorCorrupt(path: String)
  AnchorIncomplete(missing: String)
  AnchorNotRegularFile(path: String)
  AnchorMismatch
  AnchorExpired
  AnchorKeyExposed(path: String)
  AnchorWriteFailed(path: String)
  AnchorLocked(path: String)
}

/// A usable root: its certificate (DER) and private key.
pub opaque type Root {
  Root(der: BitArray, key: ec.PrivateKey)
}

pub fn root_der(root: Root) -> BitArray {
  root.der
}

const certificate_name = "hellhound-root.pem"

const key_name = "hellhound-root-key.pem"

const lock_name = "hellhound-root.lock"

/// The root's lifetime, and its leaves' longest lifetime.
const root_seconds = 7_776_000

const leaf_seconds = 2_592_000

/// Certificates start an hour early, for clock skew.
const backdate_seconds = 3600

/// How long a start waits for another start's lock.
const lock_wait_ms = 5000

/// Path of the root certificate a developer trusts.
pub fn certificate_file(directory: String) -> String {
  join(directory, certificate_name)
}

fn key_file(directory: String) -> String {
  join(directory, key_name)
}

fn base_name(path: String) -> String {
  case list.last(string.split(path, "/")) {
    Ok(name) -> name
    Error(Nil) -> path
  }
}

fn join(directory: String, name: String) -> String {
  case string.ends_with(directory, "/") {
    True -> directory <> name
    False -> directory <> "/" <> name
  }
}

// ===========================================================================
// Create, load, replace

/// The root kept in `directory`, created there on first use. Under the
/// directory's lock, so concurrent starts in any OS process see one complete
/// pair: exactly one creates it, every other one loads it.
pub fn load_or_create(directory: String) -> Result(Root, AnchorError) {
  use lock <- with_lock(directory)
  let certificate = certificate_file(directory)
  let key = key_file(directory)
  use certificate_present <- result.try(entry(certificate))
  use key_present <- result.try(entry(key))
  case certificate_present, key_present {
    False, False -> create(directory, lock)
    True, True -> load(certificate, key)
    True, False -> Error(AnchorIncomplete(key))
    False, True -> Error(AnchorIncomplete(certificate))
  }
}

/// Mint a new root in `directory`, replacing the one kept there, under the
/// same lock as `load_or_create`.
pub fn replace(directory: String) -> Result(Nil, AnchorError) {
  replace_observing(directory, fn(_) { Nil })
}

/// `replace`, calling `observe` with each file that will hold anchor bytes
/// right after it is created, before its mode is set or its content written.
/// A test seam: it lets a test check where such a file can be reached from.
pub fn replace_observing(
  directory: String,
  observe: fn(String) -> Nil,
) -> Result(Nil, AnchorError) {
  use lock <- with_lock(directory)
  create_observing(directory, lock, observe) |> result.replace(Nil)
}

fn create(directory: String, lock: String) -> Result(Root, AnchorError) {
  create_observing(directory, lock, fn(_) { Nil })
}

/// Each file is staged in the lock directory, which only this start can
/// enter, and renamed into place once its mode and content are final.
fn create_observing(
  directory: String,
  lock: String,
  observe: fn(String) -> Nil,
) -> Result(Root, AnchorError) {
  let #(key, public) = ec.generate_key_pair(ec.P256)
  let der = mint_root(key, ec.public_key_to_raw_point(public))
  let certificate_pem =
    pem_encode([#(certificate_atom(), der, not_encrypted())])
  use key_pem <- result.try(
    ec.to_pem(key)
    |> result.replace_error(AnchorWriteFailed(key_file(directory))),
  )
  // The key goes first: a directory with a key and no certificate is
  // reported as incomplete, never regenerated.
  use Nil <- result.try(write_file(
    lock,
    key_file(directory),
    key_pem,
    0o600,
    observe,
  ))
  use Nil <- result.try(write_file(
    lock,
    certificate_file(directory),
    certificate_pem,
    0o644,
    observe,
  ))
  Ok(Root(der:, key:))
}

/// Whether an anchor path holds a regular file, without following a link:
/// absent is `Ok(False)`; a symbolic link, live or dangling, or any other kind
/// of entry is refused, so a link can neither stand in for the key nor read
/// as absent and be minted over.
fn entry(path: String) -> Result(Bool, AnchorError) {
  case simplifile.link_info(path) {
    Error(simplifile.Enoent) -> Ok(False)
    Error(_) -> Error(AnchorUnreadable(path))
    Ok(info) ->
      case simplifile.file_info_type(info) {
        simplifile.File -> Ok(True)
        _ -> Error(AnchorNotRegularFile(path))
      }
  }
}

// ===========================================================================
// Ownership and files

/// Cross-process ownership of the directory: a lock directory made with
/// `mkdir`, which exactly one caller can create on a local macOS or Linux
/// file system. Holders keep it for milliseconds; a start that cannot take it
/// within `lock_wait_ms` reports `AnchorLocked` rather than breaking it, since
/// a lock left by a killed start cannot be told apart from a slow one without
/// a race of its own.
fn with_lock(
  directory: String,
  run: fn(String) -> Result(a, AnchorError),
) -> Result(a, AnchorError) {
  use Nil <- result.try(ensure_directory(directory))
  let lock = join(directory, lock_name)
  // Monotonic, so a wall-clock step cannot stretch or cut the wait; the wall
  // clock is used only for certificate validity.
  let deadline = secure.monotonic_ms() + lock_wait_ms
  use Nil <- result.try(acquire(lock, deadline))
  exception.defer(fn() { simplifile.delete(lock) }, fn() { run(lock) })
}

fn acquire(lock: String, deadline: Int) -> Result(Nil, AnchorError) {
  case simplifile.create_directory(lock) {
    // Owner-only before anything is created in it. A user who entered it
    // while `mkdir` left it traversable can no longer look up names in it:
    // the search permission is checked on every lookup, and it was empty.
    Ok(Nil) ->
      case simplifile.set_permissions_octal(lock, 0o700) {
        Ok(Nil) -> Ok(Nil)
        Error(_) -> {
          let _ = simplifile.delete(lock)
          Error(AnchorWriteFailed(lock))
        }
      }
    Error(simplifile.Eexist) ->
      case secure.monotonic_ms() < deadline {
        True -> {
          process.sleep(10 + int.random(20))
          acquire(lock, deadline)
        }
        False -> Error(AnchorLocked(lock))
      }
    Error(_) -> Error(AnchorWriteFailed(lock))
  }
}

/// A directory this creates is owner-only; an existing one is the caller's.
/// Concurrent first starts may race to create it: a create that fails because
/// the directory now exists is success, and anything else stays an error.
fn ensure_directory(directory: String) -> Result(Nil, AnchorError) {
  let failed = Error(AnchorWriteFailed(directory))
  case simplifile.is_directory(directory) {
    Ok(True) -> Ok(Nil)
    Error(_) -> failed
    Ok(False) -> {
      let _ = simplifile.create_directory_all(parent(directory))
      case simplifile.create_directory(directory) {
        Ok(Nil) ->
          simplifile.set_permissions_octal(directory, 0o700)
          |> result.replace_error(AnchorWriteFailed(directory))
        Error(_) ->
          case simplifile.is_directory(directory) {
            Ok(True) -> Ok(Nil)
            _ -> failed
          }
      }
    }
  }
}

fn parent(path: String) -> String {
  let trimmed = case string.ends_with(path, "/") {
    True -> string.drop_end(path, 1)
    False -> path
  }
  case list.reverse(string.split(trimmed, "/")) {
    [_, ..rest] if rest != [] -> string.join(list.reverse(rest), "/")
    _ -> "."
  }
}

/// Write through a file staged in the owner-only lock directory: created
/// there, given its mode, written, then renamed over the final path. No other
/// user can reach it before the rename, and it arrives with its final mode.
fn write_file(
  lock: String,
  path: String,
  contents: String,
  mode: Int,
  observe: fn(String) -> Nil,
) -> Result(Nil, AnchorError) {
  let temporary = join(lock, base_name(path))
  let _ = simplifile.delete(temporary)
  let written = {
    use Nil <- result.try(simplifile.create_file(temporary))
    observe(temporary)
    use Nil <- result.try(simplifile.set_permissions_octal(temporary, mode))
    use Nil <- result.try(simplifile.write(temporary, contents))
    simplifile.rename(temporary, path)
  }
  case written {
    Ok(Nil) -> Ok(Nil)
    Error(_) -> {
      let _ = simplifile.delete(temporary)
      Error(AnchorWriteFailed(path))
    }
  }
}

// ===========================================================================
// Load and profile

fn load(certificate: String, key: String) -> Result(Root, AnchorError) {
  use info <- result.try(
    simplifile.file_info(key) |> result.replace_error(AnchorUnreadable(key)),
  )
  use <- bool.guard(
    int.bitwise_and(simplifile.file_info_permissions_octal(info), 0o077) != 0,
    Error(AnchorKeyExposed(key)),
  )
  use certificate_pem <- result.try(
    simplifile.read(certificate)
    |> result.replace_error(AnchorUnreadable(certificate)),
  )
  use key_pem <- result.try(
    simplifile.read(key) |> result.replace_error(AnchorUnreadable(key)),
  )
  use der <- result.try(
    decode_certificate(certificate_pem)
    |> result.replace_error(AnchorCorrupt(certificate)),
  )
  use #(private, _) <- result.try(
    ec.from_pem(key_pem) |> result.replace_error(AnchorCorrupt(key)),
  )
  use <- bool.guard(ec.curve(private) != ec.P256, Error(AnchorCorrupt(key)))
  // A root Hellhound did not mint can hold any well-formed field; inspecting
  // it must not raise out of `testing.start`.
  let profile = exception.rescue(fn() { has_root_profile(der, private) })
  use <- bool.guard(profile != Ok(True), Error(AnchorMismatch))
  use <- bool.guard(!is_current(der), Error(AnchorExpired))
  Ok(Root(der:, key: private))
}

/// The PEM holds exactly one certificate that OTP can decode.
fn decode_certificate(pem: String) -> Result(BitArray, Nil) {
  let entries =
    exception.rescue(fn() { pem_decode(pem) })
    |> result.replace_error(Nil)
  use entries <- result.try(entries)
  case entries {
    [#(kind, der, _)] ->
      case kind == certificate_atom() {
        False -> Error(Nil)
        True ->
          case exception.rescue(fn() { decode_cert(der, otp()) }) {
            Ok(_) -> Ok(der)
            Error(_) -> Error(Nil)
          }
      }
    _ -> Error(Nil)
  }
}

/// The key's private scalar derives the root's public key, and the root has
/// exactly the profile `mint_root` gives: version 3, ECDSA P-256 with
/// SHA-256 in both signature fields, self-issued, at most `root_seconds`
/// (plus the backdate), and exactly the extensions `root_extensions` lists.
/// Minting and checking share one definition of every field.
fn has_root_profile(der: BitArray, key: ec.PrivateKey) -> Bool {
  let assert Ok(#(_, derived)) = ec.from_bytes(ec.P256, ec.to_bytes(key))
  let point = ec.public_key_to_raw_point(derived)
  let stored = ec.public_key_to_raw_point(ec.public_key_from_private_key(key))
  let certificate = decode_cert(der, otp())
  let field = fn(path) {
    let assert Ok(value) =
      decode.run(certificate, decode.at(path, decode.dynamic))
    value
  }
  let assert Ok(extensions) =
    decode.run(
      certificate,
      decode.at(
        [1, 10],
        decode.one_of(decode.list(decode.dynamic), [
          decode.success([]),
        ]),
      ),
    )
  let expected = root_extensions(point)
  point == stored
  && field([1, 7]) == to_dynamic(public_key_info(point))
  && field([1, 1]) == to_dynamic(atom.create("v3"))
  && field([1, 3]) == to_dynamic(signature_algorithm())
  && field([2]) == to_dynamic(signature_algorithm())
  && field([1, 4]) == field([1, 6])
  && list.length(extensions) == list.length(expected)
  && list.all(expected, fn(extension) { list.contains(extensions, extension) })
  && lifetime_seconds(der) <= root_seconds + backdate_seconds
  && verify(der, derived)
}

fn validity(der: BitArray) -> #(Timestamp, Timestamp) {
  let certificate = decode_cert(der, otp())
  let time = fn(index) {
    let assert Ok(text) =
      decode.run(
        certificate,
        decode.at([1, 5, index, 1], decode.list(decode.int)),
      )
    let assert Ok(seconds) = parse_time(text)
    seconds
  }
  #(time(1), time(2))
}

fn lifetime_seconds(der: BitArray) -> Int {
  let #(from, to) = validity(der)
  let #(seconds, _) =
    timestamp.difference(from, to) |> duration.to_seconds_and_nanoseconds
  seconds
}

fn is_current(der: BitArray) -> Bool {
  case exception.rescue(fn() { validity(der) }) {
    Ok(#(from, to)) -> {
      let now = timestamp.system_time()
      timestamp.compare(from, now) != order.Gt
      && timestamp.compare(now, to) != order.Gt
    }
    Error(_) -> False
  }
}

/// `YYMMDDHHMMSSZ` (UTCTime) or `YYYYMMDDHHMMSSZ` (GeneralizedTime).
fn parse_time(text: List(Int)) -> Result(Timestamp, Nil) {
  use codepoints <- result.try(list.try_map(text, string.utf_codepoint))
  let text = string.from_utf_codepoints(codepoints)
  use full <- result.try(case string.length(text) {
    13 ->
      case int.parse(string.slice(text, 0, 2)) {
        Ok(year) if year >= 50 -> Ok("19" <> text)
        Ok(_) -> Ok("20" <> text)
        Error(Nil) -> Error(Nil)
      }
    15 -> Ok(text)
    _ -> Error(Nil)
  })
  let part = fn(start, length) { string.slice(full, start, length) }
  timestamp.parse_rfc3339(
    part(0, 4)
    <> "-"
    <> part(4, 2)
    <> "-"
    <> part(6, 2)
    <> "T"
    <> part(8, 2)
    <> ":"
    <> part(10, 2)
    <> ":"
    <> part(12, 2)
    <> "Z",
  )
}

// ===========================================================================
// Minting

fn mint_root(key: ec.PrivateKey, point: BitArray) -> BitArray {
  let now = timestamp.system_time()
  let name = root_name()
  sign(
    tbs(
      issuer: name,
      subject: name,
      not_before: timestamp.add(now, duration.seconds(0 - backdate_seconds)),
      not_after: timestamp.add(now, duration.seconds(root_seconds)),
      point:,
      extensions: root_extensions(point),
    ),
    key,
  )
}

/// A fresh leaf for `localhost` and `127.0.0.1`, signed by `root`: its DER
/// and the key term `ssl:listen` takes.
pub fn leaf(root: Root) -> Result(#(BitArray, Dynamic), Nil) {
  let #(key, public) = ec.generate_key_pair(ec.P256)
  use key_der <- result.try(ec.to_der(key))
  let point = ec.public_key_to_raw_point(public)
  let root_certificate = decode_cert(root.der, otp())
  use issuer <- result.try(
    decode.run(root_certificate, decode.at([1, 6], decode.dynamic))
    |> result.replace_error(Nil),
  )
  let root_point =
    ec.public_key_to_raw_point(ec.public_key_from_private_key(root.key))
  let now = timestamp.system_time()
  let #(_, root_end) = validity(root.der)
  let until = timestamp.add(now, duration.seconds(leaf_seconds))
  let until = case timestamp.compare(until, root_end) {
    order.Gt -> root_end
    _ -> until
  }
  let der =
    sign(
      tbs(
        issuer:,
        subject: to_dynamic(
          name([
            #(to_dynamic(#(2, 5, 4, 3)), bit_array.from_string("localhost")),
          ]),
        ),
        not_before: timestamp.add(now, duration.seconds(0 - backdate_seconds)),
        not_after: until,
        point:,
        extensions: leaf_extensions(root_point),
      ),
      root.key,
    )
  Ok(#(der, to_dynamic(#(atom.create("PrivateKeyInfo"), key_der))))
}

// OTP certificate records, built from Gleam values: an Erlang record is a
// tuple whose first element is the record name.

fn tbs(
  issuer issuer: Dynamic,
  subject subject: Dynamic,
  not_before not_before: Timestamp,
  not_after not_after: Timestamp,
  point point: BitArray,
  extensions extensions: List(Dynamic),
) -> Dynamic {
  to_dynamic(#(
    atom.create("OTPTBSCertificate"),
    atom.create("v3"),
    serial(),
    signature_algorithm(),
    issuer,
    #(atom.create("Validity"), time(not_before), time(not_after)),
    subject,
    public_key_info(point),
    no_value(),
    no_value(),
    extensions,
  ))
}

/// The whole extension list of a root: what minting writes and what loading
/// requires, no more and no less.
fn root_extensions(point: BitArray) -> List(Dynamic) {
  [
    extension(to_dynamic(#(2, 5, 29, 19)), True, #(
      atom.create("BasicConstraints"),
      True,
      0,
    )),
    extension(to_dynamic(#(2, 5, 29, 15)), True, [
      atom.create("keyCertSign"),
      atom.create("cRLSign"),
    ]),
    name_constraints(),
    extension(to_dynamic(#(2, 5, 29, 14)), False, key_id(point)),
  ]
}

/// The root may only certify loopback names: `localhost` (and, by DNS name
/// constraint semantics, names under it), 127.0.0.1/32 and ::1/128.
fn name_constraints() -> Dynamic {
  let subtree = fn(base: Dynamic) {
    to_dynamic(#(atom.create("GeneralSubtree"), base, 0, no_value()))
  }
  let ip = fn(address: BitArray) {
    to_dynamic(#(atom.create("iPAddress"), address))
  }
  extension(to_dynamic(#(2, 5, 29, 30)), True, #(
    atom.create("NameConstraints"),
    [
      subtree(
        to_dynamic(#(atom.create("dNSName"), charlist.from_string("localhost"))),
      ),
      subtree(ip(<<127, 0, 0, 1, 255, 255, 255, 255>>)),
      subtree(ip(<<0:120, 1:8, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:128>>)),
    ],
    no_value(),
  ))
}

fn leaf_extensions(root_point: BitArray) -> List(Dynamic) {
  [
    extension(to_dynamic(#(2, 5, 29, 19)), True, #(
      atom.create("BasicConstraints"),
      False,
      no_value(),
    )),
    extension(to_dynamic(#(2, 5, 29, 15)), True, [
      atom.create("digitalSignature"),
    ]),
    extension(to_dynamic(#(2, 5, 29, 37)), False, [
      to_dynamic(#(1, 3, 6, 1, 5, 5, 7, 3, 1)),
    ]),
    extension(to_dynamic(#(2, 5, 29, 17)), False, [
      to_dynamic(#(atom.create("dNSName"), charlist.from_string("localhost"))),
      to_dynamic(#(atom.create("iPAddress"), <<127, 0, 0, 1>>)),
    ]),
    extension(to_dynamic(#(2, 5, 29, 35)), False, #(
      atom.create("AuthorityKeyIdentifier"),
      key_id(root_point),
      no_value(),
      no_value(),
    )),
  ]
}

fn extension(id: Dynamic, critical: Bool, value: a) -> Dynamic {
  to_dynamic(#(atom.create("Extension"), id, critical, value))
}

fn root_name() -> Dynamic {
  to_dynamic(
    name([
      #(to_dynamic(#(2, 5, 4, 10)), bit_array.from_string("Hellhound testing")),
      #(
        to_dynamic(#(2, 5, 4, 3)),
        bit_array.from_string("Hellhound local development root"),
      ),
    ]),
  )
}

fn name(
  attributes: List(#(Dynamic, BitArray)),
) -> #(Atom, List(List(Dynamic))) {
  #(
    atom.create("rdnSequence"),
    list.map(attributes, fn(attribute) {
      [
        to_dynamic(#(
          atom.create("AttributeTypeAndValue"),
          attribute.0,
          #(atom.create("utf8String"), attribute.1),
        )),
      ]
    }),
  )
}

fn public_key_info(point: BitArray) -> Dynamic {
  to_dynamic(#(
    atom.create("OTPSubjectPublicKeyInfo"),
    #(
      atom.create("PublicKeyAlgorithm"),
      to_dynamic(#(1, 2, 840, 10_045, 2, 1)),
      #(atom.create("namedCurve"), to_dynamic(#(1, 2, 840, 10_045, 3, 1, 7))),
    ),
    #(atom.create("ECPoint"), point),
  ))
}

fn signature_algorithm() -> Dynamic {
  to_dynamic(#(
    atom.create("SignatureAlgorithm"),
    to_dynamic(#(1, 2, 840, 10_045, 4, 3, 2)),
    no_value(),
  ))
}

fn key_id(point: BitArray) -> BitArray {
  crypto.hash(crypto.Sha1, point)
}

/// A random positive 127-bit serial, so a replaced root or a new leaf never
/// repeats an issuer and serial pair a browser has seen.
fn serial() -> Int {
  case crypto.strong_random_bytes(16) {
    <<_:1, value:127>> -> int.bitwise_or(value, 1)
    _ -> 1
  }
}

/// UTCTime before 2050, GeneralizedTime from then on (RFC 5280).
fn time(at: Timestamp) -> Dynamic {
  let #(date, clock) = timestamp.to_calendar(at, calendar.utc_offset)
  let two = fn(value) { string.pad_start(int.to_string(value), 2, "0") }
  let rest =
    two(calendar.month_to_int(date.month))
    <> two(date.day)
    <> two(clock.hours)
    <> two(clock.minutes)
    <> two(clock.seconds)
    <> "Z"
  case date.year < 2050 {
    True ->
      to_dynamic(#(
        atom.create("utcTime"),
        charlist.from_string(two(date.year % 100) <> rest),
      ))
    False ->
      to_dynamic(#(
        atom.create("generalTime"),
        charlist.from_string(int.to_string(date.year) <> rest),
      ))
  }
}

fn no_value() -> Atom {
  atom.create("asn1_NOVALUE")
}

fn certificate_atom() -> Atom {
  atom.create("Certificate")
}

fn not_encrypted() -> Atom {
  atom.create("not_encrypted")
}

fn otp() -> Atom {
  atom.create("otp")
}

// ===========================================================================
// OTP `public_key`: the primitives kryptos lacks (see the module doc).

@external(erlang, "public_key", "pkix_sign")
fn sign(tbs: Dynamic, key: ec.PrivateKey) -> BitArray

@external(erlang, "public_key", "pkix_decode_cert")
fn decode_cert(der: BitArray, form: Atom) -> Dynamic

@external(erlang, "public_key", "pkix_verify")
fn verify(der: BitArray, key: ec.PublicKey) -> Bool

@external(erlang, "public_key", "pem_decode")
fn pem_decode(pem: String) -> List(#(Atom, BitArray, Dynamic))

@external(erlang, "public_key", "pem_encode")
fn pem_encode(entries: List(#(Atom, BitArray, Atom))) -> String

@external(erlang, "gleam_stdlib", "identity")
fn to_dynamic(value: a) -> Dynamic
