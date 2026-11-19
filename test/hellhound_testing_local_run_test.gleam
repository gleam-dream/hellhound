//// Public fixture behaviour for a local run: a fixed loopback port and a
//// root a developer trusts once, reused from a caller-chosen directory.

import exception
import gleam/erlang/process
import gleam/http/request
import gleam/int
import gleam/list
import gleam/string
import gleeunit/should
import hellhound
import hellhound/testing

pub fn default_start_keeps_a_random_port_and_a_fresh_root_test() -> Nil {
  let assert Ok(first) = testing.start(testing.provider_options())
  use <- exception.defer(fn() { testing.stop_provider(first) })
  let assert Ok(second) = testing.start_provider(testing.provider_options())
  use <- exception.defer(fn() { testing.stop_provider(second) })
  should.not_equal(testing.issuer(first), testing.issuer(second))
  should.not_equal(
    testing.trust_anchor_pem(first),
    testing.trust_anchor_pem(second),
  )
}

pub fn the_same_anchor_and_port_give_the_same_root_and_issuer_test() -> Nil {
  let directory = fresh_dir()
  let options =
    testing.provider_options()
    |> testing.with_port(free_port())
    |> testing.with_trust_anchor(directory)
  let assert Ok(first) = testing.start(options)
  let trusted = testing.config(first, "https://app.test/callback")
  let first_root = testing.trust_anchor_pem(first)
  let first_issuer = testing.issuer(first)
  testing.stop_provider(first)

  let assert Ok(second) = testing.start(options)
  use <- exception.defer(fn() { testing.stop_provider(second) })
  testing.trust_anchor_pem(second) |> should.equal(first_root)
  testing.issuer(second) |> should.equal(first_issuer)
  // A client that trusted the first run's root signs in through the second.
  let assert Ok(client) = hellhound.new(trusted)
  use <- exception.defer(fn() { hellhound.stop(client) })
  let assert Ok(Nil) = hellhound.start(client)
  let assert Ok(redirect) =
    hellhound.begin_login(client, request.new(), hellhound.default_login())
  let assert Ok(callback) = testing.authorize(second, redirect, subject: "ada")
  let assert Ok(session) = hellhound.complete_login(client, callback)
  hellhound.subject(hellhound.session_identity(session)) |> should.equal("ada")
}

pub fn the_anchor_root_is_constrained_to_loopback_test() -> Nil {
  let directory = fresh_dir()
  let assert Ok(provider) =
    testing.start(
      testing.provider_options() |> testing.with_trust_anchor(directory),
    )
  let root = testing.trust_anchor_pem(provider)
  testing.stop_provider(provider)
  let #(names, ca, path_length, seconds, usage) = root_shape(root)
  names |> should.equal(["dns:localhost", "ip:127.0.0.1/32", "ip:::1/128"])
  ca |> should.equal(True)
  path_length |> should.equal(0)
  { seconds <= 91 * 86_400 } |> should.be_true
  usage |> should.equal(["cRLSign", "keyCertSign"])
  // An independent verifier refuses a non-loopback leaf the key signs and
  // accepts a loopback one.
  foreign_leaf_validation(directory)
  |> should.equal(#("permitted subtree violation", "ok"))
  // The developer trusts exactly this file.
  read(testing.trust_anchor_file(directory)) |> should.equal(root)
}

pub fn the_private_key_is_owner_only_test() -> Nil {
  let directory = fresh_dir()
  let assert Ok(provider) =
    testing.start(
      testing.provider_options() |> testing.with_trust_anchor(directory),
    )
  testing.stop_provider(provider)
  mode(key_path(directory)) |> should.equal(0o600)
  mode(directory) |> should.equal(0o700)
  set_mode(key_path(directory), 0o644)
  testing.start(
    testing.provider_options() |> testing.with_trust_anchor(directory),
  )
  |> should.equal(
    Error(testing.TrustAnchorFailed(
      directory,
      testing.AnchorKeyExposed(key_path(directory)),
    )),
  )
}

pub fn a_second_provider_on_the_same_port_is_refused_test() -> Nil {
  let port = free_port()
  let options = testing.provider_options() |> testing.with_port(port)
  let assert Ok(first) = testing.start(options)
  use <- exception.defer(fn() { testing.stop_provider(first) })
  testing.start(options) |> should.equal(Error(testing.PortInUse(port)))
  // The 0.2.2 entry point keeps its error type.
  testing.start_provider(options)
  |> should.equal(Error(testing.ProviderStartFailed))
}

pub fn an_invalid_port_is_refused_test() -> Nil {
  testing.start(testing.provider_options() |> testing.with_port(70_000))
  |> should.equal(Error(testing.InvalidPort(70_000)))
}

pub fn a_corrupt_anchor_is_an_error_not_a_new_root_test() -> Nil {
  let directory = created_anchor()
  let certificate = testing.trust_anchor_file(directory)
  write(certificate, "not a certificate")
  start_anchored(directory)
  |> should.equal(
    Error(testing.TrustAnchorFailed(
      directory,
      testing.AnchorCorrupt(certificate),
    )),
  )
  // Nothing was regenerated behind the developer's back.
  read(certificate) |> should.equal("not a certificate")
}

pub fn a_mismatched_key_is_an_error_test() -> Nil {
  let directory = created_anchor()
  let other = created_anchor()
  copy(key_path(other), key_path(directory))
  set_mode(key_path(directory), 0o600)
  start_anchored(directory)
  |> should.equal(
    Error(testing.TrustAnchorFailed(directory, testing.AnchorMismatch)),
  )
}

pub fn a_key_whose_scalar_does_not_match_its_point_is_a_mismatch_test() -> Nil {
  let directory = created_anchor()
  swap_scalar(directory)
  mode(key_path(directory)) |> should.equal(0o600)
  start_anchored(directory)
  |> should.equal(
    Error(testing.TrustAnchorFailed(directory, testing.AnchorMismatch)),
  )
}

pub fn a_root_without_extensions_is_a_mismatch_not_a_crash_test() -> Nil {
  let directory = created_anchor()
  resign(directory, "no_extensions")
  start_anchored(directory)
  |> should.equal(
    Error(testing.TrustAnchorFailed(directory, testing.AnchorMismatch)),
  )
}

pub fn an_incomplete_anchor_is_an_error_test() -> Nil {
  let directory = created_anchor()
  let certificate = testing.trust_anchor_file(directory)
  delete(certificate)
  start_anchored(directory)
  |> should.equal(
    Error(testing.TrustAnchorFailed(
      directory,
      testing.AnchorIncomplete(certificate),
    )),
  )
}

pub fn an_expired_anchor_is_an_error_test() -> Nil {
  let directory = created_anchor()
  expire(directory)
  start_anchored(directory)
  |> should.equal(
    Error(testing.TrustAnchorFailed(directory, testing.AnchorExpired)),
  )
}

pub fn replace_mints_a_new_root_explicitly_test() -> Nil {
  let directory = created_anchor()
  let before = read(testing.trust_anchor_file(directory))
  expire(directory)
  let assert Ok(Nil) = testing.replace_trust_anchor(directory)
  let assert Ok(provider) = start_anchored(directory)
  testing.stop_provider(provider)
  let after = testing.trust_anchor_pem(provider)
  should.not_equal(after, before)
  read(testing.trust_anchor_file(directory)) |> should.equal(after)
  mode(key_path(directory)) |> should.equal(0o600)
}

pub fn concurrent_starts_on_an_empty_directory_share_one_root_test() -> Nil {
  let directory = fresh_dir()
  let replies = process.new_subject()
  list.repeat(Nil, 16)
  |> list.each(fn(_) {
    process.spawn(fn() {
      case start_anchored(directory) {
        Ok(provider) -> {
          process.send(replies, testing.trust_anchor_pem(provider))
          testing.stop_provider(provider)
        }
        Error(error) -> process.send(replies, string.inspect(error))
      }
    })
  })
  let roots =
    list.repeat(Nil, 16)
    |> list.map(fn(_) {
      let assert Ok(root) = process.receive(replies, 30_000)
      root
    })
  let stored = read(testing.trust_anchor_file(directory))
  list.unique(roots) |> should.equal([stored])
}

pub fn separate_os_processes_share_one_root_test() -> Nil {
  let directory = fresh_dir()
  let roots = os_process_roots(directory, 6)
  let stored = read(testing.trust_anchor_file(directory))
  list.unique(roots) |> should.equal([stored])
}

pub fn a_lock_left_by_a_killed_start_is_reported_not_broken_test() -> Nil {
  let directory = created_anchor()
  let lock = directory <> "/hellhound-root.lock"
  write(lock, "a start that was killed")
  start_anchored(directory)
  |> should.equal(
    Error(testing.TrustAnchorFailed(directory, testing.AnchorLocked(lock))),
  )
  delete(lock)
  let assert Ok(provider) = start_anchored(directory)
  testing.stop_provider(provider)
}

fn start_anchored(
  directory: String,
) -> Result(testing.Provider, testing.StartError) {
  testing.start(
    testing.provider_options() |> testing.with_trust_anchor(directory),
  )
}

fn created_anchor() -> String {
  let directory = fresh_dir()
  let assert Ok(provider) = start_anchored(directory)
  testing.stop_provider(provider)
  directory
}

fn key_path(directory: String) -> String {
  directory <> "/hellhound-root-key.pem"
}

/// A port the OS just handed out and released.
fn free_port() -> Int {
  let assert Ok(provider) = testing.start_provider(testing.provider_options())
  let issuer = testing.issuer(provider)
  testing.stop_provider(provider)
  let assert Ok(#(_, port)) = string.split_once(issuer, "https://localhost:")
  let assert Ok(port) = int.parse(port)
  port
}

@external(erlang, "hellhound_anchor_test_ffi", "fresh_dir")
fn fresh_dir() -> String

@external(erlang, "hellhound_anchor_test_ffi", "mode")
fn mode(path: String) -> Int

@external(erlang, "hellhound_anchor_test_ffi", "set_mode")
fn set_mode(path: String, mode: Int) -> Nil

@external(erlang, "hellhound_anchor_test_ffi", "write")
fn write(path: String, contents: String) -> Nil

@external(erlang, "hellhound_anchor_test_ffi", "read")
fn read(path: String) -> String

@external(erlang, "hellhound_anchor_test_ffi", "delete")
fn delete(path: String) -> Nil

@external(erlang, "hellhound_anchor_test_ffi", "copy")
fn copy(from: String, to: String) -> Nil

@external(erlang, "hellhound_anchor_test_ffi", "root_shape")
fn root_shape(pem: String) -> #(List(String), Bool, Int, Int, List(String))

@external(erlang, "hellhound_anchor_test_ffi", "foreign_leaf_validation")
fn foreign_leaf_validation(directory: String) -> #(String, String)

@external(erlang, "hellhound_anchor_test_ffi", "expire")
fn expire(directory: String) -> Nil

@external(erlang, "hellhound_anchor_test_ffi", "os_process_roots")
fn os_process_roots(directory: String, count: Int) -> List(String)

@external(erlang, "hellhound_anchor_test_ffi", "swap_scalar")
fn swap_scalar(directory: String) -> Nil

@external(erlang, "hellhound_anchor_test_ffi", "resign")
fn resign(directory: String, change: String) -> Nil
