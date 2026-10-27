//// Both provider recipes compile against public Hellhound imports only.

import exception
import gleam/bit_array
import gleam/bytes_tree
import gleam/dynamic/decode
import gleam/erlang/process
import gleam/http/request
import gleam/http/response
import gleam/int
import gleam/json
import gleam/list
import gleam/option.{None, Some}
import gleam/otp/static_supervisor as supervisor
import gleam/string
import gleam/time/timestamp
import gleam/uri
import hellhound/config
import hellhound/exchange
import hellhound_reference/usage/assertion_exchange as recipe
import mist
import simplifile

type ExitReason {
  Shutdown
}

type ObservedRequest =
  #(String, Result(String, Nil), String)

fn with_endpoint(
  respond: fn(String) -> #(Int, String),
  run: fn(
    exchange.Client,
    String,
    config.SigningKey,
    process.Subject(ObservedRequest),
  ) -> Nil,
) -> Nil {
  let assert Ok(pem) = simplifile.read("../build/test-pki/localhost.key")
  let assert Ok(ca) = simplifile.read("../build/test-pki/ca.pem")
  let assert Ok(key) = config.signing_key_from_pem(pem)
  let observed = process.new_subject()
  let port = process.new_subject()
  let assert Ok(server) =
    mist.new(fn(req) {
      let assert Ok(req) = mist.read_body(req, 65_536)
      let assert Ok(body) = bit_array.to_string(req.body)
      process.send(observed, #(
        req.path,
        request.get_header(req, "authorization"),
        body,
      ))
      let #(status, body) = respond(req.path)
      response.new(status)
      |> response.set_header("content-type", "application/json")
      |> response.set_body(mist.Bytes(bytes_tree.from_string(body)))
    })
    |> mist.bind("127.0.0.1")
    |> mist.port(0)
    |> mist.with_tls(
      certfile: "../build/test-pki/localhost.pem",
      keyfile: "../build/test-pki/localhost.key",
    )
    |> mist.after_start(fn(value, _, _) { process.send(port, value) })
    |> mist.start
  use <- exception.defer(fn() { stop(server.pid) })
  let assert Ok(port) = process.receive(port, 1000)
  let base = "https://localhost:" <> int.to_string(port)
  let defaults = exchange.options()
  let assert Ok(client) =
    exchange.new(
      exchange.Options(
        ..defaults,
        trust: config.TrustAnchorsPem(ca),
        destinations: config.AllowLoopbackForTesting,
      ),
    )
  let assert Ok(started) =
    supervisor.new(supervisor.OneForOne)
    |> supervisor.add(exchange.supervised(client))
    |> supervisor.start
  use <- exception.defer(fn() { stop(started.pid) })
  run(client, base, key, observed)
}

pub fn distinct_provider_recipes_share_the_public_exchange_api_test() {
  use client, base, key, observed <- with_endpoint(fn(path) {
    case path {
      "/app/installations/42/access_tokens" -> #(
        201,
        "{\"token\":\"installation-token\",\"expires_at\":\"2030-01-01T00:00:00Z\"}",
      )
      "/oauth/token" -> #(
        200,
        "{\"access_token\":\"service-token\",\"token_type\":\"Bearer\",\"expires_in\":60}",
      )
      _ -> #(404, "{}")
    }
  })
  let now = timestamp.from_unix_seconds(1000)
  let assert Ok(github) =
    recipe.github_installation_token(client, base, 42, key, "client-id", now, [
      "repo-one",
    ])
  assert exchange.token_value(github) == "installation-token"
  let assert Ok(expiry) = timestamp.parse_rfc3339("2030-01-01T00:00:00Z")
  assert exchange.expires_at(github) == Some(expiry)
  let assert Ok(#("/app/installations/42/access_tokens", Ok(bearer), body)) =
    process.receive(observed, 1000)
  assert json.parse(
      body,
      decode.at(["repositories"], decode.list(decode.string)),
    )
    == Ok(["repo-one"])
  let assert Ok(#("Bearer", signed)) = string.split_once(bearer, " ")
  let claims = payload(signed)
  assert json.parse(claims, decode.at(["iss"], decode.string))
    == Ok("client-id")
  assert json.parse(claims, decode.at(["iat"], decode.int)) == Ok(940)
  assert json.parse(claims, decode.at(["exp"], decode.int)) == Ok(1600)
  let assert Ok(service) =
    recipe.oauth_service_token(
      client,
      base <> "/oauth/token",
      "https://issuer.example",
      key,
      config.Rs256,
      "client-id",
      "unique-id",
      now,
      ["read", "write"],
    )
  assert exchange.token_value(service) == "service-token"
  assert exchange.expires_at(service) == Some(timestamp.from_unix_seconds(1060))
  let assert Ok(#("/oauth/token", Error(Nil), body)) =
    process.receive(observed, 1000)
  let assert Ok(fields) = uri.parse_query(body)
  assert list.key_find(fields, "grant_type") == Ok("client_credentials")
  assert list.key_find(fields, "scope") == Ok("read write")
  let assert Ok(signed) = list.key_find(fields, "client_assertion")
  assert json.parse(payload(signed), decode.at(["aud"], decode.string))
    == Ok("https://issuer.example")
  assert process.receive(observed, 20) == Error(Nil)
}

/// RFC6749 section 5.1 requires a known token_type. Optional expires_in is
/// absent only when omitted: explicit null is not a numeric lifetime.
pub fn oauth_response_profile_rejects_invalid_type_and_lifetime_test() {
  use client, base, key, observed <- with_endpoint(fn(path) {
    let body = case path {
      "/missing-type" ->
        "{\"access_token\":\"SENTINEL-TOKEN\",\"expires_in\":60}"
      "/null-type" ->
        "{\"access_token\":\"SENTINEL-TOKEN\",\"token_type\":null}"
      "/number-type" ->
        "{\"access_token\":\"SENTINEL-TOKEN\",\"token_type\":123}"
      "/unknown-type" ->
        "{\"access_token\":\"SENTINEL-TOKEN\",\"token_type\":\"SENTINEL-UNKNOWN\"}"
      "/null-lifetime" ->
        "{\"access_token\":\"SENTINEL-TOKEN\",\"token_type\":\"Bearer\",\"expires_in\":null}"
      "/negative-lifetime" ->
        "{\"access_token\":\"SENTINEL-TOKEN\",\"token_type\":\"Bearer\",\"expires_in\":-1}"
      "/string-lifetime" ->
        "{\"access_token\":\"SENTINEL-TOKEN\",\"token_type\":\"Bearer\",\"expires_in\":\"60\"}"
      _ -> panic as "unexpected fixture path"
    }
    #(200, body)
  })
  list.each(
    [
      "/missing-type", "/null-type", "/number-type", "/unknown-type",
      "/null-lifetime", "/negative-lifetime", "/string-lifetime",
    ],
    fn(path) {
      let result =
        recipe.oauth_service_token(
          client,
          base <> path,
          "https://issuer.example",
          key,
          config.Rs256,
          "client-id",
          "test-" <> path,
          timestamp.from_unix_seconds(1000),
          ["read"],
        )
      assert result == Error(recipe.Exchanging(exchange.MalformedResponse))
      assert !string.contains(string.inspect(result), "SENTINEL")
      let assert Ok(_) = process.receive(observed, 1000)
    },
  )
  assert process.receive(observed, 20) == Error(Nil)
}

pub fn oauth_response_profile_accepts_bearer_case_and_absent_expiry_test() {
  use client, base, key, observed <- with_endpoint(fn(path) {
    let body = case path {
      "/mixed-case" ->
        "{\"access_token\":\"service-token\",\"token_type\":\"bEaReR\",\"expires_in\":60}"
      "/absent-expiry" ->
        "{\"access_token\":\"service-token\",\"token_type\":\"Bearer\"}"
      _ -> panic as "unexpected fixture path"
    }
    #(200, body)
  })
  list.each(
    [
      #("/mixed-case", Some(timestamp.from_unix_seconds(1060))),
      #("/absent-expiry", None),
    ],
    fn(case_) {
      let #(path, expiry) = case_
      let assert Ok(token) =
        recipe.oauth_service_token(
          client,
          base <> path,
          "https://issuer.example",
          key,
          config.Rs256,
          "client-id",
          "test-" <> path,
          timestamp.from_unix_seconds(1000),
          ["read"],
        )
      assert exchange.token_value(token) == "service-token"
      assert exchange.expires_at(token) == expiry
      let assert Ok(_) = process.receive(observed, 1000)
    },
  )
  assert process.receive(observed, 20) == Error(Nil)
}

fn payload(token: String) -> String {
  let assert [_, encoded, _] = string.split(token, ".")
  let assert Ok(bytes) = bit_array.base64_url_decode(encoded)
  let assert Ok(text) = bit_array.to_string(bytes)
  text
}

fn stop(pid: process.Pid) -> Nil {
  process.unlink(pid)
  process.send_abnormal_exit(pid, Shutdown)
}
