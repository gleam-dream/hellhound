//// Provider-specific profiles composed from Hellhound's public generic API.
//// The application owns endpoint selection, profile values, decoder semantics,
//// token reuse and retry policy. These examples establish no conformance claim.

import gleam/dynamic/decode
import gleam/int
import gleam/json
import gleam/option.{None, Some}
import gleam/result
import gleam/string
import gleam/time/duration
import gleam/time/timestamp.{type Timestamp}
import hellhound/assertion
import hellhound/config
import hellhound/exchange

pub type Error {
  Signing(assertion.SignError)
  Exchanging(exchange.Error)
}

// snips-start: github-assertion-exchange
pub fn github_installation_token(
  client: exchange.Client,
  api_base: String,
  installation_id: Int,
  key: config.SigningKey,
  client_id: String,
  now: Timestamp,
  repositories: List(String),
) -> Result(exchange.Token, Error) {
  use signed <- result.try(
    assertion.claims()
    |> assertion.with_issuer(client_id)
    |> assertion.with_issued_at(timestamp.add(now, duration.seconds(-60)))
    |> assertion.with_expiration(timestamp.add(now, duration.seconds(600)))
    |> assertion.sign(key, config.Rs256)
    |> result.map_error(Signing),
  )
  let endpoint =
    api_base
    <> "/app/installations/"
    <> int.to_string(installation_id)
    <> "/access_tokens"
  let request =
    exchange.new_request(endpoint, exchange.Bearer(signed))
    |> exchange.with_header("accept", "application/vnd.github+json")
    |> exchange.with_header("x-github-api-version", "2026-03-10")
    |> exchange.with_body(
      exchange.Json(
        json.object([
          #("repositories", json.array(repositories, json.string)),
        ]),
      ),
    )
  exchange.perform(client, request, github_response())
  |> result.map_error(Exchanging)
}

// snips-end: github-assertion-exchange

fn github_response() -> decode.Decoder(exchange.TokenResponse) {
  use token <- decode.field("token", decode.string)
  use expires_at <- decode.field("expires_at", timestamp_decoder())
  decode.success(exchange.TokenResponse(token, Some(expires_at)))
}

fn timestamp_decoder() -> decode.Decoder(Timestamp) {
  use value <- decode.then(decode.string)
  case timestamp.parse_rfc3339(value) {
    Ok(time) -> decode.success(time)
    Error(_) ->
      decode.failure(timestamp.from_unix_seconds(0), "RFC3339 timestamp")
  }
}

/// OAuth service grant using a caller-selected assertion algorithm and jti.
/// A caller owns the uniqueness/replay policy for that id and the chosen audience.
pub fn oauth_service_token(
  client: exchange.Client,
  token_endpoint: String,
  audience: String,
  key: config.SigningKey,
  algorithm: config.SigningAlgorithm,
  client_id: String,
  jwt_id: String,
  now: Timestamp,
  scopes: List(String),
) -> Result(exchange.Token, Error) {
  use signed <- result.try(
    assertion.claims()
    |> assertion.with_issuer(client_id)
    |> assertion.with_subject(client_id)
    |> assertion.with_audience(audience)
    |> assertion.with_jwt_id(jwt_id)
    |> assertion.with_issued_at(now)
    |> assertion.with_expiration(timestamp.add(now, duration.seconds(60)))
    |> assertion.sign(key, algorithm)
    |> result.map_error(Signing),
  )
  let request =
    exchange.new_request(
      token_endpoint,
      exchange.FormAssertion("client_assertion", signed),
    )
    |> exchange.with_body(
      exchange.Form([
        #("client_id", client_id),
        #("grant_type", "client_credentials"),
        #("scope", string.join(scopes, " ")),
        #(
          "client_assertion_type",
          "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ),
      ]),
    )
  exchange.perform(client, request, oauth_response(now))
  |> result.map_error(Exchanging)
}

fn oauth_response(now: Timestamp) -> decode.Decoder(exchange.TokenResponse) {
  use token <- decode.field("access_token", decode.string)
  use token_type <- decode.field("token_type", decode.string)
  use lifetime <- decode.optional_field(
    "expires_in",
    None,
    decode.map(decode.int, Some),
  )
  let expiry = case lifetime {
    None -> None
    Some(seconds) -> Some(timestamp.add(now, duration.seconds(seconds)))
  }
  case string.lowercase(token_type), lifetime {
    "bearer", Some(seconds) if seconds < 0 ->
      decode.failure(exchange.TokenResponse("", None), "nonnegative expires_in")
    "bearer", _ -> decode.success(exchange.TokenResponse(token, expiry))
    _, _ ->
      decode.failure(exchange.TokenResponse("", None), "Bearer token_type")
  }
}
