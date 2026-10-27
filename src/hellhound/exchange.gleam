//// Explicit HTTPS credential exchange, independent of discovery and custody.
////
//// `new` validates pure options. Start `supervised(client)` under your owning
//// supervisor before calling `perform`; stop it through that supervisor.
//// Each call sends at most one request. Applications own token reuse and retry
//// authority, including a failure whose evidence is MaybeSent.
////
//// A caller decoder converts the provider's JSON into TokenResponse. Decoder
//// failures/exceptions are sanitized. Its purity, runtime and captured-resource
//// lifetime belong to the application. No raw response is kept in errors.
//// Transport policy applies before status classification: an oversized,
//// incomplete or unsupported-encoding response fails as TransportFailure,
//// including when its observed status is non-2xx.

import exception
import gleam/bit_array
import gleam/dynamic/decode.{type Decoder}
import gleam/json
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/otp/supervision
import gleam/result
import gleam/string
import gleam/time/duration.{type Duration}
import gleam/time/timestamp.{type Timestamp}
import gleam/uri
import hellhound/assertion.{type Assertion}
import hellhound/config
import hellhound/internal/redacted.{type Redacted}
import hellhound/internal/transport
import hellhound/internal/trust
import hellhound/telemetry.{type Evidence, type TransportReason}
import sinal/correlation.{type Correlation}

pub type Options {
  Options(
    trust: config.Trust,
    destinations: config.DestinationPolicy,
    allowed_hosts: Option(List(String)),
    timeout: Duration,
    max_response_bytes: Int,
    max_header_bytes: Int,
    max_headers: Int,
  )
}

pub fn options() -> Options {
  Options(
    trust: config.SystemTrust,
    destinations: config.PublicInternetOnly,
    allowed_hosts: None,
    timeout: duration.seconds(10),
    max_response_bytes: 1_048_576,
    max_header_bytes: 16_384,
    max_headers: 100,
  )
}

pub type ConfigError {
  InvalidTrust
  InvalidTimeout
  InvalidResponseLimit
  InvalidHeaderLimit
  InvalidHost
}

pub opaque type Client {
  Client(policy: transport.Policy, pool: transport.Pool)
}

pub fn new(options: Options) -> Result(Client, ConfigError) {
  let timeout = duration.to_milliseconds(options.timeout)
  use _ <- result.try(case timeout > 0 && timeout <= 600_000 {
    True -> Ok(Nil)
    False -> Error(InvalidTimeout)
  })
  use _ <- result.try(
    case
      options.max_response_bytes > 0 && options.max_response_bytes <= 16_777_216
    {
      True -> Ok(Nil)
      False -> Error(InvalidResponseLimit)
    },
  )
  use _ <- result.try(
    case
      options.max_header_bytes > 0
      && options.max_header_bytes <= 1_048_576
      && options.max_headers > 0
      && options.max_headers <= 1000
    {
      True -> Ok(Nil)
      False -> Error(InvalidHeaderLimit)
    },
  )
  use _ <- result.try(case options.allowed_hosts {
    None -> Ok(Nil)
    Some(hosts) ->
      case list.all(hosts, valid_host) {
        True -> Ok(Nil)
        False -> Error(InvalidHost)
      }
  })
  use trust <- result.try(case options.trust {
    config.SystemTrust -> Ok(transport.SystemTrust)
    config.TrustAnchorsPem(pem) ->
      trust.pem_certificates(pem)
      |> result.map(transport.Anchors)
      |> result.replace_error(InvalidTrust)
  })
  let pool = transport.new_pool()
  let policy =
    transport.Policy(
      ..transport.policy(trust),
      pool: Some(pool),
      timeout_ms: timeout,
      max_body: options.max_response_bytes,
      max_header_bytes: options.max_header_bytes,
      max_headers: options.max_headers,
      allowed_hosts: options.allowed_hosts,
      allow_loopback: options.destinations == config.AllowLoopbackForTesting,
      allow_private: options.destinations == config.AllowPrivateNetwork,
    )
  Ok(Client(policy, pool))
}

fn valid_host(host: String) -> Bool {
  case uri.parse("https://" <> host) {
    Ok(uri.Uri(
      host: Some(parsed),
      userinfo: None,
      port: None,
      path: "",
      query: None,
      fragment: None,
      ..,
    )) -> parsed == host && host != ""
    _ -> False
  }
}

/// The application owns the returned child's supervisor and shutdown.
pub fn supervised(client: Client) -> supervision.ChildSpecification(Nil) {
  transport.pool_child(client.policy, client.pool)
}

pub fn with_correlation(client: Client, correlation: Correlation) -> Client {
  Client(
    ..client,
    policy: transport.Policy(..client.policy, correlation: Some(correlation)),
  )
}

pub type Authentication {
  Bearer(Assertion)
  FormAssertion(name: String, assertion: Assertion)
}

pub type Body {
  Empty
  Form(List(#(String, String)))
  Json(json.Json)
}

pub opaque type Request {
  Request(material: Redacted(RequestData))
}

type RequestData {
  RequestData(
    endpoint: String,
    authentication: Authentication,
    body: Body,
    headers: List(#(String, String)),
  )
}

pub fn new_request(
  endpoint: String,
  authentication: Authentication,
) -> Request {
  Request(redacted.new(RequestData(endpoint, authentication, Empty, [])))
}

pub fn with_body(request: Request, body: Body) -> Request {
  let data = redacted.reveal(request.material)
  Request(redacted.new(RequestData(..data, body:)))
}

/// Adds one header. Credential/framing overrides and duplicates are refused
/// by `perform`, rather than silently replacing existing configured headers.
pub fn with_header(request: Request, name: String, value: String) -> Request {
  let data = redacted.reveal(request.material)
  Request(redacted.new(
    RequestData(..data, headers: [
      #(string.lowercase(name), value),
      ..data.headers
    ]),
  ))
}

/// A decoder's transient input to token admission. The raw string here belongs
/// to the caller decoder; only the admitted opaque Token is returned by perform.
pub type TokenResponse {
  TokenResponse(token: String, expires_at: Option(Timestamp))
}

pub opaque type Token {
  Token(material: Redacted(String), expires_at: Option(Timestamp))
}

pub type Error {
  InvalidRequest
  TransportFailure(evidence: Evidence, reason: TransportReason)
  ProviderRejected(status: Int)
  MalformedResponse
  InvalidToken
}

pub fn perform(
  client: Client,
  request: Request,
  decoder: Decoder(TokenResponse),
) -> Result(Token, Error) {
  use prepared <- result.try(
    exception.rescue(fn() { prepare(redacted.reveal(request.material)) })
    |> result.replace_error(InvalidRequest)
    |> result.try(fn(value) { value }),
  )
  use response <- result.try(
    transport.send(client.policy, prepared) |> result.map_error(transport_error),
  )
  case response.status >= 200 && response.status < 300 {
    False -> Error(ProviderRejected(response.status))
    True -> decode_token(response.body, decoder)
  }
}

fn decode_token(
  body: BitArray,
  decoder: Decoder(TokenResponse),
) -> Result(Token, Error) {
  use text <- result.try(
    bit_array.to_string(body) |> result.replace_error(MalformedResponse),
  )
  use decoded <- result.try(
    exception.rescue(fn() { json.parse(text, decoder) })
    |> result.replace_error(MalformedResponse)
    |> result.try(result.replace_error(_, MalformedResponse)),
  )
  case decoded.token != "" && clean(decoded.token) {
    True -> Ok(Token(redacted.new(decoded.token), decoded.expires_at))
    False -> Error(InvalidToken)
  }
}

fn prepare(data: RequestData) -> Result(transport.Request, Error) {
  let header_names = list.map(data.headers, fn(pair) { pair.0 })
  use _ <- result.try(
    case
      list.unique(header_names) == header_names
      && !list.any(header_names, reserved_header)
    {
      True -> Ok(Nil)
      False -> Error(InvalidRequest)
    },
  )
  use #(body, content_type, credential_headers) <- result.try(encode_body(
    data.authentication,
    data.body,
  ))
  let accept = case list.contains(header_names, "accept") {
    True -> []
    False -> [#("accept", "application/json")]
  }
  let content_type = case content_type {
    Some(kind) -> [#("content-type", kind)]
    None -> []
  }
  Ok(transport.Request(
    method: transport.Post,
    url: data.endpoint,
    headers: list.flatten([
      data.headers,
      accept,
      content_type,
      credential_headers,
    ]),
    body:,
  ))
}

fn encode_body(
  authentication: Authentication,
  body: Body,
) -> Result(#(Option(BitArray), Option(String), List(#(String, String))), Error) {
  case authentication {
    Bearer(assertion) -> {
      use #(body, content_type) <- result.map(encode_payload(body))
      #(body, content_type, [
        #("authorization", "Bearer " <> assertion.to_string(assertion)),
      ])
    }
    FormAssertion(name, assertion) -> {
      use fields <- result.try(case body {
        Empty -> Ok([])
        Form(fields) -> Ok(fields)
        Json(_) -> Error(InvalidRequest)
      })
      use _ <- result.try(
        case name != "" && !list.any(fields, fn(pair) { pair.0 == name }) {
          True -> Ok(Nil)
          False -> Error(InvalidRequest)
        },
      )
      use #(encoded, content_type) <- result.map(
        encode_payload(
          Form([#(name, assertion.to_string(assertion)), ..fields]),
        ),
      )
      #(encoded, content_type, [])
    }
  }
}

fn encode_payload(
  body: Body,
) -> Result(#(Option(BitArray), Option(String)), Error) {
  case body {
    Empty -> Ok(#(None, None))
    Json(value) ->
      Ok(#(
        Some(json.to_string(value) |> bit_array.from_string),
        Some("application/json"),
      ))
    Form(fields) -> {
      let names = list.map(fields, fn(pair) { pair.0 })
      case list.unique(names) == names && !list.contains(names, "") {
        True ->
          Ok(#(
            Some(uri.query_to_string(fields) |> bit_array.from_string),
            Some("application/x-www-form-urlencoded"),
          ))
        False -> Error(InvalidRequest)
      }
    }
  }
}

fn reserved_header(name: String) -> Bool {
  list.contains(
    [
      "authorization",
      "proxy-authorization",
      "content-type",
      "content-length",
      "host",
      "transfer-encoding",
      "connection",
      "trailer",
      "te",
      "upgrade",
    ],
    name,
  )
}

fn transport_error(failure: transport.Failure) -> Error {
  TransportFailure(
    case failure.stage {
      transport.NotSent -> telemetry.NotSent
      transport.Sent -> telemetry.MaybeSent
    },
    transport.telemetry_reason(failure.class),
  )
}

fn clean(value: String) -> Bool {
  value
  |> string.to_utf_codepoints
  |> list.all(fn(point) {
    let point = string.utf_codepoint_to_int(point)
    point >= 32 && { point < 127 || point > 159 }
  })
}

/// Deliberately expose the credential for an application-owned resource request.
pub fn token_value(token: Token) -> String {
  redacted.reveal(token.material)
}

/// Absent or past expiry remains honest evidence; the application owns reuse.
pub fn expires_at(token: Token) -> Option(Timestamp) {
  token.expires_at
}
