//// Public exchange behavior against real disposable HTTPS endpoints.

import exception
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
import gleam/time/duration
import gleam/time/timestamp
import gleam/uri
import hellhound/assertion
import hellhound/assertion_test as oracle
import hellhound/config
import hellhound/exchange
import hellhound/internal/test_pki
import hellhound/internal/tls_server
import hellhound/telemetry
import sinal

pub fn credential() -> assertion.Assertion {
  let assert Ok(key) = config.signing_key_from_jwk(oracle.key("EC"))
  let assert Ok(signed) = assertion.sign(assertion.claims(), key, config.Es256)
  signed
}

fn decoder() -> decode.Decoder(exchange.TokenResponse) {
  use value <- decode.field("token", decode.string)
  decode.success(exchange.TokenResponse(value, None))
}

pub fn bearer_json_exchange_works_without_discovery_test() {
  let assert Ok(pki) = test_pki.generate()
  let observed = process.new_subject()
  let assert Ok(server) =
    tls_server.start(pki, fn(request) {
      process.send(observed, request)
      response.new(201) |> response.set_body("{\"token\":\"SENTINEL-TOKEN\"}")
    })
  use <- exception.defer(fn() { tls_server.stop(server) })
  let settings = exchange.options()
  let assert Ok(client) =
    exchange.new(
      exchange.Options(
        ..settings,
        trust: config.TrustAnchorsPem(pki.ca_pem),
        destinations: config.AllowLoopbackForTesting,
      ),
    )
  let assert Ok(started) =
    supervisor.new(supervisor.OneForOne)
    |> supervisor.add(exchange.supervised(client))
    |> supervisor.start
  use <- exception.defer(fn() {
    process.unlink(started.pid)
    process.send_abnormal_exit(started.pid, Shutdown)
  })
  let signed = credential()
  let req =
    exchange.new_request(
      "https://localhost:" <> int.to_string(server.port) <> "/credentials",
      exchange.Bearer(signed),
    )
    |> exchange.with_body(
      exchange.Json(
        json.object([#("repositories", json.array(["one"], json.string))]),
      ),
    )
    |> exchange.with_header("accept", "application/vnd.example+json")
  let assert Ok(token) = exchange.perform(client, req, decoder())
  assert exchange.token_value(token) == "SENTINEL-TOKEN"
  assert exchange.expires_at(token) == None
  assert !string.contains(string.inspect(#(req, token)), "SENTINEL-TOKEN")
  assert !string.contains(string.inspect(req), assertion.to_string(signed))
  let assert Ok(received) = process.receive(observed, 1000)
  assert request.get_header(received, "authorization")
    == Ok("Bearer " <> assertion.to_string(signed))
  assert request.get_header(received, "content-type") == Ok("application/json")
  assert request.get_header(received, "accept")
    == Ok("application/vnd.example+json")
  assert received.path == "/credentials"
  assert process.receive(observed, 20) == Error(Nil)
}

type ExitReason {
  Shutdown
}

fn with_endpoint(
  configure: fn(exchange.Options) -> exchange.Options,
  respond: fn(request.Request(String)) -> response.Response(String),
  run: fn(exchange.Client, String, process.Subject(request.Request(String))) ->
    Nil,
) -> Nil {
  let assert Ok(pki) = test_pki.generate()
  let observed = process.new_subject()
  let assert Ok(server) =
    tls_server.start(pki, fn(request) {
      process.send(observed, request)
      respond(request)
    })
  use <- exception.defer(fn() { tls_server.stop(server) })
  let defaults = exchange.options()
  let assert Ok(client) =
    exchange.new(configure(
      exchange.Options(
        ..defaults,
        trust: config.TrustAnchorsPem(pki.ca_pem),
        destinations: config.AllowLoopbackForTesting,
      ),
    ))
  use <- running(client)
  run(client, "https://localhost:" <> int.to_string(server.port), observed)
}

fn running(client: exchange.Client, run: fn() -> Nil) -> Nil {
  let assert Ok(started) =
    supervisor.new(supervisor.OneForOne)
    |> supervisor.add(exchange.supervised(client))
    |> supervisor.start
  use <- exception.defer(fn() { stop(started.pid) })
  run()
}

fn stop(pid: process.Pid) -> Nil {
  process.unlink(pid)
  process.send_abnormal_exit(pid, Shutdown)
  wait_stopped(pid, 100)
}

fn wait_stopped(pid: process.Pid, attempts: Int) -> Nil {
  case process.is_alive(pid), attempts {
    False, _ -> Nil
    True, 0 -> panic as "supervisor did not stop"
    True, _ -> {
      process.sleep(10)
      wait_stopped(pid, attempts - 1)
    }
  }
}

fn unchanged(options: exchange.Options) -> exchange.Options {
  options
}

fn success(_request: request.Request(String)) -> response.Response(String) {
  response.new(200) |> response.set_body("{\"token\":\"token\"}")
}

pub fn form_assertion_and_relative_expiry_are_caller_configurable_test() {
  use client, url, observed <- with_endpoint(unchanged, fn(_) {
    response.new(200)
    |> response.set_body("{\"access_token\":\"form-token\",\"expires_in\":60}")
  })
  let signed = credential()
  let req =
    exchange.new_request(
      url <> "/oauth",
      exchange.FormAssertion("client_assertion", signed),
    )
    |> exchange.with_body(
      exchange.Form([
        #("grant_type", "client_credentials"),
        #(
          "client_assertion_type",
          "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        ),
        #("scope", "read write+special&value"),
      ]),
    )
  let decoder = {
    use token <- decode.field("access_token", decode.string)
    use lifetime <- decode.field("expires_in", decode.int)
    decode.success(exchange.TokenResponse(
      token,
      Some(timestamp.from_unix_seconds(1000 + lifetime)),
    ))
  }
  let assert Ok(token) = exchange.perform(client, req, decoder)
  assert exchange.expires_at(token) == Some(timestamp.from_unix_seconds(1060))
  let assert Ok(received) = process.receive(observed, 1000)
  assert request.get_header(received, "authorization") == Error(Nil)
  assert request.get_header(received, "content-type")
    == Ok("application/x-www-form-urlencoded")
  let assert Ok(fields) = uri.parse_query(received.body)
  assert list.key_find(fields, "client_assertion")
    == Ok(assertion.to_string(signed))
  assert list.key_find(fields, "scope") == Ok("read write+special&value")
}

pub fn invalid_request_combinations_are_refused_before_transmission_test() {
  use client, url, observed <- with_endpoint(unchanged, success)
  let signed = credential()
  let bearer = exchange.new_request(url, exchange.Bearer(signed))
  let form =
    exchange.new_request(url, exchange.FormAssertion("assertion", signed))
  let invalid = [
    bearer |> exchange.with_header("Authorization", "SENTINEL-OVERRIDE"),
    bearer |> exchange.with_header("content-length", "0"),
    bearer |> exchange.with_header("Host", "other.test"),
    bearer |> exchange.with_header("connection", "close"),
    bearer
      |> exchange.with_header("x-extra", "one")
      |> exchange.with_header("X-Extra", "two"),
    bearer
      |> exchange.with_body(
        exchange.Form([#("scope", "one"), #("scope", "two")]),
      ),
    form
      |> exchange.with_body(
        exchange.Form([#("assertion", "SENTINEL-OVERRIDE")]),
      ),
    form |> exchange.with_body(exchange.Json(json.object([]))),
    exchange.new_request(url, exchange.FormAssertion("", signed)),
  ]
  list.each(invalid, fn(req) {
    assert exchange.perform(client, req, decoder())
      == Error(exchange.InvalidRequest)
  })
  assert process.receive(observed, 20) == Error(Nil)
}

pub fn transport_rejects_insecure_unsafe_and_oversized_requests_test() {
  use client, url, observed <- with_endpoint(unchanged, success)
  let signed = credential()
  let requests = [
    exchange.new_request(
      string.replace(url, "https:", "http:"),
      exchange.Bearer(signed),
    ),
    exchange.new_request(url, exchange.Bearer(signed))
      |> exchange.with_header("x-extra", "bad\r\nvalue"),
    exchange.new_request(url, exchange.Bearer(signed))
      |> exchange.with_body(
        exchange.Json(json.string(string.repeat("x", 65_537))),
      ),
  ]
  list.each(requests, fn(req) {
    let assert Error(exchange.TransportFailure(telemetry.NotSent, _)) =
      exchange.perform(client, req, decoder())
  })
  assert process.receive(observed, 20) == Error(Nil)
}

pub fn provider_rejections_and_redirects_are_not_followed_or_retried_test() {
  use client, url, observed <- with_endpoint(unchanged, fn(request) {
    let status = case request.path {
      "/redirect" -> 302
      _ -> 500
    }
    response.new(status)
    |> response.set_header("location", "/unexpected")
    |> response.set_body("SENTINEL-PRIVATE-ERROR")
  })
  list.each([#("/redirect", 302), #("/failure", 500)], fn(pair) {
    let req = exchange.new_request(url <> pair.0, exchange.Bearer(credential()))
    let result = exchange.perform(client, req, decoder())
    assert result == Error(exchange.ProviderRejected(pair.1))
    assert !string.contains(string.inspect(result), "SENTINEL")
    let assert Ok(_) = process.receive(observed, 1000)
    assert process.receive(observed, 30) == Error(Nil)
  })
}

pub fn malformed_response_and_invalid_token_failures_are_sanitized_test() {
  use client, url, observed <- with_endpoint(unchanged, fn(request) {
    let body = case request.path {
      "/empty" -> "{\"token\":\"\"}"
      "/control" -> "{\"token\":\"bad\\tvalue\"}"
      "/wrong-type" -> "{\"token\":123}"
      "/missing" -> "{\"SENTINEL-PRIVATE\":true}"
      _ -> "SENTINEL-NOT-JSON"
    }
    response.new(200) |> response.set_body(body)
  })
  list.each(
    [
      #("/empty", exchange.InvalidToken),
      #("/control", exchange.InvalidToken),
      #("/wrong-type", exchange.MalformedResponse),
      #("/missing", exchange.MalformedResponse),
      #("/malformed", exchange.MalformedResponse),
    ],
    fn(pair) {
      let result =
        exchange.perform(
          client,
          exchange.new_request(url <> pair.0, exchange.Bearer(credential())),
          decoder(),
        )
      assert result == Error(pair.1)
      assert !string.contains(string.inspect(result), "SENTINEL")
      let assert Ok(_) = process.receive(observed, 1000)
      Nil
    },
  )
}

pub fn decoder_exception_is_sanitized_test() {
  use client, url, _ <- with_endpoint(unchanged, success)
  let decoder = {
    use _ <- decode.then(decode.dynamic)
    panic as "SENTINEL-DECODER-SECRET"
  }
  assert exchange.perform(
      client,
      exchange.new_request(url, exchange.Bearer(credential())),
      decoder,
    )
    == Error(exchange.MalformedResponse)
}

pub fn response_limit_retains_possible_send_evidence_test() {
  use client, url, observed <- with_endpoint(
    fn(options) { exchange.Options(..options, max_response_bytes: 100) },
    fn(_) { response.new(200) |> response.set_body(string.repeat("x", 101)) },
  )
  assert exchange.perform(
      client,
      exchange.new_request(url, exchange.Bearer(credential())),
      decoder(),
    )
    == Error(exchange.TransportFailure(
      telemetry.MaybeSent,
      telemetry.ResponseTooLarge,
    ))
  let assert Ok(_) = process.receive(observed, 1000)
  assert process.receive(observed, 20) == Error(Nil)
}

pub fn transport_policy_applies_before_provider_status_classification_test() {
  use client, url, observed <- with_endpoint(
    fn(options) { exchange.Options(..options, max_response_bytes: 100) },
    fn(request) {
      case request.path {
        "/oversized-error" ->
          response.new(500) |> response.set_body(string.repeat("x", 101))
        _ ->
          response.new(401)
          |> response.set_header("content-encoding", "gzip")
          |> response.set_body("SENTINEL-ENCODED-ERROR")
      }
    },
  )
  list.each(
    [
      #("/oversized-error", telemetry.ResponseTooLarge),
      #("/encoded-error", telemetry.UnsupportedContentEncoding),
    ],
    fn(case_) {
      let result =
        exchange.perform(
          client,
          exchange.new_request(url <> case_.0, exchange.Bearer(credential())),
          decoder(),
        )
      assert result
        == Error(exchange.TransportFailure(telemetry.MaybeSent, case_.1))
      assert !string.contains(string.inspect(result), "SENTINEL")
      let assert Ok(_) = process.receive(observed, 1000)
      Nil
    },
  )
  assert process.receive(observed, 20) == Error(Nil)
}

pub fn timeout_after_receipt_does_not_resend_test() {
  use client, url, observed <- with_endpoint(
    fn(options) {
      exchange.Options(..options, timeout: duration.milliseconds(100))
    },
    fn(_) {
      process.sleep(300)
      success(request.new())
    },
  )
  let result =
    exchange.perform(
      client,
      exchange.new_request(url, exchange.Bearer(credential())),
      decoder(),
    )
  assert result
    == Error(exchange.TransportFailure(telemetry.MaybeSent, telemetry.Timeout))
  let assert Ok(_) = process.receive(observed, 1000)
  assert process.receive(observed, 50) == Error(Nil)
}

pub fn missing_pool_never_starts_an_unowned_replacement_test() {
  let assert Ok(pki) = test_pki.generate()
  let observed = process.new_subject()
  let assert Ok(server) =
    tls_server.start(pki, fn(req) {
      process.send(observed, req)
      success(req)
    })
  use <- exception.defer(fn() { tls_server.stop(server) })
  let defaults = exchange.options()
  let assert Ok(client) =
    exchange.new(
      exchange.Options(
        ..defaults,
        trust: config.TrustAnchorsPem(pki.ca_pem),
        destinations: config.AllowLoopbackForTesting,
      ),
    )
  let req =
    exchange.new_request(
      "https://localhost:" <> int.to_string(server.port),
      exchange.Bearer(credential()),
    )
  let assert Error(exchange.TransportFailure(telemetry.NotSent, _)) =
    exchange.perform(client, req, decoder())
  assert process.receive(observed, 20) == Error(Nil)
  running(client, fn() {
    let assert Ok(_) = exchange.perform(client, req, decoder())
    let assert Ok(_) = process.receive(observed, 1000)
    Nil
  })
  let assert Error(exchange.TransportFailure(telemetry.NotSent, _)) =
    exchange.perform(client, req, decoder())
  running(client, fn() {
    let assert Ok(_) = exchange.perform(client, req, decoder())
    let assert Ok(_) = process.receive(observed, 1000)
    Nil
  })
}

pub fn options_are_validated_before_start_test() {
  let defaults = exchange.options()
  assert exchange.new(
      exchange.Options(..defaults, timeout: duration.seconds(0)),
    )
    == Error(exchange.InvalidTimeout)
  assert exchange.new(exchange.Options(..defaults, max_response_bytes: 0))
    == Error(exchange.InvalidResponseLimit)
  assert exchange.new(exchange.Options(..defaults, max_headers: 1001))
    == Error(exchange.InvalidHeaderLimit)
  assert exchange.new(
      exchange.Options(..defaults, allowed_hosts: Some(["host/path"])),
    )
    == Error(exchange.InvalidHost)
  assert exchange.new(
      exchange.Options(
        ..defaults,
        trust: config.TrustAnchorsPem("SENTINEL-NOT-PEM"),
      ),
    )
    == Error(exchange.InvalidTrust)
}

pub fn user_agent_has_one_default_or_one_caller_value_test() {
  use client, url, observed <- with_endpoint(unchanged, success)
  let req = exchange.new_request(url, exchange.Bearer(credential()))
  let assert Ok(_) = exchange.perform(client, req, decoder())
  let assert Ok(default_request) = process.receive(observed, 1000)
  assert list.filter(default_request.headers, fn(header) {
      string.lowercase(header.0) == "user-agent"
    })
    == [#("user-agent", "hellhound")]
  let custom = req |> exchange.with_header("UsEr-AgEnT", "application-client")
  let assert Ok(_) = exchange.perform(client, custom, decoder())
  let assert Ok(custom_request) = process.receive(observed, 1000)
  assert list.filter(custom_request.headers, fn(header) {
      string.lowercase(header.0) == "user-agent"
    })
    == [#("user-agent", "application-client")]
}

pub fn control_token_admission_covers_c0_del_and_c1_test() {
  use client, url, observed <- with_endpoint(unchanged, fn(request) {
    let token = case request.path {
      "/c0-start" -> "bad\u{0}value"
      "/c0-end" -> "bad\u{1f}value"
      "/del" -> "bad\u{7f}value"
      "/c1-start" -> "bad\u{80}value"
      "/c1-nel" -> "bad\u{85}value"
      "/c1-end" -> "bad\u{9f}value"
      "/c1-after" -> "allowed\u{a0}value"
      _ -> "tökén"
    }
    response.new(200)
    |> response.set_body(
      json.object([#("token", json.string(token))]) |> json.to_string,
    )
  })
  list.each(
    ["/c0-start", "/c0-end", "/del", "/c1-start", "/c1-nel", "/c1-end"],
    fn(path) {
      assert exchange.perform(
          client,
          exchange.new_request(url <> path, exchange.Bearer(credential())),
          decoder(),
        )
        == Error(exchange.InvalidToken)
      let assert Ok(_) = process.receive(observed, 1000)
      Nil
    },
  )
  list.each(
    [#("/c1-after", "allowed\u{a0}value"), #("/unicode", "tökén")],
    fn(pair) {
      let assert Ok(token) =
        exchange.perform(
          client,
          exchange.new_request(url <> pair.0, exchange.Bearer(credential())),
          decoder(),
        )
      assert exchange.token_value(token) == pair.1
      let assert Ok(_) = process.receive(observed, 1000)
      Nil
    },
  )
}

pub fn destination_allowlist_refuses_credentials_before_sending_test() {
  use client, url, observed <- with_endpoint(
    fn(options) {
      exchange.Options(..options, allowed_hosts: Some(["allowed.example"]))
    },
    success,
  )
  assert exchange.perform(
      client,
      exchange.new_request(url, exchange.Bearer(credential())),
      decoder(),
    )
    == Error(exchange.TransportFailure(
      telemetry.NotSent,
      telemetry.DestinationRejected,
    ))
  assert process.receive(observed, 20) == Error(Nil)
}

pub fn production_destination_policy_rejects_loopback_test() {
  use client, url, observed <- with_endpoint(
    fn(options) {
      exchange.Options(..options, destinations: config.PublicInternetOnly)
    },
    success,
  )
  assert exchange.perform(
      client,
      exchange.new_request(url, exchange.Bearer(credential())),
      decoder(),
    )
    == Error(exchange.TransportFailure(
      telemetry.NotSent,
      telemetry.DestinationRejected,
    ))
  assert process.receive(observed, 20) == Error(Nil)
}

pub fn telemetry_omits_assertions_headers_and_response_material_test() {
  use client, url, _ <- with_endpoint(unchanged, fn(_) {
    response.new(200) |> response.set_body("{\"token\":\"SENTINEL-RESPONSE\"}")
  })
  let events = process.new_subject()
  let observer =
    sinal.observe(telemetry.http_request(), fn(_, event) {
      process.send(events, event)
    })
  use <- exception.defer(fn() {
    let _ = sinal.detach(observer)
    Nil
  })
  let signed = credential()
  let req =
    exchange.new_request(
      url <> "/exchange?private=SENTINEL-QUERY",
      exchange.Bearer(signed),
    )
    |> exchange.with_header("x-extra", "SENTINEL-HEADER")
  let assert Ok(_) = exchange.perform(client, req, decoder())
  let assert Ok(event) = process.receive(events, 1000)
  let text = string.inspect(event)
  assert !string.contains(text, "SENTINEL")
  assert !string.contains(text, assertion.to_string(signed))
  assert event.path == "/exchange"
}
