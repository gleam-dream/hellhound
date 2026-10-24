//// Hellhound reference relying party.
////
//// Configuration comes from the environment; every Hellhound call uses public
//// imports. Run with `gleam run` inside `consumer/`:
////
//// | Variable | Meaning |
//// | --- | --- |
//// | `HELLHOUND_ISSUER` | Provider issuer URL |
//// | `HELLHOUND_CLIENT_ID`, `HELLHOUND_CLIENT_SECRET` | Client credentials (secret optional) |
//// | `HELLHOUND_AUTH` | `basic` (default), `post`, `jwt`, `public` |
//// | `HELLHOUND_BASE_URL` | This app's external origin, e.g. `https://localhost:18080` |
//// | `HELLHOUND_RESPONSE_MODE` | `query` (default) or `form_post` |
//// | `HELLHOUND_SCOPES` | Space-separated extra scopes |
//// | `HELLHOUND_CA_FILE` | PEM trust anchors (default: system trust) |
//// | `HELLHOUND_ALLOW_LOOPBACK` | `1` to allow loopback providers (tests only) |
//// | `HELLHOUND_TLS_CERT`, `HELLHOUND_TLS_KEY` | Serve HTTPS with these files |
//// | `HELLHOUND_LOGIN_LIFETIME` | Pending-login lifetime in seconds (default 600) |
//// | `HELLHOUND_ASSUME_UNADVERTISED_S256` | `1` to accept a provider that omits PKCE metadata (confidential clients) |
//// | `PORT` | Listening port (default 18080) |

import envoy
import gleam/erlang/process
import gleam/int
import gleam/io
import gleam/list
import gleam/result
import gleam/string
import gleam/time/duration
import hellhound
import hellhound/config
import hellhound/telemetry
import hellhound_reference/web
import mist
import simplifile
import sinal
import wisp
import wisp/wisp_mist

pub fn main() -> Nil {
  let env = fn(name, default) { envoy.get(name) |> result.unwrap(default) }
  let base_url = env("HELLHOUND_BASE_URL", "https://localhost:18080")
  let response_mode = case env("HELLHOUND_RESPONSE_MODE", "query") {
    "form_post" -> config.FormPost
    _ -> config.Query
  }
  let secret = config.secret(env("HELLHOUND_CLIENT_SECRET", ""))
  let authentication = case env("HELLHOUND_AUTH", "basic") {
    "post" -> config.ClientSecretPost(secret)
    "jwt" -> config.ClientSecretJwt(secret)
    "public" -> config.PublicClient
    _ -> config.ClientSecretBasic(secret)
  }
  let lifetime =
    env("HELLHOUND_LOGIN_LIFETIME", "600") |> int.parse |> result.unwrap(600)
  let configuration =
    config.new(
      issuer: env("HELLHOUND_ISSUER", ""),
      client_id: env("HELLHOUND_CLIENT_ID", ""),
      redirect_uri: base_url <> "/callback",
      authentication:,
    )
    |> config.with_scopes(
      string.split(env("HELLHOUND_SCOPES", "profile email"), " ")
      |> list.filter(fn(s) { s != "" }),
    )
    |> config.with_response_mode(response_mode)
    |> config.with_login_lifetime(duration.seconds(lifetime))
  let configuration = case envoy.get("HELLHOUND_CA_FILE") {
    Ok(path) -> {
      let assert Ok(pem) = simplifile.read(path)
      config.with_trust(configuration, config.TrustAnchorsPem(pem))
    }
    Error(Nil) -> configuration
  }
  // HELLHOUND_ASSUME_UNADVERTISED_S256=1 accepts a provider whose metadata
  // omits code_challenge_methods_supported, such as the
  // OpenID conformance suite's test OP.
  let configuration = case env("HELLHOUND_ASSUME_UNADVERTISED_S256", "") {
    "1" ->
      config.with_pkce_advertisement(
        configuration,
        config.AssumeS256WhenUnadvertised,
      )
    _ -> configuration
  }
  let configuration = case env("HELLHOUND_ALLOW_LOOPBACK", "") {
    "1" ->
      config.with_destinations(configuration, config.AllowLoopbackForTesting)
    _ -> configuration
  }
  let client = case hellhound.new(configuration) {
    Ok(client) -> client
    Error(error) ->
      panic as {
        "hellhound configuration: " <> hellhound.describe_start_error(error)
      }
  }
  log_outbound_requests()
  case hellhound.start(client) {
    Ok(Nil) -> Nil
    Error(error) ->
      panic as {
        "hellhound did not start: " <> hellhound.describe_start_error(error)
      }
  }
  let context =
    web.Context(
      client:,
      issuer: env("HELLHOUND_ISSUER", ""),
      post_logout_redirect_uri: base_url <> "/logged-out",
      origin: base_url,
    )
  let port = env("PORT", "18080") |> int.parse |> result.unwrap(18_080)
  let server =
    wisp_mist.handler(web.handle(_, context), wisp.random_string(64))
    |> mist.new
    |> mist.bind("127.0.0.1")
    |> mist.port(port)
  let server = case
    envoy.get("HELLHOUND_TLS_CERT"),
    envoy.get("HELLHOUND_TLS_KEY")
  {
    Ok(cert), Ok(key) -> mist.with_tls(server, certfile: cert, keyfile: key)
    _, _ -> server
  }
  let assert Ok(_) = mist.start(server)
  io.println("hellhound reference RP listening on " <> base_url)
  process.sleep_forever()
}

/// One log line per outbound Hellhound request, from the typed telemetry
/// event. The event holds no secrets, so it is safe to print whole.
fn log_outbound_requests() -> Nil {
  let _attachment =
    sinal.observe(telemetry.http_request(), fn(measurements, request) {
      let outcome = case request.outcome {
        telemetry.Status(code) -> int.to_string(code)
        telemetry.Failed(evidence: telemetry.MaybeSent, reason:) ->
          "failed after send: " <> telemetry.transport_reason_name(reason)
        telemetry.Failed(evidence: telemetry.NotSent, reason:) ->
          "not sent: " <> telemetry.transport_reason_name(reason)
      }
      let method = case request.method {
        telemetry.Get -> "GET"
        telemetry.Post -> "POST"
      }
      io.println(
        "hellhound http "
        <> method
        <> " "
        <> request.host
        <> request.path
        <> " -> "
        <> outcome
        <> " ("
        <> int.to_string(measurements.duration_ms)
        <> " ms)",
      )
    })
  Nil
}
