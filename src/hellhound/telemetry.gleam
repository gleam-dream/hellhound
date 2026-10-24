//// Typed Hellhound events, as `sinal` descriptors over `:telemetry`.
////
//// Every event carries closed, non-secret values only: no token, code,
//// state, nonce, verifier, secret, claim, identity, query string, header or
//// body ever reaches an event. Each carries the `correlation` that the
//// caller set with `hellhound.with_correlation`, which Hellhound also passes to
//// its HTTP Gun requests.
////
//// | Event | When |
//// | --- | --- |
//// | `[hellhound, http, request]` (`http_request`) | an outbound provider request completes or fails |
//// | `[hellhound, login]` (`login`) | `complete_login` or `recover_custody` returns |
//// | `[hellhound, refresh]` (`refresh`) | a refresh completes, joins another, or fails |
//// | `[hellhound, logout]` (`logout`) | `logout` ends a session |
////
//// ```gleam
//// sinal.observe(telemetry.http_request(), fn(measurements, request) {
////   // measurements.duration_ms, request.host, request.outcome, ...
////   Nil
//// })
//// ```

import gleam/dynamic.{type Dynamic}
import gleam/dynamic/decode
import gleam/erlang/atom
import gleam/option.{type Option}
import sinal
import sinal/correlation.{type Correlation}
import sinal/fields

// ---------------------------------------------------------------------------
// HTTP requests

pub type HttpMeasurements {
  HttpMeasurements(duration_ms: Int)
}

/// `[hellhound, http, request]` metadata: discovery, keys, token, userinfo,
/// introspection and revocation requests. Queries are never recorded.
pub type HttpRequest {
  HttpRequest(
    method: HttpMethod,
    host: String,
    path: String,
    outcome: Outcome,
    correlation: Option(Correlation),
  )
}

pub type HttpMethod {
  Get
  Post
}

/// A response status, or a failure with its submission evidence.
pub type Outcome {
  Status(code: Int)
  Failed(evidence: Evidence, reason: TransportReason)
}

/// Whether a failed request may have reached the provider.
pub type Evidence {
  /// Proven not sent.
  NotSent
  /// May have been sent.
  MaybeSent
}

/// The closed transport failure reasons, as `hellhound.TransportReason` names
/// them. May gain variants as HTTP Gun does.
pub type TransportReason {
  DestinationRejected
  InsecureScheme
  InvalidDestination
  ResolutionFailed
  ConnectionRefused
  ConnectionFailed
  TlsRejected
  Timeout
  ResponseTooLarge
  ResponseHeadersTooLarge
  MalformedHttp
  ReceiveFailed
  UnsupportedContentEncoding
  OtherTransportFailure
}

/// The descriptor for `[hellhound, http, request]`. On the wire the metadata is
/// `#{method => <<"get">> | <<"post">>, host => Binary, path => Binary,
/// outcome => {status, Code} | {failure, not_sent | maybe_sent, Reason},
/// correlation => Binary}` (correlation omitted when unset) and the
/// measurements are `#{duration_ms => Integer}`.
pub fn http_request() -> sinal.Event(HttpMeasurements, HttpRequest) {
  let metadata = {
    use method <- fields.include(
      fields.enum("method", [Get, Post], fn(m) {
        case m {
          Get -> "get"
          Post -> "post"
        }
      }),
      get: fn(r) { r.method },
    )
    use host <- fields.include(fields.string("host"), get: fn(r) { r.host })
    use path <- fields.include(fields.string("path"), get: fn(r) { r.path })
    use outcome <- fields.include(outcome_field(), get: fn(r) { r.outcome })
    use correlation <- fields.include(correlation.field(), get: fn(r) {
      r.correlation
    })
    fields.success(HttpRequest(method:, host:, path:, outcome:, correlation:))
  }
  sinal.event(["hellhound", "http", "request"], duration(), metadata)
}

fn duration() -> fields.Fields(HttpMeasurements) {
  use duration_ms <- fields.include(fields.int("duration_ms"), get: fn(m) {
    m.duration_ms
  })
  fields.success(HttpMeasurements(duration_ms:))
}

/// Every transport reason, for codecs and tests.
pub const transport_reasons = [
  DestinationRejected,
  InsecureScheme,
  InvalidDestination,
  ResolutionFailed,
  ConnectionRefused,
  ConnectionFailed,
  TlsRejected,
  Timeout,
  ResponseTooLarge,
  ResponseHeadersTooLarge,
  MalformedHttp,
  ReceiveFailed,
  UnsupportedContentEncoding,
  OtherTransportFailure,
]

/// The snake_case wire name of a transport reason.
pub fn transport_reason_name(reason: TransportReason) -> String {
  case reason {
    DestinationRejected -> "destination_rejected"
    InsecureScheme -> "insecure_scheme"
    InvalidDestination -> "invalid_destination"
    ResolutionFailed -> "resolution_failed"
    ConnectionRefused -> "connection_refused"
    ConnectionFailed -> "connection_failed"
    TlsRejected -> "tls_rejected"
    Timeout -> "timeout"
    ResponseTooLarge -> "response_too_large"
    ResponseHeadersTooLarge -> "response_headers_too_large"
    MalformedHttp -> "malformed_http"
    ReceiveFailed -> "receive_failed"
    UnsupportedContentEncoding -> "unsupported_content_encoding"
    OtherTransportFailure -> "other_transport_failure"
  }
}

fn outcome_field() -> fields.Fields(Outcome) {
  let status = {
    use tag <- decode.field(0, atom.decoder())
    use code <- decode.field(1, decode.int)
    case atom.to_string(tag) {
      "status" -> decode.success(Status(code))
      _ -> decode.failure(Status(0), "outcome")
    }
  }
  let failure = {
    use tag <- decode.field(0, atom.decoder())
    use evidence <- decode.field(1, atom.decoder())
    use reason <- decode.field(2, atom.decoder())
    let reason = atom.to_string(reason)
    let found = find_reason(transport_reasons, reason)
    case atom.to_string(tag), atom.to_string(evidence), found {
      "failure", "not_sent", Ok(reason) ->
        decode.success(Failed(NotSent, reason))
      "failure", "maybe_sent", Ok(reason) ->
        decode.success(Failed(MaybeSent, reason))
      _, _, _ -> decode.failure(Status(0), "outcome")
    }
  }
  fields.field("outcome", encode_outcome, decode.one_of(status, [failure]))
}

fn find_reason(
  reasons: List(TransportReason),
  name: String,
) -> Result(TransportReason, Nil) {
  case reasons {
    [] -> Error(Nil)
    [first, ..rest] ->
      case transport_reason_name(first) == name {
        True -> Ok(first)
        False -> find_reason(rest, name)
      }
  }
}

fn encode_outcome(outcome: Outcome) -> Dynamic {
  case outcome {
    Status(code) -> to_dynamic(#(atom.create("status"), code))
    Failed(evidence:, reason:) ->
      to_dynamic(#(
        atom.create("failure"),
        atom.create(case evidence {
          NotSent -> "not_sent"
          MaybeSent -> "maybe_sent"
        }),
        atom.create(transport_reason_name(reason)),
      ))
  }
}

@external(erlang, "gleam_stdlib", "identity")
fn to_dynamic(value: a) -> Dynamic

// ---------------------------------------------------------------------------
// Session events

pub type SessionMeasurements {
  SessionMeasurements(duration_ms: Int)
}

/// `[hellhound, login]` metadata.
pub type Login {
  Login(outcome: LoginOutcome, correlation: Option(Correlation))
}

pub type LoginOutcome {
  /// A session was installed.
  LoginSucceeded
  /// The callback was malformed, unbound to this browser, replayed or
  /// expired; nothing was sent.
  LoginCallbackRefused
  /// The provider denied the authorization.
  LoginDenied
  /// The code exchange failed or its outcome is unknown.
  LoginExchangeFailed
  /// Tokens arrived but the identity was not accepted.
  LoginIdentityRejected
  /// Installation was not confirmed; a recovery value was returned.
  LoginCustodyUnconfirmed
  /// A store did not answer, or the login timed out before the exchange.
  LoginUnavailable
}

pub const login_outcomes = [
  LoginSucceeded,
  LoginCallbackRefused,
  LoginDenied,
  LoginExchangeFailed,
  LoginIdentityRejected,
  LoginCustodyUnconfirmed,
  LoginUnavailable,
]

/// The descriptor for `[hellhound, login]`; `outcome` is a snake_case binary.
pub fn login() -> sinal.Event(SessionMeasurements, Login) {
  let metadata = {
    use outcome <- fields.include(
      fields.enum("outcome", login_outcomes, fn(o) {
        case o {
          LoginSucceeded -> "succeeded"
          LoginCallbackRefused -> "callback_refused"
          LoginDenied -> "denied"
          LoginExchangeFailed -> "exchange_failed"
          LoginIdentityRejected -> "identity_rejected"
          LoginCustodyUnconfirmed -> "custody_unconfirmed"
          LoginUnavailable -> "unavailable"
        }
      }),
      get: fn(m) { m.outcome },
    )
    use correlation <- fields.include(correlation.field(), get: fn(m) {
      m.correlation
    })
    fields.success(Login(outcome:, correlation:))
  }
  sinal.event(["hellhound", "login"], session_duration(), metadata)
}

/// `[hellhound, refresh]` metadata.
pub type Refresh {
  Refresh(outcome: RefreshOutcome, correlation: Option(Correlation))
}

pub type RefreshOutcome {
  /// This request refreshed the session.
  Refreshed
  /// Another request's refresh was waited for and used.
  RefreshJoined
  /// Proven not sent; the generation was released.
  RefreshNotSent
  /// Rejected before grant processing; the generation was released.
  RefreshRejected
  /// The refresh token is revoked (`invalid_grant`).
  RefreshRevoked
  /// The generation is quarantined after an uncertain outcome.
  RefreshQuarantined
  /// Another request's refresh did not settle within the wait.
  RefreshWaitTimedOut
  /// Publication was not confirmed; a recovery value was returned.
  RefreshUnconfirmed
  /// The custody store did not answer.
  RefreshUnavailable
}

pub const refresh_outcomes = [
  Refreshed,
  RefreshJoined,
  RefreshNotSent,
  RefreshRejected,
  RefreshRevoked,
  RefreshQuarantined,
  RefreshWaitTimedOut,
  RefreshUnconfirmed,
  RefreshUnavailable,
]

/// The descriptor for `[hellhound, refresh]`; `outcome` is a snake_case binary.
pub fn refresh() -> sinal.Event(SessionMeasurements, Refresh) {
  let metadata = {
    use outcome <- fields.include(
      fields.enum("outcome", refresh_outcomes, fn(o) {
        case o {
          Refreshed -> "refreshed"
          RefreshJoined -> "joined"
          RefreshNotSent -> "not_sent"
          RefreshRejected -> "rejected"
          RefreshRevoked -> "revoked"
          RefreshQuarantined -> "quarantined"
          RefreshWaitTimedOut -> "wait_timed_out"
          RefreshUnconfirmed -> "unconfirmed"
          RefreshUnavailable -> "unavailable"
        }
      }),
      get: fn(m) { m.outcome },
    )
    use correlation <- fields.include(correlation.field(), get: fn(m) {
      m.correlation
    })
    fields.success(Refresh(outcome:, correlation:))
  }
  sinal.event(["hellhound", "refresh"], session_duration(), metadata)
}

/// `[hellhound, logout]` metadata: emitted once custody is removed.
pub type Logout {
  Logout(revocation: Revocation, correlation: Option(Correlation))
}

pub type Revocation {
  Revoked
  RevocationUnsupported
  RevocationFailed
  RevocationSkipped
}

pub const revocations = [
  Revoked,
  RevocationUnsupported,
  RevocationFailed,
  RevocationSkipped,
]

/// The descriptor for `[hellhound, logout]`; `revocation` is a snake_case
/// binary.
pub fn logout() -> sinal.Event(SessionMeasurements, Logout) {
  let metadata = {
    use revocation <- fields.include(
      fields.enum("revocation", revocations, fn(r) {
        case r {
          Revoked -> "revoked"
          RevocationUnsupported -> "unsupported"
          RevocationFailed -> "failed"
          RevocationSkipped -> "skipped"
        }
      }),
      get: fn(m) { m.revocation },
    )
    use correlation <- fields.include(correlation.field(), get: fn(m) {
      m.correlation
    })
    fields.success(Logout(revocation:, correlation:))
  }
  sinal.event(["hellhound", "logout"], session_duration(), metadata)
}

fn session_duration() -> fields.Fields(SessionMeasurements) {
  use duration_ms <- fields.include(fields.int("duration_ms"), get: fn(m) {
    m.duration_ms
  })
  fields.success(SessionMeasurements(duration_ms:))
}
