//// Reference relying party routes. Public Hellhound imports only.

import gleam/bit_array
import gleam/crypto
import gleam/dynamic/decode
import gleam/erlang/atom
import gleam/http
import gleam/http/request as http_request
import gleam/http/response
import gleam/list
import gleam/option.{type Option, None, Some}
import gleam/result
import gleam/string
import hellhound
import hellhound_reference/protect
import wisp.{type Request, type Response}

pub type Context {
  Context(
    client: hellhound.Client,
    issuer: String,
    post_logout_redirect_uri: String,
    /// This application's origin, for the same-origin check on POSTs.
    origin: String,
  )
}

const session_cookie = protect.session_cookie

/// Server-side session lifetime, also the session cookie's Max-Age.
const session_max_age = 3600

pub fn handle(request: Request, context: Context) -> Response {
  use <- wisp.rescue_crashes
  protect.security_headers(route(request, context))
}

fn route(request: Request, context: Context) -> Response {
  case request.method, wisp.path_segments(request) {
    http.Get, [] -> home(request, context)
    http.Get, ["login"] -> login(request, context, None)
    http.Get, ["initiate-login"] -> third_party_initiated(request, context)
    http.Get, ["callback"] ->
      callback(request, context, http_request.set_body(request, ""))
    http.Post, ["callback"] -> {
      use body <- wisp.require_string_body(request)
      callback(request, context, http_request.set_body(request, body))
    }
    http.Post, ["refresh"] -> {
      use <- same_origin(request, context)
      refresh(request, context)
    }
    http.Get, ["userinfo"] -> userinfo(request, context)
    http.Get, ["client-token"] -> client_token(request, context)
    http.Post, ["logout"] -> {
      use <- same_origin(request, context)
      logout(request, context)
    }
    http.Get, ["logged-out"] ->
      page(200, "Signed out", "<p>You are signed out.</p>")
    http.Get, ["health"] -> wisp.ok()
    // Front-channel logout is not implemented by Hellhound (explicit gap); the
    // route exists only so logout plans accept the client configuration.
    http.Get, ["frontchannel-logout"] -> wisp.ok()
    _, _ -> wisp.not_found()
  }
}

/// Refuse state-changing requests that do not come from this application's
/// own pages (cross-site request forgery).
fn same_origin(
  request: Request,
  context: Context,
  next: fn() -> Response,
) -> Response {
  case protect.same_origin(request, context.origin) {
    True -> next()
    False -> page(403, "Forbidden", "<p>Cross-site request refused.</p>")
  }
}

// --- Login -------------------------------------------------------------------

fn login(request: Request, context: Context, hint: Option(String)) -> Response {
  let options =
    hellhound.LoginOptions(..hellhound.default_login(), login_hint: hint)
  case hellhound.begin_login(context.client, request, options) {
    // Hellhound sets the browser-binding cookie and the redirect.
    Ok(redirect) -> hellhound.login_response(wisp.response(303), redirect)
    Error(error) ->
      page(
        503,
        "Sign-in unavailable",
        escape(hellhound.describe_login_error(error)),
      )
  }
}

/// OpenID Connect third-party initiated login: accept only this issuer.
fn third_party_initiated(request: Request, context: Context) -> Response {
  let query = wisp.get_query(request)
  case list.key_find(query, "iss") {
    Ok(issuer) if issuer == context.issuer ->
      login(
        request,
        context,
        option.from_result(list.key_find(query, "login_hint")),
      )
    _ -> page(400, "Unknown issuer", "<p>Login initiation rejected.</p>")
  }
}

fn callback(
  request: Request,
  context: Context,
  callback: http_request.Request(String),
) -> Response {
  let completed = case hellhound.complete_login(context.client, callback) {
    // Installation unconfirmed: resubmit once; the code is not exchanged
    // again.
    Error(hellhound.CustodyUnconfirmed(recovery)) ->
      hellhound.recover_custody(context.client, recovery)
    other -> other
  }
  case completed {
    Ok(session) ->
      // Userinfo is fetched after every login; a subject mismatch rejects it.
      case hellhound.userinfo(context.client, session) {
        Ok(_) | Error(hellhound.UserinfoNotSupported) ->
          wisp.redirect("/")
          |> response.set_cookie(
            session_cookie,
            wisp.sign_message(
              request,
              <<
                protect.session_value(
                  hellhound.session_reference(session),
                  issued_at: now_seconds(),
                ):utf8,
              >>,
              crypto.Sha512,
            ),
            protect.session_attributes(session_max_age),
          )
        Error(error) -> {
          let _ =
            hellhound.logout(
              context.client,
              session,
              hellhound.default_logout(),
            )
          failure_page(BadRequest(
            "userinfo rejected: " <> hellhound.describe_userinfo_error(error),
          ))
        }
      }
    Error(error) -> failure_page(login_failure(error))
  }
}

/// The application's own failure vocabulary.
pub type AppFailure {
  /// Start a new login; the old one cannot be resumed.
  RetryLogin(reason: String)
  /// The request itself is invalid or not ours.
  BadRequest(reason: String)
  /// A dependency is unavailable; retrying later may succeed.
  TryLater(reason: String)
}

/// Hellhound login errors mapped by their action: the union may grow, the
/// action does not.
pub fn login_failure(error: hellhound.LoginError) -> AppFailure {
  let reason = hellhound.describe_login_error(error)
  case hellhound.login_error_action(error) {
    hellhound.Reauthenticate -> RetryLogin(reason)
    hellhound.RejectRequest -> BadRequest(reason)
    hellhound.RetryLater | hellhound.Recover | hellhound.FixConfiguration ->
      TryLater(reason)
  }
}

fn failure_page(failure: AppFailure) -> Response {
  case failure {
    RetryLogin(reason) ->
      page(
        401,
        "Sign-in failed",
        "<p>"
          <> escape(reason)
          <> "</p><p><a href=\"/login\">Sign in again</a></p>",
      )
    BadRequest(reason) ->
      page(400, "Bad request", "<p>" <> escape(reason) <> "</p>")
    TryLater(reason) ->
      page(503, "Try again later", "<p>" <> escape(reason) <> "</p>")
  }
}

// --- Session -----------------------------------------------------------------

fn session(
  request: Request,
  context: Context,
) -> Result(hellhound.Session, Nil) {
  use value <- result.try(wisp.get_cookie(request, session_cookie, wisp.Signed))
  use reference <- result.try(protect.read_session_value(
    value,
    now: now_seconds(),
    max_age: session_max_age,
  ))
  hellhound.restore_session(context.client, reference)
  |> result.replace_error(Nil)
}

fn now_seconds() -> Int {
  system_time(atom.create("second"))
}

@external(erlang, "erlang", "system_time")
fn system_time(unit: atom.Atom) -> Int

/// A caller-owned claim type decoded from verified ID-token claims.
pub type Profile {
  Profile(department: Option(String), locale: Option(String))
}

pub fn profile_decoder() -> decode.Decoder(Profile) {
  use department <- decode.optional_field(
    "department",
    None,
    decode.optional(decode.string),
  )
  use locale <- decode.optional_field(
    "locale",
    None,
    decode.optional(decode.string),
  )
  decode.success(Profile(department:, locale:))
}

fn home(request: Request, context: Context) -> Response {
  case session(request, context) {
    Error(Nil) ->
      page(
        200,
        "Hellhound reference RP",
        "<p><a id=\"login\" href=\"/login\">Sign in</a></p>",
      )
    Ok(s) -> {
      let identity = hellhound.session_identity(s)
      let profile =
        hellhound.decode_claims(identity, profile_decoder())
        |> result.unwrap(Profile(None, None))
      page(
        200,
        "Signed in",
        "<dl><dt>Issuer</dt><dd id=\"issuer\">"
          <> escape(hellhound.issuer(identity))
          <> "</dd><dt>Subject</dt><dd id=\"subject\">"
          <> escape(hellhound.subject(identity))
          <> "</dd><dt>Email</dt><dd id=\"email\">"
          <> escape(option.unwrap(hellhound.email(identity), ""))
          <> "</dd><dt>Department</dt><dd id=\"department\">"
          <> escape(option.unwrap(profile.department, ""))
          <> "</dd><dt>Token</dt><dd id=\"token\">"
          <> token_fingerprint(context, s)
          <> "</dd></dl>"
          <> "<form method=\"post\" action=\"/refresh\"><button id=\"refresh\">Refresh</button></form>"
          <> "<form method=\"post\" action=\"/logout\"><button id=\"logout\">Sign out</button></form>",
      )
    }
  }
}

/// A short digest of the session's current access token, so a page can
/// show that a refresh replaced it without showing the token.
fn token_fingerprint(context: Context, session: hellhound.Session) -> String {
  case hellhound.access_token(context.client, session) {
    Ok(access) ->
      crypto.hash(crypto.Sha256, <<
        hellhound.access_token_value(access.token):utf8,
      >>)
      |> bit_array.base16_encode
      |> string.slice(0, 12)
    Error(_) -> ""
  }
}

fn refresh(request: Request, context: Context) -> Response {
  case session(request, context) {
    Error(Nil) -> wisp.redirect("/")
    Ok(s) -> {
      let refreshed = case hellhound.refresh(context.client, s) {
        Error(hellhound.RefreshUnconfirmed(recovery)) ->
          hellhound.recover_refresh(context.client, recovery)
        other -> other
      }
      let outcome = case refreshed {
        Ok(access) ->
          case hellhound.userinfo(context.client, access.session) {
            Ok(_) | Error(hellhound.UserinfoNotSupported) -> "completed"
            Error(_) -> "completed-userinfo-rejected"
          }
        Error(error) ->
          case hellhound.session_error_action(error) {
            hellhound.Reauthenticate -> "reauthenticate"
            hellhound.RetryLater -> "retry-later"
            hellhound.Recover -> "unresolved"
            hellhound.FixConfiguration | hellhound.RejectRequest -> "error"
          }
      }
      page(
        200,
        "Refresh",
        "<p id=\"refresh-outcome\">"
          <> escape(outcome)
          <> "</p><p><a href=\"/\">Back</a></p>",
      )
    }
  }
}

fn userinfo(request: Request, context: Context) -> Response {
  case session(request, context) {
    Error(Nil) -> wisp.response(401)
    Ok(s) ->
      case hellhound.userinfo(context.client, s) {
        Ok(info) ->
          wisp.json_response(
            "{\"sub\":\""
              <> json_escape(hellhound.userinfo_subject(info))
              <> "\"}",
            200,
          )
        Error(error) ->
          page(
            502,
            "Userinfo failed",
            escape(hellhound.describe_userinfo_error(error)),
          )
      }
  }
}

/// Signed-in users only: an anonymous route would let anyone spend the
/// client's credentials at the provider.
fn client_token(request: Request, context: Context) -> Response {
  use <- signed_in(request, context)
  case hellhound.client_credentials(context.client, []) {
    Ok(token) ->
      wisp.json_response(
        "{\"expires\":" <> bool_json(option.is_some(token.expires_at)) <> "}",
        200,
      )
    Error(error) ->
      page(
        502,
        "Client credentials failed",
        escape(hellhound.describe_client_credentials_error(error)),
      )
  }
}

fn signed_in(
  request: Request,
  context: Context,
  next: fn() -> Response,
) -> Response {
  case session(request, context) {
    Ok(_) -> next()
    Error(Nil) -> wisp.response(401)
  }
}

fn bool_json(value: Bool) -> String {
  case value {
    True -> "true"
    False -> "false"
  }
}

fn logout(request: Request, context: Context) -> Response {
  let cleared = fn(response) {
    response.set_cookie(
      response,
      session_cookie,
      "",
      protect.session_attributes(0),
    )
  }
  case session(request, context) {
    Error(Nil) -> wisp.redirect("/logged-out") |> cleared
    Ok(s) -> {
      let options =
        hellhound.LogoutOptions(
          ..hellhound.default_logout(),
          post_logout_redirect_uri: Some(context.post_logout_redirect_uri),
          state: Some(wisp.random_string(16)),
        )
      // Hellhound revokes the refresh token (RFC 7009) after removing custody;
      // a failed revocation does not keep the session.
      case hellhound.logout(context.client, s, options) {
        Ok(hellhound.LoggedOut(
          provider_logout: hellhound.RedirectToProvider(redirect),
          ..,
        )) -> hellhound.logout_response(wisp.response(303), redirect) |> cleared
        Ok(hellhound.LoggedOut(..)) -> wisp.redirect("/logged-out") |> cleared
        // Already ended (another tab's logout, or expiry): signed out.
        Error(hellhound.LogoutSession(hellhound.SessionNotFound)) ->
          wisp.redirect("/logged-out") |> cleared
        Error(error) ->
          page(
            503,
            "Sign-out failed",
            escape(hellhound.describe_logout_error(error)),
          )
      }
    }
  }
}

// --- Pages ---------------------------------------------------------------------

fn page(status: Int, title: String, body: String) -> Response {
  wisp.html_response(
    "<!doctype html><html><head><meta charset=\"utf-8\"><title>"
      <> escape(title)
      <> "</title></head><body><h1>"
      <> escape(title)
      <> "</h1>"
      <> body
      <> "</body></html>",
    status,
  )
}

fn escape(text: String) -> String {
  wisp.escape_html(text)
}

fn json_escape(text: String) -> String {
  text |> string.replace("\\", "\\\\") |> string.replace("\"", "\\\"")
}
