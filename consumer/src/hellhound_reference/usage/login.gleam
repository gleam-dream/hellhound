//// Usage: sign a user in, call an API with the token, sign out.
////
//// `common_path_test` exercises this path against the local test provider.

// snips-start: login
import gleam/http/request.{type Request}
import gleam/http/response.{type Response}
import gleam/result
import hellhound
import hellhound/config

pub fn start(secret: String) -> Result(hellhound.Client, hellhound.StartError) {
  let config =
    config.new(
      issuer: "https://login.example.com",
      client_id: "app",
      redirect_uri: "https://app.example.com/auth/callback",
      authentication: config.ClientSecretBasic(config.secret(secret)),
    )
    |> config.with_scopes(["email", "profile"])
  // Validates; starts nothing.
  use client <- result.try(hellhound.new(config))
  // Discovery, keys, processes.
  use Nil <- result.map(hellhound.start(client))
  client
}

/// GET /login: Hellhound sets the browser-binding cookie and the redirect.
pub fn login(client: hellhound.Client, req: Request(a)) -> Response(String) {
  case hellhound.begin_login(client, req, hellhound.default_login()) {
    Ok(redirect) -> hellhound.login_response(response.new(303), redirect)
    Error(error) ->
      response.new(503)
      |> response.set_body(hellhound.describe_login_error(error))
  }
}

/// GET (or POST, for form-post) /auth/callback, with the body as a String.
pub fn callback(
  client: hellhound.Client,
  req: Request(String),
) -> Result(String, hellhound.Action) {
  case hellhound.complete_login(client, req) {
    // Keep the reference in the application's session.
    Ok(session) -> Ok(hellhound.session_reference(session))
    // Reauthenticate, RejectRequest, Recover, ...
    Error(error) -> Error(hellhound.login_error_action(error))
  }
}

/// Any later request: a current token, refreshed within 30 s of expiry;
/// concurrent requests share one refresh.
pub fn call_api(
  client: hellhound.Client,
  reference: String,
  api_request: Request(a),
) -> Result(Request(a), hellhound.SessionError) {
  use session <- result.try(hellhound.restore_session(client, reference))
  use access <- result.map(hellhound.access_token(client, session))
  hellhound.authorize(api_request, access.token)
}

/// POST /logout: custody removed, refresh token revoked (RFC 7009).
pub fn logout(
  client: hellhound.Client,
  session: hellhound.Session,
) -> Response(String) {
  case hellhound.logout(client, session, hellhound.default_logout()) {
    Ok(hellhound.LoggedOut(
      provider_logout: hellhound.RedirectToProvider(redirect),
      ..,
    )) -> hellhound.logout_response(response.new(303), redirect)
    _ -> response.new(303) |> response.set_header("location", "/")
  }
}
// snips-end: login
