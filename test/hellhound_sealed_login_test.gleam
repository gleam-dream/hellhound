//// The pending login lives in a sealed cookie held by the browser that
//// started it: a forged, tampered, foreign or expired cookie is refused
//// before any token request, parallel logins in one browser each keep
//// their own cookie, and a flood of login starts leaves no shared state
//// that could refuse another browser's login.

import gleam/http/request.{type Request}
import gleam/http/response
import gleam/list
import gleam/option.{Some}
import gleam/string
import gleam/time/duration
import gleam/uri
import hellhound
import hellhound/config
import hellhound/testing
import hellhound_login_test.{authorize, param, settings, start, with_clock}
import hellhound_store_support as faults
import hellhound_test_support as support

/// The `name=value` pair of the login cookie a redirect sets.
fn login_cookie(redirect: hellhound.LoginRedirect) -> #(String, String) {
  let assert Ok(header) =
    list.key_find(testing.browser_request(redirect).headers, "cookie")
  let assert Ok(pair) = string.split_once(header, "=")
  pair
}

fn with_cookies(
  request: Request(String),
  cookies: List(#(String, String)),
) -> Request(String) {
  let header =
    cookies
    |> list.map(fn(pair) { pair.0 <> "=" <> pair.1 })
    |> string.join("; ")
  request.set_header(request, "cookie", header)
}

/// Flip one character of a base64url value.
fn flip(value: String) -> String {
  let #(head, last) = #(string.drop_end(value, 1), string.last(value))
  case last {
    Ok("A") -> head <> "B"
    _ -> head <> "A"
  }
}

pub fn tampered_login_cookie_is_refused_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let assert Ok(redirect) =
    hellhound.begin_login(client, hellhound.default_login())
  let request = authorize(provider, redirect, "tampered-code")
  let #(name, value) = login_cookie(redirect)
  // One flipped character in the middle of the ciphertext.
  let middle = string.length(value) / 2
  let tampered =
    string.slice(value, 0, middle)
    <> flip(string.slice(value, middle, 1))
    <> string.drop_start(value, middle + 1)
  assert hellhound.complete_login(
      client,
      with_cookies(request, [#(name, tampered)]),
    )
    == Error(hellhound.CallbackRejected(hellhound.LoginCookieInvalid))
  assert support.token_requests(provider) == 0
  hellhound.stop(client)
  support.provider_stop(provider)
}

pub fn forged_login_cookie_is_refused_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let assert Ok(redirect) =
    hellhound.begin_login(client, hellhound.default_login())
  let request = authorize(provider, redirect, "forged-code")
  let #(name, _) = login_cookie(redirect)
  let forged = string.repeat("A", 400)
  assert hellhound.complete_login(
      client,
      with_cookies(request, [#(name, forged)]),
    )
    == Error(hellhound.CallbackRejected(hellhound.LoginCookieInvalid))
  // A login sealed by another client under its own key does not open here.
  let other = start(settings(provider))
  let assert Ok(foreign) =
    hellhound.begin_login(other, hellhound.default_login())
  let #(_, foreign_value) = login_cookie(foreign)
  assert hellhound.complete_login(
      client,
      with_cookies(request, [#(name, foreign_value)]),
    )
    == Error(hellhound.CallbackRejected(hellhound.LoginCookieInvalid))
  assert support.token_requests(provider) == 0
  hellhound.stop(other)
  hellhound.stop(client)
  support.provider_stop(provider)
}

/// The cookie is sealed for its own state: a valid cookie of another login
/// presented under this login's name does not open.
pub fn login_cookie_is_bound_to_its_state_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let assert Ok(first) =
    hellhound.begin_login(client, hellhound.default_login())
  let assert Ok(second) =
    hellhound.begin_login(client, hellhound.default_login())
  let request = authorize(provider, first, "swapped-code")
  let #(name, _) = login_cookie(first)
  let #(_, other_value) = login_cookie(second)
  assert hellhound.complete_login(
      client,
      with_cookies(request, [#(name, other_value)]),
    )
    == Error(hellhound.CallbackRejected(hellhound.LoginCookieInvalid))
  assert support.token_requests(provider) == 0
  hellhound.stop(client)
  support.provider_stop(provider)
}

/// A callback from a browser that did not start the login (login CSRF) has
/// no cookie for its state.
pub fn callback_without_its_login_cookie_is_refused_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let assert Ok(redirect) =
    hellhound.begin_login(client, hellhound.default_login())
  let request = authorize(provider, redirect, "csrf-code")
  assert hellhound.complete_login(
      client,
      request.Request(..request, headers: []),
    )
    == Error(hellhound.CallbackRejected(hellhound.LoginCookieMissing))
  assert support.token_requests(provider) == 0
  hellhound.stop(client)
  support.provider_stop(provider)
}

/// Two clients sharing one sealing key (for example two tenants of one
/// application) do not accept each other's logins: the sealed login names
/// its issuer and client id.
pub fn login_of_another_client_is_refused_test() {
  let provider = support.provider_start(support.Standard)
  let other_provider = support.provider_start(support.Standard)
  let key = faults.sealing_key()
  let client = start(settings(provider) |> config.with_sealing_key(key))
  // Same issuer, another client id.
  let sibling =
    start(
      config.new(
        issuer: support.provider_issuer(provider),
        client_id: "another-rp",
        redirect_uri: "https://app.example/callback",
        authentication: config.ClientSecretBasic(config.secret("other-secret")),
      )
      |> config.with_trust(config.TrustAnchorsPem(support.ca_pem()))
      |> config.with_destinations(config.AllowLoopbackForTesting)
      |> config.with_signing_algorithms([config.Rs256])
      |> config.with_sealing_key(key),
    )
  // Same client id, another issuer.
  let tenant = start(settings(other_provider) |> config.with_sealing_key(key))
  let assert Ok(redirect) =
    hellhound.begin_login(client, hellhound.default_login())
  let request = authorize(provider, redirect, "mixed-code")
  assert hellhound.complete_login(sibling, request)
    == Error(hellhound.CallbackRejected(hellhound.ForeignLogin))
  assert hellhound.complete_login(tenant, request)
    == Error(hellhound.CallbackRejected(hellhound.ForeignLogin))
  assert support.token_requests(provider) == 0
  assert support.token_requests(other_provider) == 0
  // The login still completes at the client that started it.
  let assert Ok(_) = hellhound.complete_login(client, request)
  hellhound.stop(tenant)
  hellhound.stop(sibling)
  hellhound.stop(client)
  support.provider_stop(other_provider)
  support.provider_stop(provider)
}

pub fn expired_login_cookie_is_refused_test() {
  let provider = support.provider_start(support.Standard)
  let base = support.now_seconds()
  let clock = support.clock_new(base)
  let client =
    start(
      settings(provider)
      |> config.with_login_lifetime(duration.seconds(60))
      |> with_clock(clock),
    )
  let assert Ok(redirect) =
    hellhound.begin_login(client, hellhound.default_login())
  let request = authorize(provider, redirect, "late-code")
  support.clock_set(clock, base + 60)
  assert hellhound.complete_login(client, request)
    == Error(hellhound.LoginExpired)
  assert support.token_requests(provider) == 0
  hellhound.stop(client)
  support.provider_stop(provider)
}

/// Two tabs of one browser start two logins. Each has its own cookie, the
/// browser sends both to the callback, and each callback completes.
pub fn parallel_logins_in_one_browser_both_complete_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  let assert Ok(first) =
    hellhound.begin_login(client, hellhound.default_login())
  let assert Ok(second) =
    hellhound.begin_login(client, hellhound.default_login())
  let cookies = [login_cookie(first), login_cookie(second)]
  assert { login_cookie(first).0 } != { login_cookie(second).0 }
  let second_callback =
    authorize(provider, second, "tab-2") |> with_cookies(cookies)
  let first_callback =
    authorize(provider, first, "tab-1") |> with_cookies(cookies)
  let assert Ok(_) = hellhound.complete_login(client, second_callback)
  let assert Ok(_) = hellhound.complete_login(client, first_callback)
  assert support.token_requests(provider) == 2
  hellhound.stop(client)
  support.provider_stop(provider)
}

/// Starting a login stores nothing on the server, so any number of starts
/// leaves another browser's login unaffected.
pub fn login_flood_leaves_other_logins_working_test() {
  let provider = support.provider_start(support.Standard)
  let client = start(settings(provider))
  list.repeat(Nil, 5000)
  |> list.each(fn(_) {
    let assert Ok(_) = hellhound.begin_login(client, hellhound.default_login())
    Nil
  })
  let assert Ok(redirect) =
    hellhound.begin_login(client, hellhound.default_login())
  let assert Ok(_) =
    hellhound.complete_login(client, authorize(provider, redirect, "victim"))
  hellhound.stop(client)
  support.provider_stop(provider)
}

/// The login cookie is `__Secure-`, `HttpOnly`, scoped to the callback path,
/// `SameSite=Lax` (`None` for form post) and lives one login lifetime. The
/// callback response expires it.
pub fn login_cookie_attributes_and_clearing_test() {
  let assert Ok(provider) = testing.start_provider(testing.provider_options())
  let assert Ok(client) =
    hellhound.new(testing.config(provider, "https://app.test/auth/callback"))
  let assert Ok(Nil) = hellhound.start(client)
  let assert Ok(redirect) =
    hellhound.begin_login(client, hellhound.default_login())
  let reply = hellhound.login_response(response.new(200), redirect)
  assert reply.status == 303
  assert response.get_header(reply, "location")
    == Ok(hellhound.login_url(redirect))
  assert response.get_header(reply, "cache-control") == Ok("no-store")
  let assert Ok(set) = response.get_header(reply, "set-cookie")
  let #(name, value) = login_cookie(redirect)
  assert string.starts_with(set, name <> "=" <> value <> ";")
  assert string.starts_with(name, "__Secure-hellhound_login_")
  list.each(
    ["Secure", "HttpOnly", "Path=/auth/callback", "SameSite=Lax", "Max-Age=600"],
    fn(attribute) {
      assert #(attribute, string.contains(set, attribute)) == #(attribute, True)
    },
  )
  assert !string.contains(set, "Domain")
  // The cookie holds the sealed login, well under the 4 KiB browsers keep.
  assert string.byte_size(set) < 1024
  // The callback response expires exactly this login's cookie.
  let state = param(hellhound.login_url(redirect), "state")
  let callback =
    request.Request(
      ..testing.browser_request(redirect),
      path: "/auth/callback",
      query: Some(uri.query_to_string([#("code", "c"), #("state", state)])),
    )
  let cleared = hellhound.callback_response(response.new(303), client, callback)
  let assert Ok(expiry) = response.get_header(cleared, "set-cookie")
  assert string.starts_with(expiry, name <> "=;")
  assert string.contains(expiry, "Max-Age=0")
  assert string.contains(expiry, "Path=/auth/callback")
  hellhound.stop(client)
  let assert Ok(form_client) =
    hellhound.new(
      testing.config(provider, "https://app.test/auth/callback")
      |> config.with_response_mode(config.FormPost),
    )
  let assert Ok(Nil) = hellhound.start(form_client)
  let assert Ok(form) =
    hellhound.begin_login(form_client, hellhound.default_login())
  let assert Ok(form_set) =
    response.get_header(
      hellhound.login_response(response.new(200), form),
      "set-cookie",
    )
  assert string.contains(form_set, "SameSite=None")
  assert string.contains(form_set, "Secure")
  hellhound.stop(form_client)
  testing.stop_provider(provider)
}
