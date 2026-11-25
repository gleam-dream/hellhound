# Hellhound

[![CI](https://github.com/gleam-dream/hellhound/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/gleam-dream/hellhound/actions/workflows/ci.yml)
[![hellhound on Hex](https://img.shields.io/hexpm/v/hellhound?label=Hex%3A%20hellhound)](https://hex.pm/packages/hellhound)
[![Gleam](https://img.shields.io/badge/Gleam-FFAFF3?logo=gleam&logoColor=000000)](https://gleam.run/)

OIDC login, OAuth 2.0 tokens and JWT access-token validation for Gleam on
Erlang/OTP. Hellhound manages provider discovery, signing keys and token custody;
your application owns its accounts, session cookies and permission checks.

This package is pre-production. Production use requires the
[release conditions](docs/design/design-layer.pdf) and independent security review of
Hellhound-owned code. Hellhound is not certified.

## Capabilities

- OIDC authorization-code login with S256 PKCE and query or form-post callbacks.
- Checked identity and application-decoded claims, keyed by issuer and subject.
- Opaque user sessions, near-expiry refresh and shared concurrent refreshes.
- Logout with separate local-custody, revocation and provider-redirect outcomes.
- Confidential service clients for client credentials, userinfo and introspection.
- Local RFC 9068 JWT access-token validation with audience and scope policy.
- Standalone signed JWT assertions and configurable HTTPS credential exchange.
- Supervised discovery and signing-key caches with restart-stable client handles.
- Optional sealed durable custody through a conditional-record store, including
  the separate [PostgreSQL adapter](integrations/hellhound_postgres/README.md).

## When to use Hellhound

Use it to sign users into a Gleam web application through an existing identity
provider, obtain OAuth tokens for a service, or protect an API with JWT access
tokens. It does not supply an authorization server or your application's browser
session and authorization policy.

## Installation

Requires Gleam 1.18 or later and the Erlang target. Add Hellhound from Hex:

```sh
gleam add hellhound
```

Commit `gleam.toml` and `manifest.toml` to retain the resolved versions. The
[reference application](consumer/) includes the HTTP dependencies and route
integration used below.
The optional [PostgreSQL adapter](integrations/hellhound_postgres/README.md)
installs from a Git subdirectory.

### Upgrading to 0.3.0

Version 0.3.0 makes every session read return the claims of the latest verified
ID token, and adds `hellhound.current_identity` for permission checks. It has
breaking changes: new `SessionError` and `ProviderFailure` variants and a new
field on the refresh telemetry event. [CHANGELOG.md](CHANGELOG.md) lists them
with migration notes.

### Upgrading from 0.1.0 to 0.2.0

Version 0.2.0 adds standalone JWT assertion signing, PEM private-key loading and
explicit HTTPS credential exchange. Existing exhaustive matches on
`config.SigningKeyError` must handle the new `config.NotAPrivateSigningPem`
variant, including callers that only load JWK keys.

JWK `alg` and `kid` members must be strings when present. Explicit `null` values
are now rejected; omit these members when no algorithm restriction or key
identifier is intended.

## Sign an assertion and exchange it for a token

`hellhound/assertion` signs explicitly configured standard and custom JSON claims.
Load a private key with `config.signing_key_from_jwk` or
`config.signing_key_from_pem`, then select the signing algorithm. Claims are
optional at this layer: your protocol profile determines issuer, audience,
subject and lifetime. Signing reads no clock and performs no network calls.

`hellhound/exchange` sends a bearer or form assertion to an explicit HTTPS
endpoint, with an empty, form or JSON body and a caller-owned response decoder.
Create an exchange client with `exchange.new(exchange.options())` and add
`exchange.supervised(client)` to your application supervisor. It needs no OpenID
discovery. Each call sends at most one request; your application decides caching,
expiry usability and retries. Transport failures distinguish proven no-send from
possible transmission, and provider failures expose their status without raw
response bodies. Transport validation failures take precedence over a provider status, including oversized or incomplete error bodies. Ordinary inspection of requests, assertions and returned tokens
omits their credential material; explicit token accessors expose it for use.

The compiled [GitHub App and OAuth service recipes](consumer/src/hellhound_reference/usage/assertion_exchange.gleam)
show distinct claim profiles, credential placement, body encodings and absolute
or relative expiry decoders. Their [consumer tests](consumer/test/assertion_exchange_test.gleam)
run against a local HTTPS endpoint. These examples do not establish live GitHub
acceptance or RFC 7523/8693 conformance.

## Sign a user in, then call an API

Register the callback address with your issuer and load the client secret from
trusted configuration. This excerpt defines startup, login/callback handlers,
API authorization and logout:

<!-- prettier-ignore-start -->

<!-- snips: consumer/src/hellhound_reference/usage/login.gleam#login -->
```gleam
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

/// GET /login: the redirect to the provider and the sealed login cookie.
pub fn login(client: hellhound.Client) -> Response(String) {
  case hellhound.begin_login(client, hellhound.default_login()) {
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
  signed_in: fn(String) -> Response(String),
  failed: fn(hellhound.Action) -> Response(String),
) -> Response(String) {
  case hellhound.complete_login(client, req) {
    // Keep the reference in the application's session.
    Ok(session) -> signed_in(hellhound.session_reference(session))
    // Reauthenticate, RejectRequest, Recover, ...
    Error(error) -> failed(hellhound.login_error_action(error))
  }
  // Whatever the outcome, the browser drops this login's cookie.
  |> hellhound.callback_response(client, req)
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
```

<!-- prettier-ignore-end -->

The [complete module](consumer/src/hellhound_reference/usage/login.gleam) compiles in
the reference consumer. Its [common-path test](consumer/test/hellhound_reference_test.gleam)
exercises the equivalent login, token and logout flow against a local test provider.
The application stores the session reference in its protected browser session.

### How a pending login is kept

The server stores nothing between `begin_login` and the callback. The pending
login (state, nonce, PKCE verifier, redirect URI, issuer, client id and expiry)
is sealed with AES-256-GCM into a cookie that `login_response` sets:

- The cookie name is `__Host-hellhound_login_` plus a digest of the state, so
  logins started in several tabs keep separate cookies and each completes.
- The `__Host-` prefix makes the cookie `Secure`, `Path=/` and host-only (no
  `Domain`), so a sibling subdomain cannot plant a pending login of its own. A
  cookie under any other name is ignored.
- The cookie is also `HttpOnly`, `SameSite=Lax` (`None` with form-post
  callbacks) and kept for the login lifetime (10 minutes by default). With
  `Path=/` the browser sends each pending login's cookie on every request to
  the host until the callback or `Max-Age` ends it.
- `complete_login` refuses a callback whose cookie is missing
  (`LoginCookieMissing`), altered or sealed under another key or state
  (`LoginCookieInvalid`), sealed by a client with another issuer or client id
  (`ForeignLogin`), or past its lifetime (`LoginExpired`). None of these sends a
  token request.
- `callback_response` expires the login's cookie. Call it on the callback
  response whatever `complete_login` returned.
- Without `config.with_sealing_key` each client uses a random in-memory key, so a
  callback must reach the node that started the login, before a restart. Give
  every node that serves callbacks the same sealing key.

Login starts hold no server capacity, so a flood of them cannot refuse other
users' logins. Hellhound does not refuse a second callback that carries the same
cookie and code: the provider accepts an authorization code once, and the PKCE
verifier exists only in that cookie. RFC 6749 §4.1.2 asks a provider to revoke
the tokens already issued for a code used twice, so a duplicated callback
request can end the first session.

## Check a permission on current claims

A refresh that returns an ID token replaces the session's claims, so a session
read shows the roles the provider last issued. `hellhound.session_identity` is
that read without any check, and is not for authorization. A permission check
calls `hellhound.current_identity` with a bound the application chooses: it
returns the claims only when they were issued within the bound, and renews them
with one shared refresh when they were not.

<!-- prettier-ignore-start -->

<!-- snips: consumer/src/hellhound_reference/usage/authorization.gleam#authorization -->
```gleam
/// Built once at startup, from the client it is used with. The bound is the
/// application's policy; Hellhound has no default. `claims_age` refuses less
/// than 60 s, and a bound not greater than the client's clock tolerance.
pub fn role_claims_age(client: hellhound.Client) -> hellhound.ClaimsAge {
  let assert Ok(age) = hellhound.claims_age(client, duration.minutes(15))
  age
}

pub type Decision {
  Allowed
  /// The person lacks the role.
  Denied
  /// Nothing was decided: deny this request and keep the session.
  TryAgainLater
  /// Refreshed tokens are still not confirmed in custody: deny this request,
  /// keep the value, and pass it to `hellhound.recover_refresh` again. It is
  /// the only copy of those tokens.
  Recovering(hellhound.RefreshRecovery)
  /// The session was ended: send the person to sign in.
  SignInAgain
  /// An operator must act: deny, keep the session, and alert.
  Misconfigured
}

/// Authorization helpers take a `Current`, never a `VerifiedIdentity`, so
/// the type shows that the age of the claims was checked. A missing roles
/// claim means no roles.
pub fn has_role(current: hellhound.Current, role: String) -> Bool {
  hellhound.decode_claims(
    hellhound.current_claims(current),
    decode.at(["https://example.test/roles"], decode.list(decode.string)),
  )
  |> option.from_result
  |> option.unwrap([])
  |> list.contains(role)
}

/// One call per role check, on every protected request.
pub fn require_role(
  client: hellhound.Client,
  session: hellhound.Session,
  claims_age: hellhound.ClaimsAge,
  role: String,
) -> Decision {
  case hellhound.current_identity(client, session, claims_age) {
    Ok(current) ->
      case has_role(current, role) {
        True -> Allowed
        False -> Denied
      }
    Error(error) -> denied(client, session, error)
  }
}

fn denied(
  client: hellhound.Client,
  session: hellhound.Session,
  error: hellhound.SessionError,
) -> Decision {
  case hellhound.session_error_action(error), error {
    // Publication was not confirmed. Recover it, without another provider
    // call; the next request reads the renewed claims.
    hellhound.Recover, hellhound.RefreshUnconfirmed(recovery) ->
      recover(client, recovery, 3)
    hellhound.Recover, _ | hellhound.RetryLater, _ -> TryAgainLater
    // The session cannot be used again (its refresh token is revoked or
    // quarantined, or it is gone): end it before redirecting.
    hellhound.Reauthenticate, _ ->
      case hellhound.logout(client, session, hellhound.default_logout()) {
        // Only these two say the session is gone.
        Ok(_) | Error(hellhound.LogoutSession(hellhound.SessionNotFound)) ->
          SignInAgain
        // Custody did not confirm the removal, so the session may still
        // exist: the next request ends it.
        Error(hellhound.LogoutStoreUnavailable) -> TryAgainLater
        Error(_) -> Misconfigured
      }
    // The provider returns no ID token on refresh, so no refresh can renew
    // the claims. This is the application's choice. Denying keeps the
    // session and makes the fault visible until an operator fixes the
    // provider. To send the person to sign in once per bound instead, end
    // the session here as the `Reauthenticate` branch does.
    hellhound.FixConfiguration,
      hellhound.ClaimsNotRenewed(hellhound.NotReturned)
    -> Misconfigured
    hellhound.FixConfiguration, _ | hellhound.RejectRequest, _ -> Misconfigured
  }
}

/// Until custody confirms the publication, the refreshed tokens exist only
/// in the recovery value. Each unconfirmed attempt returns the value to pass
/// to the next one. A request cannot wait for ever, so after a few attempts
/// the value is handed to the caller, which keeps it and tries again.
fn recover(
  client: hellhound.Client,
  recovery: hellhound.RefreshRecovery,
  attempts: Int,
) -> Decision {
  case hellhound.recover_refresh(client, recovery) {
    Error(hellhound.RefreshUnconfirmed(next)) if attempts > 1 ->
      recover(client, next, attempts - 1)
    Error(hellhound.RefreshUnconfirmed(next)) -> Recovering(next)
    _ -> TryAgainLater
  }
}

```

<!-- prettier-ignore-end -->

The bound limits the age of the last ID token. A removed role is denied within
it only if your provider evaluates claims again on refresh, so verify that for
your provider, request a refresh token, and keep node clocks within the clock
tolerance. `authentication_time`, `acr` and `amr` always read the login's
values. The [complete module](consumer/src/hellhound_reference/usage/authorization.gleam)
runs against the local test provider.

## How it works

```mermaid
flowchart LR
  App["Application routes and policy"] --> Client["Hellhound client handle"]
  Supervisor["Application supervisor"] --> Runtime["Hellhound provider and cache processes"]
  Client --> Runtime
  Runtime --> Issuer["OIDC / OAuth issuer"]
  Runtime --> Store["Memory or sealed record store"]
```

`Config` describes the client role. `hellhound.new` allocates stable names;
`hellhound.start` starts a manually owned client, while `hellhound.supervised` installs
it under your supervisor. Background discovery can return `ProviderNotReady`
until metadata and keys arrive. A `Session` is an opaque custody reference, not
an application session or permission grant.

Use the [supervision example](consumer/src/hellhound_reference/usage/supervision.gleam)
for a long-lived service. Stop supervised clients through their parent; manually
started clients need `hellhound.stop` after the application stops admitting work.
Any process that holds the client can call it.

## Resource servers

Use the separate resource-server role to check JWT access tokens against cached
issuer keys. This example maps verification outcomes to HTTP status codes:

<!-- prettier-ignore-start -->

<!-- snips: consumer/src/hellhound_reference/usage/resource_server.gleam#resource-server -->
```gleam
pub fn start(
  issuer: String,
) -> Result(#(hellhound.Client, resource.Validator), hellhound.StartError) {
  let assert Ok(client) = hellhound.new(config.resource_server(issuer:))
  use Nil <- result.map(hellhound.start(client))
  #(client, resource.new(client, audience: "https://api.example.com"))
}

/// The HTTP status a failed token earns: 401, 403 or 503. A token issued for
/// another resource is answered as a rejected one here.
pub fn status(validator: resource.Validator, bearer: String) -> Int {
  case resource.verify(validator, bearer) {
    Ok(_claims) -> 200
    Error(error) ->
      case resource.error_kind(error) {
        resource.Rejected | resource.WrongAudience -> 401
        resource.Forbidden -> 403
        resource.Unavailable -> 503
      }
  }
}

```

<!-- prettier-ignore-end -->

[Local validation](src/hellhound/resource.gleam) does not observe immediate token
revocation. A suitably authenticated service client can instead use
`hellhound.introspect` to ask the provider for current token state. Resource-server
configuration alone supplies no introspection credentials.

## Operational notes

- Use `(issuer, subject)` as identity, not email. Protect application session
  cookies and apply CSRF/origin and permission checks at your routes.
- Memory storage loses sessions on restart. Durable custody needs a protected
  32-byte sealing key, conditional writes and rollback protection; the application
  owns migrations, pool lifetime, capacity and backup policy.
- Decide permissions from `hellhound.current_identity`, never from
  `session_identity`. On `Reauthenticate` from it, call `logout` before
  redirecting. On `FixConfiguration` deny the request, keep the session and
  alert an operator. A long-lived connection checks on each incoming message and
  closes on a timer when the claims pass the bound, without polling while idle.
- Do not blindly resend a possibly consumed authorization code or refresh token.
  Branch on `login_error_action` or `session_error_action`; keep errors carrying
  `Recover` evidence for `recover_custody` or `recover_refresh`.
- Provider traffic uses verified HTTPS and public destinations by default.
  Login checks issuer, audience, nonce and callback matching. Register every
  allowed callback address with the provider.
- `hellhound.stop` and the login deadline do not prove that every worker or external
  effect has finished. Keep borrowed resources alive for the required completion boundary.

## Examples and reference

- [Usage modules](consumer/src/hellhound_reference/usage/): supervision, durable stores,
  callback addresses, resource servers, permission checks on current claims and a
  local HTTPS test provider. For a local run
  with a real browser, the test provider can keep a fixed port and a loopback-only root
  the developer trusts once (`hellhound/testing`, development only).
- [Relay integration](relay_consumer/src/recipe.gleam): JWT and introspection verifiers.
- [PostgreSQL storage](integrations/hellhound_postgres/README.md): optional adapter;
  the core does not depend on it.
- [Design](docs/design/design-layer.pdf): protocol scope, defaults and unresolved requirements.
- [Oracle](docs/ORACLE.md) and [measurements](docs/BENCHMARKS.md): retained evidence
  with its revisions and limits, not a release certification or current performance promise.
- [Development commands](AGENTS.md): local checks, provider suites and browser tests.
