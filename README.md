# Hellhound

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
```

<!-- prettier-ignore-end -->

The [complete module](consumer/src/hellhound_reference/usage/login.gleam) compiles in
the reference consumer. Its [common-path test](consumer/test/hellhound_reference_test.gleam)
exercises the equivalent login, token and logout flow against a local test provider.
The application stores the session reference in its protected browser session.

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
  callback addresses, resource servers and a local HTTPS test provider.
- [Relay integration](relay_consumer/src/recipe.gleam): JWT and introspection verifiers.
- [PostgreSQL storage](integrations/hellhound_postgres/README.md): optional adapter;
  the core does not depend on it.
- [Design](docs/design/design-layer.pdf): protocol scope, defaults and unresolved requirements.
- [Oracle](docs/ORACLE.md) and [measurements](docs/BENCHMARKS.md): retained evidence
  with its revisions and limits, not a release certification or current performance promise.
- [Development commands](AGENTS.md): local checks, provider suites and browser tests.
