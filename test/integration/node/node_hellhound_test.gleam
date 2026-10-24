//// Hellhound against node-oidc-provider 9.12.2 (`scripts/node-provider up`).
//// ID tokens in the hostile corpus are produced by panva/jose 6.2.12 from
//// the provider's own token for each transaction, so nonce and times belong
//// to that transaction. Client assertions Hellhound sends are verified
//// independently by panva/jose at the provider.

import gleam/http/request
import gleam/list
import gleam/option.{Some}
import gleam/string
import gleam/time/duration
import hellhound
import hellhound/config
import hellhound_test_support as support

const issuer = "https://localhost:19443"

const secret = "hellhound-node-disposable-secret-0123456789"

pub fn settings(
  client_id: String,
  authentication: config.ClientAuthentication,
) -> config.Config {
  config.new(
    issuer:,
    client_id:,
    redirect_uri: "https://localhost:1/callback",
    authentication:,
  )
  |> config.with_scopes(["email", "profile"])
  |> config.with_trust(config.TrustAnchorsPem(support.ca_pem()))
  |> config.with_destinations(config.AllowLoopbackForTesting)
}

pub fn start(config: config.Config) -> hellhound.Client {
  support.start_client(config)
}

pub fn basic() -> hellhound.Client {
  start(settings(
    "hellhound-rp",
    config.ClientSecretBasic(config.secret(secret)),
  ))
}

pub fn attempt(
  client: hellhound.Client,
  user: String,
) -> Result(hellhound.Session, hellhound.LoginError) {
  let options =
    hellhound.LoginOptions(..hellhound.default_login(), login_hint: Some(user))
  let assert Ok(redirect) =
    hellhound.begin_login(client, request.new(), options)
  let assert Ok(support.Query(query)) =
    support.authorize(hellhound.login_url(redirect), issuer)
  hellhound.complete_login(client, support.query_callback(redirect, query))
}

/// The hostile ID-token corpus. Expected Hellhound outcomes; `"ok"` means a
/// completed login.
pub fn corpus() -> List(#(String, String)) {
  [
    #("resign", "ok"),
    #("es256", "ok"),
    #("good_at_hash", "ok"),
    #("bad_signature", "BadSignature"),
    #("alg_none", "UnsignedIdToken"),
    #("hs256_confusion", "AlgorithmNotAllowed"),
    #("hs256_client_secret", "AlgorithmNotAllowed"),
    #("unknown_kid", "UnknownSigningKey"),
    #("no_kid_wrong_key", "BadSignature"),
    #("wrong_iss", "IdTokenIssuerMismatch"),
    #("wrong_aud", "IdTokenAudienceMismatch"),
    #("extra_aud", "IdTokenAudienceMismatch"),
    #("wrong_azp", "AuthorizedPartyMismatch"),
    #("expired", "IdTokenExpired"),
    #("nbf_future", "IdTokenNotYetValid"),
    #("missing_sub", "MissingClaim(\"sub\")"),
    #("missing_iat", "MissingClaim(\"iat\")"),
    #("wrong_nonce", "NonceMismatch"),
    #("missing_nonce", "NonceMismatch"),
    #("bad_at_hash", "AccessTokenHashMismatch"),
    #("encrypted_unsigned", "EncryptedIdTokenUnsupported"),
  ]
}

pub fn outcome(
  result: Result(hellhound.Session, hellhound.LoginError),
) -> String {
  case result {
    Ok(_) -> "ok"
    Error(hellhound.IdentityRejected(problem)) -> string.inspect(problem)
    other -> "unexpected " <> string.inspect(other)
  }
}

pub fn hostile_id_token_corpus_test() {
  support.node_reset()
  let client = basic()
  let results =
    list.map(corpus(), fn(c) {
      support.node_next("authorization_code", [support.NodeIdToken(c.0)])
      #(c.0, outcome(attempt(client, "alice")))
    })
  let mismatches =
    list.zip(corpus(), results)
    |> list.filter(fn(pair) { pair.0 != pair.1 })
  assert mismatches == []
  hellhound.stop(client)
}

pub fn provider_denial_test() {
  let client = basic()
  let assert Error(hellhound.ProviderDenied(hellhound.AccessDenied)) =
    attempt(client, "deny")
  hellhound.stop(client)
}

pub fn form_post_test() {
  let client =
    start(
      settings("hellhound-rp", config.ClientSecretBasic(config.secret(secret)))
      |> config.with_response_mode(config.FormPost),
    )
  let assert Ok(redirect) =
    hellhound.begin_login(client, request.new(), hellhound.default_login())
  let assert Ok(support.FormPost(body)) =
    support.authorize(hellhound.login_url(redirect), issuer)
  let assert Ok(_) =
    hellhound.complete_login(client, support.form_callback(redirect, body))
  hellhound.stop(client)
}

pub fn client_authentication_methods_test() {
  support.node_reset()
  let es =
    config.signing_key_from_jwk(support.pki_file(
      "node-client-client-es256.jwk.json",
    ))
  let rs =
    config.signing_key_from_jwk(support.pki_file(
      "node-client-client-rs256.jwk.json",
    ))
  let assert Ok(es) = es
  let assert Ok(rs) = rs
  let cases = [
    #("hellhound-rp", config.ClientSecretBasic(config.secret(secret)), "none"),
    #("hellhound-post", config.ClientSecretPost(config.secret(secret)), "none"),
    #(
      "hellhound-hs",
      config.ClientSecretJwt(config.secret(secret)),
      "verified:HS256",
    ),
    #("hellhound-es", config.PrivateKeyJwt(es), "verified:ES256"),
    #("hellhound-rs", config.PrivateKeyJwt(rs), "verified:RS256"),
  ]
  list.each(cases, fn(c) {
    support.node_reset()
    let client = start(settings(c.0, c.1))
    let assert Ok(_) = attempt(client, "alice")
    let log = support.node_log()
    assert log == [#("authorization_code", c.0, c.2)]
    hellhound.stop(client)
  })
}

pub fn refresh_cases_through_hellhound_test() {
  support.node_reset()
  let client =
    start(
      settings("hellhound-rp", config.ClientSecretBasic(config.secret(secret)))
      |> config.with_request_timeout(duration.milliseconds(800)),
    )
  let session = fn() {
    let assert Ok(s) = attempt(client, "alice")
    s
  }
  // Present ID token, rotation.
  let s = session()
  let assert Ok(a2) = hellhound.refresh(client, s)
  let assert Ok(_) = hellhound.refresh(client, a2.session)
  // Absent ID token: OIDC Core §12.2 allows the omission; identity retained.
  let s = session()
  support.node_next("refresh_token", [support.NodeOmitIdToken])
  case hellhound.refresh(client, s) {
    Ok(refreshed) -> {
      let assert Ok(_) = hellhound.refresh(client, refreshed.session)
      Nil
    }
    other -> panic as string.inspect(other)
  }
  // Omitted refresh token: retained, and the provider still accepts it.
  let s = session()
  support.node_next("refresh_token", [support.NodeDropRefreshToken])
  let assert Ok(a2) = hellhound.refresh(client, s)
  let r = hellhound.refresh(client, a2.session)
  assert outcome_refresh(r) == "completed-or-provider-rejected"
  // Changed nonce continuity.
  let s = session()
  support.node_next("refresh_token", [support.NodeIdToken("changed_nonce")])
  let assert Error(hellhound.RefreshQuarantined(hellhound.ResponseRejected(
    hellhound.RefreshedNonceMismatch,
  ))) = hellhound.refresh(client, s)
  // Response lost after the provider rotated.
  let s = session()
  support.node_next("refresh_token", [support.NodeDelayMs(2000)])
  let assert Error(hellhound.RefreshQuarantined(
    hellhound.ProviderOutcomeUnknown,
  )) = hellhound.refresh(client, s)
  hellhound.stop(client)
}

/// node-oidc-provider consumes a refresh token even when the response omits
/// its successor (rotation is server-side), so the retained token may be
/// rejected afterwards. Either outcome is a definite, correctly classified
/// result; neither is silent success.
fn outcome_refresh(
  r: Result(hellhound.Access, hellhound.SessionError),
) -> String {
  case r {
    Ok(_) -> "completed-or-provider-rejected"
    Error(hellhound.RefreshRevoked) -> "completed-or-provider-rejected"
    other -> string.inspect(other)
  }
}
