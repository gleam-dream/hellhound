// snips-start: relay-verifier
import gleam/option.{type Option, None, Some}
import hellhound
import hellhound/resource
import relay/authorization.{type Attestation, type Verifier}

pub type Principal {
  Principal(subject: String, client_id: Option(String), scopes: List(String))
}

/// Local RFC 9068 validation: no provider request per token. A token for
/// another resource gets Relay's "issued for another resource" challenge.
pub fn jwt_verifier(validator: resource.Validator) -> Verifier(Principal) {
  let verify =
    resource.verifier(
      validator,
      authorization.token_value,
      attest,
      on_error: refuse,
    )
  use token, _correlation <- authorization.verifier("hellhound-jwt")
  verify(token)
}

fn refuse(kind: resource.ErrorKind) -> authorization.VerificationError {
  case kind {
    resource.Rejected | resource.Forbidden -> authorization.BearerRejected
    resource.WrongAudience -> authorization.IssuedForAnotherResource
    resource.Unavailable -> authorization.VerifierUnavailable
  }
}

fn attest(claims: resource.AccessClaims) -> Attestation(Principal) {
  let scopes = resource.scopes(claims)
  authorization.attestation(
    Principal(resource.subject(claims), resource.client_id(claims), scopes),
    resource.audiences(claims),
    scopes,
  )
}

/// RFC 7662 introspection: one provider request per token, so a revoked
/// token is refused at once. The request's correlation tags the provider
/// call, so it joins the MCP request in telemetry.
pub fn introspection_verifier(client: hellhound.Client) -> Verifier(Principal) {
  use token, correlation <- authorization.verifier("hellhound-introspection")
  let client = hellhound.with_correlation(client, correlation)
  case hellhound.introspect(client, authorization.token_value(token)) {
    Ok(hellhound.ActiveToken(
      hellhound.TokenInfo(subject: Some(subject), ..) as info,
    )) ->
      Ok(authorization.attestation(
        Principal(subject, info.client_id, info.scopes),
        info.audiences,
        info.scopes,
      ))
    Ok(hellhound.ActiveToken(hellhound.TokenInfo(subject: None, ..))) ->
      Error(authorization.VerifierUnmapped)
    Ok(hellhound.InactiveToken) | Error(hellhound.IntrospectionTokenTooLarge) ->
      Error(authorization.BearerRejected)
    Error(hellhound.IntrospectionNotSupported)
    | Error(hellhound.IntrospectionFailed(_)) ->
      Error(authorization.VerifierUnavailable)
  }
}
// snips-end: relay-verifier
