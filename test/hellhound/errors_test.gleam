//// Every error type has a description and a caller action; uncertain
//// outcomes never map to a plain retry. HTTP Gun's connect, pool and idle
//// bounds stay separate from the request timeout.

import gleam/list
import gleam/string
import hellhound
import hellhound/config
import hellhound/internal/transport
import hellhound/resource
import hellhound/store
import http_gun/internal/settings as gun_settings

pub fn every_login_error_describes_itself_and_has_an_action_test() {
  let errors = [
    hellhound.InvalidLoginOption(hellhound.InvalidMaxAge),
    hellhound.LoginNotConfigured,
    hellhound.LoginProviderUnavailable(hellhound.ProviderNotReady),
    hellhound.LoginProviderIncompatible([hellhound.NoS256]),
    hellhound.CallbackMalformed(hellhound.MissingState),
    hellhound.CallbackRejected(hellhound.LoginCookieMissing),
    hellhound.CallbackRejected(hellhound.LoginCookieInvalid),
    hellhound.CallbackRejected(hellhound.ForeignLogin),
    hellhound.LoginExpired,
    hellhound.ProviderDenied(hellhound.AccessDenied),
    hellhound.ProviderUnavailableBeforeExchange(hellhound.ProviderNotReady),
    hellhound.ExchangeRejected(hellhound.InvalidGrant),
    hellhound.ExchangeOutcomeUnknown,
    hellhound.IdentityRejected(hellhound.NonceMismatch),
    hellhound.LoginTimedOut,
    hellhound.RecoveryForeign,
    hellhound.RecoveryEnded,
    hellhound.RecoveryExpired,
  ]
  list.each(errors, fn(error) {
    assert hellhound.describe_login_error(error) != ""
    let _ = hellhound.login_error_action(error)
  })
  assert hellhound.login_error_action(hellhound.CallbackMalformed(
      hellhound.MissingCode,
    ))
    == hellhound.RejectRequest
  assert hellhound.login_error_action(hellhound.ExchangeOutcomeUnknown)
    == hellhound.Reauthenticate
  assert hellhound.login_error_action(hellhound.ExchangeRejected(
      hellhound.InvalidClient,
    ))
    == hellhound.FixConfiguration
}

pub fn every_session_error_describes_itself_and_has_an_action_test() {
  let errors = [
    hellhound.SessionNotFound,
    hellhound.SessionLost,
    hellhound.SessionForeign,
    hellhound.SessionStoreUnavailable,
    hellhound.SessionRecordUnreadable,
    hellhound.SessionHasNoAccessToken,
    hellhound.RefreshTokenUnavailable,
    hellhound.RefreshRevoked,
    hellhound.RefreshRejected(hellhound.InvalidScope),
    hellhound.RefreshNotSent(hellhound.ProviderNotReady),
    hellhound.RefreshQuarantined(hellhound.ProviderOutcomeUnknown),
    hellhound.RefreshQuarantined(hellhound.RefresherLost),
    hellhound.RefreshQuarantined(
      hellhound.ResponseRejected(
        hellhound.RefreshedIdTokenInvalid(hellhound.MissingClaim("sub")),
      ),
    ),
    hellhound.RefreshRateLimited,
    hellhound.RefreshWaitTimedOut,
    hellhound.RefreshRecoveryForeign,
    hellhound.ClaimsNotRenewed(hellhound.NotReturned),
    hellhound.ClaimsNotRenewed(hellhound.IssuedTooLongAgo),
  ]
  list.each(errors, fn(error) {
    assert hellhound.describe_session_error(error) != ""
  })
  // An uncertain refresh is never "try the same request again".
  assert hellhound.session_error_action(hellhound.RefreshQuarantined(
      hellhound.ProviderOutcomeUnknown,
    ))
    == hellhound.Reauthenticate
  assert hellhound.session_error_action(hellhound.RefreshRevoked)
    == hellhound.Reauthenticate
  assert hellhound.session_error_action(hellhound.RefreshNotSent(
      hellhound.ProviderNotReady,
    ))
    == hellhound.RetryLater
  assert hellhound.session_error_action(hellhound.SessionStoreUnavailable)
    == hellhound.RetryLater
  // A record this node cannot open is the operator's to fix: signing in
  // again would delete a record that the right sealing key still opens.
  assert hellhound.session_error_action(hellhound.SessionRecordUnreadable)
    == hellhound.FixConfiguration
  // A rate limiter refused the request before the grant: nothing was lost.
  assert hellhound.session_error_action(hellhound.RefreshRateLimited)
    == hellhound.RetryLater
  // A refresh that cannot renew the claims will not after a new login
  // either.
  assert hellhound.session_error_action(hellhound.ClaimsNotRenewed(
      hellhound.NotReturned,
    ))
    == hellhound.FixConfiguration
}

pub fn other_errors_describe_themselves_test() {
  assert hellhound.describe_start_error(hellhound.StartupTimedOut) != ""
  assert string.contains(
    hellhound.describe_start_error(
      hellhound.InvalidConfig([config.InvalidIssuer]),
    ),
    "issuer",
  )
  assert hellhound.describe_provider_failure(hellhound.TransportFailure(
      evidence: hellhound.MaybeSent,
      reason: hellhound.Timeout,
    ))
    == "timeout (may have been sent)"
  assert hellhound.describe_userinfo_error(hellhound.UserinfoNotSupported) != ""
  assert hellhound.describe_client_credentials_error(
      hellhound.ClientCredentialsOutcomeUnknown,
    )
    != ""
  assert hellhound.describe_introspection_error(
      hellhound.IntrospectionTokenTooLarge,
    )
    != ""
  assert hellhound.describe_logout_error(hellhound.LogoutStoreUnavailable) != ""
  assert resource.describe_error(resource.AudienceMismatch) != ""
  assert store.describe_error(store.StoreFull) != ""
}

/// The connect, pool-checkout, idle-read and idle
/// connection bounds are HTTP Gun's own (5 s, 5 s, 30 s, 60 s), not copies
/// of the request timeout, which each call sets as its own deadline
/// (`transport_test` and `transport_pool_test`).
pub fn http_gun_keeps_its_separate_bounds_test() {
  let policy =
    transport.Policy(
      ..transport.policy(transport.SystemTrust),
      timeout_ms: 20_000,
    )
  let gun = transport.gun_config(policy)
  assert gun.connect_timeout == 5000
  assert gun.pool_timeout == 5000
  assert gun.idle_timeout == gun_settings.Within(30_000)
  assert gun.connection_idle_timeout == 60_000
}
