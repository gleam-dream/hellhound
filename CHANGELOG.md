# Changelog

Notable changes to Hellhound. Versions follow semantic versioning; before 1.0 a
minor version may break compatibility.

## 0.4.0

Pending logins move from a server-side store into sealed per-login browser
cookies. This release breaks the login API; the
[migration guide](docs/MIGRATION.md) has before and after code for each change.
Custody records keep their format, so installed sessions survive the upgrade;
logins in flight during it must start again.

### Changed

- **`begin_login(client, options)` stores nothing on the server.** It seals
  the pending login with the client's sealing key into a
  `__Host-hellhound_login_<digest>` cookie that `login_response` sets. The
  request argument is removed. A flood of login starts holds no server capacity.
- **`config.with_sealing_key` seals login cookies too.** Give every node that
  serves callbacks the same key. Without one, a callback must reach the node
  that started the login, before a restart.
- `SealingKeyRequired` is raised only for a custody store without a sealing
  key.
- `hellhound/testing.browser_request(redirect)` carries that login's cookie.
- Depends on `sinal >= 0.2.0 and < 0.3.0` and `http_gun >= 0.4.0 and < 0.5.0`.
  Telemetry handlers now belong to the process that attaches them (Sinal 0.2).

### Added

- `hellhound.callback_response(response, client, request)` expires the login
  cookie on the callback response.
- `BindingProblem` variants `LoginCookieMissing`, `LoginCookieInvalid` and
  `ForeignLogin`, all mapped to `RejectRequest`.
- `ConfigError.LoginCookieTooLarge`: the issuer, client id, longest
  redirect URI and configured scopes must fit in 2 KiB together.
- `LoginOptionProblem.LoginCookieTooLarge`: `begin_login` refuses a login
  whose sealed cookie, with its per-login scopes, would exceed 4 KiB.

### Removed

- `config.with_transaction_store`, `config.with_max_pending_logins` and the
  `config.MaxPendingLogins` limit.
- `LoginError` variants `LoginStoreUnavailable`, `TooManyPendingLogins`,
  `LoginReplayed`, `LoginChanged`, `TransactionStoreUnavailable` and
  `LoginRecordUnreadable`; `BindingProblem` variants `UnknownState`,
  `BrowserBindingMissing` and `BrowserBindingMismatch`.
- The `__Host-hellhound_binding` cookie.

### Fixed

- `hellhound.stop` stops a client started by another process. It used to wait
  five seconds and leave the client running.
- A code-exchange response without `scope` records the requested scopes, so
  the first refresh that states the scope is no longer refused as a scope
  change.
- JWT validation and metadata reads take the provider snapshot without a
  message to the cache process, so a busy cache no longer delays them. A
  restarted cache answers `ProviderNotReady` until its own discovery is
  accepted.

- The renewal circuit takes a probe as lost only after the renewal can no
  longer be running. Its lease left out the store calls, including a
  reservation's retries after conflicts, so a slow store let a second probe
  start beside the first.
- A renewal report applies only to the provider-cache incarnation that
  admitted it. A report sent across a cache restart could open the new
  circuit, or close it while its probe was in flight.

## 0.3.0

Sessions now read the claims of the latest verified ID token, and one new call
bounds how old the claims of a permission check may be. The stored record
format is unchanged: 0.2.x and 0.3.0 read the same records, in both directions.

### Changed

- **`session_identity` returns the current claims.** After a refresh that
  returned an ID token, a session read (`restore_session`, and the session in
  the `Access` that `access_token`, `refresh` and `recover_refresh` return)
  shows that token's claims. In 0.2.x it always showed the login's claims.
  Replacement is whole: a claim missing from the refreshed token is gone, so a
  missing roles claim means no roles, and profile claims can be thinner after a
  refresh. A refresh that returns no ID token leaves the claims as they were.
- **`authentication_time`, `acr` and `amr` read the login claims.** They keep
  the values of the login whatever a refreshed ID token says. `decode_claims`
  reads the current claims, including raw `acr`, `amr` and `auth_time` members.
- A `Session` value is a view of custody when it was read. Read the session
  again to see claims a later refresh replaced.

### Added

- `hellhound.current_identity(client, session, claims_age)`, the authorization
  read. It returns an opaque `Current` only when the session's current claims
  were issued within the bound, with no provider call when they already were,
  and renews them with one refresh shared by concurrent callers when they were
  not. Accessors: `current_claims`, `current_session`, `current_issued_at`.
- `hellhound.claims_age(client, duration) -> Result(ClaimsAge, Nil)`, the
  checked bound, built from the client it is used with. It refuses less than
  60 s, and a bound not greater than that client's clock tolerance. There is no
  default and no configuration key.
- A renewal circuit. That node starts no renewal from `current_identity` for
  60 s, and returns `RefreshNotSent(RenewalPaused)`, after a renewal started by
  `current_identity` ends with the provider's outcome unknown (a 5xx, or a
  timeout after the request was sent), with a 429, or with `ClaimsNotRenewed`.
  After the window one renewal is sent as a probe and the others stay paused
  until it reports. A response rejected for one session does not open the
  circuit. `access_token` and `refresh` do not consult it.
- `telemetry.current_identity()`, the event `[hellhound, current_identity]`.
  It is emitted once for every bounded read, including the reads that send
  nothing, with `outcome`: `within_bound`, `renewed`, `paused`, `not_returned`,
  `issued_too_long_ago` or `failed`. Alert on `not_returned` and
  `issued_too_long_ago`; count `paused` to see the circuit.
- `hellhound/testing`: `RefreshAnswer`, `with_refresh_answer` and
  `set_refresh_answer` script the refresh grant: with or without an ID token,
  or a 503 or 429 that leaves the grant untouched. The default is unchanged
  (no ID token on refresh).

### Breaking

- `SessionError` gains `ClaimsNotRenewed(NotRenewedReason)`, with
  `NotReturned` and `IssuedTooLongAgo`, both FixConfiguration: a new login
  would end the same way, so the session is kept. Only `current_identity`
  returns it.
- **A 429 from the token endpoint no longer quarantines the session.** A rate
  limiter refuses the request before the grant is processed, so the refresh
  token is kept and may be sent again. `SessionError` gains
  `RefreshRateLimited` (RetryLater), returned by `access_token`, `refresh` and
  `current_identity`; in 0.2.x the same answer was
  `RefreshQuarantined(ProviderOutcomeUnknown)` (Reauthenticate). A 5xx and a
  timeout after the request was sent still quarantine.
- `session_error_action(SessionRecordUnreadable)` is `FixConfiguration`; it
  was `Reauthenticate`. A stored session that does not open is most often an
  unknown sealing key, which affects every session at once, and `logout` on
  `Reauthenticate` would delete records that the right key still opens. Deny
  the request, keep the session and alert an operator.
- `ProviderFailure` gains `RenewalPaused` (RetryLater). Only `current_identity`
  returns it, inside `RefreshNotSent`.
- `telemetry.Refresh` gains the field `claims: RefreshClaims`, `Replaced` or
  `NotReturned`, and the `[hellhound, refresh]` metadata gains `claims`
  (`<<"replaced">>` or `<<"not_returned">>`).
- `telemetry.Refresh` gains the field `quarantine: RefreshQuarantine`, and the
  metadata gains `quarantine`: `<<"none">>`, `<<"outcome_unknown">>`,
  `<<"response_rejected">>` or `<<"refresher_lost">>`. It tells one session's
  rejected response from a provider that stopped answering.
- `telemetry.RefreshOutcome` gains `RefreshRateLimited` (`<<"rate_limited">>`).
- The behaviour changes under "Changed" above.

### Migrating from 0.2.x

1. **Exhaustive matches.** Add the new variants where you match every
   `SessionError` or `ProviderFailure`, or branch on `session_error_action`,
   which already covers them. Code that constructs `telemetry.Refresh` adds
   `claims:`; handlers that only read fields need no change.
2. **Reads of claims.** Nothing to change for display. If you relied on
   `session_identity` returning the login's claims for the whole session, note
   that it now follows refreshes; the login's `authentication_time`, `acr` and
   `amr` are still available through their accessors.
3. **Permission checks.** Move every decision drawn from claims (roles, groups,
   tenant) from `session_identity` to `current_identity`, with a bound you
   choose, and make your authorization helpers take `Current`. Then:
   - on `Reauthenticate`, call `logout` before redirecting to sign-in. Do not
     treat `FixConfiguration` the same way: it keeps the session;
   - on `RetryLater`, deny the request and keep the session;
   - on `Recover`, call `recover_refresh`, then `current_identity` again;
   - on `FixConfiguration`, deny the request, keep the session and alert an
     operator.
4. **Provider and deployment.** The bound limits the age of the last ID token.
   A removed role is denied within it only if your provider evaluates claims
   again on refresh and returns an ID token, so verify both. A provider that
   returns no ID token on refresh denies every permission check once the
   claims pass the bound (`ClaimsNotRenewed(NotReturned)`), until an operator
   fixes it. Your application may match that one error and send the person to
   sign in instead; the `authorization` usage example marks where. To catch it
   before anyone is denied, alert when `[hellhound, refresh]` reports
   `outcome` `refreshed` with `claims` `not_returned`: every refresh carries
   it, including the ones `access_token` makes, so it fires on the first
   refresh after a provider change. Request a refresh
   token, and keep node clocks within the clock tolerance
   (`config.with_clock_tolerance`, default 5 s). Past the bound each permission
   check costs one refresh per session, so size that load against your
   provider's limits. A long-lived connection calls `current_identity` on each
   incoming message and closes on a timer when the claims pass the bound; it
   does not poll while idle.
5. **Claims that restrict.** Replacement is whole, so it fails closed for a
   claim that grants (a removed role is gone) and open for a claim that
   restricts. A claim such as `restricted` or `mfa_required` that your provider
   adds only at interactive login is absent from the first refreshed ID token,
   and the restriction disappears with it. Make the provider emit such a claim
   on refresh as well, or read it from the login's values and not from the
   current claims.
6. **Rolling back.** Pinning 0.2.x again is safe for stored records. Do it only
   before you rely on claim replacement to remove permissions, because 0.2.x
   reads the login's claims and would give removed roles back.

The reasons, and the alternatives that were rejected, are in
[ADR 0025](docs/adr/0025-current-claims-and-a-bounded-claims-read.md).
