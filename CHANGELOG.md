# Changelog

Notable changes to Hellhound. Versions follow semantic versioning; before 1.0 a
minor version may break compatibility.

## Unreleased (0.3.0)

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
- `hellhound.claims_age(duration) -> Result(ClaimsAge, Nil)`, the checked bound.
  It refuses less than 60 s. There is no default and no configuration key.
- A renewal circuit. After a renewal started by `current_identity` ends in
  quarantine, that node starts no renewal from `current_identity` for 60 s and
  returns `RefreshNotSent(RenewalPaused)`. `access_token` and `refresh` are not
  affected, and no rotation or quarantine rule changed.
- `hellhound/testing`: `RefreshAnswer`, `with_refresh_answer` and
  `set_refresh_answer` script the refresh grant: with or without an ID token,
  or a 503 or 429 that leaves the grant untouched. The default is unchanged
  (no ID token on refresh).

### Breaking

- `SessionError` gains `ClaimsNotRenewed(NotRenewedReason)`, with
  `NotReturned` (Reauthenticate) and `IssuedTooLongAgo` (FixConfiguration).
  Only `current_identity` returns it.
- `ProviderFailure` gains `RenewalPaused` (RetryLater). Only `current_identity`
  returns it, inside `RefreshNotSent`.
- `telemetry.Refresh` gains the field `claims: RefreshClaims`, `Replaced` or
  `NotReturned`, and the `[hellhound, refresh]` metadata gains `claims`
  (`<<"replaced">>` or `<<"not_returned">>`).
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
   - on `Reauthenticate`, call `logout` before redirecting to sign-in;
   - on `RetryLater`, deny the request and keep the session;
   - on `Recover`, call `recover_refresh`, then `current_identity` again;
   - on `FixConfiguration`, alert an operator.
4. **Provider and deployment.** The bound limits the age of the last ID token.
   A removed role is denied within it only if your provider evaluates claims
   again on refresh and returns an ID token, so verify both. Request a refresh
   token, and keep node clocks within the clock tolerance
   (`config.with_clock_tolerance`, default 5 s). Past the bound each permission
   check costs one refresh per session, so size that load against your
   provider's limits. A long-lived connection calls `current_identity` on each
   incoming message and closes on a timer when the claims pass the bound; it
   does not poll while idle.
5. **Rolling back.** Pinning 0.2.x again is safe for stored records. Do it only
   before you rely on claim replacement to remove permissions, because 0.2.x
   reads the login's claims and would give removed roles back.

The reasons, and the alternatives that were rejected, are in
[ADR 0025](docs/adr/0025-current-claims-and-a-bounded-claims-read.md).
