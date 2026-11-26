# Migrating from Hellhound 0.3 to 0.4

Hellhound 0.4.0 is a breaking release. Change the dependency to `hellhound >= 0.4.0 and < 0.5.0` in `gleam.toml`, then work through the sections below in order. The first ones affect every application that signs users in.

| Change                                                                                          | Who must act                                                                 |
| ----------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| [Pending logins live in sealed browser cookies](#pending-logins-live-in-sealed-browser-cookies) | Every application that calls `begin_login`                                   |
| [Logins in flight during the upgrade](#logins-in-flight-during-the-upgrade)                     | Every application that signs users in                                        |
| [The sealing key also seals login cookies](#the-sealing-key-also-seals-login-cookies)           | Applications that serve callbacks on more than one node, or rotate the key   |
| [Login errors changed](#login-errors-changed)                                                   | Code that matches `LoginError` or `BindingProblem` variants                  |
| [A new configuration error](#a-new-configuration-error)                                         | Applications with a long issuer, client id or redirect URI                   |
| [Sinal 0.2 and HTTP Gun 0.4](#sinal-02-and-http-gun-04)                                         | Applications that observe Hellhound telemetry or depend on Sinal or HTTP Gun |
| [PostgreSQL adapter](#postgresql-adapter)                                                       | Applications that use `hellhound_postgres`                                   |

Not breaking, but visible:

- `hellhound.stop` now stops a client started by another process. In 0.3 it waited five seconds and left the client running, so the next `start` answered `AlreadyStarted`.
- A code-exchange response without `scope` records the requested scopes. In 0.3 the session held no scopes, `Access.scopes` was `[]`, and the first refresh that stated a scope was refused as `RefreshedScopeChangeUnsupported`. Sessions installed by 0.3 with an empty scope set are not repaired.
- JWT validation and metadata reads no longer pass through the provider-cache process, so a busy cache does not delay `resource.verify`. Each cache process publishes the provider snapshot it has accepted. A cache that supervision restarts publishes nothing until its own discovery is accepted, so in that window `begin_login`, `resource.verify` and refresh answer `ProviderNotReady` (`RetryLater`) instead of using the previous process's snapshot. Handle `ProviderNotReady` as `RetryLater`, as you already do while a supervised client starts.
- A custom `hellhound/store` implementation receives custody records only. Hellhound writes no pending-login records, so a store that served `with_transaction_store` has nothing to keep for logins.

## Pending logins live in sealed browser cookies

**What changed.** The server keeps no state between `begin_login` and the callback. `begin_login` seals the pending login (state, nonce, PKCE verifier, redirect URI, `max_age`, issuer, client id and expiry) with the client's sealing key into a cookie, and `login_response` sets it. `complete_login` opens the cookie that the callback's `state` names. The cookie is named `__Host-hellhound_login_` plus a digest of the state, so logins in several tabs keep separate cookies.

**Why.** Every login start held a slot in a bounded server-side store. About 84 anonymous `GET /login` requests per second filled the default store, and every user's login then failed with `TooManyPendingLogins`. A durable transaction store had no bound, so the same requests grew a table without limit.

**What to do.**

1. Drop the request argument of `begin_login`:

   ```gleam
   // 0.3
   hellhound.begin_login(client, request, hellhound.default_login())
   // 0.4
   hellhound.begin_login(client, hellhound.default_login())
   ```

2. Pipe the callback route's response through the new `callback_response`, whatever `complete_login` returned. It expires the login's cookie:

   ```gleam
   case hellhound.complete_login(client, request) {
     Ok(session) -> signed_in(hellhound.session_reference(session))
     Error(error) -> failed(hellhound.login_error_action(error))
   }
   |> hellhound.callback_response(client, request)
   ```

   `request` is the callback as a `Request(String)`: the query, or the form body read once.

3. Delete every call to `config.with_transaction_store` and `config.with_max_pending_logins`. Both are removed, and so is the `config.MaxPendingLogins` limit: remove it from matches on `config.Limit` (it appears in `ConfigError.InvalidLimit`). A store passed only to `with_transaction_store` is no longer used.

4. Serve the application over HTTPS on a host name. The `__Host-` prefix makes the browser keep the cookie only when it is `Secure`, `Path=/` and without `Domain`. The cookie is `HttpOnly` and `SameSite=Lax`, or `SameSite=None` with form-post callbacks.

**Cookie size.** A login cookie is about 470 characters for a typical configuration. Configuration validation and `begin_login` keep it within the 4 KiB a browser keeps per cookie (see [A new configuration error](#a-new-configuration-error)). With `Path=/`, the browser sends every pending login's cookie on every request to the host until the callback clears it or its `Max-Age`, the login lifetime (`config.with_login_lifetime`), ends. Ten abandoned logins of a typical configuration add about 5 KiB to each request in that window. Check that the request-header limit of your server and proxies allows this.

**Other effects.**

- Hellhound no longer sets the `__Host-hellhound_binding` cookie and ignores it. Browsers drop the old cookie when its `Max-Age` ends.
- A callback is no longer refused as a replay. A reload after `callback_response` is refused locally (`LoginCookieMissing`). Truly concurrent duplicate callbacks each send a token request, and the provider accepts the code once. RFC 6749 §4.1.2 asks a provider to revoke tokens already issued for a reused code, so a duplicated callback can end the first session.
- `hellhound/testing.browser_request(redirect)` now carries that login's cookie, and `testing.authorize` sends it on the callback.

## Logins in flight during the upgrade

A login that 0.3 started has no 0.4 login cookie, and its server-side record is no longer read. When its callback reaches 0.4, `complete_login` returns `CallbackRejected(LoginCookieMissing)` and sends no token request. `login_error_action` maps it to `RejectRequest`.

- Show a page that starts the login again on `RejectRequest` from the callback, rather than a bare error. The user signs in once more.
- Only logins started within one login lifetime (`config.with_login_lifetime`) before the upgrade are affected. Sessions already installed are unaffected: custody records keep their format.
- During a rolling deployment, a login started on a 0.4 node fails on a 0.3 node and the reverse. Route callbacks to one version, or accept failed callbacks for one login lifetime.

## The sealing key also seals login cookies

**What changed.** `config.with_sealing_key` now seals login cookies as well as durable custody records. `SealingKeyRequired` is now raised only for a custody store without a sealing key.

**What to do.**

- Without `with_sealing_key`, each client seals with a random key held in memory. A callback must then reach the node that started the login, before a restart; this matches the 0.3 in-memory store.
- To complete logins on any node, give every node that serves callbacks the same 32-byte sealing key (`config.sealing_key`). This replaces a durable transaction store.
- Keep the key secret and stable across restarts. A cookie sealed with a key the client no longer holds is refused as `LoginCookieInvalid`.
- Rotate with `config.with_previous_sealing_keys`: seal with the new key and keep the old key in the previous list for at least the login lifetime and, with durable custody, for as long as records sealed with it exist. Removing the old key earlier makes its pending logins fail with `LoginCookieInvalid`.

## Login errors changed

`login_error_action` is unchanged for the cases that remain, so code that branches only on it needs no change. Code that matches variants must change:

| 0.3                                                                         | 0.4                                                                                                     |
| --------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `LoginStoreUnavailable`, `TooManyPendingLogins`                             | removed: `begin_login` uses no store                                                                    |
| `LoginReplayed`, `LoginChanged`                                             | removed: the provider enforces single use of the code                                                   |
| `TransactionStoreUnavailable`, `LoginRecordUnreadable`                      | removed                                                                                                 |
| `CallbackRejected(UnknownState)`, `CallbackRejected(BrowserBindingMissing)` | nearest case: `CallbackRejected(LoginCookieMissing)`                                                    |
| `CallbackRejected(BrowserBindingMismatch)`                                  | nearest case: `CallbackRejected(LoginCookieInvalid)`                                                    |
| —                                                                           | `CallbackRejected(ForeignLogin)`: a client with another issuer or client id sealed it with the same key |

All three new `BindingProblem` variants map to `RejectRequest`. The `telemetry.LoginCallbackRefused` and `LoginUnavailable` outcomes keep their names; only their documented causes changed.

## A new configuration error

`config.validate` and `hellhound.new` return `ConfigError.LoginCookieTooLarge` when the issuer, the client id, the longest redirect URI (the configured one or one passed to `with_allowed_redirect_uris`) and the configured scopes exceed 2 KiB together, so that the login cookie fits in 4 KiB. Add the variant to exhaustive matches on `ConfigError`. Shorten the longest redirect URI or the scope list if a configuration is refused.

`begin_login` also measures the sealed cookie, which includes the per-login scopes of `LoginOptions`. It returns `InvalidLoginOption(LoginCookieTooLarge)` (`FixConfiguration`) when the cookie would exceed 4 KiB, instead of a redirect whose callback could only fail. Add the variant to exhaustive matches on `LoginOptionProblem`.

## Sinal 0.2 and HTTP Gun 0.4

Hellhound 0.4 depends on `sinal >= 0.2.0 and < 0.3.0` and `http_gun >= 0.4.0 and < 0.5.0`. Move your own requirements on these packages to the same ranges. No Hellhound function exposes an HTTP Gun type, and every provider call keeps its own deadline (`config.with_request_timeout`).

Hellhound telemetry handlers attached with `sinal.observe` now belong to the process that attaches them and are detached when it exits. Attach them from a long-lived supervised process. See the [Sinal 0.2 migration guide](https://github.com/gleam-dream/sinal/blob/main/docs/MIGRATION.md) and the [HTTP Gun 0.4 migration guide](https://github.com/gleam-dream/http_gun/blob/main/docs/MIGRATION.md).

## PostgreSQL adapter

`hellhound_postgres` 0.2.1 (Git tag `hellhound_postgres-v0.2.1`) is the adapter release that accepts Hellhound 0.4. It serves custody only. Release 0.2.0 requires Hellhound 0.3. The adapter [README](https://github.com/gleam-dream/hellhound/blob/main/integrations/hellhound_postgres/README.md) shows the installation.

- Move to `ref = "hellhound_postgres-v0.2.1"` and to `hellhound >= 0.4.0 and < 0.5.0` together.
- Delete `config.with_transaction_store(records)`. Keep `config.with_custody_store(records)` and `config.with_sealing_key(key)`.
- Rows that 0.3 wrote as pending logins are no longer read. When the transaction store was the same store as custody, the session sweeper deletes them once they expire. When it was a separate table or schema, nothing deletes its rows: drop it after one login lifetime has passed since the upgrade.
- The adapter's schema and the custody record format are unchanged.
