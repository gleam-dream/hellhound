# Hellhound oracles

Hellhound is compared with independent references so that its own tests are not the
only authority. This document names each reference, the revision it is pinned to,
what the comparison establishes, how to run it and where the claim stops. The
design's [validation gates](design/design.typ) section owns the obligations,
[ADR 0008](adr/0008-oracles-and-evidence-limits.md) records the interpretation of
the retained receipts, and [BENCHMARKS.md](BENCHMARKS.md) holds the measurements,
which use the same local provider fixtures. Agent commands are in
[`AGENTS.md`](../AGENTS.md).

A match is bounded to its case and revision. It does not prove compatibility with
an arbitrary provider, cryptographic safety, or certification. A local receipt is
regression evidence only; an older receipt never qualifies a new dependency
resolution or fixture pin.

## References

| Reference                              | Role                                                                                                | Upstream                                          | Pin                                                                                                                                                                                                        |
| -------------------------------------- | --------------------------------------------------------------------------------------------------- | ------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| OpenID Foundation RP conformance suite | Selected relying-party plans (Basic, Config, Form Post, refresh, RP logout, third-party initiation) | <https://gitlab.com/openid/conformance-suite>     | `release-v5.3.1`, revision `440eec8bac7b12b7389d7ca9cbc459b53507a443` (MIT); compose pins in `test/conformance/`                                                                                           |
| oidcc (test-only)                      | Differential oracle for protocol decisions                                                          | <https://github.com/erlef/oidcc>                  | `== 3.9.0`; tag `v3.9.0` at `aa212d52d0140addf057c34917b734647401b34e`, annotated tag `e5bad400ecb538bc0d826d54516fd7ee3b1cb2a8` (Apache-2.0); record declarations in `test/integration/oidcc_records.hrl` |
| oidcc conformance harness              | Upstream harness the differential corpus follows                                                    | upstream location not retained in this repository | revision `b632d9745b9490229ebca004b4df9928e1457d51` (Apache-2.0)                                                                                                                                           |
| Keycloak                               | Browser login, races, rotating refresh, revoked sessions                                            | <https://www.keycloak.org>                        | `quay.io/keycloak/keycloak:26.7.5`, digest `sha256:37dbaf6f0722c9ec246335f36e1ef8b2e6cb960f7c27e0d8c615121a3d475a85`                                                                                       |
| node-oidc-provider                     | Scriptable provider: forged and changed claims, transport cases, comparison with oidcc              | <https://github.com/panva/node-oidc-provider>     | `oidc-provider` 9.12.2 with `jose` 6.2.12 (lock: `test/providers/node-oidc/package-lock.json`)                                                                                                             |
| Dex                                    | Particular interoperability contract                                                                | <https://github.com/dexidp/dex>                   | `ghcr.io/dexidp/dex:v2.45.1@sha256:8499afd690c437f52301efd2b05b2455da5bd2dfc20332cd697dc9937f808462`                                                                                                       |
| Hydra                                  | Particular interoperability contract                                                                | <https://github.com/ory/hydra>                    | `oryd/hydra:v26.2.0@sha256:ff67c7fb5f95074fa53374d41151713554960504b340cd3f95b09e65deaea2a9`                                                                                                               |
| erlang-jose (test-only)                | Signs scripted provider tokens and independently verifies standalone assertions                     | <https://github.com/potatosalad/erlang-jose>      | `== 1.11.13`; upstream security and OTP 29 fixes (ADR 0022)                                                                                                                                                |
| Legacy JOSE vector inventory           | Token and key parsing; corpus/runner inventory remains unverified                                   | RFC 7515, 7517, 7520; Project Wycheproof          | previous broad retained-vector claim requires a named input and runner                                                                                                                                     |

## Standalone assertion and exchange evidence

The new assertion cases have three distinct executable checks:

- `test/hellhound/assertion_test.gleam` reproduces the RSA v1.5 signing example from RFC 7520 section 4.1 at the shared JWS signing layer. The example payload is ordinary text, so this is not a JWT profile test. The input is [`jws/4_1.rsa_v15_signature.json`](https://github.com/ietf-jose/cookbook/blob/13692b68bfc18b99557a5b1ed311fd5077bfff04/jws/4_1.rsa_v15_signature.json), pinned to revision `13692b68bfc18b99557a5b1ed311fd5077bfff04` (Unlicense; upstream public-domain dedication), SHA-256 `5836d16f4fa62fa311b047002e0636eba2789a6f558a26d49acfaeeb26fa470c`. `scripts/prepare-assertion-oracles` downloads it to `build/oracle-inputs/` and verifies cached and newly downloaded bytes. No upstream vector is committed.
- The same public assertion tests use the existing test-only erlang-jose 1.11.13 oracle to verify RS256, PS256, ES256 and Ed25519 output. They exercise claim omission, nested values, key metadata, weak RSA refusal, PKCS#1/PKCS#8 input and redaction. Regressions reject malformed present algorithm/key-id metadata and normalize DER-valid PEM containers with invalid RSA integers into typed refusals. Unsupported inputs and local policy have their own expected outcomes, rather than treating oracle agreement as policy authority.
- `test/oracles/assertion.mjs` independently verifies the emitted public-API RS256 token with Node's crypto API, checks its exact decoded claims/header, and rejects a changed signing input. Only a disposable public key and signed test token are emitted to `build/assertion-oracles/`. Both Node crypto and the Erlang backend may use OpenSSL: this comparison checks independent JOSE composition and interoperability, not independently implemented cryptographic primitives. The Node version comes from the Nix pin; record it alongside any retained run.

`test/hellhound/exchange_test.gleam` uses real local TLS endpoints to exercise request placement, framing refusals, relative/absent expiry, response decoding, redaction, bounds, provider failures, no redirects/resends and pool lifetime. Additional cases preserve a single default or custom User-Agent, reject C0/DEL/C1 token controls and establish transport-policy precedence over provider-status classification. `consumer/test/assertion_exchange_test.gleam` executes separate GitHub-style bearer/JSON and OAuth-style form recipes through public imports, with absolute and relative expiry decoders. The OAuth recipe rejects missing or unknown token types and null/malformed lifetime fields, while admitting case-insensitive Bearer and honestly absent expiry. These stand-ins establish wire contracts, not live GitHub acceptance or full OAuth grant conformance.

The following inspected upstream tests inform the cases; they are source references, not additional executed suites:

| Reference                                                                                                                                                                                                                                                                                                                                                                          | Inspected revision                         | Relevant cases                                                          |
| ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------ | ----------------------------------------------------------------------- |
| [panva/jose signing](https://github.com/panva/jose/blob/408077285541d63e37590604ff7946ef90595463/test/jwt/sign.test.ts), [key restrictions](https://github.com/panva/jose/blob/408077285541d63e37590604ff7946ef90595463/test/jws/restrictions.test.ts) and [property tests](https://github.com/panva/jose/blob/408077285541d63e37590604ff7946ef90595463/test/jwt/property.test.ts) | `408077285541d63e37590604ff7946ef90595463` | Claim representation, protected headers, key strength, time boundaries  |
| [oauth4webapi exchange](https://github.com/panva/oauth4webapi/blob/8ba831955ca3dc808e772747b12aa608fba36138/test/token_exchange.test.ts) and [client authentication](https://github.com/panva/oauth4webapi/blob/8ba831955ca3dc808e772747b12aa608fba36138/test/client_auth.test.ts)                                                                                                 | `8ba831955ca3dc808e772747b12aa608fba36138` | Form credential placement, malformed responses and field types          |
| [Octokit auth-app](https://github.com/octokit/auth-app.js/blob/2bb631046f01adfad1c179d7b4891b40715c97fb/test/index.test.ts)                                                                                                                                                                                                                                                        | `2bb631046f01adfad1c179d7b4891b40715c97fb` | Installation-token requests, repository restrictions, provider failures |
| [universal-github-app-jwt](https://github.com/gr2m/universal-github-app-jwt/blob/20c397039838e731d0a6768e7c6cf11122beb5bb/test/index.test.js)                                                                                                                                                                                                                                      | `20c397039838e731d0a6768e7c6cf11122beb5bb` | PEM formats and explicit clock adjustment                               |
| [Wycheproof RSA/SHA-256](https://github.com/C2SP/wycheproof/blob/d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9/testvectors_v1/rsa_signature_2048_sha256_test.json)                                                                                                                                                                                                                      | `d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9` | 259 verification vectors; not added to the signer/exchange gate         |

A source search did not locate a named corpus or runner supporting the previous broad claim that RFC 7515/7517/7520 and Wycheproof vectors were retained under `test/`. That legacy inventory remains an evidence gap; the concrete RFC7520 input above establishes only its own case. Wycheproof verification coverage primarily belongs to gose/kryptos and cannot be inferred from these signing tests.

The canonical `nix develop -c scripts/check` fetches/checks the fixed input, runs the Gleam/Erlang tests and then the Node oracle. For a focused rerun after compilation:

```sh
scripts/prepare-assertion-oracles
node test/oracles/assertion.mjs
```

The Node command requires the output emitted by the public assertion test. It never verifies against a key generated by the runtime signer itself.

Runtime JOSE is gose and kryptos and runtime HTTPS is HTTP Gun. oidcc, erlang-jose
and telemetry_registry are development oracles; an application does not install
them by using Hellhound.

No upstream oracle input is committed except one header. `scripts/conformance-suite`
fetches the suite's `docker-compose-prebuilt.yml` at tag `release-v5.3.1` from
<https://gitlab.com/openid/conformance-suite/-/raw/release-v5.3.1/docker-compose-prebuilt.yml>
into `build/oracle-inputs/` and stops unless its sha256 is
`c80e417b2a0c735e595dd49e6cd95fc43a75b692389016ddb863c4539e41d330`. The
oidcc 3.9.0 record declarations that the raw probes compile against stay in
`test/integration/oidcc_records.hrl`. Every project that depends on Hellhound by
path compiles those probes without the oidcc development dependency, so an
`-include_lib` of oidcc's own headers would force oidcc and its JOSE oracle
into each consumer. Container images are pulled by the digests above.

## What each comparison establishes

| Comparison         | Classification of outcomes                                                                                                                                          | Establishes                                                               |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------- |
| OpenID RP plans    | `PASSED` is a pass. `SKIPPED` and `REVIEW` are non-pass and stay distinct; interruption, unknown outcomes, driver errors, missing modules and empty selections fail | Regression of selected modules against the retained suite release         |
| oidcc differential | A difference is either recorded (stricter audience, required ID token, refresh handling) or fails the run                                                           | Agreement on the compared cases at the pinned oidcc revision              |
| Keycloak           | Pass or fail per scenario; logs and browser journey JSON retained                                                                                                   | Browser login, races, rotating refresh and revoked sessions on this image |
| node-oidc-provider | Forged and changed claims and transport cases are refused or accepted as recorded; compared with oidcc                                                              | Claim and transport handling against a scriptable independent provider    |
| Dex and Hydra      | Pass or fail per scenario                                                                                                                                           | Their particular interoperability contracts                               |

OpenID verdicts default to strict: every selected module must finish `PASSED`.
`regression` mode (`HELLHOUND_CONFORMANCE_POLICY=regression`) permits only the exact
`SKIPPED` unsigned-token and `REVIEW` logout outcomes listed in
`test/conformance/known-outcomes.json`; they remain non-pass evidence. Neither
policy confers certification.

## Exclusions and deliberate differences

- The 2026-10-01 local runs used the non-default confidential-client option
  `AssumeS256WhenUnadvertised`, because the suite's test provider omits PKCE
  metadata. Unsigned-token modules were skipped because Hellhound refuses `none`.
  RP logout modules required human review. Third-party initiation stopped in suite
  setup before any relying-party request. None of these is promoted to a pass.
- Hellhound is deliberately stricter than the oracle in three recorded cases: exact
  access-token audience, a required ID token, and refresh handling. These
  differences are the expected outcome, not failures.
- The advisory-query control found oidcc `GHSA-mj35-2rgf-cv8p` but missed
  `GHSA-533g-4vf3-xwrj`, so an empty advisory query is weak evidence. The oidcc
  tag signature was not verified locally because its key was absent.
- Kid-less wrong-key rotation may not refetch, `allowed_hosts` does not restrict
  ports, and certificate revocation checking is not claimed.

## Run a comparison

All fixtures are disposable and local; no public issuer or production tenant is
used. `scripts/test-pki` generates the test PKI under `build/test-pki`.

```sh
scripts/keycloak up && HELLHOUND_SUITE=keycloak gleam test
scripts/node-provider up && HELLHOUND_SUITE=node gleam test
scripts/interop up && HELLHOUND_SUITE=interop gleam test
scripts/browser-journey
scripts/conformance-suite up
HELLHOUND_CONFORMANCE_POLICY=regression scripts/conformance-check basic,formpost,config,refresh,logout
```

`scripts/provider-check node|keycloak|interop|browser` runs a suite and stops its
fixture. Stop a fixture with its `down` command. Node provider and Hydra consent
startup refuse an occupied port or an existing ownership record; after an
uncatchable fixture death, inspect and remove the stale `build/*.owner` directory by
hand. The full gate (`scripts/check full`) runs all four provider suites and needs
Docker Compose and Google Chrome. Ports 8443 and 19443 must be free for the
conformance-driver and fixture-lifecycle gate checks.

## Receipts

| Receipt                                                   | Contents                                                                                                                                                                                           |
| --------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [`evidence/conformance/`](evidence/conformance/README.md) | [Historical summary](https://github.com/gleam-dream/hellhound/blob/4033c7885215c73661b717ca8d93938bdc95169c/docs/evidence/conformance/summary.json), the outcomes of the native backend's last run |

The conformance run log, the removed backend's receipts, the browser journey
receipts and the raw logs of the HTTP Gun adoption experiment (ADR 0002) are
retained in repository history at commit `afd4f25`.

Retain a new result with the exact package, fixture, option and toolchain
revisions, and keep skipped and human-review modules separate from passes. Never
overwrite checked-in history. The retained 1 October 2026 conformance summary
recorded Basic and Form Post at 13 passed and one skipped each, Config at five
passed and one skipped, refresh at three passed and RP logout at three
review-needed modules.

## Limits of the claim

A conformance or differential result does not establish security, certification or
provider compatibility beyond its case. Races, unknown store effects, provider
uncertainty, expiry barriers, process replacement and redaction need the runtime
evidence the design names. Release acceptance also requires changed dependency and
advisory review, a release SBOM and independent review of Hellhound-owned security
code (ADR 0008).
