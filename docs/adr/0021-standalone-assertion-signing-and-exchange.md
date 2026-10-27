# Standalone assertions and explicit credential exchange

<a id="adr-0021"></a>

- **Decision:** expose application-agnostic JWT signing and one-request HTTPS credential exchange independently of the discovery-backed Client roles. Claims, protected headers and credential placement are explicit. Typed request builders and caller-owned response decoders express provider variation.
- **Motivation:** GitHub App installation authentication needs an RS256 JWT with issuer/issued-at/expiry claims delivered as a bearer credential to an explicit endpoint. OAuth client assertions use form fields and additional profile requirements. Neither requires inventing a browser login or treating GitHub as an OpenID issuer.
- **Ownership:** Hellhound admits keys, signs through gose, owns transport limits, framing, redaction and send evidence. Applications choose claim profiles, destinations, decoder semantics, token usability, caching and retries. An exchange client owns only a supervised HTTP pool; its application supervisor owns that pool's lifetime.
- **Alternatives:** a signer-only API leaves credential delivery to each application. Arbitrary request callbacks obscure credential/framing authority. A GitHub-specific runtime API couples a generic library to provider paths and response fields. Typed bearer/form placement, empty/form/JSON bodies and caller decoding cover both demonstrated consumers without those costs.
- **Compatibility:** preserve existing private_key_jwt claims and authentication form. Share key admission without exposing private material. Generic HTTP credential exchange does not resolve the separate RFC 7523 grant or RFC 8693 token-exchange capability gaps retained by ADR 0009.
- **Evidence:** use failing public-boundary tests before implementation, published RS256 vectors, independent verification, two compiled consumers and adversarial transport/redaction tests. ORACLE.md records exact inputs and the limits of each comparison.
