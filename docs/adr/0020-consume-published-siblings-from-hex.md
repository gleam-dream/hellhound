# Consume published siblings from Hex

<a id="adr-0020"></a>

## Decision

Use Hex version requirements for published Sinal, HTTP Gun, Relay and JSON
Blueprint. Reconcile every affected root, consumer and adapter manifest through
Gleam, then run the canonical and full local gates.

This supersedes the Git dependency declarations in [ADR 0015](0015-ci-runs-the-local-gate-on-locked-dependencies.md).
Its explicit updates, locked resolution, read-only CI permissions and evidence
limits remain. Historical oracle and provider pins remain frozen.

## Rationale

Hex consumers need one registry source for each released library. Git requirements
for published siblings would conflict with that source and prevent publication.
The existing release qualification obligations in [ADR 0008](0008-oracles-and-evidence-limits.md)
continue to apply.
