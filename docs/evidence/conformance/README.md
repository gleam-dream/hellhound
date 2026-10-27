# OpenID RP conformance receipts

[![CI](https://github.com/gleam-dream/hellhound/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/gleam-dream/hellhound/actions/workflows/ci.yml)
[![hellhound on Hex](https://img.shields.io/hexpm/v/hellhound?label=Hex%3A%20hellhound)](https://hex.pm/packages/hellhound)
[![Gleam](https://img.shields.io/badge/Gleam-FFAFF3?logo=gleam&logoColor=000000)](https://gleam.run/)

The [historical summary](https://github.com/gleam-dream/hellhound/blob/4033c7885215c73661b717ca8d93938bdc95169c/docs/evidence/conformance/summary.json) records the outcomes of selected OpenID Foundation relying-party
plans for the native backend. The historical summary is retained in repository history and is not a validation gate. The
run log and the removed backend's receipts are retained in repository history at
commit `afd4f25`. The suite pin, outcome classification, deliberate differences
and limits are in [ORACLE.md](../../ORACLE.md);
[ADR 0008](../../adr/0008-oracles-and-evidence-limits.md) interprets the receipt.

- Run `scripts/conformance-suite up`, then `scripts/conformance`. Output goes under `build/conformance/`.
- A local receipt is regression evidence and does not certify a release.
