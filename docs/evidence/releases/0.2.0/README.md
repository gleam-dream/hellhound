# Hellhound 0.2.0 release preparation evidence

The candidate was prepared on 27 October 2026 from commit
`4c95a70f0bdbc36701533ae12d458a33fcc77487` and the release changes recorded in
`build/release-0.2.0/release-candidate.json` inside the archive. That receipt
identifies the checked source files, dependency manifests and fixture inputs by
SHA-256. It does not record a publication.

- [Dependency SBOM](sbom.cdx.json): 21 runtime dependencies and four development
  dependencies, with the assessed outbound-header mitigation retained.
- [Receipts archive](receipts.tar.gz): 107 captured reports, logs and artifacts,
  preserving their original `build/` paths. It includes the candidate Hex archive,
  dependency metadata, advisory queries and assessments, provider logs, browser
  results, conformance summaries and the release-candidate receipt.

The receipts archive has SHA-256
`2368600d9f4bc89bca6a8985e4a23d8cc36446e577c0325781b45fef5854c500`.

| Check | Recorded outcome |
| --- | --- |
| Canonical full gate | Passed: 331 tests, compiler rejection fixtures and independent signing verification |
| PostgreSQL adapter against the 0.2.0 candidate | 17 tests passed; constructor privacy and positive control passed |
| Formatting, design integrity and README snippets | Passed |
| Hex archive and API documentation | Built; packaged sources matched the candidate |
| Selected OpenID regression plans | 34 PASSED, three SKIPPED and three REVIEW; accepted by the existing regression policy |

The initial OpenID logout attempt reached an unrelated IPv4 service. Its three
results were superseded by the recorded logout rerun. That rerun used process-local
IPv6 routing and an isolated Docker database volume. Test cases and the existing
test-certificate trust settings were unchanged. The combined receipt names both
runs and preserves the superseded results separately.

Skipped unsigned-token cases and logout REVIEW outcomes remain non-pass evidence.
Independent security review and the documented certification gaps remain release
conditions. Earlier attempts and superseded dependency snapshots are retained as
history and do not qualify the final candidate.

Disposable helper scripts and generated PKI are excluded. Conformance module
exports containing fixture private keys remain in the ignored local build output;
the retained summaries record their outcomes without those keys. The repository's
existing checks remain the validation commands.
