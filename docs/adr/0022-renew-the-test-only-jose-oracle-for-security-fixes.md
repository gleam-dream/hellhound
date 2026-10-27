# Renew the test-only JOSE oracle for upstream security fixes

<a id="adr-0022"></a>

- **Decision:** pin the unmodified test-only erlang-jose 1.11.13 release. It replaces 1.11.12 for scripted provider signing and independent assertion verification. Applications using Hellhound do not install this development dependency.
- **Reason:** upstream 1.11.13 fixes the security advisories published on 26 October 2026 and replaces the unary `catch` expressions deprecated by OTP 29. Retaining the earlier pin would preserve known vulnerable oracle code.
- **Build consequence:** ordinary `gleam build --warnings-as-errors` and `scripts/erlang-check` require no compiler exception. This supersedes the deprecated-catch exception in [ADR 0016](0016-nowarn-deprecated-catch-is-scoped-to-the-oracle-build.md).
- **Evidence contract:** rerun the local, independent provider and browser gates against the new exact manifest resolution. Old receipts remain historical evidence and do not qualify this pin. Independent review and the other release obligations remain unchanged.
- **Upstream:** [1.11.13 release and security changes](https://github.com/potatosalad/erlang-jose/releases/tag/1.11.13); `manifest.toml` records the exact Hex checksum. Runtime JOSE remains gose and kryptos.
