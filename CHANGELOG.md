# Changelog

## 1.1.0 — 2026-07-16

### Repository security

- Added pull-request CI, CodeQL SAST, OpenSSF Scorecard, Dependabot, and multi-platform release workflows.
- Pinned every GitHub Action to a full commit SHA and every direct npm dependency to an exact version.
- Added a reproducible npm lockfile, least-privilege workflow permissions, CODEOWNERS, contribution guidance, governance, and a coordinated disclosure policy.
- Added property-based fuzzing with 2,000 generated cases per run.
- Added checksums and Sigstore-backed build provenance to tagged releases.

### Application hardening

- Validated every IPC sender and bounded all renderer-to-main inputs.
- Restricted file reveal operations to reports from the active scan and resolved paths before containment checks.
- Denied renderer permissions, webviews, downloads, unexpected navigation, and unsafe external URLs.
- Refused token persistence when Electron falls back to an insecure Linux storage backend.
- Added atomic owner-only cache/settings writes, bounded local and remote JSON processing, iterative report parsing, CSV formula neutralization, and stricter CSP.
- Bounded raw JSON and vulnerability-intelligence text before rendering.

### Validation

- Added 16 unit/security tests and 2,000 property-based fuzz cases.
- Added repository checks for JavaScript syntax, required policy files, workflow permissions, unsafe triggers, dependency pins, and immutable action references.
