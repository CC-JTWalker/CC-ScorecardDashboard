# Hardening changes in 1.1.0

- Added CI, CodeQL, OpenSSF Scorecard, and signed-provenance release workflows.
- Added Dependabot configuration, CODEOWNERS, pull-request requirements, issue forms, and security/contribution governance documents.
- Pinned direct npm dependencies and every GitHub Action to an immutable commit SHA.
- Added fast-check property-based fuzz tests.
- Restricted IPC calls to the packaged renderer and limited file-reveal operations to files from the active scan.
- Denied renderer permissions, webviews, navigation, and downloads; retained context isolation, sandboxing, and disabled Node integration.
- Added input limits for tokens, identifiers, CSV output, JSON reports, file counts, and remote response bodies.
- Wrote credential/cache files atomically with owner-only POSIX modes where supported.
- Filtered external URLs and advisory references to credential-free HTTPS URLs.
- Neutralized spreadsheet formula prefixes in CSV cells.
