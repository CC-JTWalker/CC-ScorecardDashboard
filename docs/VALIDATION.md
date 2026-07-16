# Validation record

Validation performed on 2026-07-16 with Node.js 22.16.0:

- `npm run check`: passed (16 unit/security tests plus repository static checks).
- `npm run fuzz`: passed (2,000 generated property-based cases).
- `npm audit --audit-level=high`: passed with 0 known vulnerabilities.
- All GitHub workflow and configuration YAML files parsed successfully.
- All GitHub Action references are full 40-character commit SHAs.
- All 286 lockfile download URLs use the npm registry and include integrity metadata where npm supplies it.
- The supplied Scorecard report parsed successfully as one report with 18 checks.

A local installer build was attempted, but this execution environment could not resolve `github.com` while Electron's install step attempted to retrieve the platform binary. No platform installer is represented as locally validated here. The tagged release workflow performs clean native builds on GitHub-hosted Linux, Windows, and macOS runners before publishing artifacts.
