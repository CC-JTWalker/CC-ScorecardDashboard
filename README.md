# Scorecard Radar

[![CI](https://github.com/CC-JTWalker/CC-ScorecardDashboard/actions/workflows/ci.yml/badge.svg)](https://github.com/CC-JTWalker/CC-ScorecardDashboard/actions/workflows/ci.yml)
[![CodeQL](https://github.com/CC-JTWalker/CC-ScorecardDashboard/actions/workflows/codeql.yml/badge.svg)](https://github.com/CC-JTWalker/CC-ScorecardDashboard/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/CC-JTWalker/CC-ScorecardDashboard/badge)](https://scorecard.dev/viewer/?uri=github.com/CC-JTWalker/CC-ScorecardDashboard)

Scorecard Radar is a local-first Electron dashboard for reviewing directories of OpenSSF Scorecard JSON reports. It is designed for a fast portfolio-level answer to four questions:

1. Which repositories have the weakest security posture?
2. Which findings deserve attention first?
3. Which reports are too old to trust?
4. Are referenced vulnerabilities likely to matter in the real world?

## Features

- Opens a directory from the UI or from a command-line directory argument.
- Recursively scans `.json` files, with support for JSON objects, arrays, and newline-delimited JSON.
- Handles common Scorecard JSON/API field variants rather than requiring one exact export shape.
- Groups multiple scans of the same repository and shows the latest score plus change from the previous report.
- Highlights the entire row yellow when the report is **over 270 days old** and red when it is **over 360 days old**.
- Ranks weak checks using both the Scorecard check score and the check's security risk category.
- Extracts CVE and GHSA identifiers from any nested part of a report.
- Enriches vulnerabilities with:
  - GitHub Advisory Database summaries, affected packages, fix versions, CVSS, and EPSS when supplied.
  - OSV advisory aliases, affected ranges, fix events, and references.
  - FIRST EPSS current exploitation probability and percentile.
  - CISA Known Exploited Vulnerabilities confirmation, required action, due date, and ransomware-use indicator.
- Produces a contextual 0–100 remediation priority with a visible rationale instead of sorting only by static CVSS.
- Caches vulnerability results for 24 hours and the CISA KEV catalog for 12 hours, with graceful offline fallback.
- Includes filtering, search, score history, raw JSON inspection, source status, and CSV export.
- Uses Electron security boundaries: context isolation, a sandboxed renderer, no Node.js integration, trusted-sender IPC validation, permission denial, active-scan file authorization, credential-free HTTPS links, response-size limits, and encrypted token storage through the operating system.

## Run it

Requirements: Node.js 22.12 or newer and npm 10 or newer.

```bash
npm ci
npm start
```

You can also launch it with a report directory:

```bash
npm start -- /path/to/scorecard-reports
```

Try the included data by choosing the `sample-data` directory.

## Build an installer

```bash
npm run dist
```

`electron-builder` creates platform-appropriate output in `dist/`. Build each target operating system on that operating system unless your CI setup supports cross-compilation and signing.

## Test

```bash
npm run check
npm run fuzz
```

The tests cover parsing, NDJSON, identifier extraction, exact stale thresholds, repository history, KEV prioritization, CVSS v3 vector calculation, IPC input validation helpers, path containment, URL restrictions, and export limits. Property-based tests generate 2,000 additional report and identifier cases with `fast-check`.

## Repository security and releases

The repository includes immutable-SHA-pinned workflows for CI, CodeQL, OpenSSF Scorecard, and multi-platform releases. Dependabot tracks npm and GitHub Actions updates. Tagged releases produce installers, SHA-256 checksums, and Sigstore-backed build provenance. See `SECURITY.md`, `CONTRIBUTING.md`, `docs/HARDENING.md`, `docs/SCORECARD_REMEDIATION.md`, `docs/REPOSITORY_SECURITY_SETUP.md`, and `docs/VALIDATION.md`.

Several Scorecard checks depend on settings and history that files cannot create. After merging through an approved pull request, enable the repository rules and security settings in `docs/REPOSITORY_SECURITY_SETUP.md`. Create release tags with a maintainer-controlled signing key.

When dependencies change, run `npm install --package-lock-only` and commit the resulting `package-lock.json`. Do not replace exact dependency versions with ranges.

## Contextual vulnerability priority

The priority is deliberately explainable. It combines:

- Confirmed active exploitation in CISA KEV, which forces priority 100.
- CVSS base impact where available.
- Current EPSS probability and percentile.
- Network attack vector, privileges, and user-interaction signals from CVSS vectors.
- Whether a fixed version is identified.
- Advisory package and affected-range information.

This is a triage aid, not proof that a repository is exploitable. A Scorecard report may mention a CVE without containing the exact dependency version, runtime exposure, reachability, deployment controls, or compensating mitigations needed for a definitive applicability decision. The UI therefore says “contextual risk” and shows its evidence rather than claiming certainty.

## Data sent over the network

Report files remain on the computer. During vulnerability enrichment, only discovered CVE/GHSA identifiers are sent to public intelligence endpoints. A GitHub token is optional and is used only for GitHub Advisory API requests. When secure OS credential encryption is unavailable, the app refuses to persist the token.

Endpoints used:

- `https://api.github.com/advisories`
- `https://api.osv.dev/v1/vulns/{id}`
- `https://api.first.org/data/v1/epss`
- `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`

## Supported report shape

The canonical shape is similar to:

```json
{
  "date": "2026-07-01T12:00:00Z",
  "repo": { "name": "github.com/org/repo", "commit": "..." },
  "score": 7.8,
  "checks": [
    {
      "name": "Branch-Protection",
      "score": 5,
      "reason": "...",
      "details": ["..."]
    }
  ]
}
```

The parser also recognizes several alternate names for repository, timestamp, score, commit, and check fields. If a report does not contain a usable date, the JSON file's modification time is shown and labeled as such.

## Design notes

- No frontend framework or bundler is required; this keeps installation and auditing simple.
- Public API failures are isolated by source. One failed source does not discard information from the others.
- The unauthenticated GitHub API has relatively low rate limits. Add a token in Settings for large directories.
- The app caps a single JSON file at 25 MB and a scan at 10,000 JSON files to avoid accidental resource exhaustion. Remote intelligence responses, identifier batches, token length, and CSV exports are also bounded.

## License

MIT
