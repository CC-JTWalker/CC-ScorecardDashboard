# Scorecard Radar

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
- Uses Electron security boundaries: context isolation, sandboxed renderer, no Node.js integration, IPC allowlisting, HTTPS-only external links, and encrypted token storage through the operating system.

## Run it

Requirements: Node.js 20 or newer and npm.

```bash
npm install
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
npm test
```

The tests cover parsing, NDJSON, identifier extraction, exact stale thresholds, repository history, KEV prioritization, and CVSS v3 vector calculation.

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
- The app caps a single JSON file at 25 MB and a scan at 10,000 JSON files to avoid accidental resource exhaustion.

## License

MIT
