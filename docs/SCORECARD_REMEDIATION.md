# Scorecard remediation map

This release was hardened against the OpenSSF Scorecard report dated 2026-07-16 for `github.com/CC-JTWalker/CC-ScorecardDashboard` (aggregate score 2.6). A new scan is required after these changes are merged and GitHub settings are applied.

| Check | Reported | Repository change | What still must happen |
|---|---:|---|---|
| Binary-Artifacts | 10 | Generated output remains ignored. | Keep installers out of the source branch. |
| Branch-Protection | 0 | CODEOWNERS, required checks, and setup instructions added. | Enable the `main` repository ruleset in GitHub. |
| CI-Tests | -1 | Pull-request CI now runs static checks, unit tests, fuzzing, and audit. | Merge through a pull request so Scorecard can observe CI history. |
| CII-Best-Practices | 0 | Evidence checklist and registration instructions added. | Register the project and complete the external questionnaire. |
| Code-Review | 0 | CODEOWNERS and a review-focused PR template added. | Require approval and merge approved pull requests. |
| Contributors | 0 | Contribution and governance documents added. | Accept contributions from additional independent people or organizations. |
| Dangerous-Workflow | -1 | Workflows use safe triggers, least privilege, and immutable action SHAs. | Run the workflows on GitHub and review every future workflow change. |
| Dependency-Update-Tool | 0 | Dependabot covers npm and GitHub Actions. | Enable Dependabot alerts and security updates in repository settings. |
| Fuzzing | 0 | `fast-check` property tests generate 2,000 cases per run. | Let CI establish successful fuzzing history. |
| License | 10 | MIT license retained. | No action. |
| Maintained | 0 | CI and maintenance automation added. | Repository age and continued activity must accumulate naturally. |
| Packaging | -1 | Tagged release workflow builds Linux, Windows, and macOS installers. | Push a reviewed release tag and publish the first release. |
| Pinned-Dependencies | -1 | Exact direct versions, `package-lock.json`, and full-SHA action pins added. | Keep the lockfile and use Dependabot PRs for updates. |
| SAST | 0 | CodeQL scans JavaScript on pushes, pull requests, and weekly. | Enable code scanning and complete a successful run. |
| Security-Policy | 0 | `SECURITY.md` and private-reporting issue routing added. | Enable GitHub private vulnerability reporting. |
| Signed-Releases | -1 | Release checksums and Sigstore-backed provenance are generated. | Use a signed tag; add native platform signing/notarization when certificates are available. |
| Token-Permissions | -1 | Top-level read permissions and narrowly scoped job writes are declared. | Set the repository default `GITHUB_TOKEN` permission to read-only. |
| Vulnerabilities | 10 | Dependency audit is part of CI; current local audit found none. | Keep audit and Dependabot findings resolved. |

Scorecard checks measure observable repository state. Adding a file does not guarantee a score until the associated workflow, setting, review, release, or external registration exists and can be read by Scorecard.
