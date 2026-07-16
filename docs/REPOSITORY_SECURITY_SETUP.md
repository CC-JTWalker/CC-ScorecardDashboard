# Repository security setup

Files in this repository improve automation, but several Scorecard checks depend on GitHub settings and real project history. Apply these settings after merging the hardening pull request.

## Repository rules for `main`

Create an active ruleset targeting the default branch and enable:

- Require a pull request before merging.
- Require at least one approval.
- Dismiss stale approvals when new commits are pushed.
- Require review from Code Owners.
- Require conversation resolution.
- Require the CI and CodeQL checks to pass.
- Block force pushes and branch deletion.
- Restrict bypass access to the smallest practical maintainer group.

Prefer GitHub repository rules over legacy branch protection so the Scorecard workflow can read the configuration using its default token.

## Actions and repository security

- Set the default `GITHUB_TOKEN` permission to read-only.
- Allow only selected actions, or actions owned by GitHub, OpenSSF, and the explicitly pinned actions in this repository.
- Enable Dependabot alerts, Dependabot security updates, secret scanning, push protection, private vulnerability reporting, and code scanning.
- Do not add long-lived signing keys to repository secrets. The release workflow uses short-lived OIDC identity and Sigstore-backed attestations.

## Review history

Open this hardening work as a pull request rather than pushing directly. Have another eligible maintainer approve it. Scorecard cannot award CI-Tests or Code-Review points until pull requests and approvals actually exist.

## Releases

Create a reviewed release commit, then create and push a signed annotated tag:

```bash
git tag -s v1.1.0 -m "Scorecard Radar v1.1.0"
git push origin v1.1.0
```

The release workflow builds installers on Linux, Windows, and macOS; creates SHA-256 checksums; generates signed provenance; and publishes the artifacts. Platform-native code signing and notarization require maintainer-owned certificates and should be added before broad distribution.

## OpenSSF Best Practices badge

Register the project at https://www.bestpractices.dev/ and complete the project questionnaire. Add the awarded badge to README.md only after the service reports a passing level.

## Checks that need time or community activity

The Maintained score cannot become positive until the repository is old enough and shows continuing activity. The Contributors score requires contributions from multiple organizations or independent contributors; documentation cannot manufacture that history.
