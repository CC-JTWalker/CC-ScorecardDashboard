# OpenSSF Best Practices evidence checklist

Use this file while completing the project questionnaire at https://www.bestpractices.dev/.

## Basics

- Public source repository: GitHub project root.
- License: `LICENSE` (MIT).
- Contribution process: `CONTRIBUTING.md`.
- Governance: `GOVERNANCE.md`.
- Code of conduct: `CODE_OF_CONDUCT.md`.
- Security reporting: `SECURITY.md` and GitHub private vulnerability reporting.

## Quality and security evidence

- Automated tests: `.github/workflows/ci.yml` and `test/`.
- Property-based fuzzing: `fuzz/scorecard.fuzz.js`.
- Static analysis: `.github/workflows/codeql.yml`.
- Dependency updates: `.github/dependabot.yml`.
- Locked dependencies: `package-lock.json`.
- Release provenance: `.github/workflows/release.yml`.
- Security posture monitoring: `.github/workflows/scorecard.yml`.
- Repository hardening instructions: `docs/REPOSITORY_SECURITY_SETUP.md`.

Answer questionnaire items based on actual current practice, not merely the existence of a file. Do not display a passing badge until the external service awards it.
