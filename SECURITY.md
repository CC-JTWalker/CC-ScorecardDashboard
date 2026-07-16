# Security Policy

## Supported versions

Security fixes are provided for the newest released version. Older versions should be upgraded before requesting a patch.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's private vulnerability reporting flow:

https://github.com/CC-JTWalker/CC-ScorecardDashboard/security/advisories/new

Include the affected version, operating system, reproduction steps, impact, and any suggested mitigation. Remove real access tokens, private Scorecard reports, repository secrets, and personal data from evidence.

The maintainer should acknowledge a complete report within seven calendar days, provide a preliminary assessment within fourteen days, and coordinate disclosure after a fix is available. These are targets rather than guarantees for a volunteer-maintained project.

## Scope notes

Scorecard Radar reads untrusted JSON and optionally queries public vulnerability-intelligence services. Reports remain local, but discovered CVE/GHSA identifiers are sent to the endpoints documented in README.md. Findings about those upstream services should be reported to their operators unless the problem is caused by this application's handling of them.
