# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2025-05-15

### Added

- **Policy engine** with YAML-based security policies (`.auditfix-policy.yml`). Supports match conditions (severity, scope, EPSS, KEV, fix-available, package, depth, license, provenance, behavior, dep-age, typosquat) with `all`/`any` combinators and four actions (fail, warn, notify, auto-ignore). Includes override support with expiry dates.
- **PR comment bot** (`--pr-comment`) that posts markdown scan results as GitHub PR comments with severity table, top vulnerabilities, and auto-fix suggestions. Supports update-in-place via comment marker. Auto-detects GitHub Actions environment.
- **Teams webhook support** for Microsoft Teams incoming webhooks (MessageCard format with severity facts and optional GitHub link).
- **Discord webhook support** for Discord webhook endpoints (rich embed format with color-coded severity and top vulnerability fields).
- **SARIF diff mode** (`--sarif-baseline <path>`) that outputs only NEW vulnerabilities not present in a baseline JSON report.
- **Cache-first advisory resolution** for faster repeat scans.
- **pnpm monorepo fix** for workspace detection edge cases.
- **JavaScript GitHub Action** (`action.yml` / `action/index.ts`) for using auditfix as a reusable composite action.
- **Supply chain behavior patterns** expanded with additional detection categories.

### Changed

- Webhook platform detection now auto-routes to Slack, Teams, Discord, or generic based on URL patterns.

## [2.0.0-beta] - 2025-04-20

### Added

- **EPSS + CISA KEV graduated exploit scoring** (0-20 points) replacing binary exploit detection.
- **Typosquatting detection** via Levenshtein distance and character substitution patterns against top npm packages.
- **npm provenance verification** via Sigstore attestation endpoints.
- **Deep behavioral analysis** scanning package source for eval, child_process, env harvesting, obfuscation, and 14 risk categories.
- **OpenVEX v0.2.0** document generation mapping reachability analysis to VEX statuses.
- **CVSS v4.0 support** in addition to CVSS v3.1 (v4.0 preferred when both are present).
- **AST-improved import chain analysis** with comment stripping and Node builtin filtering.
- **OSV bulk export build script** (`scripts/build-offline-index.ts`) for comprehensive offline advisory index.

## [1.4.0] - 2025-03-10

### Added

- **Scan diff** (`auditfix diff baseline.json current.json`) for regression detection between two JSON reports.
- **Fail-on strategies** (`--fail-on production-critical | production-high | any`) for configurable CI exit code behavior.
- **Dependency age checker** (`--check-deps-age`) to flag packages with no npm updates in 2+ years.
- **Watch mode** (`--watch`) to monitor lockfiles and re-scan on changes.

### Changed

- Expanded test coverage.

## [1.3.0] - 2025-02-15

### Added

- **CI mode** (`--ci`) with machine-friendly JSON output, no colors, and strict exit codes.
- **License scanner** (`--check-licenses`) to detect copyleft and problematic licenses (AGPL, GPL, LGPL, MPL, SSPL, UNLICENSED).
- **Webhook notifications** (`--webhook <url>`) to send scan results to Slack or any HTTP endpoint.
- **GitHub Action** composite action for CI/CD integration.

## [1.2.0] - 2025-01-20

### Added

- **Bundled offline advisory index** for zero-network scanning.
- **Import chain reachability analysis** via static analysis of import/require statements.

## [1.1.0] - 2025-01-05

### Added

- **CycloneDX SBOM generation** (`--sbom`) producing CycloneDX 1.5 Software Bill of Materials.
- **Install script scanner** (`--scan-scripts`) to detect suspicious postinstall/preinstall scripts.
- **Guided remediation** (`--remediate`) with holistic fix plans ranked by impact.
- **GitHub PR creation** (`--fix --create-pr`) to automatically create PRs with security fixes.

### Fixed

- Security hardening: prototype pollution prevention, cache HMAC integrity, token redaction.
- Yarn and pnpm fix strategy edge cases.

## [1.0.1] - 2024-12-20

### Fixed

- Binary path (`bin`) for global CLI install via `npm install -g`.

## [1.0.0] - 2024-12-15

### Added

- Initial release.
- **Audit engine** with production reachability analysis and composite risk scoring (0-100).
- **Multi-lockfile support**: npm (`package-lock.json` v2/v3), Yarn Classic, Yarn Berry (v2/v3/v4), pnpm (`pnpm-lock.yaml` v5/v6/v9).
- **Monorepo/workspace support** with `--workspace` filter.
- **Safe auto-fix** via lockfile overrides (npm overrides, yarn resolutions, pnpm.overrides).
- **Allow-list** (`.auditfixignore`) with expiry dates, audit trails, and GHSA/CVE alias matching.
- **SARIF v2.1.0 output** for GitHub Code Scanning integration.
- **JSON output** for CI pipelines and scripting.
- **Four-tier advisory fallback**: OSV.dev API, local cache (4hr TTL, HMAC-verified), bundled offline index, npm bulk endpoint.
- CI and security audit GitHub Actions workflows.

## [0.3.0] - 2024-11-30

### Added

- Audit engine prototype.
- SARIF output.
- Allow-list support.
- Auto-fix for npm lockfiles.

[2.0.0]: https://github.com/BFAlajid/auditfix/compare/v1.4.0...v2.0.0
[2.0.0-beta]: https://github.com/BFAlajid/auditfix/compare/v1.4.0...v2.0.0-beta
[1.4.0]: https://github.com/BFAlajid/auditfix/compare/v1.3.0...v1.4.0
[1.3.0]: https://github.com/BFAlajid/auditfix/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/BFAlajid/auditfix/compare/v1.1.0...v1.2.0
[1.1.0]: https://github.com/BFAlajid/auditfix/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/BFAlajid/auditfix/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/BFAlajid/auditfix/compare/v0.3.0...v1.0.0
[0.3.0]: https://github.com/BFAlajid/auditfix/releases/tag/v0.3.0
