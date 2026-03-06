# auditfix

[![CI](https://github.com/BFAlajid/auditfix/actions/workflows/ci.yml/badge.svg)](https://github.com/BFAlajid/auditfix/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/auditfix)](https://www.npmjs.com/package/auditfix)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-brightgreen)](https://nodejs.org)

Smarter npm dependency security CLI. Replaces `npm audit` with production reachability analysis, risk scoring, and safe auto-fixes.

## Example Output

```
auditfix v1.4.0 — scanned 847 packages

CRITICAL (1)
  lodash@4.17.20 — Prototype Pollution in lodash
  Path: my-app > lodash
  Production: YES | Exploit: NO | Fix: 4.17.21
  → Run `auditfix --fix` to auto-patch

HIGH (2)
  express@4.17.1 — Open redirect in express
  Path: my-app > express
  Production: YES | Exploit: NO | Fix: 4.19.2
  → Run `auditfix --fix` to auto-patch

  jsonwebtoken@8.5.1 — Insecure default algorithm in jsonwebtoken
  Path: my-app > jsonwebtoken
  Production: YES | Exploit: NO | Fix: 9.0.0
  → Run `auditfix --fix` to auto-patch

MEDIUM (0)
LOW (1)
  semver@5.7.1 — ReDoS in semver
  Path: my-app > semver
  Production: NO (dev only) | Exploit: NO | Fix: 7.5.2
  → Low risk. Dev tooling only.

Scanned: 847 packages
Advisory source: OSV.dev API (real-time) | Matched against: 312 advisories
Confidence: HIGH

Summary: 1 critical (1 production) | 2 high (2 production) | 1 low (dev-only)
CI exit code: 1 (production vulnerabilities found)
```

## Why auditfix?

`npm audit` is noisy. It flags every advisory regardless of whether the vulnerable package is even reachable in production. auditfix solves this by:

- **Production reachability** — Only flags vulnerabilities in packages your production code actually uses
- **Import chain analysis** — Static analysis of import/require statements to verify packages are actually imported
- **Risk scoring** — Composite score (0-100) based on CVSS, production exposure, exploit availability, and fix availability
- **Safe auto-fix** — Automatically applies non-breaking updates via lockfile overrides (npm, yarn, pnpm)
- **Scan diff** — Compare two scans to detect regressions (`auditfix diff baseline.json current.json`)
- **Multi-lockfile support** — npm, yarn (classic + berry), and pnpm
- **Monorepo support** — Workspace detection with per-workspace vulnerability mapping
- **CycloneDX SBOM** — Generate a CycloneDX 1.5 Software Bill of Materials
- **Install script scanner** — Detect suspicious `postinstall`/`preinstall` scripts
- **License scanner** — Detect copyleft and incompatible licenses in dependencies
- **Dependency age checker** — Flag unmaintained packages with no updates in 2+ years
- **Guided remediation** — Holistic fix plans ranked by impact
- **GitHub PR creation** — Automatically create PRs with security fixes
- **Webhook notifications** — Post scan results to Slack or any webhook endpoint
- **CI mode** — Machine-friendly JSON output with configurable exit code strategies
- **Watch mode** — Monitor lockfiles and re-scan on changes
- **Offline mode** — Bundled advisory index works with zero network access
- **Multiple output formats** — Terminal, JSON, and SARIF (for GitHub Code Scanning)
- **Allow-list** — Suppress known false positives with expiry dates and audit trails

## Install

```bash
npm install -g auditfix
```

Or run directly:

```bash
npx auditfix
```

## Usage

```bash
# Scan current project
auditfix

# Production vulnerabilities only
auditfix --prod-only

# Filter by severity
auditfix --severity high

# Auto-fix safe updates
auditfix --fix

# Auto-fix and create a GitHub PR
auditfix --fix --create-pr

# Show guided remediation plan
auditfix --remediate

# CI mode (JSON output, no colors, strict exit codes)
auditfix --ci

# CI with custom fail strategy
auditfix --ci --fail-on production-critical   # only fail on prod criticals
auditfix --ci --fail-on any                   # fail on any vulnerability

# Compare two scans (regression detection)
auditfix diff baseline.json current.json

# Check dependency licenses
auditfix --check-licenses

# Check for unmaintained packages
auditfix --check-deps-age

# Watch mode (re-scan on lockfile changes)
auditfix --watch

# Send results to Slack or webhook
auditfix --webhook https://hooks.slack.com/services/T00/B00/xxx

# Generate CycloneDX SBOM
auditfix --sbom > sbom.json

# Scan for suspicious install scripts
auditfix --scan-scripts

# Filter to a specific workspace (monorepo)
auditfix --workspace @myorg/api

# JSON output for scripting
auditfix --json

# SARIF output for GitHub Code Scanning
auditfix --sarif

# Scan a different directory
auditfix --dir /path/to/project

# Debug output
auditfix --verbose
```

## Allow-list

Suppress known false positives with `.auditfixignore`:

```bash
auditfix ignore GHSA-xxxx-yyyy-zzzz \
  --package lodash \
  --reason "Not reachable in our usage" \
  --expires 2026-12-31
```

This creates a `.auditfixignore` file in your project root with an audit trail.

## Scan Diff

Compare two JSON reports to detect regressions:

```bash
# Save a baseline
auditfix --json > baseline.json

# After changes, compare
auditfix --json > current.json
auditfix diff baseline.json current.json
```

Output shows new vulnerabilities (red), fixed vulnerabilities (green), and unchanged. Exits 1 if regressions are found — useful for CI PR gating.

## CI Exit Code Strategies

Control when auditfix fails your CI pipeline:

| Strategy | `--fail-on` value | Fails when |
|----------|-------------------|------------|
| Default | `production-high` | Production critical or high vulns |
| Strict | `production-critical` | Only production critical vulns |
| Zero tolerance | `any` | Any vulnerability at all |

```bash
auditfix --ci --fail-on production-critical
```

## License Scanner

Detect copyleft and problematic licenses in your dependency tree:

```bash
auditfix --check-licenses
```

Flags:
- **Network copyleft** (AGPL, SSPL) — SaaS counts as distribution
- **Copyleft** (GPL, LGPL, MPL, EPL) — Derivative works must use same license
- **Unknown** (UNLICENSED) — No license specified

Handles SPDX expressions: `(MIT OR GPL-3.0)` is OK because MIT is permissive.

## Dependency Age Checker

Flag packages with no npm updates in 2+ years:

```bash
auditfix --check-deps-age
```

Queries the npm registry for last publish dates. Helps identify abandoned or unmaintained dependencies.

## Watch Mode

Monitor lockfiles and automatically re-scan when they change:

```bash
auditfix --watch
```

Watches `package-lock.json`, `yarn.lock`, and `pnpm-lock.yaml` in the project directory. Runs an initial scan, then re-scans whenever a lockfile is modified.

## Webhook Notifications

Send scan results to Slack or any HTTP endpoint:

```bash
# Slack incoming webhook
auditfix --webhook https://hooks.slack.com/services/T00/B00/xxx

# Generic webhook (receives JSON payload)
auditfix --webhook https://your-server.com/audit-hook
```

Slack messages include severity counts, top 5 vulnerabilities, and confidence level.

## Output Formats

### Terminal (default)

Color-coded output with severity, package, version, risk score, and fix availability.

### JSON (`--json` or `--ci`)

Machine-readable output for CI pipelines and scripting.

### SARIF (`--sarif`)

SARIF v2.1.0 output for GitHub Code Scanning integration:

```bash
auditfix --sarif > results.sarif
```

### CycloneDX SBOM (`--sbom`)

Generate a CycloneDX 1.5 Software Bill of Materials:

```bash
auditfix --sbom > sbom.json
```

## GitHub Actions

### Basic SARIF workflow

Copy to `.github/workflows/auditfix.yml`:

```yaml
name: Security Audit
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]
  schedule:
    - cron: '0 6 * * *'

permissions:
  security-events: write
  contents: read

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
      - run: npm ci
      - name: Run auditfix
        run: npx auditfix --sarif > results.sarif
        continue-on-error: true
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: results.sarif
```

### PR regression gating

Fail PRs that introduce new vulnerabilities:

```yaml
- name: Baseline scan
  run: npx auditfix --json > baseline.json
  continue-on-error: true

- name: Check for regressions
  run: npx auditfix diff baseline.json current.json
```

### Auto-fix PR workflow

Automatically create PRs with security fixes on a schedule. See [`examples/auto-fix-pr.yml`](examples/auto-fix-pr.yml).

### Composite Action

auditfix ships as a reusable GitHub Action:

```yaml
- uses: BFAlajid/auditfix@v1
  with:
    severity: high
    production-only: true
    auto-fix: true
    sarif: true
    webhook-url: ${{ secrets.SLACK_WEBHOOK }}
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No production vulnerabilities found |
| 1 | Production vulnerabilities found (or regressions in `diff`) |
| 2 | Error (missing lockfile, all advisory sources failed, etc.) |

## Configuration

Create `.auditfixrc.json` or `.auditfixrc.yaml` in your project root:

```json
{
  "productionOnly": true,
  "severity": "high",
  "output": "json"
}
```

Supports: `.auditfixrc`, `.auditfixrc.json`, `.auditfixrc.yml`, `.auditfixrc.yaml`, and `package.json` (`auditfix` key).

CLI flags override config file values.

## How It Works

1. **Parse lockfile** — Reads `package-lock.json`, `yarn.lock`, or `pnpm-lock.yaml`
2. **Build dependency graph** — Maps all packages with production/dev classification
3. **Detect workspaces** — npm/yarn workspaces and pnpm-workspace.yaml
4. **Scan import chains** — Static analysis of import/require to determine reachability
5. **Fetch advisories** — Four-tier fallback: OSV.dev API, local cache (4hr TTL, HMAC-verified), bundled offline index, npm bulk endpoint
6. **Match vulnerabilities** — Checks installed versions against advisory semver ranges
7. **Score risks** — Composite scoring: CVSS base (40%), production reachability (30%), import chain (+10%), exploit status (15%), fix availability (10%), dependency depth (5%)
8. **Apply allow-list** — Filters out suppressed advisories with alias matching (GHSA/CVE cross-reference)
9. **Auto-fix** (with `--fix`) — Applies safe updates via npm overrides, yarn resolutions, or pnpm.overrides

## Supported Lockfiles

| Lockfile | Status |
|----------|--------|
| npm `package-lock.json` v2/v3 | Supported |
| Yarn Classic `yarn.lock` | Supported |
| Yarn Berry (v2/v3/v4) `yarn.lock` | Supported |
| pnpm `pnpm-lock.yaml` v5/v6/v9 | Supported |

## Security

- **No shell injection** — All child processes use `execFile` with argument arrays
- **Prototype pollution prevention** — JSON parsing uses a reviver that strips `__proto__`, `constructor`, `prototype`
- **Cache integrity** — HMAC-SHA256 verification on all cached advisory data
- **Token redaction** — GitHub, npm, GitLab, and AWS tokens are never logged
- **Path traversal prevention** — Lockfile paths and cache keys are validated against traversal attacks
- **Symlink rejection** — Cache writes and lockfile writes reject symlink targets
- **Safe YAML parsing** — Uses js-yaml v4+ DEFAULT_SCHEMA (no `!!js/function` RCE)
- **Config safety** — Only JSON/YAML config files are loaded (no JS execution via config)

## Requirements

- Node.js >= 18
- A lockfile (`package-lock.json`, `yarn.lock`, or `pnpm-lock.yaml`)
- `gh` CLI for `--create-pr` (optional)

## License

MIT
