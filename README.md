# auditfix

[![CI](https://github.com/BFAlajid/auditfix/actions/workflows/ci.yml/badge.svg)](https://github.com/BFAlajid/auditfix/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/auditfix)](https://www.npmjs.com/package/auditfix)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/node-%3E%3D18-brightgreen)](https://nodejs.org)

Smarter npm dependency security CLI. Replaces `npm audit` with production reachability analysis, risk scoring, supply chain intelligence, and safe auto-fixes.

## Example Output

```
auditfix v2.0.0 — scanned 847 packages

CRITICAL (1)
  lodash@4.17.20 — Prototype Pollution in lodash
  Path: my-app > lodash
  Production: YES | EPSS: 0.87 (18/20) | CISA KEV: NO | Fix: 4.17.21
  → Run `auditfix --fix` to auto-patch

HIGH (2)
  express@4.17.1 — Open redirect in express
  Path: my-app > express
  Production: YES | EPSS: 0.34 (7/20) | CISA KEV: NO | Fix: 4.19.2
  → Run `auditfix --fix` to auto-patch

  jsonwebtoken@8.5.1 — Insecure default algorithm in jsonwebtoken
  Path: my-app > jsonwebtoken
  Production: YES | EPSS: 0.52 (10/20) | CISA KEV: NO | Fix: 9.0.0
  → Run `auditfix --fix` to auto-patch

MEDIUM (0)
LOW (1)
  semver@5.7.1 — ReDoS in semver
  Path: my-app > semver
  Production: NO (dev only) | EPSS: 0.02 (0/20) | CISA KEV: NO | Fix: 7.5.2
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
- **Risk scoring** — Composite score (0-100) based on CVSS (v3.1 + v4.0), production exposure, EPSS exploit probability, CISA KEV status, and fix availability
- **EPSS + CISA KEV scoring** — Graduated exploit scoring (0-20 points) using real-time EPSS probabilities and the CISA Known Exploited Vulnerabilities catalog
- **Supply chain protection** — Typosquatting detection, provenance verification, and behavioral analysis of package source code
- **VEX generation** — OpenVEX v0.2.0 documents mapping reachability analysis to machine-readable vulnerability statuses
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

# Check for typosquatted packages
auditfix --check-typosquats

# Verify package provenance (Sigstore attestation)
auditfix --check-provenance

# Deep behavioral analysis of package source
auditfix --scan-behavior

# Generate OpenVEX document
auditfix --vex > audit.vex.json

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

## Policy Engine

The policy engine lets you codify your security requirements as YAML rules. auditfix evaluates every finding against your policy and reports violations, warnings, and auto-ignored items.

### Creating a policy file

Create `.auditfix-policy.yml` (or `.auditfix-policy.yaml`) in your project root:

```yaml
version: 1

rules:
  - name: block-critical-prod
    description: Fail on critical production vulnerabilities
    match:
      all:
        - severity: [critical]
        - scope: production
    action: fail

  - name: warn-high-with-exploit
    description: Warn on high-severity vulns with active exploits
    match:
      all:
        - severity: [high]
        - scope: production
      any:
        - epss: { gte: 0.5 }
        - kev: true
    action: warn

  - name: ignore-dev-low
    description: Auto-suppress low-severity dev-only findings
    match:
      all:
        - severity: [low, info]
        - scope: dev
    action: auto-ignore
    reason: Dev-only low-severity findings are acceptable risk

overrides:
  - rule: block-critical-prod
    action: warn
    reason: "Temporary exception for migration sprint"
    expires: "2026-06-30"
    approved-by: security-team
```

### YAML format

A policy file requires:

- **`version`** — Must be `1`.
- **`rules`** — An array of rule objects. Each rule has:
  - `name` (required) — Kebab-case identifier (e.g., `block-critical-prod`).
  - `description` (optional) — Human-readable description.
  - `match` (required) — Condition block with `all` (AND) and/or `any` (OR) arrays.
  - `action` (required) — One of `fail`, `warn`, `notify`, `auto-ignore`.
  - `reason` (required for `auto-ignore`) — Justification for suppression.
  - `message` (optional) — Custom message for violations.
- **`overrides`** (optional) — Temporarily change a rule's action.
- **`extends`** (optional) — Array of relative paths to inherit rules from other policy files (max depth 3).
- **`settings`** (optional) — Configure which scans the policy enables (e.g., `enable-scans: [licenses, typosquats, provenance, behavior, dep-age]`).

### Match conditions

Conditions are placed inside `all` (every condition must match) and `any` (at least one must match) blocks:

| Condition | Type | Description |
|-----------|------|-------------|
| `severity` | `string[]` | Match severity levels: `critical`, `high`, `medium`, `low`, `info` |
| `scope` | `string` | Match dependency scope: `production` or `dev` |
| `epss` | `numeric` | EPSS exploit probability (0.0-1.0). Supports `gt`, `gte`, `lt`, `lte`, `eq` |
| `kev` | `boolean` | Whether the vulnerability is in the CISA KEV catalog |
| `fix-available` | `boolean` | Whether a fix version exists |
| `package` | `string[]` | Package name patterns (supports `*` glob, e.g., `@types/*`) |
| `depth` | `numeric` | Dependency tree depth. Supports `gt`, `gte`, `lt`, `lte`, `eq` |
| `direct-dep` | `boolean` | Whether the package is a direct dependency |
| `license` | `string[]` | License identifiers (e.g., `GPL-3.0`, `AGPL-3.0`) |
| `provenance` | `boolean` | Whether the package has Sigstore provenance attestation |
| `behavior` | `string[]` | Behavioral patterns detected (e.g., `eval`, `http-request`, `env-access`). All listed behaviors must be present. |
| `dep-age` | `numeric` | Months since last publish. Supports `gt`, `gte`, `lt`, `lte`, `eq` |
| `typosquat` | `boolean` | Whether the package is flagged as a potential typosquat |

### Actions

| Action | Effect |
|--------|--------|
| `fail` | Marks the finding as a violation. Causes a non-zero exit code. |
| `warn` | Records a warning but does not fail the scan. |
| `notify` | Same as warn; intended for webhook/notification integrations. |
| `auto-ignore` | Suppresses the finding (requires `reason` field). |

The first matching rule wins for each finding. Rule order matters.

### Overrides

Overrides temporarily change a rule's action without editing the rule itself:

```yaml
overrides:
  - rule: block-critical-prod     # must match a rule name
    action: warn                   # new action
    reason: "Sprint exception"     # required justification
    expires: "2026-06-30"          # optional expiry date (ISO 8601)
    approved-by: security-team     # optional audit trail
```

Expired overrides are automatically ignored and the original action is restored.

### CLI flags

```bash
# Use a specific policy file
auditfix --policy path/to/policy.yml

# Skip policy evaluation entirely
auditfix --no-policy
```

When no `--policy` flag is provided, auditfix auto-detects `.auditfix-policy.yml` or `.auditfix-policy.yaml` in the project root.

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

## Supply Chain Intelligence

v2.0.0 adds deep supply chain analysis beyond vulnerability scanning.

### EPSS + CISA KEV Scoring

Exploit scoring now uses a graduated 0-20 point scale instead of a binary yes/no:

- **EPSS** (Exploit Prediction Scoring System) — Real-time exploit probability from the FIRST.org API. Higher EPSS percentiles contribute more points.
- **CISA KEV** — Cross-references the CISA Known Exploited Vulnerabilities catalog. Packages listed in KEV receive maximum exploit points.

EPSS and KEV data are fetched automatically during scans and cached alongside advisories.

### Typosquatting Detection

```bash
auditfix --check-typosquats
```

Compares every installed package name against the top 100 npm packages using:

- Levenshtein distance (edit distance <= 2)
- Common character substitution patterns (`0` for `o`, `1` for `l`, `rn` for `m`)
- Scope-stripping detection (e.g., `express` mimicking `@expressjs/express`)

Flags suspicious matches with the likely impersonation target.

### Provenance Verification

```bash
auditfix --check-provenance
```

Checks npm registry Sigstore attestation endpoints for each installed package. Reports:

- Total verified vs. unverified package count
- Production packages without provenance attestation (flagged as higher risk)

Useful for enforcing build provenance policies in CI.

### Behavioral Analysis

```bash
auditfix --scan-behavior
```

Deep-scans package source code for risky patterns across 14 categories:

| Category | Examples |
|----------|----------|
| Code execution | `eval()`, `new Function()`, `vm.runInNewContext()` |
| Process spawning | `child_process.exec()`, `execSync()` |
| Network access | `http.request()`, `fetch()`, `net.connect()` |
| Environment access | `process.env` harvesting |
| Filesystem access | Writes outside package directory |
| DNS lookups | `dns.resolve()`, `dns.lookup()` |
| Obfuscation | Hex-encoded strings, base64 decoding chains |

Each finding includes a risk level. Combine with `--scan-scripts` for full install-time and runtime coverage.

### VEX Generation

```bash
auditfix --vex > audit.vex.json
```

Generates an [OpenVEX](https://openvex.dev/) v0.2.0 document that maps auditfix reachability analysis to standardized VEX statuses:

| Reachability | VEX Status |
|-------------|-----------|
| Dev-only dependency | `not_affected` (justification: `component_not_present`) |
| Production but not imported | `under_investigation` |
| Production and imported | `affected` |

VEX documents can be attached to SBOMs to communicate vulnerability triage decisions to downstream consumers.

### CVSS v4.0 Support

auditfix now parses CVSS v4.0 vectors from OSV advisories in addition to CVSS v3.1. When both are present, the v4.0 score is preferred for risk calculation.

## Watch Mode

Monitor lockfiles and automatically re-scan when they change:

```bash
auditfix --watch
```

Watches `package-lock.json`, `yarn.lock`, and `pnpm-lock.yaml` in the project directory. Runs an initial scan, then re-scans whenever a lockfile is modified.

## Webhook Notifications

Send scan results to Slack, Microsoft Teams, Discord, or any HTTP endpoint:

```bash
# Slack incoming webhook
auditfix --webhook https://hooks.slack.com/services/T00/B00/xxx

# Microsoft Teams incoming webhook
auditfix --webhook https://outlook.office.com/webhook/...

# Discord webhook
auditfix --webhook https://discord.com/api/webhooks/...

# Generic webhook (receives JSON payload)
auditfix --webhook https://your-server.com/audit-hook
```

The webhook platform is auto-detected from the URL:

| URL pattern | Platform | Payload format |
|-------------|----------|----------------|
| `hooks.slack.com` | Slack | Block Kit with header, severity counts, top 5 vulns |
| `webhook.office.com` / `outlook.office.com` | Teams | MessageCard with severity facts and optional GitHub link |
| `discord.com/api/webhooks` | Discord | Rich embed with color-coded severity and top 5 vuln fields |
| Any other URL | Generic | JSON object with `event`, `summary`, and `vulnerabilities` arrays |

## PR Comment Bot

Post scan results directly as a GitHub PR comment:

```bash
auditfix --pr-comment
```

Requires `GITHUB_TOKEN` (automatically available in GitHub Actions). The comment includes:

- Severity summary table (critical, high, medium, low counts)
- Top 10 vulnerabilities with package, version, severity, score, and fix version
- Auto-fix suggestions listing upgradeable packages
- Scan metadata footer (advisory source, packages scanned, confidence, duration)

The bot auto-detects the PR number from the GitHub Actions environment (`GITHUB_REF` or `GITHUB_EVENT_PATH`). On subsequent runs, it updates the existing comment in-place rather than creating duplicates.

### GitHub Actions example

```yaml
- name: Audit and comment
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
  run: npx auditfix --pr-comment
```

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

### SARIF Diff Mode (`--sarif-baseline`)

When used with `--sarif`, the `--sarif-baseline` flag compares the current scan against a previous JSON report and outputs only **new** vulnerabilities not present in the baseline. This is useful for PR gating where you only want to flag regressions:

```bash
# Save a baseline report
auditfix --json > baseline.json

# On the next scan, output SARIF containing only new findings
auditfix --sarif --sarif-baseline baseline.json > diff.sarif
```

Only vulnerabilities not present in the baseline are included in the SARIF output. Combine with GitHub Code Scanning to surface only newly introduced issues.

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
- uses: BFAlajid/auditfix@v2
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

## Configuration Reference

Complete reference of all configuration fields. Set these in your config file (e.g., `.auditfixrc.json`) or via CLI flags.

| Field | Type | Default | CLI flag | Description |
|-------|------|---------|----------|-------------|
| `severity` | `"critical"` \| `"high"` \| `"medium"` \| `"low"` \| `"info"` | `"low"` | `--severity <level>` | Minimum severity threshold. Vulnerabilities below this level are excluded from results. |
| `productionOnly` | `boolean` | `false` | `--prod-only` | Only report vulnerabilities in production dependencies. Dev-only findings are excluded. |
| `autoFix` | `boolean` | `false` | `--fix` | Automatically apply safe (non-breaking) version updates via lockfile overrides. |
| `ignoreDev` | `boolean` | `false` | — | Ignore all dev dependencies during scanning. Similar to `productionOnly` but applied earlier in the pipeline. |
| `communityAllowList` | `boolean` | `false` | — | Enable community-maintained allow-list of known false positives. |
| `maxAdvisoryStaleness` | `string` | `"7d"` | — | Maximum age of cached advisory data before re-fetching. Duration string (e.g., `"4h"`, `"7d"`, `"24h"`). |
| `output` | `"terminal"` \| `"json"` \| `"sarif"` | `"terminal"` | `--json` / `--sarif` | Output format. `--ci` forces `json`. |
| `ci.failOn` | `"production-critical"` \| `"production-high"` \| `"any"` | `"production-critical"` | `--fail-on <strategy>` | CI exit code strategy. Controls which findings cause a non-zero exit. |
| `ci.sarifUpload` | `boolean` | `false` | `--sarif` | Enable SARIF output in CI mode for GitHub Code Scanning integration. |

### Example config file

```json
{
  "severity": "high",
  "productionOnly": true,
  "autoFix": false,
  "ignoreDev": false,
  "communityAllowList": false,
  "maxAdvisoryStaleness": "4h",
  "output": "terminal",
  "ci": {
    "failOn": "production-high",
    "sarifUpload": true
  }
}
```

### YAML equivalent

```yaml
severity: high
productionOnly: true
autoFix: false
maxAdvisoryStaleness: 4h
output: terminal
ci:
  failOn: production-high
  sarifUpload: true
```

### Merge order

Configuration is resolved in the following precedence (highest wins):

1. CLI flags
2. Config file (`.auditfixrc.json`, `.auditfixrc.yml`, etc.)
3. Built-in defaults

The `ci` object is deep-merged: you can set `ci.failOn` in the config file and `ci.sarifUpload` via CLI without one overwriting the other.

## How It Works

1. **Parse lockfile** — Reads `package-lock.json`, `yarn.lock`, or `pnpm-lock.yaml`
2. **Build dependency graph** — Maps all packages with production/dev classification
3. **Detect workspaces** — npm/yarn workspaces and pnpm-workspace.yaml
4. **Scan import chains** — Static analysis of import/require to determine reachability
5. **Fetch advisories** — Four-tier fallback: OSV.dev API, local cache (4hr TTL, HMAC-verified), bundled offline index, npm bulk endpoint
6. **Match vulnerabilities** — Checks installed versions against advisory semver ranges
7. **Score risks** — Composite scoring: CVSS base v3.1/v4.0 (40%), production reachability (30%), import chain (+10%), EPSS + CISA KEV exploit score (15%), fix availability (10%), dependency depth (5%)
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
