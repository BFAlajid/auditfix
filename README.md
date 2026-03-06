# auditfix

[![CI](https://github.com/BFAlajid/auditfix/actions/workflows/ci.yml/badge.svg)](https://github.com/BFAlajid/auditfix/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/auditfix)](https://www.npmjs.com/package/auditfix)

Smarter npm dependency security CLI. Replaces `npm audit` with production reachability analysis, risk scoring, and safe auto-fixes.

## Why auditfix?

`npm audit` is noisy. It flags every advisory regardless of whether the vulnerable package is even reachable in production. auditfix solves this by:

- **Production reachability** — Only flags vulnerabilities in packages your production code actually uses
- **Risk scoring** — Composite score (0-100) based on CVSS, production exposure, exploit availability, and fix availability
- **Safe auto-fix** — Automatically applies non-breaking updates via lockfile overrides (npm, yarn, pnpm)
- **Multi-lockfile support** — npm, yarn (classic + berry), and pnpm
- **Monorepo support** — Workspace detection with per-workspace vulnerability mapping
- **CycloneDX SBOM** — Generate a CycloneDX 1.5 Software Bill of Materials
- **Install script scanner** — Detect suspicious `postinstall`/`preinstall` scripts
- **Guided remediation** — Holistic fix plans ranked by impact
- **GitHub PR creation** — Automatically create PRs with security fixes
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
  --expires 2025-12-31
```

This creates a `.auditfixignore` file in your project root with an audit trail.

## Output Formats

### Terminal (default)

Color-coded table with severity, package, version, risk score, and fix availability.

### JSON (`--json`)

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

### GitHub Actions Workflow

Full GitHub Actions workflow (copy to `.github/workflows/auditfix.yml`):

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

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No production vulnerabilities found |
| 1 | Production vulnerabilities found |
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
4. **Fetch advisories** — Three-tier fallback: OSV.dev API, local cache (4hr TTL, HMAC-verified), npm bulk endpoint
5. **Match vulnerabilities** — Checks installed versions against advisory semver ranges
6. **Score risks** — Composite scoring: CVSS base (40%), production reachability (30%), exploit status (15%), fix availability (10%), dependency depth (5%)
7. **Apply allow-list** — Filters out suppressed advisories with alias matching (GHSA/CVE cross-reference)
8. **Auto-fix** (with `--fix`) — Applies safe updates via npm overrides, yarn resolutions, or pnpm.overrides

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
