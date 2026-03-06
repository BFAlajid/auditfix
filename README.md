# auditfix

[![CI](https://github.com/BFAlajid/auditfix/actions/workflows/ci.yml/badge.svg)](https://github.com/BFAlajid/auditfix/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/auditfix)](https://www.npmjs.com/package/auditfix)

Smarter npm dependency security CLI. Replaces `npm audit` with production reachability analysis, risk scoring, and safe auto-fixes.

## Why auditfix?

`npm audit` is noisy. It flags every advisory regardless of whether the vulnerable package is even reachable in production. auditfix solves this by:

- **Production reachability** - Only flags vulnerabilities in packages your production code actually uses
- **Risk scoring** - Composite score (0-100) based on CVSS, production exposure, exploit availability, and fix availability
- **Safe auto-fix** - Automatically applies non-breaking updates via lockfile overrides
- **Multi-lockfile support** - npm, yarn (classic + berry), and pnpm
- **Multiple output formats** - Terminal, JSON, and SARIF (for GitHub Code Scanning)
- **Allow-list** - Suppress known false positives with expiry dates and audit trails

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

Create `.auditfixrc.json` in your project root:

```json
{
  "productionOnly": true,
  "severity": "high",
  "output": "json"
}
```

Supports: `.auditfixrc.json`, `.auditfixrc.yaml`, `.auditfixrc.yml`, `auditfix.config.js`, `auditfix.config.cjs`.

CLI flags override config file values.

## How It Works

1. **Parse lockfile** - Reads `package-lock.json`, `yarn.lock`, or `pnpm-lock.yaml`
2. **Build dependency graph** - Maps all packages with production/dev classification
3. **Fetch advisories** - Three-tier fallback: OSV.dev API, local cache (4hr TTL, HMAC-verified), npm bulk endpoint
4. **Match vulnerabilities** - Checks installed versions against advisory semver ranges
5. **Score risks** - Composite scoring: CVSS base (40%), production reachability (30%), exploit status (15%), fix availability (10%), dependency depth (5%)
6. **Apply allow-list** - Filters out suppressed advisories with alias matching (GHSA/CVE cross-reference)
7. **Auto-fix** (with `--fix`) - Applies safe updates within declared semver ranges via npm overrides

## Supported Lockfiles

| Lockfile | Status |
|----------|--------|
| npm `package-lock.json` v2/v3 | Supported |
| Yarn Classic `yarn.lock` | Supported |
| Yarn Berry (v2/v3/v4) `yarn.lock` | Supported |
| pnpm `pnpm-lock.yaml` v5/v6/v9 | Supported |

## Security

- **No shell injection** - All child processes use `execFile` with argument arrays, never string interpolation
- **Prototype pollution prevention** - JSON parsing uses a reviver that strips `__proto__`, `constructor`, `prototype`
- **Cache integrity** - HMAC-SHA256 verification on all cached advisory data
- **Token redaction** - GitHub tokens (`ghp_`, `ghs_`, `github_pat_`) are never logged
- **Path traversal prevention** - Lockfile paths and cache keys are validated against traversal attacks
- **Safe YAML parsing** - Uses js-yaml v4+ (no `!!js/function` RCE)

## Requirements

- Node.js >= 18
- A lockfile (`package-lock.json`, `yarn.lock`, or `pnpm-lock.yaml`)

## License

MIT
