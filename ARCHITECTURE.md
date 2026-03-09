# auditfix — Architecture Plan

## Overview

A smarter npm dependency security CLI that replaces `npm audit` with actionable, noise-free vulnerability reports. Filters by production reachability, auto-patches safe updates, community-driven false positive allow-lists, and monitors for supply chain attacks.

## The Problem (Quantified)

- 65% of teams bypass or delay vulnerability fixes due to alert fatigue
- Only 40% of developers are satisfied with npm security tools
- npm audit doesn't distinguish production vs devDependency exposure
- 4.3 hours/week wasted on dependency issues per developer
- Sept 2025: debug, chalk, and 16 packages with billions of downloads were hijacked
- `npm audit fix --force` breaks lockfiles and introduces regressions
- That one `nth-check` ReDoS has been haunting React projects for 3+ years

## Tech Stack

- **Language:** TypeScript (ESM, `"type": "module"`, Node.js 18+)
- **Package Manager:** pnpm (for development), works with npm/yarn/pnpm projects
- **CLI Framework:** commander v12+ (mature, first-class TypeScript, ships own `.d.ts`)
- **Bundler:** tsup (wraps esbuild, single-file output with shebang injection, fast `npx` startup)
- **Lockfile Parsing:** Direct JSON.parse (npm), @yarnpkg/lockfile (yarn v1, ~20KB), js-yaml v4+ (yarn berry + pnpm — v3 had RCE via `!!js/function`, CVE-2013-4660)
- **Semver:** node-semver >= 7.5.4 (npm's own library — `satisfies()`, `maxSatisfying()`, `intersects()`. Versions < 7.5.4 have ReDoS CVE-2022-25883)
- **Vulnerability Data:** OSV.dev batch API (primary, real-time) + bundled index from OSV bulk export (offline fallback, ~1-2MB) + npm bulk advisory endpoint (tertiary)
- **CVSS Parsing:** cvss-parser or manual vector string parsing (OSV returns CVSS vector strings, not numeric scores)
- **Config Loading:** lilconfig (~3KB, loads `.auditfixrc.json` — lighter than cosmiconfig's 15KB)
- **Output:** Terminal (chalk + cli-table3), JSON, SARIF v2.1.0 (manual generation, no library needed)
- **Testing:** Vitest
- **Publishing:** npm (npx auditfix)

### Advisory Data Strategy

Three-tier advisory resolution with graceful degradation:

| Tier          | Source                                                                 | Auth | Use Case                                                                                                  |
| ------------- | ---------------------------------------------------------------------- | ---- | --------------------------------------------------------------------------------------------------------- |
| **Primary**   | OSV.dev batch API (`POST /v1/querybatch`)                              | None | Real-time scanning. Up to 1,000 packages per request. 1-3s for typical project.                           |
| **Secondary** | Bundled advisory index (built from OSV bulk export at publish time)    | None | Offline/fallback. Pre-built index shipped in the npm package (~1-2MB gzip).                               |
| **Tertiary**  | npm bulk advisory endpoint (`POST /-/npm/v1/security/advisories/bulk`) | None | Fallback when OSV unreachable. Send `{ "pkg": ["1.2.3"] }` map. This is what `npm audit` uses internally. |

**Why OSV batch API as primary (not git repo clone):**

- Real-time freshness — no staleness window
- Single HTTP call for entire lockfile (up to 1,000 packages per batch)
- 1-3 seconds for typical project with 500 dependencies
- Zero local storage management
- No `git` dependency required
- The `github/advisory-database` git repo is ~2-3GB — **unacceptable for a CLI tool**

**OSV batch API caveats:**

- Batch endpoint returns **abbreviated** results (just `id` + `modified`)
- Must follow up with `GET /v1/vulns/{id}` for full details (CVSS, affected ranges, fix versions)
- Follow-up fetches use bounded concurrency (10 parallel requests)

**Bundled advisory index (offline fallback):**

- Built at npm publish time from the OSV bulk data export: `https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip`
- The GCS bucket `gs://osv-vulnerabilities/npm/` contains all npm advisories as individual JSON files + `all.zip`
- ~8,000-10,000 npm advisories, each 1-5KB → ~24MB raw JSON → ~5-15MB zip
- Strip to essential fields only (id, package name, affected ranges, severity, fix versions) → ~2-5MB raw → **~1-2MB gzipped**
- Index keyed by package name for O(1) lookup
- Acceptable npm package size (lodash: 1.4MB, eslint: 3MB, typescript: 65MB)

**Optional auto-refresh:** On first run, if bundled index is stale (> 24hr), download fresh `npm/all.zip` in background and cache to `~/.auditfix/cache/`. ~5-15MB download, takes 2-5 seconds.

**GHSA GraphQL API (enrichment only, not primary):**

- Requires GitHub token (any token with zero scopes works)
- 5,000 points/hr rate limit (point-cost system, not simple request count)
- Cannot batch by package name natively — must use GraphQL aliases (~20-30 packages per query)
- Best for: CWE classifications, CVSS scores guaranteed on every advisory
- Token sourced from: `GITHUB_TOKEN` env var > `gh auth token` fallback > degrade to OSV-only

### Config Merge Order

```
finalConfig = { ...defaults, ...configFile, ...cliFlags }
```

Commander's `getOptionValueSource()` distinguishes explicit CLI flags from defaults, enabling correct merge precedence.

## Project Structure

```
auditfix/
├── src/
│   ├── cli/
│   │   ├── index.ts           # Entry point, arg parsing
│   │   ├── commands/
│   │   │   ├── audit.ts       # Main audit command
│   │   │   ├── fix.ts         # Auto-fix safe updates
│   │   │   ├── ignore.ts      # Add to allow-list
│   │   │   ├── monitor.ts     # Watch for supply chain signals
│   │   │   └── init.ts        # Create .auditfixrc config
│   │   └── output/
│   │       ├── terminal.ts    # Pretty terminal output
│   │       ├── json.ts        # JSON output for scripting
│   │       └── sarif.ts       # SARIF for GitHub/GitLab CI
│   ├── core/
│   │   ├── analyzer.ts        # Main analysis pipeline
│   │   ├── lockfile/
│   │   │   ├── parser.ts      # Detect lockfile type, dispatch to correct parser
│   │   │   ├── npm.ts         # package-lock.json v2/v3 direct JSON parser (no arborist)
│   │   │   ├── npm-v1.ts      # package-lock.json v1 legacy parser (nested dependencies)
│   │   │   ├── yarn-classic.ts # yarn.lock v1 parser (via @yarnpkg/lockfile)
│   │   │   ├── yarn-berry.ts  # yarn.lock v2+/v3+/v4 parser (YAML format)
│   │   │   ├── pnpm.ts        # pnpm-lock.yaml parser (v6/v9 formats)
│   │   │   └── workspace.ts   # Workspace/monorepo resolution (npm/yarn/pnpm workspaces)
│   │   ├── graph/
│   │   │   ├── dependency-graph.ts  # Build adjacency-list graph (not tree — handles dedup)
│   │   │   ├── reachability.ts      # BFS from production roots with visited set. O(V+E)
│   │   │   └── upgrade-path.ts      # Find safe upgrade path for a vuln
│   │   ├── advisory/
│   │   │   ├── source-osv.ts  # Primary: OSV.dev batch API + per-vuln detail fetcher
│   │   │   ├── source-bulk.ts # Bundled/cached index from OSV npm/all.zip bulk export
│   │   │   ├── source-npm.ts  # Tertiary: npm bulk advisory endpoint
│   │   │   ├── osv-ranges.ts  # Convert OSV events[] arrays to semver range strings
│   │   │   ├── resolver.ts    # Orchestrate sources with fallback chain
│   │   │   ├── cache.ts       # Local cache (~/.auditfix/cache/) with TTL + stale fallback
│   │   │   ├── cvss.ts        # Parse CVSS v3.1 vector strings to numeric scores
│   │   │   ├── matcher.ts     # Match advisories to installed packages by name + semver range
│   │   │   └── scorer.ts      # Risk scoring (reachability + CVSS + exploit maturity)
│   │   ├── fixer/
│   │   │   ├── safe-update.ts    # Non-breaking semver-compatible updates
│   │   │   ├── breaking-update.ts # Flag breaking changes for manual review
│   │   │   └── lockfile-writer.ts # Write updated lockfile without breaking it
│   │   ├── supply-chain/
│   │   │   ├── maintainer-watch.ts  # Detect maintainer changes
│   │   │   ├── script-scanner.ts    # Flag new/changed install scripts
│   │   │   └── publish-anomaly.ts   # Unusual publish patterns
│   │   └── allowlist/
│   │       ├── local.ts       # Project-level .auditfixignore
│   │       ├── community.ts   # Fetch community-voted false positives
│   │       └── types.ts
│   ├── types/
│   │   ├── advisory.ts
│   │   ├── package.ts
│   │   ├── config.ts
│   │   └── report.ts
│   └── utils/
│       ├── semver.ts          # Semver helpers (wraps node-semver: satisfies with includePrerelease:true)
│       ├── logger.ts          # Structured logging with verbosity levels + token redaction
│       ├── hash.ts            # Integrity checks + HMAC for cache
│       ├── sanitize.ts        # Input validation: JSON reviver, path traversal checks, ID regex
│       ├── shell.ts           # Safe child_process wrapper (execFile only, never exec)
│       └── platform.ts        # Cross-platform path/shell helpers (Windows + Unix)
├── data/
│   └── advisory-index.json.gz # Pre-built npm advisory index from OSV bulk export (built at publish time, ~1-2MB)
├── community/
│   └── known-false-positives.json  # Curated, version-controlled
├── tests/
│   ├── fixtures/              # Sample lockfiles, package.jsons
│   │   ├── npm-basic/
│   │   ├── yarn-monorepo/
│   │   ├── pnpm-workspace/
│   │   └── vulnerable-project/
│   ├── core/
│   │   ├── analyzer.test.ts
│   │   ├── reachability.test.ts
│   │   ├── scorer.test.ts
│   │   └── safe-update.test.ts
│   ├── security/
│   │   ├── allow-list-integrity.test.ts
│   │   ├── cache-traversal.test.ts
│   │   ├── shell-injection.test.ts
│   │   ├── api-response-validation.test.ts
│   │   ├── osv-range-conversion.test.ts
│   │   ├── token-redaction.test.ts
│   │   ├── prototype-pollution.test.ts
│   │   ├── lockfile-edge-cases.test.ts
│   │   └── filename-sanitization.test.ts
│   └── cli/
│       └── commands.test.ts
├── .auditfixrc.example        # Example config
├── package.json
├── tsconfig.json
├── vitest.config.ts
└── README.md
```

## Architecture Phases

### Phase 1: Core Audit Engine

**1.1 Lockfile Detection & Parsing**

Auto-detect project type and parse using the lightest possible approach (no arborist):

| Lockfile                 | Parser                                                       | Dev Detection                                                                                 | Notes                                                                                                                                                                                                                          |
| ------------------------ | ------------------------------------------------------------ | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `package-lock.json` v3   | `JSON.parse` → read `packages` field (flat map)              | Trust `dev`/`optional`/`devOptional` flags (npm pre-computes these)                           | Preferred. npm 9+. No flag = production.                                                                                                                                                                                       |
| `package-lock.json` v2   | `JSON.parse` → read `packages` field (ignore `dependencies`) | Same as v3 — `packages` field identical                                                       | npm 7-8. Contains both formats; always read `packages`.                                                                                                                                                                        |
| `package-lock.json` v1   | `JSON.parse` → recursively walk nested `dependencies`        | `dev: true` flag on entries                                                                   | Legacy (npm 5-6). Increasingly rare.                                                                                                                                                                                           |
| `yarn.lock` v1 (classic) | `@yarnpkg/lockfile` (~20KB)                                  | **NOT in lockfile.** Must cross-reference `package.json` and BFS from production roots.       | Custom format (not JSON/YAML).                                                                                                                                                                                                 |
| `yarn.lock` v2+ (berry)  | `js-yaml` (standard YAML)                                    | **NOT in lockfile.** Must cross-reference `package.json` and BFS from production roots.       | PnP vs node_modules doesn't affect lockfile format.                                                                                                                                                                            |
| `pnpm-lock.yaml` v9      | `js-yaml` → read `importers` + `snapshots`                   | `importers['.']` separates `dependencies` from `devDependencies`. Walk from production roots. | pnpm v9+. `snapshots` has dependency graph. Snapshot keys include peer dep suffixes: `react-dom@18.2.0(react@18.2.0)`. Importer `version` fields contain the full snapshot key. Strip `(...)` suffix to map to `packages` key. |
| `pnpm-lock.yaml` v5/v6   | `js-yaml` → read `packages`                                  | `dev: true` flag on entries (like npm)                                                        | Older pnpm. Keys are `/pkg/version` paths.                                                                                                                                                                                     |

Parse into normalized dependency graph (adjacency list, not tree):

```typescript
// Key: "name@version" — handles deduplication properly
type DependencyGraph = Map<string, DependencyNode>;

type DependencyNode = {
  name: string;
  version: string;
  resolved: string; // registry URL
  integrity: string; // sha hash
  dependencies: string[]; // keys into the graph ("name@version")
  isProduction: boolean; // true if reachable from production roots
  isDev: boolean; // true if ONLY reachable via devDependencies
  isOptional: boolean; // true if ONLY reachable via optionalDependencies
  depth: number; // shortest distance from root
  dependencyPath: string[]; // shortest root -> ... -> this package
};
```

**Runtime dependencies for lockfile parsing: only 2 packages** (`@yarnpkg/lockfile` + `js-yaml`). npm lockfiles use native `JSON.parse`. This is dramatically lighter than arborist's 50-80 transitive dependencies.

**1.2 Production Reachability Analysis**

Two strategies depending on lockfile type:

**Strategy A — Trust pre-computed flags (npm lockfiles):**

- npm lockfile v2/v3 `packages` entries already have `dev`, `optional`, `devOptional` boolean flags
- npm computes these at install time by walking the graph from root
- Rule: if none of `dev`, `optional`, `devOptional` are `true` → the package is production
- No graph traversal needed — just read the flags. O(n) scan.

**Strategy B — BFS from production roots (yarn/pnpm, or when flags are unavailable):**

1. Read `package.json` → collect `dependencies` keys (production roots)
2. Build adjacency list from lockfile dependency entries
3. BFS from each production root, following `dependencies` edges
4. Mark every visited node as `isProduction: true`
5. Use a `visited: Set<string>` (keyed by `name@version`) to handle circular dependencies
6. Anything not visited is dev-only

Time complexity: O(V + E) — single-pass graph traversal. Handles cycles via visited set.

**Key insight:** For npm lockfiles, Strategy A eliminates the graph walk entirely. For yarn/pnpm, Strategy B is required. Both produce the same result.

This single feature eliminates ~60-70% of npm audit noise.

**1.3 Advisory Fetching & Matching**

Three-tier resolution with fallback chain (see Advisory Data Strategy above):

1. **Primary: OSV.dev batch API** (real-time, default)
   - `POST https://api.osv.dev/v1/querybatch` with `ecosystem: "npm"` + version per package
   - Up to 1,000 packages per batch request (one HTTP call for entire lockfile)
   - **Caveat:** batch returns abbreviated results (`id` + `modified` only)
   - Must follow up with `GET /v1/vulns/{id}` for full advisory details (CVSS, fix versions, affected ranges)
   - Fetch full details in parallel with bounded concurrency (10 concurrent requests)
   - Cache full advisory responses locally for repeat runs

2. **Fallback: Bundled advisory index** if OSV unreachable
   - Pre-built at publish time from `https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip`
   - Shipped as `data/advisory-index.json.gz` (~1-2MB) in the npm package
   - Index keyed by package name → array of `{ id, ranges, severity, fixVersion }`
   - Stale by hours/days depending on when user last updated the package

3. **Tertiary: npm bulk advisory endpoint** if bundled index too stale
   - `POST /-/npm/v1/security/advisories/bulk` — same endpoint `npm audit` uses internally
   - Send `{ "package-name": ["1.2.3"] }` map
   - Returns full advisory objects with severity, CWE, fix info

4. **Last resort: stale cache** — use cached advisories regardless of TTL, warn user

**OSV events[] → semver range conversion (`osv-ranges.ts`):**

```typescript
// Convert OSV affected[].ranges[].events to a node-semver range string
// ~20 lines, no library needed
function eventsToSemverRange(events: OsvEvent[]): string {
  const ranges: string[] = [];
  let currentIntroduced: string | null = null;

  for (const event of events) {
    // process in order (already sorted by OSV)
    if (event.introduced !== undefined) {
      currentIntroduced = event.introduced === "0" ? "0.0.0" : event.introduced;
    }
    if (event.fixed !== undefined && currentIntroduced) {
      ranges.push(`>=${currentIntroduced} <${event.fixed}`); // exclusive upper bound
      currentIntroduced = null;
    }
    if (event.last_affected !== undefined && currentIntroduced) {
      ranges.push(`>=${currentIntroduced} <=${event.last_affected}`); // inclusive upper bound
      currentIntroduced = null;
    }
  }
  if (currentIntroduced !== null) {
    ranges.push(`>=${currentIntroduced}`); // no fix exists — open-ended
  }
  return ranges.join(" || ");
}

// "introduced":"0" is a sentinel meaning "all versions from the beginning" (OSV spec)
// "last_affected" = inclusive upper bound (used when exact fix version is unknown)
// Unpaired "introduced" with no "fixed" = vulnerability has no patch yet
// For npm, SEMVER and ECOSYSTEM range types are functionally identical
```

Match advisories to installed packages by:

- Package name (exact match — use `name` field for npm aliased packages, not path key)
- Version in affected range: `semver.satisfies(version, convertedRange, { includePrerelease: true })`
  - **CRITICAL:** Without `includePrerelease: true`, semver returns `false` for pre-release versions (e.g., `1.0.5-beta.1`) against ranges like `<1.0.5`. The beta almost certainly lacks the fix — this would be a silent false negative.

**1.4 Risk Scoring**

```typescript
type RiskScore = {
  score: number; // 0-100
  label: "critical" | "high" | "medium" | "low" | "info";
  factors: {
    cvssScore: number; // numeric 0.0-10.0 (parsed from CVSS v3.1 vector string)
    cvssVector: string; // raw vector, e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    productionReachable: boolean; // massive weight — the key differentiator
    exploitAvailable: boolean; // cross-reference CISA KEV or advisory references
    fixAvailable: boolean; // true if advisory has a "fixed" event in ranges
    fixVersion: string | null; // the patched version, if available
    depth: number; // shortest distance from root
    directDependency: boolean; // do you control this dep directly?
  };
};
```

Scoring formula:

- Production-reachable + exploit available + CVSS >= 7 = **critical**
- Production-reachable + no exploit + CVSS >= 7 = **high**
- Dev-only + any CVSS = **low** (unless install script vulnerability)
- In community allow-list = **info** (shown but doesn't fail CI)

### Phase 2: Smart Fixing

**2.1 Safe Auto-Fix**

- For each vulnerability with a fix version:
  1. Check if fix is within parent's declared range: `semver.satisfies(fixVersion, parentDeclaredRange)`
  2. If YES → **safe update**. Can update lockfile without changing any `package.json`.
  3. If NO → check if the parent package has a newer version that widens the range to include the fix
  4. Verify no peer dependency constraints are violated: for every peer consumer, check `semver.satisfies(fixVersion, peerDeclaredRange)`
  5. If safe: apply update to lockfile
  6. If breaking: report with the exact upgrade path, what might break, and whether `overrides`/`resolutions` can force it

**2.2 Upgrade Path Calculation**

```
Vulnerability: qs@6.5.2 (ReDoS)
Fix: qs@6.5.3+
Path: express@4.17.1 -> body-parser@1.19.0 -> qs@6.5.2

Options:
  1. [SAFE] Update qs to 6.5.3 (patch bump, no breaking changes)
  2. [BREAKING] Update express to 4.18.0 (bumps body-parser, which bumps qs)

Recommendation: Option 1 (auto-fixable)
```

**2.3 Lockfile Writing**

- Use the native package manager's resolution algorithm
- npm: spawn `npm install --package-lock-only` with targeted overrides
- pnpm: use `pnpm.overrides` in package.json
- yarn: use `resolutions` field
- Never run a blind `npm audit fix --force`
- **Security (S3):** All shell commands use `execFile`/`spawn` with argument arrays — NEVER string interpolation via `exec`. Validate all package names and versions against strict regex before use. Write overrides/resolutions via `JSON.stringify` only.
- **Re-verify after fix:** Run the vulnerability check again after applying fixes to confirm the new state is clean (prevents TOCTOU issues between check and apply).

### Phase 3: CLI & Output

**3.1 Commands**

```bash
# Main audit (default)
npx auditfix

# Audit with auto-fix for safe updates
npx auditfix --fix

# JSON output for scripting
npx auditfix --json

# SARIF output for GitHub Actions
npx auditfix --sarif > results.sarif

# Only show production vulnerabilities
npx auditfix --prod-only

# Add a vulnerability to project allow-list
npx auditfix ignore GHSA-xxxx-yyyy --reason "dev-only, not reachable"

# Monitor supply chain signals
npx auditfix monitor

# Initialize config
npx auditfix init
```

**3.2 Terminal Output**

```
auditfix v1.0.0 — scanning 847 packages

CRITICAL (1)
  qs@6.5.2 — ReDoS in querystring parsing
  Path: express > body-parser > qs
  Production: YES | Exploit: YES | Fix: qs@6.5.3
  → Run `auditfix --fix` to auto-patch

HIGH (0)

MEDIUM (2)
  json5@1.0.1 — Prototype pollution
  Path: tsconfig-paths > json5
  Production: NO (dev only) | Fix: json5@1.0.2
  → Low risk. Dev tooling only.

  semver@5.7.1 — ReDoS
  Path: @babel/core > semver
  Production: NO (build only) | Fix: semver@5.7.2
  → Low risk. Build tooling only.

IGNORED (via .auditfixignore) (3)
  nth-check@1.0.2, postcss@7.0.39, glob-parent@5.1.2

Scanned: 847 packages | Skipped: 2 (local file: deps)
Advisory source: OSV.dev API (real-time) | Matched against: 23 advisories
Confidence: HIGH

Summary: 1 critical (production) | 2 medium (dev-only) | 3 ignored
CI exit code: 1 (production vulnerabilities found)
```

**3.3 CI Integration**

Exit code convention (matches industry standard: npm audit, Snyk, audit-ci):

- Exit code 0: no vulnerabilities above threshold (or all below configured severity)
- Exit code 1: production-reachable vulnerabilities found above threshold
- Exit code 2: tool error / misconfiguration (could not complete scan)

SARIF output follows v2.1.0 spec (the only version GitHub Code Scanning supports):

- `tool.driver.rules[]` — advisory definitions with `properties.security-severity` (float string 0.0-10.0)
- `results[]` — each finding with `ruleId`, `level` (error/warning/note), `locations[].physicalLocation.artifactLocation.uri`
- File size must be under 10MB (5MB gzip for GitHub upload)
- Built manually with typed interfaces — no SARIF library dependency needed

GitHub Actions example in README + SARIF upload for GitHub Security tab

### Phase 4: Supply Chain Monitoring (Post-v1)

> **Deferred to post-v1.** This phase is essentially a separate product vertical (comparable to Socket.dev). Ship the core audit engine first, prove value, then layer supply chain features.

**4.1 Maintainer Watch**

- For each direct dependency, check:
  - Has the npm maintainer changed recently?
  - Has the GitHub repo ownership transferred?
  - Flag: "chalk maintainer changed 3 days ago"

**4.2 Install Script Scanner**

- Parse all `preinstall`, `install`, `postinstall` scripts in dependency tree
- Flag new scripts that appeared in latest version
- Flag scripts that make network calls, exec arbitrary code, or access filesystem outside node_modules
- This catches the exact attack vector from the Sept 2025 npm incident

**4.3 Publish Anomaly Detection**

- Check npm publish metadata:
  - Published from a different IP/location than usual?
  - Massive file size change between versions?
  - New files added that don't match source repo?
  - Version jump anomalies (0.1.0 -> 0.1.1 adds 500KB)?

### Phase 5: Community Allow-List

**5.1 Local Allow-List (.auditfixignore)**

```json
{
  "ignore": [
    {
      "id": "GHSA-rp65-9cf3-cjxr",
      "package": "nth-check",
      "reason": "Only used in css-select during build. Not reachable in production.",
      "expires": "2026-12-31"
    }
  ]
}
```

**5.2 Community-Maintained False Positives**

- `community/known-false-positives.json` in the repo
- PRs welcome — maintainers review and merge
- Fetched at runtime (cached) so users get updates without upgrading
- Each entry requires: advisory ID, exact package name, affected version range, rationale, and expiry date. No wildcards.
- **Integrity verification (see S1):** Signed via Sigstore/cosign. Freshness timestamp (`notValidAfter` within 30 days). Monotonic version number (rollback protection). Verified against Rekor transparency log.
- **Default OFF.** Users must set `"communityAllowList": true` in `.auditfixrc.json` after understanding trust implications.
- Voting/confidence system (future): "47 projects ignore this advisory"

## Config File (.auditfixrc.json)

```json
{
  "severity": "high",
  "productionOnly": false,
  "autoFix": false,
  "ignoreDev": false,
  "communityAllowList": false,
  "supplyChainMonitor": true,
  "maxAdvisoryStaleness": "7d",
  "output": "terminal",
  "ci": {
    "failOn": "production-critical",
    "sarifUpload": false
  }
}
```

Note: `communityAllowList` defaults to `false` (security decision S1 — remote allow-list is high-risk, requires explicit opt-in).

## Data Flow

```
CLI Entry (commander parses args, lilconfig loads .auditfixrc.json, merge config)
    |
    v
Lockfile Detector (find package-lock.json / yarn.lock / pnpm-lock.yaml)
    |
    v
Lockfile Parser (JSON.parse for npm, @yarnpkg/lockfile for yarn v1, js-yaml for berry/pnpm)
    |
    v
Dependency Graph Builder (adjacency list: Map<"name@version", DependencyNode>)
    |
    v
Reachability Analyzer
    ├── npm: read pre-computed dev/optional/devOptional flags (O(n) scan)
    └── yarn/pnpm: BFS from production roots with visited set (O(V+E))
    |
    v
Advisory Resolver (three-tier fallback)
    ├── 1. OSV.dev batch API (querybatch + per-vuln detail fetch) — real-time, default
    ├── 2. Bundled advisory index (from OSV npm/all.zip, built at publish time)
    └── 3. npm bulk advisory endpoint (/-/npm/v1/security/advisories/bulk)
    |
    v
Advisory Matcher (name + semver.satisfies against affected ranges)
    |
    v
CVSS Parser (vector string → numeric score 0.0-10.0)
    |
    v
Risk Scorer (CVSS + reachability + exploit + fix availability)
    |
    v
Allow-List Filter (local .auditfixignore + community)
    |
    v
Report Generator (terminal / JSON / SARIF v2.1.0)
    |
    ├──> [if --fix] Safe Update Engine (semver.satisfies check) -> Lockfile Writer
    └──> [if --monitor] Supply Chain Scanner (post-v1)
```

## Milestones

Sequenced for fastest time-to-value. Ship the differentiator (reachability) first.

### MVP (v0.1) — Core Audit Engine

| #   | Milestone                    | Deliverable                                                            |
| --- | ---------------------------- | ---------------------------------------------------------------------- |
| 1   | Lockfile parsing             | Parse npm lockfile v2/v3 into normalized graph (yarn + pnpm follow)    |
| 2   | Reachability analysis        | Mark every dep as production/dev/optional                              |
| 3   | Advisory fetching + matching | Pull from OSV (batch) + GHSA (enrichment), match to installed packages |
| 4   | Risk scoring                 | Score each vuln by reachability + CVSS + exploit status                |
| 5   | Terminal output              | Pretty, actionable CLI output with clear recommendations               |

### v0.2 — CI & Allow-List

| #   | Milestone          | Deliverable                           |
| --- | ------------------ | ------------------------------------- |
| 6   | CI mode            | Exit codes, JSON output, SARIF format |
| 7   | Allow-list (local) | .auditfixignore with expiry dates     |

### v0.3 — Auto-Fix

| #   | Milestone     | Deliverable                                       |
| --- | ------------- | ------------------------------------------------- |
| 8   | Safe auto-fix | Non-breaking semver patches applied automatically |

### v1.0 — Community & Launch

| #   | Milestone                    | Deliverable                                                |
| --- | ---------------------------- | ---------------------------------------------------------- |
| 9   | Community allow-list         | Shared false-positive database with integrity verification |
| 10  | Yarn + pnpm lockfile support | Full parser coverage for yarn classic/berry + pnpm         |
| 11  | Workspace/monorepo support   | Handle npm/yarn/pnpm workspaces                            |
| 12  | Polish + README + publish    | npm publish, GitHub Actions example, logo, docs            |

### v1.1+ — Supply Chain (Post-Launch)

| #   | Milestone               | Deliverable                                            |
| --- | ----------------------- | ------------------------------------------------------ |
| 13  | Supply chain monitoring | Maintainer changes, script scanning, publish anomalies |

## Key Design Decisions

1. **Zero config by default** — `npx auditfix` works out of the box with sensible defaults. Config file is optional.
2. **Never modify node_modules** — We only touch lockfiles. The user runs their own install after.
3. **Production reachability is the killer feature** — This alone eliminates most noise. Build everything around this distinction.
4. **Advisory data is always fresh** — Cache with short TTL. Ship a bundled snapshot for offline use, but prefer live data.
5. **Community allow-list is opt-in and off by default** — Remote allow-list is a high-risk attack surface. Must be explicitly enabled. Signed via Sigstore with freshness + rollback protection. Always shows suppressed advisory count.
6. **Package manager agnostic** — Works with npm, yarn (classic + berry), pnpm. Detect automatically. Ship npm-first, expand coverage incrementally.
7. **No account/login required** — Fully open source, no SaaS backend, no telemetry.
8. **Graceful degradation** — Every external dependency (GHSA, OSV, community list) has a fallback. Tool never hard-fails due to network issues.
9. **Cross-platform** — Works on macOS, Linux, and Windows. Shell spawning and path handling use platform-aware helpers.

## Error Handling Strategy

| Failure                                | Behavior                                                                 | Exit Code        |
| -------------------------------------- | ------------------------------------------------------------------------ | ---------------- |
| OSV API unreachable                    | Fall through to bundled index + npm bulk endpoint. Warn user.            | —                |
| npm advisory endpoint also unreachable | Use local cache regardless of TTL. Warn "stale data" with age.           | —                |
| No cache + no network                  | Use bundled advisory index (built at publish time). Warn "offline mode". | 0 (with warning) |
| Invalid/corrupt lockfile               | Exit with clear error identifying parse failure location.                | 2                |
| Unsupported lockfile version           | Exit with error stating minimum supported version.                       | 2                |
| GitHub token missing                   | Not an error. GHSA is enrichment-only. OSV/npm work without auth.        | —                |
| Lockfile not found                     | Exit with "no lockfile found" and suggest running `npm install`.         | 2                |
| `--fix` with no writable lockfile      | Exit with error. Never silently skip fixes.                              | 2                |

All errors are non-destructive — the tool never modifies files on failure and always exits with a clear message.

## Security Hardening

A security tool must itself be secure. These are mandatory implementation requirements.

### Threat Model Summary

| #   | Threat                                               | Severity     | Attack Vector                                     | Mitigation                                                                                       |
| --- | ---------------------------------------------------- | ------------ | ------------------------------------------------- | ------------------------------------------------------------------------------------------------ |
| T1  | Community allow-list weaponized to suppress warnings | **CRITICAL** | Remote URL compromise, rollback, cache poisoning  | Sigstore signing + freshness timestamps + default OFF                                            |
| T2  | Bundled advisory index manipulation                  | **MEDIUM**   | npm package compromise, stale data                | Index built from OSV bulk export at publish time, cross-source verification, staleness threshold |
| T3  | Shell command injection in `--fix` mode              | **HIGH**     | Malicious lockfile content, crafted package names | `execFile`/`spawn` only (never `exec`), strict input validation                                  |
| T4  | Cache directory attacks                              | **MEDIUM**   | Local filesystem access, shared CI runners        | HMAC integrity, 0700 permissions, atomic writes, symlink protection                              |
| T5  | API response manipulation                            | **MEDIUM**   | MITM, API compromise, malformed responses         | Content-Type check, size limits, schema validation, cross-source verification                    |
| T6  | Prototype pollution via parsed data                  | **MEDIUM**   | Malicious lockfile/advisory with `__proto__` keys | Sanitize after parse, never deep-merge untrusted data                                            |
| T7  | npm typosquatting                                    | **MEDIUM**   | Attacker registers `audit-fix`, `auditFix`, etc.  | Register defensive names, npm provenance, no postinstall                                         |
| T8  | Token leakage                                        | **LOW**      | Debug logs, CI output                             | Redact token patterns, never accept via CLI args                                                 |

### S1. Community Allow-List Integrity (CRITICAL)

The community allow-list is the highest-risk attack surface — compromising it silently disables the tool's core function.

**Requirements:**

- **Default to OFF.** Config: `"communityAllowList": false`. Users must explicitly opt in after understanding the trust implications.
- **Cryptographic signing via Sigstore/cosign.** The allow-list JSON must be signed by a maintainer identity. The tool verifies the signature against the Rekor transparency log. No GPG key management needed.
- **Freshness timestamp.** The signed payload must include a `notValidAfter` date (30 days from signing). Expired signatures are rejected — the tool falls back to local-only allow-list and warns.
- **Rollback protection.** Include a monotonically increasing version number in the signed payload. The tool stores the last-seen version and rejects any payload with a lower version.
- **Always display suppressed advisories.** The "IGNORED" section in output must always show the count and IDs of community-suppressed advisories. Never fully hide them.
- **Allow-list entries must be scoped.** Each entry requires: advisory ID, exact package name, affected version range, rationale, and expiry date. No wildcards.

### S2. Advisory Data Integrity (MEDIUM)

**Requirements:**

- **Bundled index built from trusted source only.** Built at publish time from `https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip` (Google-operated GCS bucket). URL hardcoded in build script, not configurable.
- **Advisory count floor.** Maintain a minimum expected advisory count in the bundled index (updated each release). If the index has dramatically fewer entries than expected, treat as suspicious and fall through to live API.
- **Cross-reference discrepancies.** When using multiple sources (OSV API + bundled index + npm), flag if a critical advisory exists in one source but is absent from another.
- **HTTPS only.** All API calls and bulk downloads must use HTTPS. No HTTP fallback.
- **Response size validation.** OSV batch responses and bulk zip downloads must not exceed expected size limits (50MB for zip, 1MB per individual advisory). Abort on oversized responses.
- **No git dependency.** The git clone approach was eliminated — no `git` binary required on the user's machine. This removes the entire class of git client vulnerabilities (CVE-2024-32002, etc.).

### S3. Shell Injection Prevention (HIGH)

**Requirements:**

- **NEVER use `child_process.exec()` with string interpolation.** All shell commands must use `child_process.execFile()` or `child_process.spawn()` with argument arrays. These bypass the shell entirely.
- **Validate all package names** against strict regex before any use: `/^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/`
- **Validate all version strings** with `semver.valid()` before passing to any shell command or `semver.satisfies()`. Reject and skip any version string > 256 characters (semver `MAX_LENGTH`).
- **When writing `overrides`/`resolutions` to `package.json`, use only `JSON.stringify` output.** Never template values into shell commands.
- **The `platform.ts` utility must never construct shell command strings from untrusted input.**

### S4. Cache Integrity (MEDIUM)

**Requirements:**

- **Directory permissions:** Create `~/.auditfix/` with mode `0700`, cache files with mode `0600`.
- **HMAC verification:** Generate a per-installation random key stored in `~/.auditfix/cache-key` (mode 0600). HMAC each cache file. Verify before reading.
- **Never cache negative results.** Do NOT cache "no advisories found for pkg@version" — a new advisory could be published at any moment. Only cache positive advisory data (the actual advisory JSON). This prevents stale "all clear" cache entries from masking newly published vulnerabilities.
- **Atomic writes:** Write to temp file, then `fs.renameSync()` (atomic on same filesystem). Prevents partial-write corruption.
- **Symlink protection:** Before writing, verify the target is not a symlink. Use `fs.lstatSync()` and reject symlinks.
- **Advisory ID filename validation:** Strict regex validation before use as filename:
  - GHSA: `/^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/`
  - CVE: `/^CVE-\d{4}-\d{4,}$/`
  - After constructing the full path, verify `path.resolve(filePath).startsWith(cacheDir + path.sep)`
  - Reject null bytes, backslashes, `..` segments, and Windows reserved names (`CON`, `NUL`, etc.)

### S5. Input Parsing Safety (MEDIUM)

**Requirements:**

- **js-yaml:** Use `yaml.load()` with `DEFAULT_SCHEMA` only (safe by default in v4+). NEVER use `JS_SCHEMA`. Pin `js-yaml >= 4.0.0`.
- **JSON.parse reviver:** Use a reviver function that strips `__proto__`, `constructor`, and `prototype` keys from all parsed lockfiles and API responses:
  ```typescript
  JSON.parse(content, (key, value) => {
    if (key === "__proto__" || key === "constructor" || key === "prototype")
      return undefined;
    return value;
  });
  ```
- **API response validation:** Check `Content-Type: application/json` header before parsing. Abort responses exceeding 50MB (batch) or 1MB (individual). npm outages have returned HTML with status 200 — `JSON.parse` on HTML must fall through to next tier, not crash.
- **Lockfile path validation:** All lockfile path keys must:
  - Start with `node_modules/` (npm) or follow the expected format for yarn/pnpm
  - Contain no `..` segments
  - Contain no backslashes or null bytes
- **BOM stripping:** Strip UTF-8 BOM (`\uFEFF`) from file content before parsing: `content.replace(/^\uFEFF/, '')`
- **Version string pre-validation:** Before calling `semver.satisfies()`, validate with `semver.valid()` and enforce `length <= 256`.

### S6. Token Handling (LOW)

**Requirements:**

- **Never log tokens.** Redact strings matching `gh[ps]_[A-Za-z0-9_]+` and `github_pat_[A-Za-z0-9_]+` in the logger. Redact `Authorization` headers from all HTTP logging.
- **Never accept tokens via CLI arguments.** Only via `GITHUB_TOKEN` env var or `gh auth token` subprocess. CLI args are visible in `ps` output.
- **Clear token from memory after use.** Overwrite the variable once HTTP requests are configured.

### S7. Package Supply Chain (MEDIUM)

**Requirements:**

- **No `postinstall` script.** Advisory index is built at publish time and shipped in the package, or built lazily on first run.
- **Enable npm provenance.** Use `--provenance` flag during `npm publish` in GitHub Actions. Attaches Sigstore attestation proving build origin.
- **2FA on npm account.** Required for publishing. Use granular access tokens scoped to the single package.
- **Register defensive package names.** Publish empty placeholder packages for `audit-fix`, `auditFix`, `npm-auditfix`, `audit_fix` that warn and redirect.
- **Pin exact dependency versions in published package.** No ranges — prevents dependency confusion.

## Failsafe Mechanisms

The worst failure mode for a security tool is **silent false negatives** — reporting "no vulnerabilities" when vulnerabilities exist. Every pipeline stage must be designed to fail safe.

### Fail-Open Policy

When data quality is uncertain, **fail open (warn loudly) rather than fail closed (block) or fail silent (miss)**:

- Uncertain data → report with reduced confidence, not suppressed
- Stale cache → use it but display age prominently
- Parse error on one package → skip it with warning, scan the rest
- Unknown lockfile version → warn and exit 2 (don't silently misparse)

### Confidence Metadata in Output

Every scan report must include:

```
Scanned: 847 packages | Skipped: 3 (2 local, 1 unparseable)
Advisory source: OSV.dev API (real-time) | Matched against: 23 advisories
Confidence: HIGH
```

Confidence levels:

- **HIGH:** Using live OSV API, all packages parsed, no skipped entries
- **MEDIUM:** Using cached API data (< 72hr), or < 5% of packages skipped
- **LOW:** Using bundled index only, or > 5% of packages skipped, or cache > 72hr
- **UNRELIABLE (exit 2):** Bundled index > 30 days old with no live source, or > 10% of packages unparseable, or all advisory sources failed. Tool refuses to report "safe" — exits with code 2.

### Maximum Staleness Threshold

| Scenario                                               | Behavior                                                                                                  |
| ------------------------------------------------------ | --------------------------------------------------------------------------------------------------------- |
| OSV API reachable                                      | Use real-time API results. Cache responses locally. Best quality.                                         |
| OSV unreachable, local cache < 4hr old                 | Use cached API responses. Warn "using cached data (X minutes old)".                                       |
| OSV unreachable, cache 4hr-72hr old                    | Use cached data. Warn prominently. Also try npm bulk endpoint.                                            |
| OSV unreachable, cache > 72hr or missing               | Fall back to bundled index. Warn "using bundled advisory data from [publish date]".                       |
| OSV unreachable, no cache, bundled index > 30 days old | **Exit code 2.** "Advisory data is too stale. Update the auditfix package or check network connectivity." |
| All sources fail                                       | **Exit code 2.** Refuse to produce results. Never exit 0 when data integrity is uncertain.                |

The tool must NEVER exit 0 ("safe") when data quality is uncertain. Uncertain data → exit 2 (tool error).

### Lockfile Edge Case Handling

| Edge Case                                       | Detection                                            | Behavior                                                                                                             |
| ----------------------------------------------- | ---------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| **`npm:` aliased packages**                     | `name` field differs from path key                   | Use `name` field (not path) for advisory matching. **P0 — wrong name = missed vuln.**                                |
| **`file:`/`link:`/`portal:`/`workspace:` deps** | `link: true` flag, or protocol prefix in `resolved`  | Exclude from advisory matching (local code). Scan their transitive deps.                                             |
| **`git+https://` deps**                         | `resolved` starts with `git+`                        | Skip advisory matching with warning (version may not be semver).                                                     |
| **`patch:` protocol (yarn) / `pnpm patch`**     | Protocol prefix or `patchedDependencies` in lockfile | Annotate as "locally patched" in output. Still report advisory but note patch may address it.                        |
| **Same package at multiple versions**           | Multiple `name@version` entries for same `name`      | Check EACH version independently against advisories.                                                                 |
| **npm `overrides` / yarn `resolutions`**        | Present in `package.json`                            | Trust lockfile resolved versions. Note overrides in output for transparency.                                         |
| **Yarn Classic vs Berry detection**             | Check for `__metadata:` in first lines               | Berry: parse as YAML. Classic: use `@yarnpkg/lockfile`. Wrong parser = garbage.                                      |
| **pnpm lockfile v5 vs v6 vs v9**                | Read `lockfileVersion` field                         | v5: keys `/name/version`. v6: keys `/name@version`. v9: separate `packages`/`snapshots`. Dispatch to correct parser. |
| **Platform-specific optional deps**             | `os`/`cpu` fields in lockfile entry                  | Scan them (installed on other team members' machines) but annotate as platform-specific.                             |
| **Circular dependencies**                       | Visited set hit during BFS                           | Already handled by visited set. No special action needed.                                                            |
| **Scoped packages**                             | Package name starts with `@`                         | Handle correctly in all parsers. pnpm v5 key: `/@scope/name/ver`. v6: `/@scope/name@ver`. v9: `@scope/name@ver`.     |
| **Unknown lockfile version**                    | `lockfileVersion` not in known set                   | Warn and exit 2. Do NOT attempt to parse — wrong parser = silent false negatives.                                    |
| **Empty/minimal lockfile**                      | `packages` is empty or has only root entry           | Report 0 packages scanned, exit 0. No crash.                                                                         |
| **Corrupted/truncated lockfile**                | `JSON.parse` or YAML parse throws                    | Clear error: "Lockfile appears corrupted. Try running `npm install` to regenerate." Exit 2.                          |
| **BOM in lockfile**                             | `\uFEFF` at start of file                            | Strip before parsing.                                                                                                |
| **Workspace hoisted deps**                      | Package reachable from multiple workspace importers  | If production-reachable from ANY importer, classify as production. Union all production roots.                       |
| **`bundledDependencies`**                       | `bundleDependencies` field on entry                  | Parse nested `node_modules/` paths for bundled deps. They are real packages with real versions.                      |

### Cross-Source Advisory Verification

When results are available from multiple sources (OSV API + bundled index + npm), cross-reference:

- If a **critical** advisory exists in one source but is absent from another, **flag the discrepancy** in the report
- This makes single-source suppression attacks detectable
- An attacker would need to compromise all three independent sources simultaneously

## Security Test Suite

Mandatory test categories under `tests/security/`:

| Test File                         | What It Validates                                                                                                                            |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `allow-list-integrity.test.ts`    | Tampered signature rejected, expired timestamp rejected, version rollback rejected, broad entries rejected                                   |
| `cache-traversal.test.ts`         | Advisory IDs with `../`, `/`, `\`, null bytes rejected. Resolved path stays within cache dir.                                                |
| `shell-injection.test.ts`         | Package names like `foo; rm -rf /`, `foo$(whoami)`, `` foo`id` `` and versions like `1.0.0 && curl evil.com` produce no shell interpretation |
| `api-response-validation.test.ts` | Malformed JSON, HTML responses, oversized payloads, `__proto__` keys all handled gracefully with fallthrough                                 |
| `osv-range-conversion.test.ts`    | OSV events→semver conversion: paired events, unpaired introduced, "0" sentinel, last_affected, empty events                                  |
| `token-redaction.test.ts`         | Fake tokens injected into env, verbose logging triggered — tokens never appear in output                                                     |
| `prototype-pollution.test.ts`     | Lockfiles and API responses with `__proto__`/`constructor` keys do not pollute `Object.prototype`                                            |
| `lockfile-edge-cases.test.ts`     | Aliased packages, git deps, file deps, circular deps, multi-version, BOM, empty lockfiles all handled correctly                              |
| `filename-sanitization.test.ts`   | Cache filenames derived from external data are validated against strict patterns                                                             |

## Concurrency Model

- **Lockfile parsing:** Synchronous `JSON.parse` / YAML parse. File I/O bound, not a bottleneck.
- **Reachability analysis:** Single-pass BFS. O(V+E) where V = packages, E = dependency edges. For npm lockfiles, O(n) flag scan instead.
- **Advisory resolution (OSV primary):** Single batch request handles up to 1,000 packages. Follow-up detail fetches (`/v1/vulns/{id}`) use bounded concurrency (10 parallel requests).
- **Advisory resolution (bundled fallback):** Index lookup is synchronous — O(1) per package name. No concurrency needed.
- **Advisory resolution (npm fallback):** Single bulk POST request. No concurrency needed.
- **CVSS parsing:** Synchronous string parsing per advisory. Negligible cost.
- **OSV events→semver conversion:** Synchronous, ~20 lines, per advisory. Negligible cost.
- **Total API calls for typical project (500 packages, 20 vulnerabilities):**
  - OSV mode (primary): 1 batch request + 20 detail requests = 21 total, 1-3 seconds
  - Bundled index mode (offline): 0 API calls, instant
  - npm mode (fallback): 1 bulk request = 1 total

## Competitive Analysis

| Feature                     | npm audit          | audit-ci       | Snyk                   | Socket     | auditfix                 |
| --------------------------- | ------------------ | -------------- | ---------------------- | ---------- | ------------------------ |
| Free                        | Yes                | Yes            | Freemium               | Freemium   | Yes (forever)            |
| Production vs dev filtering | No                 | No             | Partial (`--dev` flag) | No         | Yes (core feature)       |
| Actionable fix paths        | No                 | No             | Yes                    | No         | Yes                      |
| Safe auto-fix               | Broken (`--force`) | No             | Yes                    | No         | Yes (semver-checked)     |
| Allow-list with expiry      | No                 | Yes (IDs only) | Yes (.snyk policy)     | No         | Yes (ID + path + expiry) |
| Community allow-list        | No                 | No             | No                     | No         | Yes                      |
| Supply chain monitoring     | No                 | No             | Yes                    | Yes (core) | Post-v1                  |
| CI exit codes (0/1/2)       | Partial            | Yes            | Yes (0/1/2/3)          | Yes        | Yes                      |
| SARIF output                | Yes                | No             | Yes                    | No         | Yes                      |
| No account required         | Yes                | Yes            | No                     | No         | Yes                      |
| Works offline               | No                 | No             | No                     | No         | Yes (bundled index)      |
| Lightweight (`npx` fast)    | N/A (built-in)     | Yes            | No (heavy)             | No (SaaS)  | Yes (~263KB deps)        |

### What we learn from each competitor

- **npm audit:** Uses `/-/npm/v1/security/advisories/bulk` — efficient bulk endpoint we can also use as fallback
- **audit-ci:** Proved that allowlisting + CI exit codes is the minimum viable feature set for adoption
- **Snyk:** Graph-based dependency model (not tree) handles deduplication correctly — we adopt this
- **Socket.dev:** Behavioral analysis (install scripts, network calls) catches what CVE databases miss — deferred to post-v1
- **Renovate/Dependabot:** Coordinated group updates needed for peer dependency conflicts — relevant for our fix engine

## Runtime Dependency Budget

Keeping the dependency footprint minimal is critical for `npx` cold-start time and supply chain surface area.

| Dependency          | Purpose                           | Size   | Required For               |
| ------------------- | --------------------------------- | ------ | -------------------------- |
| `commander`         | CLI framework                     | ~50KB  | Always                     |
| `chalk`             | Terminal colors                   | ~20KB  | Terminal output            |
| `cli-table3`        | Terminal tables                   | ~30KB  | Terminal output            |
| `semver`            | Semver range matching             | ~40KB  | Reachability, fixing       |
| `js-yaml`           | Parse yarn berry + pnpm lockfiles | ~100KB | Yarn berry / pnpm projects |
| `@yarnpkg/lockfile` | Parse yarn v1 lockfiles           | ~20KB  | Yarn v1 projects           |
| `lilconfig`         | Config file loading               | ~3KB   | Config                     |

**Total: ~263KB** (7 dependencies). Compare to arborist alone at 50-80 transitive deps / several MB.

Lazy-load `js-yaml` and `@yarnpkg/lockfile` — only import when that lockfile type is detected. This keeps `npx auditfix` fast for npm-only projects.

### Build & Distribution

- Bundle with `tsup` into single ESM file with shebang (`#!/usr/bin/env node`)
- `tsup src/cli/index.ts --format esm --target node18 --clean`
- Single-file output eliminates Node module resolution overhead
- `package.json`: `"type": "module"`, `"bin": { "auditfix": "./dist/cli.js" }`

## Testing Strategy

- **Unit tests:** lockfile parsing (all formats + edge cases), reachability marking, risk scoring, semver resolution, input sanitization
- **Security tests:** 9 mandatory test files (see Security Test Suite above) covering injection, traversal, poisoning, pollution, redaction
- **Integration tests:** run against fixture projects with known vulnerabilities
- **Edge case fixtures:** aliased packages, git deps, file deps, circular deps, multi-version, patched packages, empty lockfiles, BOM, all pnpm lockfile versions
- **Snapshot tests:** terminal output format stability (including confidence metadata)
- **E2E tests:** full CLI invocation against real (pinned) lockfiles
- **CI:** test against npm lockfile v1/v2/v3, yarn classic, yarn berry, pnpm v5/v6/v9
- **CI:** test on Ubuntu, macOS, and Windows runners
- **CI:** verify minimum dependency versions (semver >= 7.5.4, js-yaml >= 4.0.0)
- Mock external APIs (GHSA, OSV, npm) in tests — never hit live endpoints in CI

## Open Source Strategy

- MIT license
- CONTRIBUTING.md with clear guidelines for community allow-list PRs
- GitHub Actions CI on every PR
- Semantic versioning, changelog
- npm publish via GitHub Actions on tag
- "Good first issue" labels for community onboarding

## Residual Risks

Even with all mitigations applied, the following risks cannot be fully eliminated:

1. **Upstream advisory database accuracy.** auditfix fundamentally trusts GitHub, OSV, and npm advisory databases. If all three miss a vulnerability, auditfix will too. Mitigated by cross-source verification.
2. **Zero-day in runtime dependencies.** The 7 direct dependencies could contain undiscovered vulnerabilities. Mitigated by minimal footprint, exact version pinning, and dogfooding auditfix on itself.
3. **OSV.dev availability.** If OSV.dev goes down for an extended period, users fall back to the bundled index which may be stale. Mitigated by npm bulk endpoint as tertiary source and staleness threshold enforcement.
4. **Local privilege escalation.** If an attacker has write access to `~/.auditfix/`, they can tamper with cache and config. Cache HMAC and permissions reduce but don't eliminate this.
5. **npm registry compromise.** If npm itself is compromised, auditfix or its deps could be replaced. Mitigated by npm provenance attestation via Sigstore.

## Research References

Key technical references validated during architecture research:

### API & Data Sources

- **OSV.dev API:** `POST /v1/querybatch` (1000 pkg limit, abbreviated response), `GET /v1/vulns/{id}` (full details), ecosystem = `"npm"` (lowercase)
- **OSV Bulk Export:** `https://osv-vulnerabilities.storage.googleapis.com/npm/all.zip` — all npm advisories as individual JSON files in one zip. ~5-15MB. Updated within minutes of upstream changes.
- **OSV Schema:** `affected[].ranges[].events` with `introduced`/`fixed`/`last_affected` pairs. `"introduced":"0"` = sentinel for all versions. CVSS in `severity[].score` as vector string (must parse to numeric). Events processed in order — `introduced` opens range, `fixed`/`last_affected` closes it. Unpaired `introduced` = no fix exists.
- **GHSA GraphQL:** `securityVulnerabilities(ecosystem: NPM, package: "name")` — enrichment only. Cannot batch by package, use aliases for ~20-30 per query. 5000 points/hr.
- **npm bulk advisory:** `POST /-/npm/v1/security/advisories/bulk` with `{ "pkg": ["ver"] }` — what `npm audit` uses via `libnpmaudit`.

### Lockfile Formats

- **npm lockfile v3:** `packages` field is flat map keyed by `node_modules/...` path. `""` key = root. `dev`/`optional`/`devOptional` flags pre-computed by npm. Aliased packages have `name` field that differs from path key — **must use `name` field for advisory matching**.
- **npm lockfile v1:** Legacy nested `dependencies` tree. `dev: true` flag. Increasingly rare.
- **Yarn v1 lockfile:** Custom format parsed by `@yarnpkg/lockfile`. No dev flags — must cross-reference `package.json`. Detect by first-line comment.
- **Yarn Berry lockfile:** Valid YAML despite same `yarn.lock` filename. Detect by `__metadata:` in first lines. PnP vs node_modules doesn't affect format. `patch:` protocol for locally patched packages.
- **pnpm-lock.yaml v9:** `importers` (direct deps per workspace), `packages` (metadata only — resolution, engines), `snapshots` (dep graph — dependencies, optionalDependencies). Separates deps/devDeps in `importers`. Keys no longer have leading `/`. **Snapshot keys include parenthesized peer dep suffixes:** `react-dom@18.2.0(react@18.2.0)`. Importer `version` fields contain the full snapshot key (with peer suffixes). Strip `(...)` to map back to `packages` key. Multiple snapshots can exist for the same package version with different peer resolutions.
- **pnpm-lock.yaml v5/v6:** Keys `/name/version` (v5) vs `/name@version` (v6). `dev: true` flag on entries. Scoped packages: `/@scope/name/version`.

### Security-Critical Dependencies

- **node-semver >= 7.5.4:** Versions < 7.5.4 have ReDoS (CVE-2022-25883). Pre-validate version string length (max 256 chars). **Always pass `{ includePrerelease: true }` for advisory matching.**
- **js-yaml >= 4.0.0:** v3 had RCE via `!!js/function` (CVE-2013-4660). v4+ defaults to safe schema. NEVER use `JS_SCHEMA`. Confirmed: js-yaml v4+ parses Yarn Berry lockfiles correctly (all protocol strings work because keys are always quoted YAML strings).
- **No git dependency required.** Advisory data comes from OSV API + bundled index (built from bulk export). This eliminates the entire class of git client vulnerabilities.

### Tools & Patterns

- **SARIF v2.1.0:** Only version GitHub Code Scanning supports. `properties.security-severity` (float string) maps to severity levels. Max 10MB.
- **Commander v12+:** Ships own `.d.ts`. Use `.exitOverride()` for testing. `getOptionValueSource()` for config merge.
- **Sigstore/cosign:** Modern alternative to GPG for signing. Keyless via OIDC, transparency log (Rekor). Used by npm provenance, PyPI.
- **node-semver:** `satisfies(fixVer, parentRange)` = safe update check. `maxSatisfying(versions, range)` = best upgrade finder. **ALWAYS pass `{ includePrerelease: true }`** for advisory matching — without it, pre-release versions silently evade vulnerability detection.
- **Negative caching trap:** Never cache "no advisories found" — only cache actual advisory data. A stale negative cache entry = invisible zero-day.
- **OSV events→semver:** Process events in order. `introduced` opens range, `fixed`/`last_affected` closes it. `"0"` = `"0.0.0"` sentinel. Convert to `>=X <Y` joined with `||`. ~20 lines, no library needed.
- **Yarn Berry lockfile:** Confirmed valid YAML — `js-yaml.load()` works. All protocol strings (`npm:`, `patch:`, `workspace:`, `portal:`) parse correctly (keys always quoted). Only need `@yarnpkg/lockfile` for Classic v1.
- **Atomic file writes:** Write to temp file + `fs.renameSync()` = atomic on same filesystem. Prevents cache corruption.
