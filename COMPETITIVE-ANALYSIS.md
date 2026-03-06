# auditfix Competitive Landscape Analysis

**Date:** 2026-03-06
**Author:** Staff Engineer Architect
**Status:** Research Complete
**Scope:** Competitive feature analysis and prioritized roadmap

---

## 1. Current auditfix Capabilities (Baseline)

What we have built and shipped (v1.0.1):

| Capability | Status | Quality |
|---|---|---|
| npm lockfile v2/v3 parsing | Shipped | Solid |
| yarn classic lockfile parsing | Shipped | Solid |
| yarn berry lockfile parsing | Shipped | Solid |
| pnpm lockfile v5/v6/v9 parsing | Shipped | Solid |
| Production reachability (BFS) | Shipped | Key differentiator |
| OSV.dev batch API integration | Shipped | Primary source |
| npm bulk advisory fallback | Shipped | Tertiary source |
| HMAC-verified local cache | Shipped | Hardened |
| CVSS v3.1 vector parsing | Shipped | Manual impl |
| Composite risk scoring | Shipped | CVSS + reachability + exploit + fix |
| Local allow-list (.auditfixignore) | Shipped | With expiry dates |
| Safe auto-fix (npm overrides) | Shipped | npm only |
| Terminal output (chalk) | Shipped | Actionable |
| JSON output | Shipped | For scripting |
| SARIF v2.1.0 output | Shipped | GitHub Code Scanning |
| Workspace/monorepo detection | Shipped | npm/yarn/pnpm |
| Config file (.auditfixrc) | Shipped | Via lilconfig |
| Security hardening | Shipped | Proto pollution, shell injection, cache integrity, token redaction |

What is planned but NOT built:

| Capability | Status |
|---|---|
| Bundled offline advisory index (OSV bulk export) | Planned, not shipped |
| Community allow-list (Sigstore-signed) | Planned, not shipped |
| Supply chain monitoring (maintainer watch) | Planned, not shipped |
| Install script scanner | Planned, not shipped |
| Publish anomaly detection | Planned, not shipped |
| GHSA GraphQL enrichment | Planned, not shipped |
| Cross-source advisory verification | Planned, not shipped |
| npm lockfile v1 (legacy) parser | Planned, not shipped |
| yarn/pnpm fix strategies (resolutions/overrides) | Not planned |
| SBOM generation | Not planned |
| PR/MR creation | Not planned |
| GitHub/GitLab/Bitbucket integrations | Not planned beyond SARIF |
| Reachability analysis (call-graph level) | Not planned |
| License compliance | Not planned |
| Diff/delta reporting | Not planned |

---

## 2. Competitor Deep Dives

### 2.1 npm audit

**What it does:**
- Built into npm CLI -- zero install friction
- Uses npm's own bulk advisory endpoint (`/-/npm/v1/security/advisories/bulk`)
- `npm audit fix` attempts safe semver-compatible patches
- `npm audit fix --force` forces updates regardless of breaking changes
- `npm audit --json` for machine-readable output
- `npm audit --omit=dev` to skip devDependencies (added ~npm 8)
- Signatures: `npm audit signatures` checks registry signatures on packages

**Known limitations (developer pain points):**
1. **Alert fatigue is the #1 complaint.** Projects with React/Angular/Vue regularly show 10-50+ "vulnerabilities" in build tooling (nth-check, postcss, glob-parent) that are completely unreachable in production. This is THE reason developers run `npm audit fix --force` and break things.
2. **No production/dev distinction by default.** `--omit=dev` exists but is not the default. Most developers do not know about it.
3. **`npm audit fix --force` is destructive.** It will happily upgrade you across major versions, breaking APIs, changing behavior. Many developers have been burned by this.
4. **No prioritization.** All "high" vulns look the same whether they are in your production Express middleware or in a test-only dev tool.
5. **False positives with no suppression.** No built-in way to say "I know about this, it is not relevant." The only escape is `--audit-level`.
6. **No SARIF output.** Cannot upload to GitHub Security tab natively.
7. **Advisory data is npm-only.** Does not cross-reference OSV, GitHub Advisory Database, or NVD.
8. **No workspace-aware reporting.** Monorepo users see a flat list with no indication of which workspace is affected.
9. **Slow for large projects.** No caching between runs.
10. **Exit codes are crude.** Any vuln at or above the threshold triggers exit 1, no nuance.

**What auditfix exploits:**
- Production reachability is our killer feature against npm audit's biggest weakness
- Actionable output with fix recommendations vs npm's wall of text
- Allow-list with expiry dates vs no suppression mechanism
- SARIF output vs none
- Composite scoring vs flat severity

**What npm audit has that we should note:**
- Zero friction (built-in, no install)
- `npm audit signatures` -- package signature verification (we do not have this)
- Name recognition and trust

### 2.2 Snyk

**What Snyk does (Open Source product):**
- SCA scanning for npm, pip, Maven, Go, Ruby, .NET, etc.
- `snyk test` CLI command scans lockfiles
- `snyk monitor` sends a snapshot to Snyk's platform for ongoing monitoring
- `snyk fix` suggests or applies fixes (PR creation)
- **Reachability analysis (DeepCode/Snyk Code):** For Java and JavaScript, Snyk performs actual call-graph analysis to determine if vulnerable code paths are reachable from your application. This goes far beyond lockfile-level "is it a prod dependency" -- it answers "does your code actually call the vulnerable function."
- **Priority Score (1-1000):** Combines CVSS, exploit maturity (PoC, weaponized, in-the-wild), fixability, social trends, reachability, age, and Snyk's proprietary threat intelligence. This is more granular than our 0-100 score.
- **Auto-fix PRs:** Creates PRs/MRs on GitHub/GitLab/Bitbucket with suggested fixes, including major version upgrade guidance.
- **License compliance:** Flags problematic licenses (GPL in commercial software, etc.).
- **Snyk Advisor:** Package health scoring (maintenance, community, security history).
- **Container scanning:** Scans Docker images for OS-level and language-level vulns.
- **IaC scanning:** Terraform, CloudFormation, Kubernetes manifests.
- **IDE plugins:** VS Code, IntelliJ, etc.

**Output formats:** JSON, SARIF, HTML, custom templates, dashboard/UI.

**CI integrations:** GitHub Actions, GitLab CI, Bitbucket Pipelines, Jenkins, Azure DevOps, CircleCI. First-class support for all major platforms.

**What makes it worth paying for:**
1. Call-graph reachability (not just lockfile-level prod/dev)
2. Continuous monitoring with notifications
3. Auto-PR creation for fixes
4. Single dashboard across all repos
5. License compliance
6. Priority scoring with threat intelligence feeds
7. IDE integration (shift-left)

**Key gaps in auditfix vs Snyk:**
- **Call-graph reachability** -- Snyk's JS reachability analysis actually traces import chains and function calls. Our BFS reachability only answers "is this a production dependency?" not "does my code call the vulnerable function?" This is a significant gap.
- **PR creation** -- Snyk creates PRs. We require manual action after `--fix`.
- **Continuous monitoring** -- We are a point-in-time scan. Snyk monitors and alerts.
- **License compliance** -- We have nothing here.
- **IDE integration** -- We are CLI-only.
- **Multi-language** -- We are JS-only. Not necessarily a gap if we position as best-in-class for JS.

### 2.3 Socket.dev

**What Socket does:**
Socket takes a fundamentally different approach. Rather than matching CVE/GHSA advisories against installed versions, Socket performs **behavioral analysis** of package source code.

- **Install script detection:** Flags packages with preinstall/install/postinstall scripts, especially new ones.
- **Network access detection:** Static analysis to find packages making HTTP/DNS/socket calls.
- **Filesystem access detection:** Finds packages reading/writing outside their directory.
- **Shell execution detection:** Finds packages spawning child processes.
- **Obfuscated code detection:** Identifies minified/obfuscated code in packages (common in malicious packages).
- **Typosquat detection:** Checks if a package name is suspiciously similar to a popular package.
- **Maintainer analysis:** Tracks maintainer changes, new maintainers, ownership transfers.
- **Dependency diff on PRs:** GitHub App shows what changed in dependencies when a PR adds/updates/removes packages. Shows behavior changes between versions.
- **Quality signals:** Maintenance frequency, test coverage, documentation, GitHub stars.

**How Socket detects malicious packages:**
Socket's key innovation is they analyze every version of every npm package proactively (not reactively waiting for CVEs). They:
1. Run static analysis on package source code looking for suspicious patterns
2. Flag behavior changes between versions (e.g., v1.0.0 had no network calls, v1.0.1 suddenly POSTs to an IP address)
3. Detect supply chain attacks within hours/minutes, often before an advisory is published
4. Maintain their own threat intelligence feed separate from CVE/GHSA/OSV

**What makes Socket different from vulnerability scanners:**
- Traditional scanners (npm audit, Snyk, auditfix) are **reactive** -- they match known CVE/GHSA IDs against versions. A new zero-day or supply chain attack takes hours to days to get an advisory.
- Socket is **proactive** -- it detects suspicious behavior patterns regardless of whether an advisory exists. This caught the `colors`/`faker` incident, `event-stream`, and numerous typosquat attacks before advisories were published.

**Key gaps in auditfix vs Socket:**
- **Behavioral analysis** -- We do not analyze package source code. This is Socket's entire value proposition and would be a massive engineering investment to replicate.
- **PR-level dependency diffs** -- We do not integrate at the PR review level.
- **Typosquat detection** -- We have no name-similarity checking.
- **Proactive detection** -- We are purely advisory-matching (reactive).

**What we can learn from Socket:**
- Our planned supply chain features (Phase 4: maintainer watch, script scanner, publish anomaly) are heading in Socket's direction but at a much simpler level.
- Install script scanning is the lowest-hanging fruit -- we planned it but have not built it.
- Typosquat detection for direct dependencies would be a useful warning.

### 2.4 Grype / Syft (Anchore)

**What they do:**
- **Syft:** SBOM generator. Scans container images, filesystems, and archives. Outputs CycloneDX, SPDX, and Syft's native format. Supports npm/yarn/pnpm lockfiles among many other ecosystems.
- **Grype:** Vulnerability scanner that consumes SBOMs. Matches against NVD, GitHub Advisory Database, and other feeds.
- Open source, written in Go, designed for CI/CD pipelines.

**Relevant patterns:**
1. **SBOM generation is the industry direction.** Executive Order 14028 (US) and EU CRA mandate SBOMs for software supply chain transparency. CycloneDX and SPDX are the standards.
2. **Separation of SBOM generation from vulnerability matching.** Syft generates the inventory, Grype scans it. This composability is powerful.
3. **Multi-ecosystem in a single tool.** Grype scans npm, pip, Go, Ruby, Java, etc. from a single binary.
4. **Offline mode with local database.** Grype downloads a vulnerability database and can run fully offline.

**Key gaps in auditfix vs Grype/Syft:**
- **No SBOM generation.** We should be able to output a CycloneDX or SPDX SBOM from our lockfile parse. We already have all the data (name, version, integrity hash, dependency graph, license info from registry). This is a high-value, relatively low-effort addition.
- **No SBOM consumption.** We cannot scan an existing SBOM -- only lockfiles.

### 2.5 Renovate / Dependabot

**What they do:**
Automated dependency update tools that create PRs/MRs.

**Renovate:**
- Open source (Mend/WhiteSource), self-hostable
- Supports npm, yarn, pnpm, pip, Go, Maven, Docker, Terraform, Helm, etc.
- Highly configurable via `renovate.json`
- **Grouping:** Can group related updates into a single PR (e.g., all ESLint packages together)
- **Auto-merge:** Can auto-merge PRs if CI passes, configurable by update type (patch, minor, major)
- **Schedule:** Run updates on specific days/times
- **Branch strategy:** Configurable branch naming, rebasing vs merge commits
- **Replacement detection:** Knows when packages are deprecated and suggests replacements
- **Lockfile-only updates:** Can update lockfiles without touching package.json (for transitive deps)
- **Security-only mode:** Can be configured to only create PRs for security updates
- **Changelogs:** Includes release notes and changelogs in PR descriptions
- **Confidence scores:** Uses Merge Confidence data showing adoption rate and test breakage rates

**Dependabot:**
- Built into GitHub (zero config for GitHub users)
- Creates PRs for dependency updates
- Security updates (based on GitHub Advisory Database) are separate from version updates
- Grouped updates (added 2023-2024)
- Auto-merge with GitHub Actions
- Less configurable than Renovate but zero friction for GitHub users

**How they handle breaking changes:**
1. Separate PRs for major version bumps with clear labels
2. Include changelogs and migration guides when available
3. Renovate's Merge Confidence scores show what percentage of users successfully upgraded
4. CI runs on the PR branch -- test suite gates the merge

**Key gaps in auditfix vs Renovate/Dependabot:**
- **PR creation** -- They create PRs. We just tell you what to fix.
- **Continuous updates** -- They run on schedule. We are point-in-time.
- **Changelog integration** -- They show what changed. We just show version numbers.
- **Merge confidence** -- Renovate shows adoption data. We have nothing comparable.
- **Grouping** -- They can batch related updates. We fix everything at once or nothing.

**What we can learn:**
- Security-only PR mode is a compelling integration. "auditfix found 3 production vulnerabilities with safe fixes, here is a PR."
- Changelog inclusion in fix output would help developers decide whether to apply fixes.
- Merge confidence data (from libraries.io, npm download stats, or Renovate's feed) could enhance our risk scoring.

### 2.6 osv-scanner (Google)

**What it does:**
- Open source scanner from Google, written in Go
- Uses OSV.dev as its sole data source (same as our primary source)
- **Guided remediation:** Calculates the minimal set of version changes needed to fix all vulnerabilities. This is more sophisticated than fixing one package at a time -- it considers the interdependencies and finds the optimal upgrade path.
- **Reachability analysis (experimental, Go-first):** For Go modules, osv-scanner can perform call-graph analysis to determine if vulnerable functions are actually called. For npm, this was experimental/limited as of early 2025.
- **SBOM input:** Can scan CycloneDX and SPDX SBOMs, not just lockfiles.
- **Container scanning:** Can scan Docker images using the `--docker` flag.
- **Offline mode:** Can download the OSV database for fully offline scanning.
- **Output formats:** Table, JSON, SARIF, Markdown.
- **License scanning:** Experimental support.
- **Configurable ignore file:** `osv-scanner.toml` with ignore entries (similar to our .auditfixignore).
- **CI integration:** Exit codes compatible with CI/CD. GitHub Actions template provided.

**Guided remediation details:**
osv-scanner's remediation engine:
1. Builds a dependency graph
2. For each vulnerability, finds all possible fix versions
3. Considers constraints from parent packages
4. Finds the minimal set of changes that resolves all vulnerabilities simultaneously
5. Distinguishes between "in-place" patches (lockfile-only) and "relax" patches (require package.json changes)
6. Can produce a patch file that modifies the lockfile directly

This is more sophisticated than our current approach, which fixes one package at a time and may create sub-optimal or conflicting upgrade paths.

**Key gaps in auditfix vs osv-scanner:**
- **Guided remediation** -- Their holistic fix planning is superior to our one-at-a-time approach.
- **SBOM input** -- They can scan existing SBOMs. We cannot.
- **Offline database** -- They have a proper offline mode. We planned a bundled index but have not shipped it.
- **Markdown output** -- Useful for PR comments. We do not have this.

**What we do better than osv-scanner:**
- Production reachability (their npm reachability was experimental/limited)
- Risk scoring (they use raw OSV severity, we add reachability + exploit maturity)
- Allow-list with expiry dates (their ignore file has no expiry)
- Better terminal UX with actionable recommendations
- Fix application (they produce a patch file, we actually run npm install)

### 2.7 audit-ci

**What it does:**
- Lightweight CI wrapper around `npm audit` (and yarn audit)
- Primary purpose: configurable CI exit code policies
- Allow-list with advisory IDs
- Configurable severity thresholds
- Path-based filtering (ignore vulns in certain dependency paths)
- Output in table format

**CI integration patterns:**
1. Runs as a simple npm script in CI: `npx audit-ci --high`
2. Fails the build only for specified severity levels
3. Allow-list is a simple JSON array of advisory IDs (no expiry dates)
4. Can be configured per-path: "ignore vulns in devDependencies of packages/admin"
5. Retries on npm registry errors
6. Zero config for basic use: `npx audit-ci --high` in one line

**What we can learn from audit-ci:**
- **Path-based filtering** -- Allow-listing by dependency path, not just advisory ID. "Ignore all vulns that only appear in `devDependencies > @storybook/*`". We do not have this.
- **Simple allow-list format** -- Their allow-list is just `["GHSA-xxx", "GHSA-yyy"]` -- simpler than our structured format (though ours is more secure with expiry dates).
- **Retry logic** -- They retry on npm registry errors. We fail through to the next tier, which is better.

---

## 3. Developer Pain Points (Community Sentiment)

Based on GitHub issues, Reddit/HN discussions, and community blog posts:

### The Top 5 Complaints About npm audit

1. **"npm audit is broken / useless"** -- This sentiment is widespread. Developers with React apps see 50+ "high" vulnerabilities, all in build tools like postcss, nth-check, glob-parent. None are exploitable in production. The signal-to-noise ratio makes the tool actively harmful because teams either ignore all alerts (dangerous) or waste time investigating false positives (expensive).

2. **"npm audit fix --force broke my app"** -- Major version upgrades applied blindly. The `--force` flag is dangerously named -- it sounds like "try harder" but means "break semver constraints."

3. **"I can't make npm audit pass in CI"** -- No suppression mechanism means CI pipelines either ignore audit entirely or are permanently red from unfixable transitive vulns.

4. **"The vulnerability is in a dev dependency / test tool / build plugin"** -- Even with `--omit=dev`, transitive dev dependencies of production packages still show up. The classification is too coarse.

5. **"This has been reported for 3 years and no one is fixing the upstream package"** -- Long-lived advisories in abandoned packages (nth-check, trim, glob-parent) that are deeply transitive and unfixable without major dependency tree changes.

### What Developers Actually Want

Based on community discussions:
1. A way to say "I know about this and it is not relevant to me" (allow-listing)
2. Distinction between "this is in my production server" vs "this is in my linter"
3. Auto-fix that does not break things
4. CI integration that is configurable (not all-or-nothing)
5. Less noise, more signal
6. SBOM generation for compliance
7. Integration with existing review workflows (PRs, Slack notifications)

---

## 4. State of the Art: JavaScript Reachability Analysis

### Lockfile-Level Reachability (What We Do)
- "Is this package in the production dependency tree?"
- BFS from `dependencies` roots, marking reachable packages
- Eliminates ~60-70% of npm audit noise
- Limitation: a package can be a production dependency but the vulnerable function may never be called

### Call-Graph Reachability (What Snyk and Google Do)
- "Does my application code actually call the vulnerable function?"
- Requires: static analysis of import/require chains, function call resolution
- **Snyk's approach (JavaScript):** Analyzes `require()`/`import` chains from application entry points, resolves to specific exported functions, checks if the vulnerable code path is reachable. Works for CJS and ESM.
- **osv-scanner's approach (Go):** Full call-graph analysis using Go's `callgraph` package. For JS, this was experimental.
- **Challenges for JS:**
  - Dynamic `require()` calls: `require(variable)` cannot be statically resolved
  - `eval()`, `new Function()`, dynamic imports
  - Re-exports and barrel files: `index.js` that re-exports everything
  - Monkey-patching: `Object.prototype.foo = ...`
  - Bundler transformations (webpack, esbuild, vite) change the call graph
  - Framework magic (Next.js, Nuxt) auto-imports and code-splits
  - Prototype chain lookups
- **Practical accuracy:** Snyk's JS reachability is effective for straightforward import chains but has false negatives for dynamic patterns. It is still a significant improvement over lockfile-level-only analysis.

### What auditfix Could Do (Pragmatic Middle Ground)
Rather than full call-graph analysis (enormous engineering investment), we could implement:

1. **Import chain analysis (medium effort):** Parse `import`/`require` statements from application source files to see if a vulnerable package is actually imported (directly or transitively) in production code. This catches cases where a production dependency is declared but never used.

2. **Vulnerable function matching (high effort):** OSV advisories sometimes identify the specific affected function (e.g., "the `parse` function in `qs`"). Cross-reference with import chains to see if that specific export is used.

3. **Framework-aware filtering (low effort):** For known frameworks (Next.js, Express, React), apply heuristics about what runs on the server vs browser. A vulnerability in a server-only function is not relevant in a client-side React component.

---

## 5. SBOM Standards Assessment

### CycloneDX
- OWASP-backed standard
- JSON and XML formats
- Strong adoption in security tooling
- Supports vulnerability data alongside component inventory
- Well-suited for JavaScript/npm ecosystems
- Tools: `@cyclonedx/bom` (npm), `cdxgen`

### SPDX
- Linux Foundation standard (ISO/IEC 5962:2021)
- Broader scope: licensing, provenance, relationships
- JSON, RDF, tag-value, spreadsheet formats
- Required by some government procurement (especially US)
- More complex to generate correctly

### Should auditfix Generate SBOMs?

**Yes, and here is why:**
1. We already parse lockfiles into a complete dependency graph with name, version, integrity, and license info. Generating CycloneDX from this is relatively low effort.
2. SBOM generation is increasingly required by enterprise and government customers (Executive Order 14028, EU Cyber Resilience Act).
3. No good single-tool exists that does vulnerability scanning + SBOM generation for npm. Syft generates SBOMs but does not do vulnerability analysis. Snyk does both but costs money.
4. An `auditfix sbom --format cyclonedx` command would be a strong differentiator for an open-source tool.
5. CycloneDX SBOMs can include vulnerability data -- we could embed our scan results directly into the SBOM.

**Recommendation:** Start with CycloneDX JSON (simpler, better security tooling integration). Add SPDX later if demand exists.

---

## 6. Integration Points Assessment

### GitHub
- **SARIF upload** (Code Scanning) -- We have this via `--sarif`
- **Dependency Graph API** -- Submit dependency snapshots for Dependabot alerts (we do not do this)
- **PR comments** -- Post scan results as PR comments via GitHub Actions (we do not do this)
- **GitHub App / Check Runs** -- Rich inline annotations on PRs (we do not do this)
- **Priority:** HIGH -- most JS developers are on GitHub

### GitLab
- **Dependency Scanning report** -- GitLab expects a specific JSON format for its Security Dashboard
- **SAST/Dependency report artifacts** -- Upload as CI artifacts for MR widgets
- **Priority:** MEDIUM -- significant enterprise user base

### Bitbucket
- **Code Insights API** -- Post annotations on PRs
- **Reports API** -- Attach scan results to builds
- **Priority:** LOW -- smaller JS developer base

### Jira
- **Create tickets from vulnerabilities** -- Auto-create Jira issues for critical vulns
- **Priority:** LOW -- nice-to-have, not core

### Slack / Teams
- **Notifications** -- Alert on new critical vulnerabilities
- **Priority:** LOW for v1, MEDIUM for continuous monitoring mode

---

## 7. Prioritized Feature Roadmap

Based on competitive gaps, developer pain points, implementation effort, and strategic value.

### Tier 1: High Impact, Achievable (Next 2-3 months)

| # | Feature | Competitive Gap | Effort | Impact |
|---|---|---|---|---|
| 1 | **CycloneDX SBOM generation** | Only Syft/Grype do this well in OSS. No single npm tool does vuln scan + SBOM. Regulatory pressure growing. | Medium | High (enterprise adoption, compliance) |
| 2 | **Bundled offline advisory index** | osv-scanner has this. We planned it. Currently if OSV is down and cache is empty, we fall back to npm bulk only. | Medium | High (reliability, air-gapped environments) |
| 3 | **Guided remediation (holistic fix planning)** | osv-scanner does this better than us. Our one-at-a-time approach can produce sub-optimal paths. | High | High (fix quality, developer trust) |
| 4 | **Markdown output format** | osv-scanner has it. Useful for PR comments, issue creation, and documentation. | Low | Medium |
| 5 | **yarn/pnpm fix strategies** | We only fix via npm overrides. yarn needs `resolutions`, pnpm needs `pnpm.overrides`. | Medium | High (pnpm/yarn users currently get no auto-fix) |
| 6 | **Install script scanner** | Socket's flagship feature (simplified). We planned it. Detects the Sept 2025 attack vector. | Medium | High (supply chain protection) |
| 7 | **Path-based allow-list filtering** | audit-ci has this. "Ignore all vulns only reachable via devDependencies > @storybook/*" | Low | Medium (monorepo UX) |

### Tier 2: Strategic Differentiators (3-6 months)

| # | Feature | Competitive Gap | Effort | Impact |
|---|---|---|---|---|
| 8 | **Import chain reachability analysis** | Snyk charges for this. We can do a pragmatic version by parsing import/require chains from source files. Much better than lockfile-only, cheaper than full call-graph. | High | Very High (THE upgrade from lockfile reachability) |
| 9 | **GitHub Actions PR comment integration** | Renovate/Dependabot do this natively. A reusable GitHub Action that posts scan results as PR comments. | Medium | High (developer workflow integration) |
| 10 | **Cross-source advisory verification** | Planned in architecture. Compare OSV vs npm bulk results. Detect single-source suppression attacks. | Medium | Medium (security posture) |
| 11 | **Fix PR creation** | Snyk/Renovate/Dependabot all create PRs. An `auditfix fix --create-pr` command that creates a branch, applies fixes, and opens a PR via `gh` CLI. | Medium | High (workflow automation) |
| 12 | **Delta/diff reporting** | "Compared to last scan: 2 new vulnerabilities, 3 resolved." Useful for CI pipelines tracking trends. | Medium | Medium (CI value) |
| 13 | **Community allow-list (Sigstore-signed)** | Planned in architecture. Would be unique in the OSS space. | High | Medium (community value, controversial) |

### Tier 3: Nice-to-Have (6+ months)

| # | Feature | Competitive Gap | Effort | Impact |
|---|---|---|---|---|
| 14 | **GitLab Dependency Scanning report format** | GitLab-native format for Security Dashboard integration. | Low | Medium (GitLab users) |
| 15 | **License compliance scanning** | Snyk has this. Read license fields from lockfile/registry. Flag GPL-in-commercial, etc. | Medium | Medium (enterprise) |
| 16 | **SPDX SBOM output** | Government procurement sometimes requires SPDX specifically. | Medium | Low (CycloneDX covers most needs) |
| 17 | **Typosquat detection** | Socket does this well. Check direct dependency names against popular package name similarity. | Medium | Low (rare but high-impact when it hits) |
| 18 | **Continuous monitoring mode** | Snyk Monitor equivalent. Run periodically, alert on new vulns. | High | Medium (requires persistence/daemon) |
| 19 | **IDE extensions** | Snyk has VS Code plugin. Show inline annotations on import statements. | Very High | Medium (shift-left) |
| 20 | **Merge confidence data** | Renovate shows adoption rates. Integrate with npm download stats or libraries.io data. | Medium | Low |

### Explicitly NOT Pursuing

| Feature | Reason |
|---|---|
| Multi-language support | We are best-in-class for JS/npm. Spreading to Python/Go/Java dilutes focus. Let Snyk/Grype own that. |
| Full call-graph analysis | Enormous engineering investment, diminishing returns vs import chain analysis. Snyk has spent years on this with a team. |
| Full behavioral analysis (Socket-style) | Requires analyzing every npm package version. Infrastructure cost alone is prohibitive. |
| Container scanning | Grype/Syft own this. Not our lane. |
| SaaS dashboard | We are a CLI tool. Adding a SaaS backend changes the product category entirely. |
| Package health scoring (Snyk Advisor) | Interesting but tangential to security scanning. |

---

## 8. Strategic Positioning

### Where auditfix should position itself

**"The best free alternative to Snyk for JavaScript dependency security."**

Target users:
1. Teams that find npm audit useless due to noise
2. Teams that cannot justify Snyk's cost but need better than npm audit
3. Open-source projects that want CI-integrated dependency security
4. Enterprise teams that need SBOM compliance without paid tooling

Differentiation pillars:
1. **Production reachability** (already built, upgrade to import chain analysis)
2. **Noise-free by default** (dev-only vulns are low, not screaming red)
3. **Fix without breaking** (safe auto-fix, holistic remediation planning)
4. **Compliance-ready** (SARIF, CycloneDX SBOM, configurable CI policies)
5. **No account required** (fully local, no SaaS, no telemetry)

### Competitive moats to build

1. **Best-in-class JS reachability** -- Import chain analysis would put us ahead of osv-scanner and close to Snyk, for free.
2. **SBOM + vuln scan in one tool** -- No other free tool does both well for npm.
3. **Community allow-list with cryptographic integrity** -- Unique in the OSS space. If executed well (Sigstore), this builds network effects.
4. **Supply chain signals** -- Install script scanning + maintainer watching bridges the gap between traditional vulnerability scanning and Socket's behavioral analysis.

---

## 9. Open Questions

1. **Import chain reachability scope:** How deep should we go? Just direct imports from application entry points? Or follow the full import chain through the dependency tree?

2. **SBOM format priority:** CycloneDX first is the recommendation, but should we support SPDX from day one for government/enterprise users?

3. **PR creation mechanism:** Use `gh` CLI (GitHub-only)? Or also support `glab` for GitLab and the Bitbucket API? Or provide a generic git-based approach (create branch + commit) and let users open the PR themselves?

4. **Install script scanner depth:** Simple detection of `preinstall`/`postinstall` scripts? Or actually analyze what the scripts do (network calls, filesystem access, etc.)?

5. **Community allow-list trust model:** Is Sigstore/cosign the right approach? How do we handle the governance of who can approve entries? Do we need a voting mechanism?

6. **Offline index size budget:** The full OSV npm export is ~15-25MB. Our architecture doc says ~1-2MB gzipped after stripping. Is that achievable with the current advisory count? Need to measure.

7. **Import chain analysis accuracy:** What false-positive rate is acceptable? Barrel file re-exports (`index.js`) that re-export everything will cause over-reporting. Is that better than under-reporting?
