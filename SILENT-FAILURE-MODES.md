# auditfix -- Silent Failure Mode Analysis

**Author:** Staff Engineer Architect
**Date:** 2026-03-06
**Status:** RESEARCH -- no implementation changes proposed
**Severity Context:** A false negative in a security tool is the worst possible failure. The tool says "no vulnerabilities" while vulnerabilities exist. Every stage of the pipeline is analyzed below.

---

## Table of Contents

1. [Lockfile Parsing Failures](#1-lockfile-parsing-failures)
2. [Reachability False Negatives](#2-reachability-false-negatives)
3. [Advisory Matching Gaps](#3-advisory-matching-gaps)
4. [Git Repo Index Staleness](#4-git-repo-index-staleness)
5. [Cache-Related False Negatives](#5-cache-related-false-negatives)
6. [Allow-List Over-Suppression](#6-allow-list-over-suppression)
7. [Overall Failsafe Mechanisms](#7-overall-failsafe-mechanisms)
8. [Summary Risk Matrix](#8-summary-risk-matrix)

---

## 1. Lockfile Parsing Failures

### 1.1 Unrecognized Dependency Protocols

**Failure:** A dependency uses `git:`, `git+ssh:`, `git+https:`, `file:`, `link:`, or `workspace:` protocol. The parser does not recognize it, silently skips it, and that package is never checked for advisories.

**How it happens in practice:**
- `package-lock.json` v2/v3 stores these in the `packages` map with `resolved` values like `git+ssh://git@github.com/user/repo.git#commitish` or `file:../local-pkg`.
- For `git:` dependencies, the `version` field may contain a commit SHA or a branch name rather than a semver string. If the parser expects semver and silently discards non-semver entries, the package vanishes from the graph.
- `link:` dependencies (npm workspaces) have `resolved` as a relative file path, not a registry URL. The parser may skip these thinking they are malformed.
- `workspace:*` protocol in pnpm/yarn berry resolves to a local workspace package. These may depend on vulnerable transitive dependencies that themselves have normal semver versions.

**Likelihood:** HIGH. Git dependencies are common in enterprise projects (private forks, pre-release testing). File/link dependencies are universal in monorepos.

**Impact:** CRITICAL. A git-resolved package with a known CVE is completely invisible to the scanner.

**Mitigations:**
1. **Enumerate all protocol schemes explicitly.** The parser must have a whitelist of recognized `resolved` formats: `https://registry.npmjs.org/...`, `git+ssh://...`, `git+https://...`, `git://...`, `file:...`, `link:...`, `workspace:...`. Any entry that does not match a known scheme must trigger a warning, never silent discard.
2. **For git dependencies:** Extract the package name from the lockfile key (e.g., `node_modules/lodash` tells you the package name is `lodash`). Extract the version from the lockfile entry's `version` field if present, or from `package.json` within the resolved path. Even if the version is a commit SHA, the package name alone is enough to check if ANY advisory exists for that package, then warn: "git dependency lodash cannot be version-matched against advisories -- manual review required."
3. **For file/link/workspace dependencies:** These resolve to local packages that themselves have `dependencies`. The parser must follow these links and include their transitive dependency trees. For workspace packages, the root lockfile already contains their resolved transitive deps -- the parser just needs to not skip entries whose `resolved` is a local path.
4. **Introduce a "skipped packages" counter in output.** If any packages were skipped for any reason, the final report must say: "WARNING: 3 packages could not be version-matched (git dependencies). These were NOT checked for vulnerabilities." This converts a silent false negative into a visible warning.
5. **Unit tests required:** Fixture lockfiles containing every protocol type, asserting that each is either parsed correctly or produces an explicit warning.

### 1.2 Phantom Dependencies (in node_modules but not in lockfile)

**Failure:** A package exists in `node_modules` and is `require()`-d at runtime, but does not appear in the lockfile. The tool only reads the lockfile, so this package is never scanned.

**How it happens in practice:**
- npm v3-v6 flat hoisting could leave phantom packages accessible via Node's resolution algorithm even when they are not direct or transitive dependencies of the project.
- A developer runs `npm install some-pkg` but the lockfile is not committed. CI installs from a stale lockfile that lacks `some-pkg`, but a different version of `some-pkg` gets hoisted as a transitive dep of something else.
- Yarn PnP mode eliminates this class of bug entirely. But node_modules-mode yarn and npm are both susceptible.
- `npx` can install packages into a global cache that are then available to the project, invisible to the lockfile.

**Likelihood:** MEDIUM. This is an inherent limitation of lockfile-only scanning. Most mature projects keep lockfiles committed and in sync.

**Impact:** HIGH. A phantom dependency with a known CVE would never be flagged.

**Mitigations:**
1. **This is a known limitation that must be documented, not silently accepted.** The README and output should state: "auditfix scans lockfile-declared dependencies only. Packages installed outside the lockfile are not checked."
2. **Optional `--scan-node-modules` flag (future).** Walk `node_modules` and compare discovered packages against the lockfile. Report any discrepancies. This is expensive but can be offered as an opt-in deep scan.
3. **Stale lockfile detection (cheap heuristic):** Compare `package.json` `dependencies` and `devDependencies` keys against lockfile top-level entries. If `package.json` declares a dependency that the lockfile does not contain, warn: "Lockfile may be stale. Run `npm install` to regenerate."
4. **CI recommendation:** Document that users should run `npm ci` (which fails on lockfile/package.json mismatch) before running `auditfix`. This is standard CI hygiene but worth reinforcing.

### 1.3 Stale Lockfile (does not match package.json)

**Failure:** `package.json` lists `express@^4.18.0` but the lockfile still resolves `express@4.17.1` because no one ran `npm install` after editing `package.json`. The tool scans the lockfile version (4.17.1), which may have a vulnerability fixed in 4.18.0. Alternatively, `package.json` adds a new dependency entirely absent from the lockfile.

**Likelihood:** MEDIUM-HIGH. Extremely common in PRs where someone edits `package.json` but forgets to regenerate the lockfile.

**Impact:** MEDIUM. The tool scans what the lockfile says, which is what `npm ci` would actually install. So the scan is technically correct for the lockfile state. But the user's mental model is "I updated to 4.18.0" when in fact the lockfile still installs 4.17.1.

**Mitigations:**
1. **Cross-reference package.json on every run.** For each `dependencies` and `devDependencies` entry in `package.json`, verify the lockfile contains a resolution for that package. If not, warn: "package.json declares `new-pkg` but lockfile does not contain it. Run `npm install` to update the lockfile."
2. **Version range check:** For each direct dependency, verify the lockfile-resolved version satisfies the `package.json` declared range. If `package.json` says `^4.18.0` but lockfile resolves `4.17.1`, that is a lockfile staleness signal. Warn explicitly.
3. **These checks should be cheap (O(direct deps) only, not full tree) and always-on, not behind a flag.**

### 1.4 Monorepo Workspace Edge Cases

**Failure:** A monorepo workspace package (`packages/api`) has production dependencies, but the root lockfile either does not include them, misrepresents their dev/production status, or the workspace resolution logic does not traverse into workspace packages.

**How it happens in practice:**
- npm workspaces: the root `package-lock.json` contains entries for all workspace packages under `node_modules/...` paths. But workspace packages themselves appear as `link:` entries. If the parser does not follow link entries and enumerate their dependencies, the workspace package's transitive tree is invisible.
- pnpm workspaces: `pnpm-lock.yaml` uses `importers` to list each workspace root separately. If the parser only reads `importers['.']` (the root) and ignores other importers like `importers['packages/api']`, those workspace packages' production dependencies are never scanned.
- yarn workspaces: similar to npm -- workspace packages are hoisted, and the lockfile must be read in its entirety, not just the root's dependency subtree.

**Likelihood:** HIGH for monorepo projects. Monorepos are increasingly the default for organizations.

**Impact:** CRITICAL. An entire workspace package's dependency tree could be invisible.

**Mitigations:**
1. **The workspace.ts module must enumerate ALL workspace packages, not just the root.** For pnpm, iterate all keys in `importers`. For npm, follow all `link:` entries in the `packages` map. For yarn, parse the `workspaces` field in root `package.json` and ensure all glob-matched workspace packages are included.
2. **Per-workspace reachability analysis.** Each workspace package has its own `package.json` with its own `dependencies` vs `devDependencies` split. Reachability must be computed per-workspace, then merged. A package that is `devDependencies` of the root but `dependencies` of `packages/api` is production-reachable.
3. **Workspace package count assertion.** After parsing, compare the number of discovered workspace packages against the `workspaces` globs in root `package.json`. If the globs match 5 directories but the parser only found 3, warn about missing workspaces.
4. **Fixture tests:** Create test fixtures for npm, yarn, and pnpm monorepos with known vulnerable transitive dependencies inside a non-root workspace package. Assert they are detected.

---

## 2. Reachability False Negatives

### 2.1 npm Lockfile dev Flag Incorrectness

**Failure:** The tool trusts npm's pre-computed `dev: true` flag in `package-lock.json` v2/v3. If npm computed this flag incorrectly, the tool inherits the error and classifies a production dependency as dev-only.

**When npm computes this incorrectly:**
- **Circular dependency edge cases.** npm's install algorithm uses a graph walk to compute dev flags. If the graph has cycles involving mixed dev/production paths, the flag computation can race or produce inconsistent results depending on traversal order. This is a known class of npm bugs (e.g., npm/cli issues around optional + dev flag interaction).
- **`optional: true` + `dev: true` interaction.** npm uses three flags: `dev`, `optional`, `devOptional`. The semantics: `devOptional: true` means "reachable only through dev AND optional paths." But if a package is reachable through both a production-optional path and a dev path, npm must set it as `optional: true` (not `devOptional`). Bugs in this logic have existed historically.
- **`bundledDependencies` / `bundleDependencies`.** Bundled dependencies are included in the published tarball. npm may not always correctly trace their reachability through the dependency graph.
- **`peerDependencies` with `peerDependenciesMeta.optional`.** If a peer dependency is optional and only required by a dev dependency, npm should mark it as dev. But peer resolution is complex and the flag may be wrong.

**Likelihood:** LOW-MEDIUM. npm's implementation is mature and well-tested. But edge cases exist, especially around optional + peer + dev interactions.

**Impact:** HIGH. Misclassifying a production dependency as dev-only means the tool deprioritizes or hides a real vulnerability.

**Mitigations:**
1. **Trust-but-verify mode (optional).** Offer a `--verify-reachability` flag that ignores npm's pre-computed flags and runs a full BFS from production roots (Strategy B) even for npm lockfiles. Compare the result against npm's flags. Report discrepancies.
2. **Always run BFS for `--prod-only` mode.** When the user explicitly requests production-only scanning (the highest-stakes mode), do not trust pre-computed flags. Run Strategy B as the source of truth.
3. **Log a diagnostic when flags are ambiguous.** If a package has both `optional: true` and no `dev` flag, log it as a borderline case in verbose mode.

### 2.2 Dynamic Requires Defeating Static Reachability

**Failure:** A package is correctly marked as `dev: true` by both npm's flags and BFS reachability. But application code does `require(devPackageName)` at runtime via a dynamic require pattern, string concatenation, or config-driven import. The package IS used in production despite being declared as a devDependency.

**Example:**
```javascript
// config.js (runs in production)
const parser = require(process.env.PARSER_LIB || 'dev-only-parser');
```

If `dev-only-parser` is listed in `devDependencies` and the environment variable is not set, it runs in production. The lockfile correctly says it is dev. The tool correctly classifies it as dev. But the classification is wrong for the actual runtime.

**Likelihood:** LOW. This is a project configuration error, not a tool error. But it does result in a false negative.

**Impact:** MEDIUM. This is fundamentally unsolvable with lockfile-only analysis.

**Mitigations:**
1. **Document this as a known limitation.** auditfix analyzes dependency declarations, not runtime behavior. If a project `require()`s a devDependency in production code, that is a project-level misconfiguration.
2. **Future enhancement (post-v1): static analysis integration.** A `--deep` flag that scans `require()` and `import()` calls in the project's source code and cross-references against the dependency graph. If a devDependency's name appears in a non-test source file, warn: "dev dependency `foo` appears to be imported in production code `src/config.js:14`."
3. **This is explicitly out of scope for the core audit engine.** No lockfile-based scanner (npm audit, Snyk, Socket) solves this either. It should be documented but not treated as a bug.

### 2.3 Optional Dependencies That Are Installed and Used

**Failure:** A package is marked `optional: true`. The tool may deprioritize or skip it. But the optional package IS installed on the target platform (e.g., `fsevents` on macOS, `@swc/core-linux-x64-gnu` on Linux) and is actively used in production.

**How it happens in practice:**
- `optional: true` means "installation may fail on some platforms and that is acceptable." It does NOT mean "this package is not used."
- Platform-specific native modules (fsevents, esbuild platform binaries, SWC platform binaries) are always optional but always used when present.
- The lockfile does not record which platform the project will be deployed on.

**Likelihood:** HIGH. Platform-specific optional dependencies are extremely common.

**Impact:** MEDIUM-HIGH. If the tool treats `optional: true` as "skip" or "deprioritize," real vulnerabilities in platform-specific packages are missed.

**Mitigations:**
1. **Never skip optional dependencies entirely.** Optional dependencies must be scanned and reported. The `optional` flag should affect the risk score (slightly lower confidence) but NOT cause the package to be excluded from advisory matching.
2. **In the risk scorer:** `optional: true` packages should be scored as "production-reachable with platform caveat," not as "dev-only." The output should say: "Optional dependency (may not be installed on all platforms) -- treat as production if deployed on a platform where it installs."
3. **Configuration option:** `treatOptionalAsProduction: true` (default: true). Users who want to exclude optional deps can set this to false, but the default must be conservative (assume optional deps are used).
4. **The `devOptional` flag is the safe one to deprioritize.** `devOptional: true` means "only reachable through both dev AND optional paths" -- these are genuinely unlikely to be in production. But `optional: true` alone (without `dev`) means "production dependency that may fail to install."

### 2.4 Peer Dependencies Misclassified

**Failure:** Package A declares `peerDependencies: { "B": "^2.0.0" }`. Package B is installed to satisfy this peer requirement. But B's dev/production classification depends on WHO is consuming A, and the lockfile flags may not reflect this correctly.

**How it happens in practice:**
- If A is a devDependency and B is installed solely to satisfy A's peer requirement, B should be dev. But if B is ALSO a direct production dependency at a different version, the lockfile may have one entry for B that is marked as production, while the version used by dev-dependency A is different and unscanned.
- npm v7+ auto-installs peer dependencies. The `dev` flag on the peer depends on the consumer's dev status. If multiple consumers exist (some dev, some production), npm should mark the peer as production. But edge cases exist.

**Likelihood:** MEDIUM. Peer dependency resolution is one of the most complex areas of package management.

**Impact:** MEDIUM. A peer dependency vulnerability could be misclassified.

**Mitigations:**
1. **For BFS-based reachability (Strategy B):** Peer dependencies must be included in the adjacency list. When building the graph, `peerDependencies` edges are traversed the same as `dependencies` edges.
2. **For npm flag-based reachability (Strategy A):** Trust the flags but include peer dependencies in the `--verify-reachability` cross-check.
3. **Test fixture:** Create a lockfile where a package is both a peer dep of a production package and a peer dep of a dev package at different versions. Assert both entries are scanned.

---

## 3. Advisory Matching Gaps

### 3.1 Scoped Package Name Mismatches

**Failure:** The advisory database lists a vulnerability for `@babel/traverse` but the matcher looks for `babel-traverse` (or vice versa). Or the advisory uses inconsistent casing.

**How it happens in practice:**
- npm is case-insensitive for package names. `Lodash` and `lodash` resolve to the same package. But advisory databases may store names with original casing.
- Scoped packages (`@scope/name`) have a very specific format. If the advisory stores `scope/name` (missing `@`), or the lockfile stores `@scope/name` but the index key strips the `@`, the match fails silently.
- npm aliases: `package.json` can declare `"my-lodash": "npm:lodash@4.17.21"`. The lockfile entry is keyed by the alias name, but the actual package is lodash. If the parser uses the alias name for advisory matching, the real package name is never checked.

**Likelihood:** MEDIUM. Scoped packages are everywhere. Aliases are less common but growing.

**Impact:** CRITICAL. A direct name mismatch means zero advisory matches for that package.

**Mitigations:**
1. **Normalize all package names to lowercase before matching.** npm itself does this internally. The advisory index must also be normalized to lowercase keys.
2. **For npm aliases:** The lockfile v2/v3 `packages` entries include a `name` field that contains the REAL package name (not the alias). The parser MUST use this `name` field for advisory matching, not the key path. Example: lockfile key is `node_modules/my-lodash` but `name: "lodash"` and `version: "4.17.21"`. Advisory matching must use `lodash@4.17.21`.
3. **Scoped package handling:** The `@` prefix and `/` separator must be preserved exactly. The matcher must not strip, split, or transform scoped package names. Normalize to lowercase only.
4. **Test fixtures required:** Advisory match tests for `@scope/pkg`, `UPPER-CASE-PKG`, and aliased packages.

### 3.2 Pre-release Version Matching

**Failure:** An advisory says versions `>=1.0.0 <1.0.5` are affected. The project has `1.0.5-beta.1` installed. Is it affected?

**Semver specification:** Pre-release versions have lower precedence than the release version. `1.0.5-beta.1 < 1.0.5`. So `1.0.5-beta.1` is technically within the range `>=1.0.0 <1.0.5`... except that `node-semver`'s `satisfies()` does NOT match pre-release versions against ranges that do not themselves include a pre-release tag on the same major.minor.patch.

**Concrete behavior of node-semver:**
```javascript
semver.satisfies('1.0.5-beta.1', '>=1.0.0 <1.0.5')  // false
semver.satisfies('1.0.5-beta.1', '>=1.0.0 <1.0.5-rc.1')  // true (pre-release on comparator)
```

This means: if the advisory range is `<1.0.5` and the installed version is `1.0.5-beta.1`, `semver.satisfies` returns `false`, and the tool reports "not vulnerable." But `1.0.5-beta.1` almost certainly does NOT contain the fix that ships in `1.0.5` -- it is a pre-release of the fix version.

**Likelihood:** LOW-MEDIUM. Pre-release versions in production lockfiles are uncommon but not rare, especially for early-stage packages or internal testing.

**Impact:** HIGH. A genuinely vulnerable pre-release version is reported as safe.

**Mitigations:**
1. **Use `includePrerelease: true` option in `semver.satisfies()`.** This changes the behavior:
   ```javascript
   semver.satisfies('1.0.5-beta.1', '>=1.0.0 <1.0.5', { includePrerelease: true })  // true
   ```
   This is the conservative (correct) choice for a security tool. A pre-release of the fix version should be assumed vulnerable until the full release is confirmed.
2. **Document this decision.** "auditfix treats pre-release versions as potentially vulnerable when they fall within an advisory's affected range. This may produce false positives for pre-releases that contain backported fixes, but the alternative (silent false negatives) is unacceptable for a security tool."
3. **Allow per-advisory override in the allow-list** if a user confirms a specific pre-release contains the fix.

### 3.3 Build Metadata in Versions

**Failure:** A version like `1.0.0+build.123` in the lockfile. Semver spec says build metadata MUST be ignored for version precedence. `node-semver` handles this correctly (strips build metadata before comparison). This is a non-issue with `node-semver` but could be an issue if any custom version parsing is done.

**Likelihood:** VERY LOW.

**Impact:** LOW (node-semver handles it).

**Mitigations:**
1. **Do not implement custom semver parsing.** Always use `node-semver` for all version comparisons. This is already the architectural decision.
2. **Test fixture:** Include a lockfile entry with build metadata. Assert it matches advisories correctly.

### 3.4 Advisory Range Format Variations

**Failure:** The advisory uses a range format the matcher does not expect. OSV format uses `affected[].ranges[].events` with `introduced`/`fixed` pairs. But some advisories may use `affected[].ranges[].type: "ECOSYSTEM"` with version strings, while others use `type: "SEMVER"` with semver ranges, and others use `type: "GIT"` with commit hashes.

**How it happens in practice:**
- OSV schema supports three range types: `SEMVER`, `ECOSYSTEM`, and `GIT`.
- For npm packages, most advisories use `ECOSYSTEM` type (npm version strings).
- The `ECOSYSTEM` type uses the ecosystem's native versioning, which for npm is semver. But the matcher must handle both `SEMVER` and `ECOSYSTEM` types.
- `GIT` ranges (commit hashes) are irrelevant for lockfile scanning but must not cause a crash or silent skip.
- Some advisories have `last_affected` instead of `fixed` -- meaning the vulnerability has no known fix, and all versions from `introduced` through `last_affected` are affected.
- Some advisories omit `introduced` entirely, meaning all versions up to `fixed` are affected (introduced at version 0).

**Likelihood:** MEDIUM. Range format variations are real and common across the advisory database.

**Impact:** HIGH. Misinterpreting a range means either false positive or false negative.

**Mitigations:**
1. **Implement the full OSV range evaluation algorithm.** The OSV specification defines exact semantics:
   - Events are ordered: `introduced` opens a vulnerable range, `fixed` closes it, `last_affected` closes it (inclusive).
   - If no `introduced` event exists, assume `0` (all versions before the fix are affected).
   - Multiple `introduced`/`fixed` pairs can exist in one range (for regressions that were fixed, re-introduced, and fixed again).
2. **Handle `last_affected` correctly.** If the advisory says `last_affected: "2.3.4"` with no `fixed`, then versions `<= 2.3.4` from the `introduced` version are affected, AND all later versions are also potentially affected (no fix exists). The matcher should flag this and warn: "No fix available for this advisory."
3. **Ignore `GIT` range type for npm ecosystem.** Log in verbose mode: "Advisory GHSA-xxxx has GIT range type, skipping (not applicable to npm version matching)." Do not error.
4. **Test against real advisory data.** Pull 100 random npm advisories from the GHSA database and verify the matcher handles all of them correctly. This is the single most important test for false negative prevention.

### 3.5 Advisory Source Gaps (GHSA vs OSV vs npm)

**Failure:** An advisory exists in one database but not another. The tool checks one source, finds nothing, and reports "no vulnerabilities." But the advisory exists in a source the tool did not check.

**How it happens in practice:**
- **Time window:** A new CVE is published. It appears in NVD first, then GHSA (usually within hours to days), then OSV (mirrors GHSA, slight delay), then npm advisory database (can lag by days). During this window, one source has the advisory and others do not.
- **Source coverage:** GHSA focuses on GitHub-reviewed advisories. OSV aggregates from multiple sources (GHSA, NVD, Linux distros, etc.). npm's database is a subset maintained by npm/GitHub. An advisory from a non-GHSA source in OSV may not appear in GHSA or npm.
- **Withdrawn advisories:** An advisory is withdrawn from GHSA but the npm database still has it, or vice versa. The tool might skip it from one source and not find it in the other.

**Likelihood:** MEDIUM. The time window between sources is real and measured in hours to days for most advisories.

**Impact:** HIGH during the gap window. A zero-day with a published advisory in one source but not the tool's primary source is invisible.

**Mitigations:**
1. **Query multiple sources by default, not just the primary.** The architecture already has a three-tier fallback chain, but it is sequential (try primary, fall back to secondary on failure). For maximum coverage, the tool should MERGE results from at least two sources, not just fall back.
2. **Recommended approach:** Always check the git repo index (primary). If the git index is older than N hours, ALSO check the OSV batch API (secondary) and merge results. Deduplication by advisory ID (GHSA-xxxx) prevents double-counting.
3. **Report data source in output.** For each advisory found, show which source it came from. This makes source gaps visible.
4. **Staleness warning:** If the primary source is the only one checked and it is more than 6 hours old, warn: "Advisory data is 6+ hours old. Run with `--refresh` to check live sources for recent disclosures."

### 3.6 Cross-Ecosystem Name Collision

**Failure:** An advisory for package "lodash" in the PyPI ecosystem is accidentally matched against "lodash" in the npm ecosystem.

**How it happens in practice:**
- OSV advisories include an `affected[].package.ecosystem` field. If the matcher does not filter by ecosystem, a PyPI advisory for a package with the same name as an npm package would produce a false positive (not a false negative). So this is actually a false POSITIVE risk, not a false negative.
- However, the reverse is possible: if the ecosystem filter is TOO strict and rejects a valid npm advisory because the ecosystem field has a variation like `"npm"` vs `"NPM"` vs `"Node"` vs `"node"`, the advisory is silently skipped -- a false negative.

**Likelihood:** LOW. OSV uses `"npm"` consistently for the npm ecosystem. But defensive coding is warranted.

**Impact:** MEDIUM if ecosystem string matching is case-sensitive and a source uses unexpected casing.

**Mitigations:**
1. **Case-insensitive ecosystem matching.** Normalize to lowercase: `ecosystem.toLowerCase() === 'npm'`.
2. **Accept known variations.** Match against `['npm', 'node', 'nodejs']` to handle any reasonable ecosystem naming. Log unrecognized ecosystem strings in verbose mode.
3. **Always filter by ecosystem.** Never match an advisory that does not have `ecosystem` set to an npm-compatible value.

---

## 4. Git Repo Index Staleness

### 4.1 Staleness Window

**Failure:** The git advisory index was last pulled 24 hours ago. A critical zero-day advisory was published 1 hour ago. The tool reports "no vulnerabilities" because the advisory is not in the local index.

**Current architecture:** The doc says "if index exists and is fresh (< 24hr): use it, skip API calls entirely." This means a 24-hour window where a newly published advisory is invisible.

**Likelihood:** HIGH that the index will be stale by some amount. LOW that a specific zero-day will be missed in a specific 24-hour window. But across all users, this will happen.

**Impact:** CRITICAL when it happens. A zero-day advisory for a widely-used package, published 6 hours ago, invisible to all users whose index is older than 6 hours.

**Mitigations:**
1. **Reduce the default freshness threshold.** 24 hours is too long for a security tool. Recommend 4 hours as the default before triggering a secondary source check.
2. **Dual-source strategy for recent advisories.** Even when the git index is "fresh," also query OSV for advisories modified in the last 48 hours. OSV's batch API supports a `modified_after` parameter (if available) or the tool can check the `modified` timestamps in batch results against the git index's last-pull time. Any advisory from OSV that is newer than the git index's last pull is a gap that must be merged.
3. **Display data freshness prominently.** Every report output must include: "Advisory data freshness: git index pulled 3h ago, 14,231 npm advisories indexed." Users can then make informed decisions.
4. **`--live` flag.** Force a live API check regardless of git index freshness. CI pipelines processing sensitive deployments should use this flag.
5. **Maximum staleness hard limit.** If the git index is older than 72 hours AND no live source is reachable, the tool should exit with code 2 and a warning: "Advisory data is more than 72 hours old and no live source is available. Results may be incomplete." Do NOT report "0 vulnerabilities" with stale data and exit 0.

### 4.2 Incomplete Git Pull

**Failure:** `git pull` on the advisory-database repo fails partway through (network interruption, disk full). The local repo is in an inconsistent state -- some advisories updated, some not. The index is rebuilt from this partial state.

**Likelihood:** LOW. Git is transactional for most operations. A failed pull should leave the repo at the previous good state.

**Impact:** LOW if git's transactional guarantees hold. But if a shallow clone (`--depth 1`) is corrupted, the state is harder to recover.

**Mitigations:**
1. **Verify git repo integrity after pull.** Run `git status` after pull. If the repo is in a dirty or detached state, warn and fall back to live sources.
2. **Store a last-known-good commit hash.** Before re-indexing, record the commit hash. If indexing fails, keep the previous index and warn.
3. **Atomic index replacement.** Build the new index to a temp file, then atomically rename over the old index. Never modify the index in place.

---

## 5. Cache-Related False Negatives

### 5.1 Cached "No Vulnerabilities" Result

**Failure:** Package `foo@1.2.3` was checked yesterday. No advisories existed. The result was cached as "no vulnerabilities." Today, a new advisory is published for `foo@1.2.3`. The tool returns the cached "no vulnerabilities" result.

**Likelihood:** HIGH. This is the most common cache-related false negative. It will happen to every user who has caching enabled and whose cache TTL extends past an advisory publication.

**Impact:** CRITICAL. The tool actively lies -- it returns "safe" for a package that has a known vulnerability.

**Mitigations:**
1. **Never cache negative results with the same TTL as positive results.** Negative results ("no advisories found") should have a MUCH shorter TTL than positive results ("advisory GHSA-xxxx found"). Recommendation:
   - Positive result (advisory exists): cache for 24 hours (advisory details rarely change once published)
   - Negative result (no advisory): cache for 1 hour maximum, or do not cache at all
2. **Cache keying must include the data source timestamp.** Cache key: `(package_name, version, advisory_source_last_updated_timestamp)`. When the advisory source is refreshed (git pull, API check), all negative cache entries become invalid.
3. **Alternative: cache only advisory data, not match results.** Cache the full advisory list per package name (or the git index). Matching is done fresh every run against cached advisory data. This way, cached data is always the full advisory list, and a new advisory invalidates the cache for that package name.
4. **Recommended architecture:** Do NOT cache per-package match results. Cache the advisory index itself (git repo or API response). Re-run matching every time. Matching is O(advisories_for_package * 1) per package -- negligible cost.

### 5.2 Cache Corruption

**Failure:** The cache file on disk is corrupted (partial write, disk error, concurrent access). The tool reads corrupted data, fails to parse it, and... what happens next?

**Likelihood:** LOW. But it will happen at scale.

**Impact:** Depends on error handling. If the tool catches the parse error and falls back to live sources, impact is ZERO. If the tool catches the error and returns "no vulnerabilities," impact is CRITICAL.

**Mitigations:**
1. **Cache parse errors must NEVER result in "no vulnerabilities."** If the cache is corrupt, treat it as a cache miss and fetch from live sources. Log a warning: "Cache corrupted, fetching fresh data."
2. **Atomic cache writes.** Write to a temp file, then rename. Never write directly to the cache file.
3. **Cache integrity check.** Store a checksum with each cache entry. Verify on read. If checksum fails, treat as cache miss.

### 5.3 TTL Configuration Too Long

**Failure:** User or default config sets cache TTL to 7 days. Tool serves week-old "safe" results.

**Likelihood:** MEDIUM (if configurable without guardrails).

**Impact:** HIGH.

**Mitigations:**
1. **Enforce a maximum cache TTL.** Regardless of user configuration, the cache TTL for advisory data must not exceed 24 hours. If the user sets `cacheTTL: "7d"`, cap it at 24 hours and warn.
2. **Display cache age in output.** "Advisory cache age: 23h. Use --refresh to update."

---

## 6. Allow-List Over-Suppression

### 6.1 Overly Broad Community Allow-List Entries

**Failure:** The community allow-list marks advisory GHSA-xxxx for package `foo` as a false positive. The entry does not specify affected versions. ALL versions of `foo` are now suppressed, including future versions where the vulnerability is real and exploitable.

**Example:** Advisory GHSA-xxxx affects `foo >= 1.0.0 < 1.5.0`. The community allow-list says "GHSA-xxxx is a false positive for foo" without version constraint. When `foo@1.3.0` is installed (genuinely affected), the allow-list suppresses the alert.

**Likelihood:** HIGH. Community contributors are likely to create overly broad entries, especially if the allow-list schema does not require version constraints.

**Impact:** CRITICAL. The allow-list -- a convenience feature -- becomes a vector for silent false negatives.

**Mitigations:**
1. **Require version constraints on all allow-list entries.** The schema must require an `affectedVersions` field:
   ```json
   {
     "id": "GHSA-xxxx",
     "package": "nth-check",
     "affectedVersions": "<2.0.0",
     "reason": "ReDoS only exploitable with untrusted CSS selectors, not applicable in build tooling",
     "expires": "2026-12-31"
   }
   ```
   Entries without `affectedVersions` must be rejected at parse time.
2. **Require an expiry date on all allow-list entries.** No entry should suppress an advisory indefinitely. Maximum expiry: 1 year. After expiry, the advisory reappears in reports.
3. **Show suppressed advisories in output.** The current architecture already shows an "IGNORED" section. This must include the reason and expiry for each suppressed entry. Users must be able to see what is being hidden.
4. **Community allow-list entries must be scoped more narrowly than advisory entries.** An allow-list entry can only suppress a SUBSET of the advisory's affected range, never a superset.

### 6.2 Stale Allow-List Entries

**Failure:** An allow-list entry was created when the advisory was considered a false positive. Later, the vulnerability was confirmed real (new exploit technique, new attack surface). The allow-list entry is never updated.

**Likelihood:** MEDIUM-HIGH. This is the natural entropy of any allow-list system.

**Impact:** HIGH. Users who trust the community allow-list are exposed.

**Mitigations:**
1. **Mandatory expiry dates** (see above). This is the primary defense.
2. **Advisory modification tracking.** When an advisory's `modified` timestamp is newer than the allow-list entry's creation date, flag it: "Advisory GHSA-xxxx was updated after this allow-list entry was created. The entry may be stale."
3. **Community allow-list version pinning.** The tool should record which version of the community allow-list it used. When a new version is released that removes an entry, the tool should alert: "Advisory GHSA-xxxx was removed from the community allow-list. It will now be reported."
4. **Review cadence enforcement.** The community allow-list repository should require periodic re-review of all entries (e.g., quarterly). Entries not re-reviewed within 90 days are automatically marked as expired.

### 6.3 Local Allow-List Without Expiry Enforcement

**Failure:** The local `.auditfixignore` has an entry with `"expires": "2025-06-01"`. It is now 2026-03-06. The tool does not check the expiry date and continues to suppress the advisory.

**Likelihood:** HIGH if expiry checking is not implemented or has a bug.

**Impact:** HIGH. Expired entries silently suppress real vulnerabilities.

**Mitigations:**
1. **Expiry checking is mandatory, not optional.** On every run, every allow-list entry must have its `expires` field checked against the current date. Expired entries must be treated as non-existent.
2. **Warn on expired entries.** "Allow-list entry for GHSA-xxxx expired on 2025-06-01. This advisory is now being reported."
3. **Require `expires` field.** Entries without an `expires` field should be rejected with an error, not silently accepted as "never expires."
4. **Test this explicitly.** Create a test with a past expiry date and assert the advisory is NOT suppressed.

---

## 7. Overall Failsafe Mechanisms

### 7.1 Advisory Count Sanity Check

**Problem:** The tool completes a scan and reports "0 vulnerabilities in 847 packages." But it actually checked against 0 advisories because the git index was empty, the API returned an error that was silently caught, and the cache was cleared.

**Mitigation: Advisory count assertion.**
- After advisory resolution, count the total number of npm advisories available from the data source.
- As of 2026, the GitHub Advisory Database contains approximately 5,000-10,000 npm advisories. If the tool resolves fewer than 1,000 npm advisories from its data source, something is wrong.
- Include in output: "Scanned 847 packages against 7,234 npm advisories."
- If advisory count is below a configurable minimum threshold (default: 500), warn: "WARNING: Unusually low advisory count (142). Data source may be incomplete. Results may not be reliable."
- This single check catches: empty git index, failed API calls silently returning empty results, cache corruption that drops entries, indexing bugs that skip advisories.

### 7.2 Confidence Level in Output

**Recommended output footer:**
```
auditfix scan complete
  Packages scanned:     847
  Advisory sources:     git index (pulled 2h ago) + OSV batch API
  Total npm advisories: 7,234
  Data freshness:       2 hours
  Skipped packages:     0
  Allow-list entries:   3 (0 expired)
  Confidence:           HIGH
```

**Confidence levels:**
- **HIGH:** Multiple advisory sources checked, data < 4 hours old, no packages skipped, no parse warnings.
- **MEDIUM:** Single advisory source, data 4-24 hours old, OR some packages skipped (git deps).
- **LOW:** Data > 24 hours old, OR advisory count below threshold, OR cache-only mode with stale cache.
- **UNRELIABLE:** Data > 72 hours old, OR advisory count below minimum, OR major parse failures. Exit code 2.

This gives users and CI systems the information to make informed trust decisions about the scan results.

### 7.3 Fail-Open vs Fail-Closed Decision

**This is the most important architectural decision for a security tool.**

**Fail-open** (report error, exit 2): When data is uncertain, report that the tool could not complete the scan reliably. Do not report "0 vulnerabilities." Let the CI pipeline decide how to handle exit code 2.

**Fail-closed** (assume everything is vulnerable): When data is uncertain, report all packages as potentially vulnerable. This produces massive false positives and renders the tool useless.

**Recommendation: Fail-open with clear signaling.**

- Exit code 0: Scan completed successfully, no vulnerabilities above threshold. HIGH or MEDIUM confidence.
- Exit code 1: Scan completed successfully, vulnerabilities found above threshold.
- Exit code 2: Scan could not be completed reliably. Data integrity concerns. Do NOT trust the results.

**Conditions that trigger exit code 2 (MUST be comprehensive):**
- No advisory source available (git index missing/corrupt + all APIs unreachable + no cache)
- Advisory count below minimum threshold
- Lockfile parse error (partial or complete)
- Data staleness exceeding maximum threshold (e.g., 72 hours) with no live source reachable
- More than 10% of packages could not be version-matched (git deps, unparseable versions)

**Conditions that do NOT trigger exit code 2:**
- Single advisory source unavailable (fallback exists)
- A few git dependencies that cannot be version-matched (warn, but scan continues)
- Cache miss (live source is checked instead)
- GHSA token missing (GHSA is enrichment, not primary)

**CI integration guidance:** Document that CI pipelines should treat exit code 2 as a failure (block the pipeline) just like exit code 1. The reason: if the security tool cannot determine safety, the deployment should not proceed. This is configurable but the recommended default.

---

## 8. Summary Risk Matrix

| # | Silent Failure Mode | Likelihood | Impact | Mitigation Priority |
|---|---------------------|-----------|--------|---------------------|
| 1.1 | Unrecognized dependency protocols (git:, file:, link:) | HIGH | CRITICAL | P0 -- must ship in v0.1 |
| 1.2 | Phantom dependencies (not in lockfile) | MEDIUM | HIGH | P2 -- document limitation, optional deep scan post-v1 |
| 1.3 | Stale lockfile (package.json mismatch) | MEDIUM-HIGH | MEDIUM | P1 -- cheap cross-reference check |
| 1.4 | Monorepo workspace packages missed | HIGH | CRITICAL | P0 -- must handle in workspace.ts |
| 2.1 | npm dev flag incorrectness | LOW-MEDIUM | HIGH | P1 -- verify-reachability flag |
| 2.2 | Dynamic requires defeating static reachability | LOW | MEDIUM | P3 -- document limitation |
| 2.3 | Optional deps skipped when actually used | HIGH | MEDIUM-HIGH | P0 -- never skip optional deps |
| 2.4 | Peer dependency misclassification | MEDIUM | MEDIUM | P1 -- include peers in BFS graph |
| 3.1 | Scoped package / alias name mismatch | MEDIUM | CRITICAL | P0 -- normalize names, use `name` field |
| 3.2 | Pre-release version matching | LOW-MEDIUM | HIGH | P0 -- use `includePrerelease: true` |
| 3.3 | Build metadata in versions | VERY LOW | LOW | P2 -- already handled by node-semver |
| 3.4 | Advisory range format variations | MEDIUM | HIGH | P0 -- implement full OSV range evaluation |
| 3.5 | Advisory source gaps (GHSA vs OSV timing) | MEDIUM | HIGH | P1 -- merge multiple sources |
| 3.6 | Cross-ecosystem name collision | LOW | MEDIUM | P1 -- filter by ecosystem |
| 4.1 | Git index staleness (24h window) | HIGH | CRITICAL | P0 -- reduce threshold, dual-source for recent advisories |
| 4.2 | Incomplete git pull | LOW | LOW | P2 -- verify after pull |
| 5.1 | Cached "no vulnerabilities" result goes stale | HIGH | CRITICAL | P0 -- do not cache negative results, or very short TTL |
| 5.2 | Cache corruption | LOW | CRITICAL (if mishandled) | P0 -- cache miss on error, never return "safe" from corrupt cache |
| 5.3 | TTL too long | MEDIUM | HIGH | P1 -- enforce max TTL cap |
| 6.1 | Overly broad allow-list entries | HIGH | CRITICAL | P0 -- require version constraints |
| 6.2 | Stale allow-list entries | MEDIUM-HIGH | HIGH | P1 -- mandatory expiry, modification tracking |
| 6.3 | Local allow-list expired entries not enforced | HIGH | HIGH | P0 -- always check expiry |
| 7.1 | Zero advisories checked (silent data source failure) | MEDIUM | CRITICAL | P0 -- advisory count sanity check |
| 7.2 | No confidence signal in output | N/A | N/A | P1 -- add confidence level and metadata |
| 7.3 | Fail-open vs fail-closed decision | N/A | N/A | P0 -- fail-open with exit code 2 |

---

## P0 Implementation Checklist

These items MUST be addressed before v0.1 ships. A security tool that silently misses vulnerabilities is worse than no security tool (it provides false confidence).

1. **Parser: warn on unrecognized dependency protocols.** Never silently skip. Count and report skipped packages.
2. **Parser: use `name` field for real package name** (not alias or path key) in advisory matching.
3. **Parser: normalize package names to lowercase.**
4. **Reachability: never skip optional dependencies.** Scan them as production by default.
5. **Matcher: use `includePrerelease: true`** in all `semver.satisfies()` calls.
6. **Matcher: implement full OSV range evaluation** including `last_affected` and missing `introduced`.
7. **Advisory source: reduce freshness threshold** from 24 hours to 4 hours.
8. **Advisory source: dual-source check** for recent advisories when git index is sole source.
9. **Cache: never cache negative results** (or 1 hour max TTL). Cache advisory data, not match results.
10. **Cache: treat parse errors as cache miss,** never as "no vulnerabilities."
11. **Allow-list: require version constraints and expiry** on all entries.
12. **Allow-list: enforce expiry dates** on every run.
13. **Output: include advisory count, data freshness, skipped package count.**
14. **Exit code 2: trigger on data integrity failures** (see conditions list above).
15. **Advisory count sanity check:** Warn if below 500 npm advisories.
16. **Workspace parsing: enumerate ALL workspace packages,** not just root.

---

## Open Questions

1. Should the tool support a `--paranoid` mode that enables ALL mitigations (dual-source, verify-reachability, scan-node-modules, shortest possible cache TTL)?
2. What is the right default for `treatOptionalAsProduction` -- `true` (conservative, more noise) or `false` (quieter, risk of false negatives)?
3. Should the community allow-list be fetched over HTTPS with certificate pinning, or is SHA-hash verification of the content sufficient?
4. For the advisory count sanity check, what is the right minimum threshold? 500? 1,000? Should it be a percentage of the known total?
5. Should exit code 2 be configurable in CI mode (e.g., `--fail-on-uncertain=warn` to downgrade to exit 0 with warning)?
