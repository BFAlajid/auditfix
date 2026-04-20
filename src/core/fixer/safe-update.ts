/**
 * Safe update detection.
 * Determines which vulnerable packages can be patched without breaking changes.
 *
 * A "safe update" means the fix version satisfies the parent's declared semver range,
 * so the lockfile can be updated without modifying any package.json.
 */
import type { ScoredVulnerability } from '../../types/report.js';
import type { DependencyGraph } from '../../types/package.js';
import { satisfies, compareVersions, isValidVersion } from '../../utils/semver.js';
import * as logger from '../../utils/logger.js';

export type FixPlan = {
  safe: SafeUpdate[];
  breaking: BreakingUpdate[];
  noFix: NoFix[];
};

export type SafeUpdate = {
  vuln: ScoredVulnerability;
  /** Additional advisories that are also resolved by this fix (deduped). */
  coveredVulns?: ScoredVulnerability[];
  packageName: string;
  currentVersion: string;
  fixVersion: string;
  reason: 'within-parent-range' | 'direct-dependency';
};

export type BreakingUpdate = {
  vuln: ScoredVulnerability;
  /** Additional advisories that are also resolved by this fix (deduped). */
  coveredVulns?: ScoredVulnerability[];
  packageName: string;
  currentVersion: string;
  fixVersion: string;
  reason: string;
};

export type NoFix = {
  vuln: ScoredVulnerability;
  packageName: string;
  currentVersion: string;
};

/**
 * Analyze all scored vulnerabilities and classify fixes as safe, breaking, or no-fix.
 *
 * Deduplication strategy (C-B fix): advisories are grouped by (packageName, fixVersion).
 * When the same package has multiple DIFFERENT fix versions, we select the HIGHEST
 * valid fix version that covers the broadest set of advisories. Rationale: a higher
 * fix version is typically a strict superset of a lower fix version's patches (security
 * fixes are cumulative in most ecosystems). All advisories dominated by the selected
 * fix (i.e. fixVersion <= selected) are bundled into `coveredVulns` so no advisory is
 * silently dropped. Advisories with a fixVersion strictly greater than the selected one
 * remain unresolved and are re-emitted as their own plan entry (so the caller can decide
 * whether to accept the breaking bump).
 */
export function planFixes(
  vulns: ScoredVulnerability[],
  graph: DependencyGraph,
  packageJsonDeps: Record<string, string>,
): FixPlan {
  const safe: SafeUpdate[] = [];
  const breaking: BreakingUpdate[] = [];
  const noFix: NoFix[] = [];

  // Phase 1: bucket vulns by package name
  const byPackage = new Map<string, ScoredVulnerability[]>();
  for (const vuln of vulns) {
    const key = vuln.match.package;
    const bucket = byPackage.get(key);
    if (bucket) {
      bucket.push(vuln);
    } else {
      byPackage.set(key, [vuln]);
    }
  }

  for (const [packageName, packageVulns] of byPackage) {
    // Separate vulns with and without a fix version
    const fixable: ScoredVulnerability[] = [];
    const unfixable: ScoredVulnerability[] = [];
    for (const v of packageVulns) {
      if (v.risk.factors.fixVersion && isValidVersion(v.risk.factors.fixVersion)) {
        fixable.push(v);
      } else {
        unfixable.push(v);
      }
    }

    // Emit unfixable vulns as noFix entries
    for (const v of unfixable) {
      noFix.push({
        vuln: v,
        packageName,
        currentVersion: v.match.installedVersion,
      });
    }

    if (fixable.length === 0) continue;

    // Phase 2: bucket fixable vulns by fixVersion (C-B dedup by compound key)
    const byFixVersion = new Map<string, ScoredVulnerability[]>();
    for (const v of fixable) {
      const fv = v.risk.factors.fixVersion as string;
      const bucket = byFixVersion.get(fv);
      if (bucket) {
        bucket.push(v);
      } else {
        byFixVersion.set(fv, [v]);
      }
    }

    // Phase 3: select the representative fixVersion — the HIGHEST version
    // that covers the most advisories (bundling all lower fixVersions into it).
    const sortedFixVersions = Array.from(byFixVersion.keys()).sort(compareVersions);
    // Highest version last — everything at-or-below this version is covered by upgrading.
    const selectedFixVersion = sortedFixVersions[sortedFixVersions.length - 1];

    const covered: ScoredVulnerability[] = [];
    const uncovered: ScoredVulnerability[] = [];
    for (const fv of sortedFixVersions) {
      const bucket = byFixVersion.get(fv) ?? [];
      if (compareVersions(fv, selectedFixVersion) <= 0) {
        covered.push(...bucket);
      } else {
        uncovered.push(...bucket);
      }
    }

    // Pick the highest-scoring vuln as the "primary" (preserves prior public field shape)
    const primary = covered.reduce((a, b) => (b.risk.score > a.risk.score ? b : a));
    const coveredVulns = covered.filter((v) => v !== primary);

    classifyAndPush(
      packageName,
      selectedFixVersion,
      primary,
      coveredVulns,
      graph,
      packageJsonDeps,
      safe,
      breaking,
    );

    // Any advisory with a strictly higher fixVersion than selectedFixVersion
    // remains unresolved — emit it as its own plan entry so it's not silently dropped.
    if (uncovered.length > 0) {
      const byHigher = new Map<string, ScoredVulnerability[]>();
      for (const v of uncovered) {
        const fv = v.risk.factors.fixVersion as string;
        const bucket = byHigher.get(fv);
        if (bucket) bucket.push(v);
        else byHigher.set(fv, [v]);
      }
      for (const [fv, bucket] of byHigher) {
        const topVuln = bucket.reduce((a, b) => (b.risk.score > a.risk.score ? b : a));
        const extra = bucket.filter((v) => v !== topVuln);
        classifyAndPush(
          packageName,
          fv,
          topVuln,
          extra,
          graph,
          packageJsonDeps,
          safe,
          breaking,
        );
      }
    }
  }

  return { safe, breaking, noFix };
}

function classifyAndPush(
  packageName: string,
  fixVersion: string,
  primary: ScoredVulnerability,
  coveredVulns: ScoredVulnerability[],
  graph: DependencyGraph,
  packageJsonDeps: Record<string, string>,
  safe: SafeUpdate[],
  breaking: BreakingUpdate[],
): void {
  const currentVersion = primary.match.installedVersion;

  // Downgrade guard: if the "fix" is older than what's installed, it's not a fix —
  // flag as breaking so the caller can decide (never silently apply).
  if (
    isValidVersion(currentVersion) &&
    isValidVersion(fixVersion) &&
    compareVersions(fixVersion, currentVersion) < 0
  ) {
    breaking.push({
      vuln: primary,
      coveredVulns,
      packageName,
      currentVersion,
      fixVersion,
      reason: `Advisory fix version ${fixVersion} is older than installed ${currentVersion}. Refusing to downgrade.`,
    });
    logger.debug(`${packageName}: refusing downgrade ${currentVersion} → ${fixVersion}`);
    return;
  }

  const declaredRange = packageJsonDeps[packageName];
  if (declaredRange) {
    if (satisfies(fixVersion, declaredRange)) {
      safe.push({
        vuln: primary,
        coveredVulns,
        packageName,
        currentVersion,
        fixVersion,
        reason: 'direct-dependency',
      });
      logger.debug(`${packageName}: safe update ${currentVersion} → ${fixVersion} (within declared range ${declaredRange})`);
    } else {
      breaking.push({
        vuln: primary,
        coveredVulns,
        packageName,
        currentVersion,
        fixVersion,
        reason: `Fix ${fixVersion} is outside declared range ${declaredRange}. Requires package.json change.`,
      });
      logger.debug(`${packageName}: breaking update — ${fixVersion} outside ${declaredRange}`);
    }
    return;
  }

  // Transitive dependency
  const graphKey = `${packageName}@${currentVersion}`;
  const node = graph.get(graphKey);

  if (!node) {
    safe.push({
      vuln: primary,
      coveredVulns,
      packageName,
      currentVersion,
      fixVersion,
      reason: 'within-parent-range',
    });
    return;
  }

  const currentMajor = currentVersion.split('.')[0];
  const fixMajor = fixVersion.split('.')[0];

  if (currentMajor === fixMajor) {
    safe.push({
      vuln: primary,
      coveredVulns,
      packageName,
      currentVersion,
      fixVersion,
      reason: 'within-parent-range',
    });
    logger.debug(`${packageName}: safe transitive update ${currentVersion} → ${fixVersion} (same major)`);
  } else {
    breaking.push({
      vuln: primary,
      coveredVulns,
      packageName,
      currentVersion,
      fixVersion,
      reason: `Fix ${fixVersion} is a major version bump from ${currentVersion}. May introduce breaking changes.`,
    });
    logger.debug(`${packageName}: breaking transitive update — major version change`);
  }
}
