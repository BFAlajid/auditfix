/**
 * Safe update detection.
 * Determines which vulnerable packages can be patched without breaking changes.
 *
 * A "safe update" means the fix version satisfies the parent's declared semver range,
 * so the lockfile can be updated without modifying any package.json.
 */
import type { ScoredVulnerability } from '../../types/report.js';
import type { DependencyGraph } from '../../types/package.js';
import { satisfies } from '../../utils/semver.js';
import semver from 'semver';
import * as logger from '../../utils/logger.js';

export type FixPlan = {
  safe: SafeUpdate[];
  breaking: BreakingUpdate[];
  noFix: NoFix[];
};

export type SafeUpdate = {
  vuln: ScoredVulnerability;
  packageName: string;
  currentVersion: string;
  fixVersion: string;
  reason: 'within-parent-range' | 'direct-dependency';
};

export type BreakingUpdate = {
  vuln: ScoredVulnerability;
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
 */
export function planFixes(
  vulns: ScoredVulnerability[],
  graph: DependencyGraph,
  packageJsonDeps: Record<string, string>,
): FixPlan {
  const safe: SafeUpdate[] = [];
  const breaking: BreakingUpdate[] = [];
  const noFix: NoFix[] = [];

  // Deduplicate by package name — only fix each package once (use highest-severity vuln)
  const byPackage = new Map<string, ScoredVulnerability>();
  for (const vuln of vulns) {
    const key = vuln.match.package;
    const existing = byPackage.get(key);
    if (!existing || vuln.risk.score > existing.risk.score) {
      byPackage.set(key, vuln);
    }
  }

  for (const [packageName, vuln] of byPackage) {
    const fixVersion = vuln.risk.factors.fixVersion;

    if (!fixVersion) {
      noFix.push({
        vuln,
        packageName,
        currentVersion: vuln.match.installedVersion,
      });
      continue;
    }

    // Check if this is a direct dependency
    const declaredRange = packageJsonDeps[packageName];
    if (declaredRange) {
      // Direct dependency — check if fix is within declared range
      if (satisfies(fixVersion, declaredRange)) {
        safe.push({
          vuln,
          packageName,
          currentVersion: vuln.match.installedVersion,
          fixVersion,
          reason: 'direct-dependency',
        });
        logger.debug(`${packageName}: safe update ${vuln.match.installedVersion} → ${fixVersion} (within declared range ${declaredRange})`);
      } else {
        breaking.push({
          vuln,
          packageName,
          currentVersion: vuln.match.installedVersion,
          fixVersion,
          reason: `Fix ${fixVersion} is outside declared range ${declaredRange}. Requires package.json change.`,
        });
        logger.debug(`${packageName}: breaking update — ${fixVersion} outside ${declaredRange}`);
      }
      continue;
    }

    // Transitive dependency — check if any parent's range allows the fix
    const graphKey = `${packageName}@${vuln.match.installedVersion}`;
    const node = graph.get(graphKey);

    if (!node) {
      // Can't find in graph — treat as safe via override
      safe.push({
        vuln,
        packageName,
        currentVersion: vuln.match.installedVersion,
        fixVersion,
        reason: 'within-parent-range',
      });
      continue;
    }

    // For transitive deps, we use npm overrides to force the version.
    // This is safe for patch/minor bumps within the same major.
    const currentParsed = semver.major(vuln.match.installedVersion);
    const fixParsed = semver.major(fixVersion);
    const currentMajor = currentParsed !== undefined ? String(currentParsed) : vuln.match.installedVersion.split('.')[0];
    const fixMajor = fixParsed !== undefined ? String(fixParsed) : fixVersion.split('.')[0];

    if (currentMajor === fixMajor) {
      safe.push({
        vuln,
        packageName,
        currentVersion: vuln.match.installedVersion,
        fixVersion,
        reason: 'within-parent-range',
      });
      logger.debug(`${packageName}: safe transitive update ${vuln.match.installedVersion} → ${fixVersion} (same major)`);
    } else {
      breaking.push({
        vuln,
        packageName,
        currentVersion: vuln.match.installedVersion,
        fixVersion,
        reason: `Fix ${fixVersion} is a major version bump from ${vuln.match.installedVersion}. May introduce breaking changes.`,
      });
      logger.debug(`${packageName}: breaking transitive update — major version change`);
    }
  }

  return { safe, breaking, noFix };
}
