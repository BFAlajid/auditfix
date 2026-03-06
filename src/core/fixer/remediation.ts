/**
 * Guided remediation engine.
 * Produces a holistic fix plan that groups vulnerabilities by the
 * minimum set of dependency updates needed to resolve them.
 *
 * Strategy: group vulns by fixable package, then rank by impact
 * (number of vulns fixed × severity weight).
 */
import type { ScoredVulnerability } from '../../types/report.js';

export type RemediationStep = {
  packageName: string;
  currentVersion: string;
  fixVersion: string;
  vulnsFixed: string[];        // advisory IDs
  impactScore: number;         // higher = more important to fix
  isBreaking: boolean;
  isDirect: boolean;
};

export type RemediationPlan = {
  steps: RemediationStep[];
  totalVulns: number;
  fixableVulns: number;
  unfixable: string[];         // advisory IDs with no fix
};

const SEVERITY_WEIGHT: Record<string, number> = {
  critical: 10,
  high: 5,
  medium: 2,
  low: 1,
};

/**
 * Generate a guided remediation plan from scored vulnerabilities.
 * Groups by fixable package and ranks by impact.
 */
export function generateRemediationPlan(
  vulns: ScoredVulnerability[],
): RemediationPlan {
  const unfixable: string[] = [];
  const byPackageFix = new Map<string, {
    packageName: string;
    currentVersion: string;
    fixVersion: string;
    vulns: ScoredVulnerability[];
    isDirect: boolean;
  }>();

  for (const vuln of vulns) {
    const fixVersion = vuln.risk.factors.fixVersion;
    if (!fixVersion) {
      unfixable.push(vuln.match.advisory.id);
      continue;
    }

    const key = `${vuln.match.package}→${fixVersion}`;
    const existing = byPackageFix.get(key);

    if (existing) {
      existing.vulns.push(vuln);
    } else {
      byPackageFix.set(key, {
        packageName: vuln.match.package,
        currentVersion: vuln.match.installedVersion,
        fixVersion,
        vulns: [vuln],
        isDirect: vuln.risk.factors.directDependency,
      });
    }
  }

  const steps: RemediationStep[] = [];
  for (const [, group] of byPackageFix) {
    const impactScore = group.vulns.reduce((acc, v) => {
      return acc + (SEVERITY_WEIGHT[v.risk.label] ?? 1);
    }, 0);

    const currentMajor = group.currentVersion.split('.')[0];
    const fixMajor = group.fixVersion.split('.')[0];

    steps.push({
      packageName: group.packageName,
      currentVersion: group.currentVersion,
      fixVersion: group.fixVersion,
      vulnsFixed: group.vulns.map((v) => v.match.advisory.id),
      impactScore,
      isBreaking: currentMajor !== fixMajor,
      isDirect: group.isDirect,
    });
  }

  // Sort by impact (highest first), then direct deps first
  steps.sort((a, b) => {
    if (b.impactScore !== a.impactScore) return b.impactScore - a.impactScore;
    if (a.isDirect !== b.isDirect) return a.isDirect ? -1 : 1;
    return 0;
  });

  return {
    steps,
    totalVulns: vulns.length,
    fixableVulns: vulns.length - unfixable.length,
    unfixable,
  };
}
