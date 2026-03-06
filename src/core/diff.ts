/**
 * Scan diff — compare two auditfix JSON reports.
 * Shows new, fixed, and changed vulnerabilities between scans.
 */

export type DiffVuln = {
  id: string;
  package: string;
  version: string;
  severity: string;
  score: number;
};

export type ScanDiff = {
  added: DiffVuln[];     // new vulnerabilities (not in baseline)
  removed: DiffVuln[];   // fixed vulnerabilities (in baseline but not current)
  unchanged: DiffVuln[]; // still present
  summary: {
    addedCount: number;
    removedCount: number;
    unchangedCount: number;
    improved: boolean;    // true if addedCount === 0 and removedCount > 0
  };
};

type JsonReport = {
  vulnerabilities: Array<{
    id: string;
    package: string;
    installedVersion: string;
    severity: string;
    score: number;
  }>;
};

/**
 * Compare two auditfix JSON reports and produce a diff.
 */
export function diffReports(baseline: JsonReport, current: JsonReport): ScanDiff {
  const baselineSet = new Map<string, DiffVuln>();
  for (const v of baseline.vulnerabilities) {
    const key = `${v.id}:${v.package}@${v.installedVersion}`;
    baselineSet.set(key, {
      id: v.id,
      package: v.package,
      version: v.installedVersion,
      severity: v.severity,
      score: v.score,
    });
  }

  const currentSet = new Map<string, DiffVuln>();
  for (const v of current.vulnerabilities) {
    const key = `${v.id}:${v.package}@${v.installedVersion}`;
    currentSet.set(key, {
      id: v.id,
      package: v.package,
      version: v.installedVersion,
      severity: v.severity,
      score: v.score,
    });
  }

  const added: DiffVuln[] = [];
  const removed: DiffVuln[] = [];
  const unchanged: DiffVuln[] = [];

  // Find added and unchanged
  for (const [key, vuln] of currentSet) {
    if (baselineSet.has(key)) {
      unchanged.push(vuln);
    } else {
      added.push(vuln);
    }
  }

  // Find removed
  for (const [key, vuln] of baselineSet) {
    if (!currentSet.has(key)) {
      removed.push(vuln);
    }
  }

  return {
    added,
    removed,
    unchanged,
    summary: {
      addedCount: added.length,
      removedCount: removed.length,
      unchangedCount: unchanged.length,
      improved: added.length === 0 && removed.length > 0,
    },
  };
}
