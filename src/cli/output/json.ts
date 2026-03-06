/**
 * JSON output for scripting and CI pipelines.
 */
import type { AuditReport } from '../../types/report.js';

export function renderJsonReport(report: AuditReport): string {
  const output = {
    vulnerabilities: report.vulnerabilities.map((v) => ({
      id: v.match.advisory.id,
      package: v.match.package,
      installedVersion: v.match.installedVersion,
      severity: v.risk.label,
      score: v.risk.score,
      summary: v.match.advisory.summary,
      production: v.match.isProduction,
      fixVersion: v.risk.factors.fixVersion,
      dependencyPath: v.match.dependencyPath,
      cvss: {
        score: v.risk.factors.cvssScore,
        vector: v.risk.factors.cvssVector,
      },
    })),
    ignored: report.ignored.map((i) => ({
      id: i.match.advisory.id,
      package: i.match.package,
      reason: i.reason,
      source: i.source,
    })),
    metadata: report.metadata,
  };

  return JSON.stringify(output, null, 2);
}
