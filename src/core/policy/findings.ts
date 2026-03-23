/**
 * Findings aggregator — converts AuditReport to PolicyFinding[] for evaluation.
 */
import type { AuditReport } from '../../types/report.js';
import type { PolicyFinding, SeverityLevel } from './types.js';

/**
 * Convert an AuditReport's vulnerabilities into the flat PolicyFinding structure
 * that the policy evaluator can query.
 */
export function aggregateFindings(report: AuditReport): PolicyFinding[] {
  const findings: PolicyFinding[] = [];

  for (const vuln of report.vulnerabilities) {
    findings.push({
      id: vuln.match.advisory.id,
      severity: vuln.risk.label as SeverityLevel,
      epss: vuln.risk.factors.epssScore ?? undefined,
      kev: vuln.risk.factors.inKev,
      fixAvailable: vuln.risk.factors.fixAvailable,
      package: vuln.match.package,
      version: vuln.match.installedVersion,
      scope: vuln.match.isProduction ? 'production' : 'dev',
      depth: vuln.match.dependencyPath.length,
      directDep: vuln.risk.factors.directDependency,
      findingType: 'vulnerability',
    });
  }

  return findings;
}
