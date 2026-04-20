/**
 * Exit code resolution for the CLI.
 *
 * Centralizes how an AuditReport and optional CLI flags (--fail-on, policy)
 * map to a single process exit code.
 *
 * Contract:
 *   0 — scan succeeded, nothing to report for the active strategy
 *   1 — scan succeeded but policy/fail-on gates produced a failure
 *   2 — scan was unreliable (tool error) — takes precedence over 1
 */
import type { AuditReport } from '../types/report.js';

export type FailOnStrategy = 'production-critical' | 'production-high' | 'any';

/**
 * Default exit code based only on the report.
 * Equivalent to the legacy `production-high` strategy.
 */
export function getExitCode(report: AuditReport): number {
  if (report.metadata.confidence === 'UNRELIABLE') return 2;

  const hasProdVulns = report.vulnerabilities.some(
    (v) => v.match.isProduction && (v.risk.label === 'critical' || v.risk.label === 'high'),
  );

  return hasProdVulns ? 1 : 0;
}

/**
 * Configurable exit code strategy for CI.
 * - production-critical: exit 1 only for production critical vulns
 * - production-high: exit 1 for production critical or high vulns (default)
 * - any: exit 1 for any vulnerability regardless of severity
 */
export function getExitCodeForStrategy(
  report: AuditReport,
  strategy: string,
): number {
  if (report.metadata.confidence === 'UNRELIABLE') return 2;

  switch (strategy) {
    case 'production-critical':
      return report.vulnerabilities.some(
        (v) => v.match.isProduction && v.risk.label === 'critical',
      ) ? 1 : 0;

    case 'any':
      return report.vulnerabilities.length > 0 ? 1 : 0;

    case 'production-high':
    default:
      return getExitCode(report);
  }
}

/**
 * Combine the exit code produced by the report/strategy with an optional
 * policy-failure signal into one final exit code.
 *
 * Behavior change vs. prior code: policy failures no longer short-circuit
 * with a bare `process.exit(1)`. They are merged with the --fail-on path
 * so a single exit code captures both signals.
 *
 * Precedence:
 *   - 2 (unreliable) always wins — reporting safe/unsafe is meaningless
 *   - otherwise, 1 wins if either policy failed or the strategy says so
 *   - otherwise, 0
 */
export function resolveFinalExitCode(params: {
  report: AuditReport;
  failOnStrategy?: string;
  policyFailed?: boolean;
}): number {
  const strategyCode = params.failOnStrategy
    ? getExitCodeForStrategy(params.report, params.failOnStrategy)
    : getExitCode(params.report);

  if (strategyCode === 2) return 2;
  if (params.policyFailed) return 1;
  return strategyCode;
}
