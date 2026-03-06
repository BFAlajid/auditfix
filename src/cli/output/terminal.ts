/**
 * Terminal output renderer.
 * Pretty, actionable CLI output with confidence metadata.
 */
import chalk from 'chalk';
import type { AuditReport, ScoredVulnerability, RiskScore } from '../../types/report.js';

const SEVERITY_COLORS: Record<RiskScore['label'], (s: string) => string> = {
  critical: chalk.bgRed.white.bold,
  high: chalk.red.bold,
  medium: chalk.yellow,
  low: chalk.dim,
  info: chalk.gray,
};

const SEVERITY_ORDER: RiskScore['label'][] = ['critical', 'high', 'medium', 'low', 'info'];

export function renderTerminalReport(report: AuditReport, version: string): string {
  const lines: string[] = [];

  lines.push(chalk.bold(`auditfix v${version}`) + ` — scanned ${report.metadata.totalPackages} packages\n`);

  // Group by severity
  const grouped = groupBySeverity(report.vulnerabilities);

  for (const severity of SEVERITY_ORDER) {
    const vulns = grouped.get(severity) ?? [];
    const header = `${severity.toUpperCase()} (${vulns.length})`;
    lines.push(SEVERITY_COLORS[severity](header));

    if (vulns.length === 0) {
      lines.push('');
      continue;
    }

    for (const vuln of vulns) {
      lines.push(renderVulnerability(vuln));
    }
    lines.push('');
  }

  // Ignored section
  if (report.ignored.length > 0) {
    lines.push(chalk.gray(`IGNORED (via allow-list) (${report.ignored.length})`));
    const names = report.ignored.map((i) => `${i.match.package}@${i.match.installedVersion}`);
    lines.push(chalk.gray(`  ${names.join(', ')}`));
    lines.push('');
  }

  // Metadata footer
  lines.push(renderMetadata(report));

  // Summary line
  const summary = buildSummary(grouped, report.ignored.length);
  lines.push(summary);

  // Exit code hint
  const hasProdVulns = report.vulnerabilities.some(
    (v) => v.match.isProduction && (v.risk.label === 'critical' || v.risk.label === 'high')
  );
  const exitCode = report.metadata.confidence === 'UNRELIABLE' ? 2 : hasProdVulns ? 1 : 0;
  lines.push(chalk.dim(`CI exit code: ${exitCode}${exitCode === 1 ? ' (production vulnerabilities found)' : exitCode === 2 ? ' (unreliable scan)' : ''}`));

  return lines.join('\n');
}

function renderVulnerability(vuln: ScoredVulnerability): string {
  const { match, risk } = vuln;
  const lines: string[] = [];

  lines.push(`  ${chalk.bold(`${match.package}@${match.installedVersion}`)} — ${match.advisory.summary || match.advisory.id}`);

  const pathStr = match.dependencyPath.length > 0
    ? match.dependencyPath.join(' > ')
    : match.package;
  lines.push(`  Path: ${pathStr}`);

  const prodLabel = match.isProduction
    ? chalk.red('YES')
    : chalk.green('NO (dev only)');
  const exploitLabel = risk.factors.exploitAvailable
    ? chalk.red('YES')
    : chalk.dim('NO');
  const fixLabel = risk.factors.fixVersion
    ? chalk.green(risk.factors.fixVersion)
    : chalk.yellow('none');

  lines.push(`  Production: ${prodLabel} | Exploit: ${exploitLabel} | Fix: ${fixLabel}`);

  if (risk.factors.fixVersion && match.isProduction) {
    lines.push(chalk.cyan(`  → Run \`auditfix --fix\` to auto-patch`));
  } else if (!match.isProduction) {
    lines.push(chalk.dim(`  → Low risk. Dev tooling only.`));
  }

  return lines.join('\n');
}

function renderMetadata(report: AuditReport): string {
  const { metadata } = report;
  const lines: string[] = [];

  const skippedInfo = metadata.skippedPackages > 0
    ? ` | Skipped: ${metadata.skippedPackages}`
    : '';
  lines.push(chalk.dim(`Scanned: ${metadata.totalPackages} packages${skippedInfo}`));
  lines.push(chalk.dim(`Advisory source: ${metadata.advisorySource} | Matched against: ${metadata.advisoryCount} advisories`));

  const confidenceColor = metadata.confidence === 'HIGH' ? chalk.green
    : metadata.confidence === 'MEDIUM' ? chalk.yellow
    : metadata.confidence === 'LOW' ? chalk.red
    : chalk.bgRed.white;
  lines.push(`Confidence: ${confidenceColor(metadata.confidence)}`);
  lines.push('');

  return lines.join('\n');
}

function buildSummary(
  grouped: Map<RiskScore['label'], ScoredVulnerability[]>,
  ignoredCount: number,
): string {
  const parts: string[] = [];
  for (const severity of SEVERITY_ORDER) {
    const count = grouped.get(severity)?.length ?? 0;
    if (count > 0) {
      const prodCount = grouped.get(severity)!.filter((v) => v.match.isProduction).length;
      const detail = prodCount > 0 ? ` (${prodCount} production)` : ' (dev-only)';
      parts.push(`${count} ${severity}${detail}`);
    }
  }
  if (ignoredCount > 0) {
    parts.push(`${ignoredCount} ignored`);
  }

  return chalk.bold(`Summary: ${parts.length > 0 ? parts.join(' | ') : 'no vulnerabilities found'}`);
}

function groupBySeverity(vulns: ScoredVulnerability[]): Map<RiskScore['label'], ScoredVulnerability[]> {
  const grouped = new Map<RiskScore['label'], ScoredVulnerability[]>();
  for (const severity of SEVERITY_ORDER) {
    grouped.set(severity, []);
  }
  for (const vuln of vulns) {
    grouped.get(vuln.risk.label)!.push(vuln);
  }
  return grouped;
}

/**
 * Determine the CLI exit code based on report results.
 */
export function getExitCode(report: AuditReport): number {
  if (report.metadata.confidence === 'UNRELIABLE') return 2;

  const hasProdVulns = report.vulnerabilities.some(
    (v) => v.match.isProduction && (v.risk.label === 'critical' || v.risk.label === 'high')
  );

  return hasProdVulns ? 1 : 0;
}
