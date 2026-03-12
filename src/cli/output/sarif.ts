/**
 * SARIF v2.1.0 output for GitHub Code Scanning integration.
 * Generates conformant JSON without external library dependencies.
 */
import type { AuditReport, ScoredVulnerability } from '../../types/report.js';

const SARIF_SCHEMA = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json';
const SARIF_VERSION = '2.1.0';

/**
 * Map a severity label to a SARIF level.
 * critical/high -> error, medium -> warning, low/info -> note.
 */
function toSarifLevel(label: string): 'error' | 'warning' | 'note' {
  switch (label) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
    case 'info':
      return 'note';
    default:
      return 'note';
  }
}

/**
 * Format a CVSS score as a float string (e.g. "7.5").
 * Clamps to 0.0-10.0 range and always includes one decimal place.
 */
function formatSecuritySeverity(cvssScore: number): string {
  const clamped = Math.max(0, Math.min(10, cvssScore));
  return clamped.toFixed(1);
}

/**
 * Build a human-readable message for a vulnerability finding.
 */
function buildMessage(vuln: ScoredVulnerability): string {
  const advisory = vuln.match.advisory;
  const pkg = vuln.match.package;
  const version = vuln.match.installedVersion;
  const summary = advisory.summary || 'No description available';
  const fix = vuln.risk.factors.fixVersion;
  const fixNote = fix ? ` Fix available in ${fix}.` : ' No fix available.';
  return `${pkg}@${version} is vulnerable: ${summary}.${fixNote}`;
}

/**
 * Determine the lockfile URI for artifact location from report metadata.
 */
function getLockfileUri(report: AuditReport): string {
  const type = report.metadata?.lockfileType;
  if (type?.startsWith('pnpm')) return 'pnpm-lock.yaml';
  if (type?.startsWith('yarn')) return 'yarn.lock';
  return 'package-lock.json';
}

type SarifRule = {
  id: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  helpUri?: string;
  properties: {
    'security-severity': string;
  };
};

type SarifResult = {
  ruleId: string;
  ruleIndex: number;
  level: 'error' | 'warning' | 'note';
  message: { text: string };
  locations: {
    physicalLocation: {
      artifactLocation: {
        uri: string;
      };
    };
  }[];
};

/**
 * Render an AuditReport as a SARIF v2.1.0 JSON string.
 *
 * @param report - The audit report to render.
 * @param version - The tool version string (e.g. "0.1.0").
 * @returns A JSON string conforming to SARIF v2.1.0.
 */
export function renderSarifReport(report: AuditReport, version: string): string {
  if (!report) {
    throw new Error('report is required');
  }
  if (!version || typeof version !== 'string') {
    throw new Error('version is required and must be a non-empty string');
  }

  // Deduplicate rules by advisory ID
  const ruleMap = new Map<string, SarifRule>();
  const ruleIndexMap = new Map<string, number>();

  for (const vuln of report.vulnerabilities) {
    const advisoryId = vuln.match.advisory.id;
    if (!ruleMap.has(advisoryId)) {
      const advisory = vuln.match.advisory;
      const helpUrl = advisory.references.find((r) => r.type === 'WEB' || r.type === 'ADVISORY')?.url;
      const rule: SarifRule = {
        id: advisoryId,
        shortDescription: { text: advisory.summary || advisoryId },
        fullDescription: {
          text: advisory.details || advisory.summary || advisoryId,
        },
        properties: {
          'security-severity': formatSecuritySeverity(vuln.risk.factors.cvssScore),
        },
      };
      if (helpUrl) {
        rule.helpUri = helpUrl;
      }
      ruleIndexMap.set(advisoryId, ruleMap.size);
      ruleMap.set(advisoryId, rule);
    }
  }

  const rules: SarifRule[] = Array.from(ruleMap.values());
  const lockfileUri = getLockfileUri(report);

  // Build results
  const results: SarifResult[] = report.vulnerabilities.map((vuln) => {
    const advisoryId = vuln.match.advisory.id;
    const ruleIndex = ruleIndexMap.get(advisoryId)!;
    return {
      ruleId: advisoryId,
      ruleIndex,
      level: toSarifLevel(vuln.risk.label),
      message: { text: buildMessage(vuln) },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: lockfileUri,
            },
          },
        },
      ],
    };
  });

  const sarif = {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: 'auditfix',
            version,
            rules,
          },
        },
        results,
      },
    ],
  };

  return JSON.stringify(sarif, null, 2);
}

/**
 * Render a SARIF report containing only NEW vulnerabilities not in the baseline.
 * Matches by advisory ID + package + version.
 */
export function renderSarifDiffReport(
  current: AuditReport,
  baseline: AuditReport,
  version: string,
): string {
  const baselineKeys = new Set(
    baseline.vulnerabilities.map(
      (v) => `${v.match.advisory.id}:${v.match.package}@${v.match.installedVersion}`,
    ),
  );

  const filtered: AuditReport = {
    ...current,
    vulnerabilities: current.vulnerabilities.filter((v) => {
      const key = `${v.match.advisory.id}:${v.match.package}@${v.match.installedVersion}`;
      return !baselineKeys.has(key);
    }),
  };

  return renderSarifReport(filtered, version);
}
