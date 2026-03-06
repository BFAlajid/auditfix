/**
 * VEX (Vulnerability Exploitability eXchange) generation.
 * Generates OpenVEX-compatible statements from auditfix scan results.
 * Embeds reachability analysis conclusions as VEX justifications.
 */
import type { AuditReport, ScoredVulnerability } from '../../types/report.js';
import { randomUUID } from 'node:crypto';

type VexStatement = {
  vulnerability: { '@id': string; name: string; description: string };
  products: Array<{ '@id': string }>;
  status: 'not_affected' | 'affected' | 'fixed' | 'under_investigation';
  justification?: string;
  impact_statement?: string;
};

type VexDocument = {
  '@context': string;
  '@id': string;
  author: string;
  role: string;
  timestamp: string;
  version: number;
  tooling: string;
  statements: VexStatement[];
};

/**
 * Generate an OpenVEX document from an audit report.
 * Uses reachability data to classify vulnerabilities.
 */
export function generateVex(
  report: AuditReport,
  toolVersion: string,
  projectName?: string,
): string {
  const statements: VexStatement[] = [];
  const product = projectName ?? 'unknown-product';

  // Active vulnerabilities → "affected"
  for (const vuln of report.vulnerabilities) {
    statements.push(vulnToStatement(vuln, product));
  }

  // Ignored vulnerabilities → "not_affected" with justification
  for (const ignored of report.ignored) {
    statements.push({
      vulnerability: {
        '@id': ignored.match.advisory.id,
        name: ignored.match.advisory.id,
        description: ignored.match.advisory.summary,
      },
      products: [{ '@id': `pkg:npm/${encodeURIComponent(product)}` }],
      status: 'not_affected',
      justification: 'vulnerable_code_not_in_execute_path',
      impact_statement: `Suppressed via ${ignored.source}: ${ignored.reason}`,
    });
  }

  const doc: VexDocument = {
    '@context': 'https://openvex.dev/ns/v0.2.0',
    '@id': `urn:uuid:${randomUUID()}`,
    author: 'auditfix',
    role: 'tool',
    timestamp: new Date().toISOString(),
    version: 1,
    tooling: `auditfix/${toolVersion}`,
    statements,
  };

  return JSON.stringify(doc, null, 2);
}

function vulnToStatement(vuln: ScoredVulnerability, product: string): VexStatement {
  const { match, risk } = vuln;

  // Determine VEX status based on reachability analysis
  if (!match.isProduction) {
    return {
      vulnerability: {
        '@id': match.advisory.id,
        name: match.advisory.id,
        description: match.advisory.summary,
      },
      products: [{ '@id': `pkg:npm/${encodeURIComponent(product)}` }],
      status: 'not_affected',
      justification: 'vulnerable_code_not_in_execute_path',
      impact_statement: `Package ${match.package}@${match.installedVersion} is a dev-only dependency, not deployed to production.`,
    };
  }

  if (match.isDirectlyImported === false) {
    return {
      vulnerability: {
        '@id': match.advisory.id,
        name: match.advisory.id,
        description: match.advisory.summary,
      },
      products: [{ '@id': `pkg:npm/${encodeURIComponent(product)}` }],
      status: 'under_investigation',
      impact_statement: `Package ${match.package}@${match.installedVersion} is a production dependency but not directly imported by application code. Risk score: ${risk.score}/100.`,
    };
  }

  // Production + directly imported → affected
  return {
    vulnerability: {
      '@id': match.advisory.id,
      name: match.advisory.id,
      description: match.advisory.summary,
    },
    products: [{ '@id': `pkg:npm/${encodeURIComponent(product)}` }],
    status: risk.factors.fixVersion ? 'affected' : 'affected',
    impact_statement: `Package ${match.package}@${match.installedVersion} is imported in production code. ${risk.factors.fixVersion ? `Fix available: ${risk.factors.fixVersion}` : 'No fix available.'}. Risk score: ${risk.score}/100.`,
  };
}
