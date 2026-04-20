/**
 * VEX (Vulnerability Exploitability eXchange) generation.
 * Generates OpenVEX-compatible statements from auditfix scan results.
 * Embeds reachability analysis conclusions as VEX justifications.
 *
 * Also exports `embedVexInCycloneDX` for building CycloneDX 1.5 SBOMs with
 * an inline `vulnerabilities` array (VEX-in-BOM profile).
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

/* -------------------------------------------------------------------------- */
/* CycloneDX 1.5 VEX embedding                                                */
/* -------------------------------------------------------------------------- */

type CdxVexAnalysisState =
  | 'resolved'
  | 'resolved_with_pedigree'
  | 'exploitable'
  | 'in_triage'
  | 'false_positive'
  | 'not_affected';

type CdxVexAnalysisJustification =
  | 'code_not_present'
  | 'code_not_reachable'
  | 'requires_configuration'
  | 'requires_dependency'
  | 'requires_environment'
  | 'protected_by_compiler'
  | 'protected_at_runtime'
  | 'protected_at_perimeter'
  | 'protected_by_mitigating_control';

type CdxVulnerability = {
  'bom-ref'?: string;
  id: string;
  source?: { name: string; url?: string };
  references?: { id: string; source: { name: string } }[];
  ratings?: { source?: { name: string }; score?: number; severity?: string; method?: string; vector?: string }[];
  description?: string;
  published?: string;
  updated?: string;
  affects: { ref: string }[];
  analysis?: {
    state?: CdxVexAnalysisState;
    justification?: CdxVexAnalysisJustification;
    detail?: string;
  };
};

type CycloneDXSbom = {
  bomFormat: string;
  specVersion: string;
  components?: { name: string; version: string; purl?: string }[];
  vulnerabilities?: CdxVulnerability[];
  [key: string]: unknown;
};

/**
 * Embed VEX information into a CycloneDX 1.5 SBOM under a `vulnerabilities`
 * array. Returns a new object — does not mutate the input SBOM.
 *
 * The embedded `vulnerabilities` follow the CycloneDX 1.5 VEX schema:
 *   - `id` is the advisory id (GHSA / CVE)
 *   - `affects` references component `purl`s present in the SBOM
 *   - `analysis.state` / `justification` are derived from reachability data
 *     using the same rules as the OpenVEX generator.
 */
export function embedVexInCycloneDX(sbom: object, report: AuditReport): object {
  // Deep-clone so we never mutate the caller's SBOM.
  const cloned = structuredClone(sbom) as CycloneDXSbom;

  const vulnerabilities: CdxVulnerability[] = Array.isArray(cloned.vulnerabilities)
    ? [...cloned.vulnerabilities]
    : [];

  for (const vuln of report.vulnerabilities) {
    vulnerabilities.push(buildCdxVulnerability(vuln));
  }
  for (const ignored of report.ignored) {
    const purl = matchToPurl(ignored.match.package, ignored.match.installedVersion);
    vulnerabilities.push({
      id: ignored.match.advisory.id,
      source: { name: 'OSV' },
      description: ignored.match.advisory.summary,
      affects: [{ ref: purl }],
      analysis: {
        state: 'not_affected',
        justification: 'code_not_reachable',
        detail: `Suppressed via ${ignored.source}: ${ignored.reason}`,
      },
    });
  }

  cloned.vulnerabilities = vulnerabilities;
  return cloned;
}

function buildCdxVulnerability(vuln: ScoredVulnerability): CdxVulnerability {
  const { match, risk } = vuln;
  const purl = matchToPurl(match.package, match.installedVersion);
  const cvssV3 = match.advisory.severity.find((s) => s.type === 'CVSS_V3');

  const cdx: CdxVulnerability = {
    id: match.advisory.id,
    source: { name: 'OSV' },
    description: match.advisory.summary,
    affects: [{ ref: purl }],
  };

  if (match.advisory.publishedAt) cdx.published = match.advisory.publishedAt;
  if (match.advisory.modifiedAt) cdx.updated = match.advisory.modifiedAt;

  if (cvssV3) {
    cdx.ratings = [
      {
        source: { name: 'OSV' },
        score: risk.factors.cvssScore,
        severity: mapSeverityLabel(risk.label),
        method: 'CVSSv31',
        vector: cvssV3.score,
      },
    ];
  }

  if (!match.isProduction) {
    cdx.analysis = {
      state: 'not_affected',
      justification: 'code_not_reachable',
      detail: `Package ${match.package}@${match.installedVersion} is a dev-only dependency, not deployed to production.`,
    };
  } else if (match.isDirectlyImported === false) {
    cdx.analysis = {
      state: 'in_triage',
      detail: `Package ${match.package}@${match.installedVersion} is a production dependency but not directly imported by application code. Risk score: ${risk.score}/100.`,
    };
  } else {
    cdx.analysis = {
      state: 'exploitable',
      detail: `Package ${match.package}@${match.installedVersion} is imported in production code.${
        risk.factors.fixVersion ? ` Fix available: ${risk.factors.fixVersion}.` : ' No fix available.'
      } Risk score: ${risk.score}/100.`,
    };
  }

  return cdx;
}

function matchToPurl(pkg: string, version: string): string {
  const encoded = pkg.startsWith('@') ? '%40' + pkg.slice(1) : pkg;
  return `pkg:npm/${encoded}@${version}`;
}

function mapSeverityLabel(label: 'critical' | 'high' | 'medium' | 'low' | 'info'): string {
  switch (label) {
    case 'critical':
      return 'critical';
    case 'high':
      return 'high';
    case 'medium':
      return 'medium';
    case 'low':
      return 'low';
    default:
      return 'info';
  }
}
