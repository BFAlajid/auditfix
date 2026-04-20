/**
 * CSAF 2.0 VEX profile generation.
 *
 * Produces a Common Security Advisory Framework (CSAF) 2.0 document conforming
 * to the VEX profile (urn:oasis:names:tc:csaf:1.0:profile:vex:1.0.0).
 * Unlike OpenVEX, CSAF is OASIS-standardised and accepted by many enterprise
 * vulnerability-disclosure pipelines.
 *
 * Structural only — we do not validate against the CSAF JSON Schema at runtime
 * to avoid pulling in a schema-validator dependency.
 */
import type { AuditReport, ScoredVulnerability, IgnoredVulnerability } from '../../types/report.js';
import type { Advisory } from '../../types/advisory.js';
import { randomUUID } from 'node:crypto';

const CSAF_VERSION = '2.0';
const VEX_CATEGORY = 'csaf_vex';
const VEX_PROFILE = 'urn:oasis:names:tc:csaf:1.0:profile:vex:1.0.0';

type CsafTlpLabel = 'AMBER' | 'GREEN' | 'RED' | 'WHITE';

type CsafRevision = {
  number: string;
  date: string;
  summary: string;
};

type CsafDocument = {
  category: typeof VEX_CATEGORY;
  csaf_version: typeof CSAF_VERSION;
  title: string;
  publisher: {
    category: 'vendor' | 'discoverer' | 'coordinator' | 'user' | 'other' | 'translator';
    name: string;
    namespace: string;
  };
  tracking: {
    id: string;
    initial_release_date: string;
    current_release_date: string;
    status: 'draft' | 'final' | 'interim';
    version: string;
    revision_history: CsafRevision[];
    generator?: {
      engine: { name: string; version: string };
    };
  };
  distribution: {
    tlp: { label: CsafTlpLabel };
  };
  profile?: string;
};

type CsafProductBranch = {
  category: 'product_version';
  name: string;
  product: { product_id: string; name: string };
};

type CsafVendorBranch = {
  category: 'vendor';
  name: string;
  branches: CsafProductBranch[];
};

type CsafProductTree = {
  branches: CsafVendorBranch[];
};

type CsafVulnerabilityId = {
  system_name: string;
  text: string;
};

type CsafScore = {
  cvss_v3: { version: '3.1' | '3.0'; vectorString: string; baseScore: number; baseSeverity: string };
  products: string[];
};

type CsafThreat = {
  category: 'exploit_status' | 'impact' | 'target_set';
  details: string;
};

type CsafVulnerability = {
  cve: string;
  ids: CsafVulnerabilityId[];
  title: string;
  product_status: {
    known_affected?: string[];
    known_not_affected?: string[];
  };
  threats?: CsafThreat[];
  scores?: CsafScore[];
  notes?: { category: string; text: string; title?: string }[];
  flags?: { label: string; product_ids: string[] }[];
};

type CsafVexDocument = {
  document: CsafDocument;
  product_tree: CsafProductTree;
  vulnerabilities: CsafVulnerability[];
};

/**
 * Generate a CSAF 2.0 VEX document from an audit report.
 */
export function generateCSAFVEX(
  report: AuditReport,
  projectName: string,
  toolVersion: string,
): string {
  const now = new Date().toISOString();
  const trackingId = `auditfix-${randomUUID()}`;

  // Build product_tree: one vendor branch (npm), with a product_version per
  // unique package@version appearing in the report.
  const productIds = new Map<string, string>(); // "pkg@ver" -> product_id
  const productBranches: CsafProductBranch[] = [];

  const registerProduct = (pkg: string, version: string): string => {
    const key = `${pkg}@${version}`;
    const existing = productIds.get(key);
    if (existing) return existing;
    const productId = sanitizeProductId(`CSAFPID-${pkg}-${version}`);
    productIds.set(key, productId);
    productBranches.push({
      category: 'product_version',
      name: key,
      product: { product_id: productId, name: key },
    });
    return productId;
  };

  for (const v of report.vulnerabilities) {
    registerProduct(v.match.package, v.match.installedVersion);
  }
  for (const i of report.ignored) {
    registerProduct(i.match.package, i.match.installedVersion);
  }

  const productTree: CsafProductTree = {
    branches: [
      {
        category: 'vendor',
        name: 'npm',
        branches: productBranches,
      },
    ],
  };

  // Build vulnerabilities.
  const vulnerabilities: CsafVulnerability[] = [];

  for (const v of report.vulnerabilities) {
    vulnerabilities.push(buildVulnerability(v, productIds));
  }
  for (const i of report.ignored) {
    vulnerabilities.push(buildIgnoredVulnerability(i, productIds));
  }

  const document: CsafDocument = {
    category: VEX_CATEGORY,
    csaf_version: CSAF_VERSION,
    title: `VEX for ${projectName}`,
    publisher: {
      category: 'vendor',
      name: 'auditfix user',
      namespace: 'https://auditfix.dev',
    },
    tracking: {
      id: trackingId,
      initial_release_date: now,
      current_release_date: now,
      status: 'final',
      version: '1',
      revision_history: [{ number: '1', date: now, summary: 'Initial' }],
      generator: {
        engine: { name: 'auditfix', version: toolVersion },
      },
    },
    distribution: { tlp: { label: 'WHITE' } },
    profile: VEX_PROFILE,
  };

  const doc: CsafVexDocument = {
    document,
    product_tree: productTree,
    vulnerabilities,
  };

  return JSON.stringify(doc, null, 2);
}

function buildVulnerability(
  vuln: ScoredVulnerability,
  productIds: Map<string, string>,
): CsafVulnerability {
  const { match, risk } = vuln;
  const advisory = match.advisory;
  const productId = productIds.get(`${match.package}@${match.installedVersion}`);
  const productList = productId ? [productId] : [];

  const { cve, ghsaId, ids, notes } = pickAdvisoryIds(advisory);

  const vulnRecord: CsafVulnerability = {
    cve,
    ids,
    title: advisory.summary || advisory.id,
    product_status: {},
    threats: [],
  };

  // Classify status from reachability, mirroring OpenVEX logic.
  if (!match.isProduction) {
    vulnRecord.product_status.known_not_affected = productList;
    vulnRecord.threats?.push({
      category: 'impact',
      details: `Package ${match.package}@${match.installedVersion} is a dev-only dependency, not deployed to production.`,
    });
    vulnRecord.flags = [
      { label: 'vulnerable_code_not_in_execute_path', product_ids: productList },
    ];
  } else if (match.isDirectlyImported === false) {
    // Production but transitive/unreached — CSAF has no first-class "under investigation";
    // the spec-aligned mapping is known_affected with an impact note.
    vulnRecord.product_status.known_affected = productList;
    vulnRecord.threats?.push({
      category: 'impact',
      details: `Package ${match.package}@${match.installedVersion} is a production dependency but not directly imported by application code. Risk score: ${risk.score}/100.`,
    });
  } else {
    vulnRecord.product_status.known_affected = productList;
    vulnRecord.threats?.push({
      category: 'impact',
      details: `Package ${match.package}@${match.installedVersion} is imported in production code.${
        risk.factors.fixVersion ? ` Fix available: ${risk.factors.fixVersion}.` : ' No fix available.'
      } Risk score: ${risk.score}/100.`,
    });
  }

  // CVSS v3 score — emit if we have a CVSS_V3 severity record.
  const cvssV3 = advisory.severity.find((s) => s.type === 'CVSS_V3');
  if (cvssV3 && productList.length > 0) {
    vulnRecord.scores = [
      {
        cvss_v3: {
          version: '3.1',
          vectorString: cvssV3.score,
          baseScore: risk.factors.cvssScore,
          baseSeverity: mapBaseSeverity(risk.factors.cvssScore),
        },
        products: productList,
      },
    ];
  }

  if (notes.length > 0) {
    vulnRecord.notes = notes;
  }

  // Drop empty threats array to keep output tidy.
  if (vulnRecord.threats && vulnRecord.threats.length === 0) {
    delete vulnRecord.threats;
  }

  // Use GHSA metadata aside for convenience when CVE was absent.
  if (ghsaId && cve === ghsaId) {
    vulnRecord.notes = [
      ...(vulnRecord.notes ?? []),
      {
        category: 'other',
        title: 'CVE alias unavailable',
        text: `No CVE alias is associated with ${ghsaId}; GHSA id used in the cve field for interop with tools that require a value there.`,
      },
    ];
  }

  return vulnRecord;
}

function buildIgnoredVulnerability(
  ignored: IgnoredVulnerability,
  productIds: Map<string, string>,
): CsafVulnerability {
  const { match, reason, source } = ignored;
  const advisory = match.advisory;
  const productId = productIds.get(`${match.package}@${match.installedVersion}`);
  const productList = productId ? [productId] : [];

  const { cve, ids, notes } = pickAdvisoryIds(advisory);

  return {
    cve,
    ids,
    title: advisory.summary || advisory.id,
    product_status: { known_not_affected: productList },
    threats: [
      {
        category: 'impact',
        details: `Suppressed via ${source}: ${reason}`,
      },
    ],
    flags: [{ label: 'vulnerable_code_not_in_execute_path', product_ids: productList }],
    ...(notes.length > 0 ? { notes } : {}),
  };
}

/**
 * Pick a CVE id for the `cve` field and GHSA/other ids for the `ids` array.
 * If the advisory has no CVE alias, fall back to the GHSA id in `cve` and
 * emit an explanatory note (per the task brief).
 */
function pickAdvisoryIds(advisory: Advisory): {
  cve: string;
  ghsaId: string | null;
  ids: CsafVulnerabilityId[];
  notes: { category: string; text: string; title?: string }[];
} {
  const ids: CsafVulnerabilityId[] = [];
  const notes: { category: string; text: string; title?: string }[] = [];
  let cve = '';
  let ghsaId: string | null = null;

  // Candidate list: advisory.id + aliases.
  const candidates = [advisory.id, ...(advisory.aliases ?? [])];
  for (const c of candidates) {
    if (/^CVE-\d{4}-\d+$/i.test(c) && !cve) {
      cve = c.toUpperCase();
    } else if (/^GHSA-/i.test(c)) {
      if (!ghsaId) ghsaId = c;
      ids.push({ system_name: 'GHSA', text: c });
    } else if (c) {
      ids.push({ system_name: 'other', text: c });
    }
  }

  if (!cve) {
    // No CVE alias — use GHSA id if available, else fall back to advisory.id.
    cve = ghsaId ?? advisory.id;
  }

  return { cve, ghsaId, ids, notes };
}

function mapBaseSeverity(cvssScore: number): string {
  if (cvssScore >= 9) return 'CRITICAL';
  if (cvssScore >= 7) return 'HIGH';
  if (cvssScore >= 4) return 'MEDIUM';
  if (cvssScore > 0) return 'LOW';
  return 'NONE';
}

/**
 * Sanitize a string for use as a CSAF product_id.
 * CSAF allows arbitrary strings but keeping them printable-ASCII and token-like
 * avoids interop issues with downstream tooling.
 */
function sanitizeProductId(id: string): string {
  return id
    .replace(/@/g, '-')
    .replace(/\//g, '-')
    .replace(/[^A-Za-z0-9.-]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-+|-+$/g, '');
}
