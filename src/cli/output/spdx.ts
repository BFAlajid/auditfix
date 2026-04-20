/**
 * SPDX 2.3 JSON SBOM generation.
 *
 * Produces a spec-conformant SPDX 2.3 document describing the project root and
 * the packages that appear in the audit report (both vulnerable and ignored).
 * Because auditfix's AuditReport only carries packages that matched advisories,
 * the generated SBOM is scoped to those packages plus the project root. It is
 * not a full dependency manifest — callers who need the complete graph should
 * use the CycloneDX generator which accepts a DependencyGraph.
 */
import type { AuditReport } from '../../types/report.js';
import type { AdvisoryMatch } from '../../types/advisory.js';
import { randomUUID } from 'node:crypto';

const SPDX_VERSION = 'SPDX-2.3';
const DATA_LICENSE = 'CC0-1.0';
const LICENSE_LIST_VERSION = '3.23';
const DOCUMENT_SPDXID = 'SPDXRef-DOCUMENT';
const ROOT_SPDXID = 'SPDXRef-Package-root';

type SpdxExternalRef = {
  referenceCategory: 'PACKAGE-MANAGER' | 'SECURITY' | 'OTHER';
  referenceType: string;
  referenceLocator: string;
};

type SpdxPackage = {
  SPDXID: string;
  name: string;
  versionInfo: string;
  downloadLocation: string;
  filesAnalyzed: boolean;
  externalRefs: SpdxExternalRef[];
};

type SpdxRelationship = {
  spdxElementId: string;
  relationshipType:
    | 'DESCRIBES'
    | 'DEPENDS_ON'
    | 'CONTAINS'
    | 'DEPENDENCY_OF';
  relatedSpdxElement: string;
};

type SpdxDocument = {
  spdxVersion: string;
  dataLicense: string;
  SPDXID: string;
  name: string;
  documentNamespace: string;
  creationInfo: {
    created: string;
    creators: string[];
    licenseListVersion: string;
  };
  packages: SpdxPackage[];
  relationships: SpdxRelationship[];
};

/**
 * Generate an SPDX 2.3 JSON SBOM from an audit report.
 *
 * @param report     The audit report to project into SBOM form.
 * @param projectName Project name used for the document and root package.
 * @param toolVersion Tool version included in creationInfo.creators.
 * @param projectVersion Optional project version for the root package.
 */
export function generateSPDX(
  report: AuditReport,
  projectName: string,
  toolVersion: string,
  projectVersion?: string,
): string {
  const now = new Date().toISOString();

  // Root package representing the project itself.
  const rootPkg: SpdxPackage = {
    SPDXID: ROOT_SPDXID,
    name: projectName,
    versionInfo: projectVersion ?? 'NOASSERTION',
    downloadLocation: 'NOASSERTION',
    filesAnalyzed: false,
    externalRefs: [],
  };

  // Collect unique packages from the report (vulnerable + ignored).
  // Dedupe on name@version — multiple advisories or dependency paths
  // must collapse to a single SPDX package.
  const pkgMap = new Map<string, SpdxPackage>();
  const packages: SpdxPackage[] = [rootPkg];
  const relationships: SpdxRelationship[] = [
    {
      spdxElementId: DOCUMENT_SPDXID,
      relationshipType: 'DESCRIBES',
      relatedSpdxElement: ROOT_SPDXID,
    },
  ];

  const addMatch = (match: AdvisoryMatch): void => {
    const key = `${match.package}@${match.installedVersion}`;
    if (pkgMap.has(key)) return;

    const spdxId = sanitizeSpdxId(
      `SPDXRef-Package-${match.package}-${match.installedVersion}`,
    );
    const pkg: SpdxPackage = {
      SPDXID: spdxId,
      name: match.package,
      versionInfo: match.installedVersion,
      downloadLocation: 'NOASSERTION',
      filesAnalyzed: false,
      externalRefs: [
        {
          referenceCategory: 'PACKAGE-MANAGER',
          referenceType: 'purl',
          referenceLocator: `pkg:npm/${encodePackageName(match.package)}@${match.installedVersion}`,
        },
      ],
    };
    pkgMap.set(key, pkg);
    packages.push(pkg);

    relationships.push({
      spdxElementId: ROOT_SPDXID,
      relationshipType: 'DEPENDS_ON',
      relatedSpdxElement: spdxId,
    });
  };

  for (const vuln of report.vulnerabilities) {
    addMatch(vuln.match);
  }
  for (const ignored of report.ignored) {
    addMatch(ignored.match);
  }

  const doc: SpdxDocument = {
    spdxVersion: SPDX_VERSION,
    dataLicense: DATA_LICENSE,
    SPDXID: DOCUMENT_SPDXID,
    name: projectName,
    documentNamespace: `https://auditfix.dev/spdx/${projectName}-${randomUUID()}`,
    creationInfo: {
      created: now,
      creators: [`Tool: auditfix-${toolVersion}`],
      licenseListVersion: LICENSE_LIST_VERSION,
    },
    packages,
    relationships,
  };

  return JSON.stringify(doc, null, 2);
}

/**
 * Sanitize a string for use in an SPDXID.
 * Per SPDX 2.3 §3.2: SPDXID must match [A-Za-z0-9.-]+ and be prefixed "SPDXRef-".
 * We sanitize the tail (after "SPDXRef-") — replacing any disallowed chars with "-",
 * then collapsing runs and trimming stray leading/trailing hyphens.
 */
export function sanitizeSpdxId(id: string): string {
  // Split the required "SPDXRef-" prefix so we only sanitize the identifier body.
  const prefix = 'SPDXRef-';
  const hasPrefix = id.startsWith(prefix);
  const body = hasPrefix ? id.slice(prefix.length) : id;

  const sanitized = body
    .replace(/@/g, '-')
    .replace(/\//g, '-')
    .replace(/[^A-Za-z0-9.-]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^[-.]+/, '')
    .replace(/[-.]+$/, '');

  return `${prefix}${sanitized || 'unnamed'}`;
}

/**
 * Encode a package name for inclusion in a purl.
 * Scoped packages use %40 in place of the leading @.
 */
function encodePackageName(name: string): string {
  if (name.startsWith('@')) {
    return '%40' + name.slice(1);
  }
  return name;
}
