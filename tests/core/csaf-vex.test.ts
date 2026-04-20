import { describe, it, expect } from 'vitest';
import { generateCSAFVEX } from '../../src/cli/output/csaf-vex.js';
import type { AuditReport } from '../../src/types/report.js';
import type { Advisory } from '../../src/types/advisory.js';

function makeAdvisory(overrides: Partial<Advisory> = {}): Advisory {
  return {
    id: 'GHSA-test-0001',
    aliases: [],
    summary: 'Test vulnerability summary',
    details: '',
    severity: [],
    affectedRange: '<2.0.0',
    fixVersion: '2.0.0',
    publishedAt: '2024-01-01T00:00:00Z',
    modifiedAt: '2024-01-01T00:00:00Z',
    references: [],
    source: 'osv-api',
    ...overrides,
  };
}

function vulnEntry(opts: {
  pkg: string;
  version: string;
  advisory?: Partial<Advisory>;
  isProduction?: boolean;
  isDirectlyImported?: boolean;
  cvssScore?: number;
}) {
  return {
    match: {
      advisory: makeAdvisory(opts.advisory),
      package: opts.pkg,
      installedVersion: opts.version,
      dependencyPath: [opts.pkg],
      isProduction: opts.isProduction ?? true,
      isDirectlyImported: opts.isDirectlyImported ?? true,
    },
    risk: {
      score: 80,
      label: 'high' as const,
      factors: {
        cvssScore: opts.cvssScore ?? 7.5,
        cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        productionReachable: true,
        directlyImported: true,
        exploitAvailable: false,
        epssScore: null,
        inKev: false,
        fixAvailable: true,
        fixVersion: '2.0.0',
        depth: 1,
        directDependency: true,
      },
    },
  };
}

function makeReport(partial: Partial<AuditReport> = {}): AuditReport {
  return {
    vulnerabilities: [],
    ignored: [],
    metadata: {
      totalPackages: 10,
      skippedPackages: 0,
      skippedReasons: [],
      advisorySource: 'test',
      advisoryCount: 0,
      confidence: 'HIGH',
      scanDurationMs: 10,
      lockfileType: 'npm-v3',
    },
    ...partial,
  };
}

describe('CSAF 2.0 VEX generation', () => {
  it('produces a spec-aligned document structure', () => {
    const report = makeReport({
      vulnerabilities: [vulnEntry({ pkg: 'lodash', version: '4.17.21' })],
    });
    const doc = JSON.parse(generateCSAFVEX(report, 'my-app', '1.0.0'));

    expect(doc.document.category).toBe('csaf_vex');
    expect(doc.document.csaf_version).toBe('2.0');
    expect(doc.document.title).toBe('VEX for my-app');
    expect(doc.document.profile).toBe('urn:oasis:names:tc:csaf:1.0:profile:vex:1.0.0');

    expect(doc.document.publisher).toEqual({
      category: 'vendor',
      name: 'auditfix user',
      namespace: 'https://auditfix.dev',
    });

    // tracking block required fields
    expect(doc.document.tracking.id).toMatch(/^auditfix-/);
    expect(doc.document.tracking.status).toBe('final');
    expect(doc.document.tracking.version).toBe('1');
    expect(doc.document.tracking.revision_history).toHaveLength(1);
    expect(doc.document.tracking.revision_history[0]).toEqual(
      expect.objectContaining({ number: '1', summary: 'Initial' }),
    );
    expect(doc.document.tracking.generator.engine).toEqual({
      name: 'auditfix',
      version: '1.0.0',
    });

    expect(doc.document.distribution.tlp.label).toBe('WHITE');
  });

  it('builds a product_tree with one vendor branch and a product_version per package', () => {
    const report = makeReport({
      vulnerabilities: [
        vulnEntry({ pkg: 'lodash', version: '4.17.21' }),
        vulnEntry({ pkg: '@babel/core', version: '7.0.0', advisory: { id: 'GHSA-xyz' } }),
      ],
    });
    const doc = JSON.parse(generateCSAFVEX(report, 'my-app', '1.0.0'));

    expect(doc.product_tree.branches).toHaveLength(1);
    const npmBranch = doc.product_tree.branches[0];
    expect(npmBranch.category).toBe('vendor');
    expect(npmBranch.name).toBe('npm');
    expect(npmBranch.branches).toHaveLength(2);

    const names = npmBranch.branches.map((b: { name: string }) => b.name);
    expect(names).toEqual(expect.arrayContaining(['lodash@4.17.21', '@babel/core@7.0.0']));

    for (const b of npmBranch.branches) {
      expect(b.category).toBe('product_version');
      expect(b.product.product_id).toMatch(/^CSAFPID-/);
      expect(b.product.name).toBe(b.name);
    }
  });

  it('dedupes products when multiple vulnerabilities hit the same package@version', () => {
    const report = makeReport({
      vulnerabilities: [
        vulnEntry({ pkg: 'lodash', version: '4.17.21' }),
        vulnEntry({
          pkg: 'lodash',
          version: '4.17.21',
          advisory: { id: 'GHSA-other-0001' },
        }),
      ],
    });
    const doc = JSON.parse(generateCSAFVEX(report, 'my-app', '1.0.0'));
    expect(doc.product_tree.branches[0].branches).toHaveLength(1);
    expect(doc.vulnerabilities).toHaveLength(2);
  });

  it('maps advisory id/aliases into cve + ids', () => {
    const report = makeReport({
      vulnerabilities: [
        vulnEntry({
          pkg: 'lodash',
          version: '4.17.21',
          advisory: {
            id: 'GHSA-jf85-cpcp-j695',
            aliases: ['CVE-2019-10744'],
          },
        }),
      ],
    });
    const doc = JSON.parse(generateCSAFVEX(report, 'my-app', '1.0.0'));
    const v = doc.vulnerabilities[0];

    expect(v.cve).toBe('CVE-2019-10744');
    expect(v.ids).toEqual(expect.arrayContaining([{ system_name: 'GHSA', text: 'GHSA-jf85-cpcp-j695' }]));
  });

  it('falls back to GHSA id in cve field and emits a note when no CVE alias exists', () => {
    const report = makeReport({
      vulnerabilities: [
        vulnEntry({
          pkg: 'lodash',
          version: '4.17.21',
          advisory: { id: 'GHSA-only-0001', aliases: [] },
        }),
      ],
    });
    const doc = JSON.parse(generateCSAFVEX(report, 'my-app', '1.0.0'));
    const v = doc.vulnerabilities[0];

    expect(v.cve).toBe('GHSA-only-0001');
    expect(v.notes).toBeDefined();
    const noteTexts = (v.notes as { text: string }[]).map((n) => n.text);
    expect(noteTexts.some((t) => /CVE alias/i.test(t))).toBe(true);
  });

  it('records known_affected for production reachable vulns', () => {
    const report = makeReport({
      vulnerabilities: [vulnEntry({ pkg: 'lodash', version: '4.17.21' })],
    });
    const doc = JSON.parse(generateCSAFVEX(report, 'my-app', '1.0.0'));
    const v = doc.vulnerabilities[0];
    expect(v.product_status.known_affected).toBeDefined();
    expect(v.product_status.known_affected).toHaveLength(1);
    expect(v.product_status.known_not_affected).toBeUndefined();
  });

  it('records known_not_affected + flag for dev-only packages', () => {
    const report = makeReport({
      vulnerabilities: [
        vulnEntry({ pkg: 'vitest', version: '1.0.0', isProduction: false }),
      ],
    });
    const doc = JSON.parse(generateCSAFVEX(report, 'my-app', '1.0.0'));
    const v = doc.vulnerabilities[0];
    expect(v.product_status.known_not_affected).toHaveLength(1);
    expect(v.product_status.known_affected).toBeUndefined();
    expect(v.flags[0].label).toBe('vulnerable_code_not_in_execute_path');
  });

  it('records known_affected with triage note for prod/not-directly-imported', () => {
    const report = makeReport({
      vulnerabilities: [
        vulnEntry({
          pkg: 'transitive',
          version: '1.0.0',
          isDirectlyImported: false,
        }),
      ],
    });
    const doc = JSON.parse(generateCSAFVEX(report, 'my-app', '1.0.0'));
    const v = doc.vulnerabilities[0];
    expect(v.product_status.known_affected).toHaveLength(1);
    expect(v.threats[0].details).toMatch(/not directly imported/);
  });

  it('adds ignored vulnerabilities as known_not_affected suppressions', () => {
    const report = makeReport({
      ignored: [
        {
          match: {
            advisory: makeAdvisory({ id: 'GHSA-ign-0001' }),
            package: 'ignored-pkg',
            installedVersion: '1.0.0',
            dependencyPath: ['ignored-pkg'],
            isProduction: true,
          },
          reason: 'Not applicable in our context',
          source: 'local-allowlist',
        },
      ],
    });
    const doc = JSON.parse(generateCSAFVEX(report, 'my-app', '1.0.0'));
    expect(doc.vulnerabilities).toHaveLength(1);
    const v = doc.vulnerabilities[0];
    expect(v.product_status.known_not_affected).toHaveLength(1);
    expect(v.flags[0].label).toBe('vulnerable_code_not_in_execute_path');
    expect(v.threats[0].details).toMatch(/local-allowlist/);
  });

  it('emits CVSS v3 scores when advisory carries a CVSS_V3 severity', () => {
    const report = makeReport({
      vulnerabilities: [
        vulnEntry({
          pkg: 'lodash',
          version: '4.17.21',
          advisory: {
            severity: [
              { type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' },
            ],
          },
          cvssScore: 9.8,
        }),
      ],
    });
    const doc = JSON.parse(generateCSAFVEX(report, 'my-app', '1.0.0'));
    const scores = doc.vulnerabilities[0].scores;
    expect(scores).toBeDefined();
    expect(scores[0].cvss_v3.baseScore).toBe(9.8);
    expect(scores[0].cvss_v3.baseSeverity).toBe('CRITICAL');
    expect(scores[0].cvss_v3.vectorString).toMatch(/^CVSS:3\.1/);
  });

  it('produces a valid document even for an empty report', () => {
    const report = makeReport();
    const doc = JSON.parse(generateCSAFVEX(report, 'empty-proj', '1.0.0'));

    expect(doc.document.category).toBe('csaf_vex');
    expect(doc.product_tree.branches[0].branches).toEqual([]);
    expect(doc.vulnerabilities).toEqual([]);
  });
});
