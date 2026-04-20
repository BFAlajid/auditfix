import { describe, it, expect } from 'vitest';
import { generateSPDX, sanitizeSpdxId } from '../../src/cli/output/spdx.js';
import type { AuditReport } from '../../src/types/report.js';
import type { Advisory } from '../../src/types/advisory.js';

function makeAdvisory(overrides: Partial<Advisory> = {}): Advisory {
  return {
    id: 'GHSA-test-0001',
    aliases: [],
    summary: 'Test vulnerability',
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

function makeReport(
  vulnSpecs: Array<{ pkg: string; version: string; advisory?: Partial<Advisory> }> = [],
  ignoredSpecs: Array<{ pkg: string; version: string; advisory?: Partial<Advisory> }> = [],
): AuditReport {
  return {
    vulnerabilities: vulnSpecs.map((v) => ({
      match: {
        advisory: makeAdvisory(v.advisory),
        package: v.pkg,
        installedVersion: v.version,
        dependencyPath: [v.pkg],
        isProduction: true,
        isDirectlyImported: true,
      },
      risk: {
        score: 50,
        label: 'medium',
        factors: {
          cvssScore: 5,
          cvssVector: '',
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
    })),
    metadata: {
      totalPackages: 10,
      skippedPackages: 0,
      skippedReasons: [],
      advisorySource: 'test',
      advisoryCount: vulnSpecs.length,
      confidence: 'HIGH',
      scanDurationMs: 10,
      lockfileType: 'npm-v3',
    },
    ignored: ignoredSpecs.map((i) => ({
      match: {
        advisory: makeAdvisory(i.advisory),
        package: i.pkg,
        installedVersion: i.version,
        dependencyPath: [i.pkg],
        isProduction: true,
      },
      reason: 'suppressed',
      source: 'local-allowlist',
    })),
  };
}

describe('SPDX 2.3 SBOM generation', () => {
  it('produces a spec-conformant minimal document', () => {
    const report = makeReport([{ pkg: 'lodash', version: '4.17.21' }]);
    const doc = JSON.parse(generateSPDX(report, 'my-app', '1.0.0', '2.3.1'));

    expect(doc.spdxVersion).toBe('SPDX-2.3');
    expect(doc.dataLicense).toBe('CC0-1.0');
    expect(doc.SPDXID).toBe('SPDXRef-DOCUMENT');
    expect(doc.name).toBe('my-app');
    expect(doc.documentNamespace).toMatch(/^https:\/\/auditfix\.dev\/spdx\//);
    expect(doc.creationInfo.creators).toContain('Tool: auditfix-1.0.0');
    expect(doc.creationInfo.licenseListVersion).toBe('3.23');
    expect(typeof doc.creationInfo.created).toBe('string');
  });

  it('includes the project root and all vulnerable packages as SPDX packages', () => {
    const report = makeReport(
      [
        { pkg: 'lodash', version: '4.17.21' },
        { pkg: '@babel/core', version: '7.0.0' },
      ],
      [{ pkg: 'ignored-pkg', version: '1.0.0' }],
    );
    const doc = JSON.parse(generateSPDX(report, 'my-app', '1.0.0'));

    // 1 root + 3 dependent packages
    expect(doc.packages).toHaveLength(4);

    const names = doc.packages.map((p: { name: string }) => p.name);
    expect(names).toContain('my-app');
    expect(names).toContain('lodash');
    expect(names).toContain('@babel/core');
    expect(names).toContain('ignored-pkg');
  });

  it('dedupes multiple paths to the same package@version', () => {
    // Two vuln records on the same package+version — should collapse to one SPDX package
    const report = makeReport([
      { pkg: 'lodash', version: '4.17.21' },
      {
        pkg: 'lodash',
        version: '4.17.21',
        advisory: { id: 'GHSA-second-0001' },
      },
    ]);
    const doc = JSON.parse(generateSPDX(report, 'my-app', '1.0.0'));

    const lodashPkgs = doc.packages.filter(
      (p: { name: string; versionInfo: string }) =>
        p.name === 'lodash' && p.versionInfo === '4.17.21',
    );
    expect(lodashPkgs).toHaveLength(1);
  });

  it('emits correct DESCRIBES and DEPENDS_ON relationships', () => {
    const report = makeReport([{ pkg: 'lodash', version: '4.17.21' }]);
    const doc = JSON.parse(generateSPDX(report, 'my-app', '1.0.0'));

    const describes = doc.relationships.find(
      (r: { relationshipType: string }) => r.relationshipType === 'DESCRIBES',
    );
    expect(describes).toEqual({
      spdxElementId: 'SPDXRef-DOCUMENT',
      relationshipType: 'DESCRIBES',
      relatedSpdxElement: 'SPDXRef-Package-root',
    });

    const dependsOn = doc.relationships.filter(
      (r: { relationshipType: string }) => r.relationshipType === 'DEPENDS_ON',
    );
    expect(dependsOn).toHaveLength(1);
    expect(dependsOn[0].spdxElementId).toBe('SPDXRef-Package-root');
  });

  it('includes a PURL externalRef for every package', () => {
    const report = makeReport([
      { pkg: 'lodash', version: '4.17.21' },
      { pkg: '@babel/core', version: '7.0.0' },
    ]);
    const doc = JSON.parse(generateSPDX(report, 'my-app', '1.0.0'));

    const lodash = doc.packages.find((p: { name: string }) => p.name === 'lodash');
    expect(lodash.externalRefs).toEqual([
      {
        referenceCategory: 'PACKAGE-MANAGER',
        referenceType: 'purl',
        referenceLocator: 'pkg:npm/lodash@4.17.21',
      },
    ]);

    const babel = doc.packages.find((p: { name: string }) => p.name === '@babel/core');
    expect(babel.externalRefs[0].referenceLocator).toBe('pkg:npm/%40babel/core@7.0.0');
  });

  it('produces valid SPDXIDs for scoped and special-character package names', () => {
    const report = makeReport([
      { pkg: '@scope/pkg', version: '1.2.3' },
      { pkg: 'normal-pkg', version: '0.1.0-beta.1' },
    ]);
    const doc = JSON.parse(generateSPDX(report, 'my-app', '1.0.0'));

    const ids: string[] = doc.packages.map((p: { SPDXID: string }) => p.SPDXID);
    // Every SPDXID must match [A-Za-z0-9.-]+ prefixed with SPDXRef-
    for (const id of ids) {
      expect(id).toMatch(/^SPDXRef-[A-Za-z0-9.-]+$/);
    }

    expect(ids).toContain('SPDXRef-Package-scope-pkg-1.2.3');
  });

  it('handles an empty report (no vulnerabilities, no ignored)', () => {
    const report = makeReport([], []);
    const doc = JSON.parse(generateSPDX(report, 'empty-proj', '1.0.0'));

    // Only the root package
    expect(doc.packages).toHaveLength(1);
    expect(doc.packages[0].SPDXID).toBe('SPDXRef-Package-root');
    // Only the DESCRIBES relationship
    expect(doc.relationships).toHaveLength(1);
    expect(doc.relationships[0].relationshipType).toBe('DESCRIBES');
  });

  it('uses NOASSERTION for projectVersion when not supplied', () => {
    const report = makeReport([]);
    const doc = JSON.parse(generateSPDX(report, 'my-app', '1.0.0'));
    const root = doc.packages.find((p: { SPDXID: string }) => p.SPDXID === 'SPDXRef-Package-root');
    expect(root.versionInfo).toBe('NOASSERTION');
  });

  it('is stable JSON (parses, well-formed)', () => {
    const report = makeReport([{ pkg: 'lodash', version: '4.17.21' }]);
    const output = generateSPDX(report, 'my-app', '1.0.0');
    expect(() => JSON.parse(output)).not.toThrow();
    // Two-space indented (matches existing sbom.ts convention)
    expect(output.split('\n').length).toBeGreaterThan(5);
  });
});

describe('sanitizeSpdxId', () => {
  it('replaces @ and / with hyphens', () => {
    expect(sanitizeSpdxId('SPDXRef-Package-@scope/pkg-1.2.3')).toBe(
      'SPDXRef-Package-scope-pkg-1.2.3',
    );
  });

  it('collapses multiple consecutive hyphens', () => {
    expect(sanitizeSpdxId('SPDXRef-foo--bar')).toBe('SPDXRef-foo-bar');
  });

  it('trims leading and trailing hyphens from the body', () => {
    expect(sanitizeSpdxId('SPDXRef--foo-')).toBe('SPDXRef-foo');
  });

  it('accepts bodies containing only allowed characters unchanged', () => {
    expect(sanitizeSpdxId('SPDXRef-lodash-4.17.21')).toBe('SPDXRef-lodash-4.17.21');
  });

  it('produces "SPDXRef-unnamed" when body collapses to empty', () => {
    expect(sanitizeSpdxId('SPDXRef-@@@')).toBe('SPDXRef-unnamed');
  });
});
