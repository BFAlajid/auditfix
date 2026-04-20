import { describe, it, expect } from 'vitest';
import { generateVex, embedVexInCycloneDX } from '../../src/cli/output/vex.js';
import type { AuditReport } from '../../src/types/report.js';

function makeReport(overrides: Partial<{
  prodImported: boolean;
  prodNotImported: boolean;
  devOnly: boolean;
}>): AuditReport {
  const vulns: AuditReport['vulnerabilities'] = [];
  const advisory = {
    id: 'GHSA-test-0001',
    aliases: [],
    summary: 'Test vuln',
    details: '',
    severity: [],
    affectedRange: '<2.0.0',
    fixVersion: '2.0.0',
    publishedAt: '2024-01-01',
    modifiedAt: '2024-01-01',
    references: [],
    source: 'osv-api' as const,
  };

  if (overrides.prodImported) {
    vulns.push({
      match: { advisory, package: 'prod-pkg', installedVersion: '1.0.0', dependencyPath: ['prod-pkg'], isProduction: true, isDirectlyImported: true },
      risk: { score: 80, label: 'high', factors: { cvssScore: 8, cvssVector: '', productionReachable: true, directlyImported: true, exploitAvailable: false, epssScore: null, inKev: false, fixAvailable: true, fixVersion: '2.0.0', depth: 1, directDependency: true } },
    });
  }

  if (overrides.prodNotImported) {
    vulns.push({
      match: { advisory: { ...advisory, id: 'GHSA-test-0002' }, package: 'transitive-pkg', installedVersion: '1.0.0', dependencyPath: ['root', 'transitive-pkg'], isProduction: true, isDirectlyImported: false },
      risk: { score: 50, label: 'medium', factors: { cvssScore: 5, cvssVector: '', productionReachable: true, directlyImported: false, exploitAvailable: false, epssScore: null, inKev: false, fixAvailable: false, fixVersion: null, depth: 2, directDependency: false } },
    });
  }

  if (overrides.devOnly) {
    vulns.push({
      match: { advisory: { ...advisory, id: 'GHSA-test-0003' }, package: 'dev-pkg', installedVersion: '1.0.0', dependencyPath: ['dev-pkg'], isProduction: false },
      risk: { score: 10, label: 'low', factors: { cvssScore: 8, cvssVector: '', productionReachable: false, directlyImported: false, exploitAvailable: false, epssScore: null, inKev: false, fixAvailable: true, fixVersion: '2.0.0', depth: 1, directDependency: true } },
    });
  }

  return {
    vulnerabilities: vulns,
    metadata: { totalPackages: 50, skippedPackages: 0, skippedReasons: [], advisorySource: 'test', advisoryCount: 1, confidence: 'HIGH', scanDurationMs: 100, lockfileType: 'npm-v3' },
    ignored: [],
  };
}

describe('VEX generation', () => {
  it('generates valid OpenVEX JSON', () => {
    const report = makeReport({ prodImported: true });
    const vex = JSON.parse(generateVex(report, '2.0.0', 'my-app'));
    expect(vex['@context']).toBe('https://openvex.dev/ns/v0.2.0');
    expect(vex.tooling).toBe('auditfix/2.0.0');
    expect(vex.statements).toHaveLength(1);
  });

  it('marks dev-only as not_affected', () => {
    const report = makeReport({ devOnly: true });
    const vex = JSON.parse(generateVex(report, '2.0.0'));
    expect(vex.statements[0].status).toBe('not_affected');
    expect(vex.statements[0].justification).toBe('vulnerable_code_not_in_execute_path');
  });

  it('marks prod not-imported as under_investigation', () => {
    const report = makeReport({ prodNotImported: true });
    const vex = JSON.parse(generateVex(report, '2.0.0'));
    expect(vex.statements[0].status).toBe('under_investigation');
  });

  it('marks prod imported as affected', () => {
    const report = makeReport({ prodImported: true });
    const vex = JSON.parse(generateVex(report, '2.0.0'));
    expect(vex.statements[0].status).toBe('affected');
  });

  it('includes ignored vulns as not_affected', () => {
    const report = makeReport({});
    report.ignored.push({
      match: {
        advisory: { id: 'GHSA-ign-0001', aliases: [], summary: 'Ignored vuln', details: '', severity: [], affectedRange: '', fixVersion: null, publishedAt: '', modifiedAt: '', references: [], source: 'osv-api' },
        package: 'ignored-pkg',
        installedVersion: '1.0.0',
        dependencyPath: ['ignored-pkg'],
        isProduction: true,
      },
      reason: 'Not applicable',
      source: 'local-allowlist',
    });
    const vex = JSON.parse(generateVex(report, '2.0.0'));
    expect(vex.statements).toHaveLength(1);
    expect(vex.statements[0].status).toBe('not_affected');
  });
});

describe('CycloneDX VEX embedding (embedVexInCycloneDX)', () => {
  // Minimal CycloneDX 1.5 SBOM for testing.
  const baseSbom = () => ({
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: 'urn:uuid:00000000-0000-0000-0000-000000000000',
    version: 1,
    metadata: { timestamp: '2024-01-01T00:00:00Z' },
    components: [
      { type: 'library', name: 'prod-pkg', version: '1.0.0', purl: 'pkg:npm/prod-pkg@1.0.0' },
    ],
    dependencies: [],
  });

  it('returns a new object without mutating the input SBOM', () => {
    const report = makeReport({ prodImported: true });
    const original = baseSbom();
    const snapshot = JSON.stringify(original);

    const result = embedVexInCycloneDX(original, report);

    expect(JSON.stringify(original)).toBe(snapshot);
    expect(result).not.toBe(original);
  });

  it('adds a vulnerabilities array with one entry per active vulnerability', () => {
    const report = makeReport({ prodImported: true });
    const result = embedVexInCycloneDX(baseSbom(), report) as {
      vulnerabilities: Array<{
        id: string;
        affects: { ref: string }[];
        analysis: { state: string };
      }>;
    };

    expect(result.vulnerabilities).toHaveLength(1);
    expect(result.vulnerabilities[0].id).toBe('GHSA-test-0001');
    expect(result.vulnerabilities[0].affects[0].ref).toBe('pkg:npm/prod-pkg@1.0.0');
    expect(result.vulnerabilities[0].analysis.state).toBe('exploitable');
  });

  it('marks dev-only vulnerabilities as not_affected with code_not_reachable', () => {
    const report = makeReport({ devOnly: true });
    const result = embedVexInCycloneDX(baseSbom(), report) as {
      vulnerabilities: Array<{ analysis: { state: string; justification: string } }>;
    };

    expect(result.vulnerabilities[0].analysis.state).toBe('not_affected');
    expect(result.vulnerabilities[0].analysis.justification).toBe('code_not_reachable');
  });

  it('marks prod-not-imported vulnerabilities as in_triage', () => {
    const report = makeReport({ prodNotImported: true });
    const result = embedVexInCycloneDX(baseSbom(), report) as {
      vulnerabilities: Array<{ analysis: { state: string } }>;
    };
    expect(result.vulnerabilities[0].analysis.state).toBe('in_triage');
  });

  it('includes ignored vulnerabilities as not_affected', () => {
    const report = makeReport({});
    report.ignored.push({
      match: {
        advisory: {
          id: 'GHSA-ign-0001',
          aliases: [],
          summary: 'Ignored',
          details: '',
          severity: [],
          affectedRange: '',
          fixVersion: null,
          publishedAt: '',
          modifiedAt: '',
          references: [],
          source: 'osv-api',
        },
        package: 'ignored-pkg',
        installedVersion: '1.0.0',
        dependencyPath: ['ignored-pkg'],
        isProduction: true,
      },
      reason: 'Not applicable',
      source: 'local-allowlist',
    });

    const result = embedVexInCycloneDX(baseSbom(), report) as {
      vulnerabilities: Array<{ id: string; analysis: { state: string; detail: string } }>;
    };
    expect(result.vulnerabilities).toHaveLength(1);
    expect(result.vulnerabilities[0].id).toBe('GHSA-ign-0001');
    expect(result.vulnerabilities[0].analysis.state).toBe('not_affected');
    expect(result.vulnerabilities[0].analysis.detail).toMatch(/local-allowlist/);
  });

  it('preserves existing CycloneDX fields on the SBOM', () => {
    const report = makeReport({ prodImported: true });
    const result = embedVexInCycloneDX(baseSbom(), report) as {
      bomFormat: string;
      specVersion: string;
      components: unknown[];
    };
    expect(result.bomFormat).toBe('CycloneDX');
    expect(result.specVersion).toBe('1.5');
    expect(result.components).toHaveLength(1);
  });

  it('appends to an existing vulnerabilities array rather than overwriting it', () => {
    const report = makeReport({ prodImported: true });
    const sbom = {
      ...baseSbom(),
      vulnerabilities: [
        { id: 'PRE-EXISTING', source: { name: 'NVD' }, affects: [] },
      ],
    };
    const result = embedVexInCycloneDX(sbom, report) as {
      vulnerabilities: Array<{ id: string }>;
    };
    expect(result.vulnerabilities).toHaveLength(2);
    expect(result.vulnerabilities.map((v) => v.id)).toContain('PRE-EXISTING');
    expect(result.vulnerabilities.map((v) => v.id)).toContain('GHSA-test-0001');
  });

  it('produces empty vulnerabilities array for an empty report', () => {
    const report = makeReport({});
    const result = embedVexInCycloneDX(baseSbom(), report) as {
      vulnerabilities: unknown[];
    };
    expect(result.vulnerabilities).toEqual([]);
  });
});
