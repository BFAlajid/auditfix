import { describe, it, expect } from 'vitest';
import { renderJsonReport } from '../../src/cli/output/json.js';
import type { AuditReport, ScoredVulnerability, ConfidenceLevel } from '../../src/types/report.js';
import type { Advisory, AdvisoryMatch } from '../../src/types/advisory.js';

function makeAdvisory(overrides?: Partial<Advisory>): Advisory {
  return {
    id: 'GHSA-test-0001-0001',
    aliases: [],
    summary: 'Test vulnerability',
    details: '',
    severity: [],
    affectedRange: '>=1.0.0',
    fixVersion: null,
    publishedAt: '2024-01-01',
    modifiedAt: '2024-01-01',
    references: [],
    source: 'osv-api',
    ...overrides,
  };
}

function makeVuln(overrides?: {
  advisoryId?: string;
  pkg?: string;
  installedVersion?: string;
  label?: 'critical' | 'high' | 'medium' | 'low' | 'info';
  score?: number;
  cvssScore?: number;
  cvssVector?: string;
  isProduction?: boolean;
  fixVersion?: string | null;
  dependencyPath?: string[];
}): ScoredVulnerability {
  const match: AdvisoryMatch = {
    advisory: makeAdvisory({
      id: overrides?.advisoryId ?? 'GHSA-test-0001-0001',
      summary: `Vulnerability in ${overrides?.pkg ?? 'test-pkg'}`,
    }),
    package: overrides?.pkg ?? 'test-pkg',
    installedVersion: overrides?.installedVersion ?? '1.0.0',
    dependencyPath: overrides?.dependencyPath ?? [overrides?.pkg ?? 'test-pkg'],
    isProduction: overrides?.isProduction ?? true,
  };

  return {
    match,
    risk: {
      score: overrides?.score ?? 50,
      label: overrides?.label ?? 'high',
      factors: {
        cvssScore: overrides?.cvssScore ?? 7.5,
        cvssVector: overrides?.cvssVector ?? 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        productionReachable: overrides?.isProduction ?? true,
        directlyImported: false,
        exploitAvailable: false,
        epssScore: null,
        inKev: false,
        fixAvailable: overrides?.fixVersion != null,
        fixVersion: overrides?.fixVersion ?? null,
        depth: 1,
        directDependency: true,
      },
    },
  };
}

function makeReport(overrides?: {
  vulns?: ScoredVulnerability[];
  ignored?: AuditReport['ignored'];
  confidence?: ConfidenceLevel;
  totalPackages?: number;
  advisoryCount?: number;
}): AuditReport {
  return {
    vulnerabilities: overrides?.vulns ?? [],
    metadata: {
      totalPackages: overrides?.totalPackages ?? 100,
      skippedPackages: 0,
      skippedReasons: [],
      advisorySource: 'OSV.dev API (real-time)',
      advisoryCount: overrides?.advisoryCount ?? 10,
      confidence: overrides?.confidence ?? 'HIGH',
      scanDurationMs: 500,
    },
    ignored: overrides?.ignored ?? [],
  };
}

describe('renderJsonReport', () => {
  describe('output validity', () => {
    it('returns valid JSON', () => {
      const report = makeReport();
      const output = renderJsonReport(report);

      expect(() => JSON.parse(output)).not.toThrow();
    });

    it('output is pretty-printed with 2-space indentation', () => {
      const report = makeReport({ vulns: [makeVuln()] });
      const output = renderJsonReport(report);

      // JSON.stringify with null, 2 produces 2-space indent
      expect(output).toContain('  "vulnerabilities"');
    });
  });

  describe('expected fields', () => {
    it('contains vulnerabilities, ignored, and metadata top-level keys', () => {
      const report = makeReport();
      const parsed = JSON.parse(renderJsonReport(report));

      expect(parsed).toHaveProperty('vulnerabilities');
      expect(parsed).toHaveProperty('ignored');
      expect(parsed).toHaveProperty('metadata');
    });

    it('metadata contains scan metadata fields', () => {
      const report = makeReport({ totalPackages: 250, advisoryCount: 42 });
      const parsed = JSON.parse(renderJsonReport(report));

      expect(parsed.metadata.totalPackages).toBe(250);
      expect(parsed.metadata.advisoryCount).toBe(42);
      expect(parsed.metadata).toHaveProperty('confidence');
      expect(parsed.metadata).toHaveProperty('scanDurationMs');
    });
  });

  describe('empty report', () => {
    it('handles report with no vulnerabilities and no ignored entries', () => {
      const report = makeReport({ vulns: [], ignored: [] });
      const parsed = JSON.parse(renderJsonReport(report));

      expect(parsed.vulnerabilities).toEqual([]);
      expect(parsed.ignored).toEqual([]);
      expect(parsed.metadata).toBeDefined();
    });
  });

  describe('report with vulnerabilities', () => {
    it('maps vulnerability fields correctly', () => {
      const vuln = makeVuln({
        advisoryId: 'GHSA-aaaa-bbbb-cccc',
        pkg: 'lodash',
        installedVersion: '4.17.19',
        label: 'critical',
        score: 85,
        cvssScore: 9.8,
        cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        isProduction: true,
        fixVersion: '4.17.21',
        dependencyPath: ['my-app', 'lodash'],
      });
      const report = makeReport({ vulns: [vuln] });
      const parsed = JSON.parse(renderJsonReport(report));

      expect(parsed.vulnerabilities).toHaveLength(1);
      const v = parsed.vulnerabilities[0];

      expect(v.id).toBe('GHSA-aaaa-bbbb-cccc');
      expect(v.package).toBe('lodash');
      expect(v.installedVersion).toBe('4.17.19');
      expect(v.severity).toBe('critical');
      expect(v.score).toBe(85);
      expect(v.production).toBe(true);
      expect(v.fixVersion).toBe('4.17.21');
      expect(v.dependencyPath).toEqual(['my-app', 'lodash']);
      expect(v.cvss.score).toBe(9.8);
      expect(v.cvss.vector).toBe('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H');
    });

    it('handles multiple vulnerabilities', () => {
      const vulns = [
        makeVuln({ advisoryId: 'GHSA-0001', pkg: 'pkg-a', label: 'high' }),
        makeVuln({ advisoryId: 'GHSA-0002', pkg: 'pkg-b', label: 'medium' }),
        makeVuln({ advisoryId: 'GHSA-0003', pkg: 'pkg-c', label: 'low' }),
      ];
      const report = makeReport({ vulns });
      const parsed = JSON.parse(renderJsonReport(report));

      expect(parsed.vulnerabilities).toHaveLength(3);
      expect(parsed.vulnerabilities.map((v: { id: string }) => v.id)).toEqual([
        'GHSA-0001',
        'GHSA-0002',
        'GHSA-0003',
      ]);
    });

    it('includes summary from advisory', () => {
      const vuln = makeVuln({ pkg: 'express' });
      const report = makeReport({ vulns: [vuln] });
      const parsed = JSON.parse(renderJsonReport(report));

      expect(parsed.vulnerabilities[0].summary).toBe('Vulnerability in express');
    });

    it('handles vulnerability with null fixVersion', () => {
      const vuln = makeVuln({ fixVersion: null });
      const report = makeReport({ vulns: [vuln] });
      const parsed = JSON.parse(renderJsonReport(report));

      expect(parsed.vulnerabilities[0].fixVersion).toBeNull();
    });
  });

  describe('ignored vulnerabilities', () => {
    it('maps ignored entries with reason and source', () => {
      const ignored: AuditReport['ignored'] = [
        {
          match: {
            advisory: makeAdvisory({ id: 'GHSA-ignored-0001' }),
            package: 'old-pkg',
            installedVersion: '1.0.0',
            dependencyPath: ['old-pkg'],
            isProduction: false,
          },
          reason: 'Not applicable to this project',
          source: 'local-allowlist',
        },
      ];
      const report = makeReport({ ignored });
      const parsed = JSON.parse(renderJsonReport(report));

      expect(parsed.ignored).toHaveLength(1);
      expect(parsed.ignored[0].id).toBe('GHSA-ignored-0001');
      expect(parsed.ignored[0].package).toBe('old-pkg');
      expect(parsed.ignored[0].reason).toBe('Not applicable to this project');
      expect(parsed.ignored[0].source).toBe('local-allowlist');
    });

    it('handles multiple ignored entries', () => {
      const ignored: AuditReport['ignored'] = [
        {
          match: {
            advisory: makeAdvisory({ id: 'GHSA-ig-0001' }),
            package: 'pkg-a',
            installedVersion: '1.0.0',
            dependencyPath: ['pkg-a'],
            isProduction: false,
          },
          reason: 'reason-a',
          source: 'local-allowlist',
        },
        {
          match: {
            advisory: makeAdvisory({ id: 'GHSA-ig-0002' }),
            package: 'pkg-b',
            installedVersion: '2.0.0',
            dependencyPath: ['pkg-b'],
            isProduction: true,
          },
          reason: 'reason-b',
          source: 'community-allowlist',
        },
      ];
      const report = makeReport({ ignored });
      const parsed = JSON.parse(renderJsonReport(report));

      expect(parsed.ignored).toHaveLength(2);
      expect(parsed.ignored[0].id).toBe('GHSA-ig-0001');
      expect(parsed.ignored[1].id).toBe('GHSA-ig-0002');
      expect(parsed.ignored[1].source).toBe('community-allowlist');
    });
  });

  describe('combined report', () => {
    it('produces correct output with both vulnerabilities and ignored entries', () => {
      const vuln = makeVuln({ advisoryId: 'GHSA-active', label: 'high' });
      const ignored: AuditReport['ignored'] = [
        {
          match: {
            advisory: makeAdvisory({ id: 'GHSA-ignored' }),
            package: 'safe-pkg',
            installedVersion: '1.0.0',
            dependencyPath: ['safe-pkg'],
            isProduction: false,
          },
          reason: 'False positive',
          source: 'local-allowlist',
        },
      ];
      const report = makeReport({ vulns: [vuln], ignored });
      const parsed = JSON.parse(renderJsonReport(report));

      expect(parsed.vulnerabilities).toHaveLength(1);
      expect(parsed.vulnerabilities[0].id).toBe('GHSA-active');
      expect(parsed.ignored).toHaveLength(1);
      expect(parsed.ignored[0].id).toBe('GHSA-ignored');
      expect(parsed.metadata).toBeDefined();
    });
  });
});
