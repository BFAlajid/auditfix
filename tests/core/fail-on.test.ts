import { describe, it, expect } from 'vitest';
import { getExitCodeForStrategy } from '../../src/cli/output/terminal.js';
import type { AuditReport } from '../../src/types/report.js';

function makeReport(
  vulns: Array<{ severity: string; production: boolean }>,
  confidence: 'HIGH' | 'MEDIUM' | 'LOW' | 'UNRELIABLE' = 'HIGH',
): AuditReport {
  return {
    vulnerabilities: vulns.map((v, i) => ({
      match: {
        advisory: { id: `GHSA-${i}`, aliases: [], summary: '', details: '', severity: [{ type: 'CVSS_V3' as const, score: '7.0' }], affectedRange: '<2.0.0', fixVersion: '2.0.0', publishedAt: '', modifiedAt: '', references: [], source: 'osv-api' as const },
        package: `pkg-${i}`,
        installedVersion: '1.0.0',
        dependencyPath: [`pkg-${i}`],
        isProduction: v.production,
      },
      risk: { score: 70, label: v.severity as 'critical' | 'high' | 'medium' | 'low', factors: { cvssScore: 7.0, cvssVector: '', productionReachable: v.production, directlyImported: false, exploitAvailable: false, epssScore: null, inKev: false, fixAvailable: true, fixVersion: '2.0.0', depth: 1, directDependency: true } },
    })),
    metadata: {
      totalPackages: 50,
      skippedPackages: 0,
      skippedReasons: [],
      advisorySource: 'test',
      advisoryCount: 10,
      confidence,
      scanDurationMs: 100,
    },
    ignored: [],
  };
}

describe('--fail-on strategies', () => {
  it('production-critical: exits 0 for production high vulns', () => {
    const report = makeReport([{ severity: 'high', production: true }]);
    expect(getExitCodeForStrategy(report, 'production-critical')).toBe(0);
  });

  it('production-critical: exits 1 for production critical vulns', () => {
    const report = makeReport([{ severity: 'critical', production: true }]);
    expect(getExitCodeForStrategy(report, 'production-critical')).toBe(1);
  });

  it('production-critical: exits 0 for dev critical vulns', () => {
    const report = makeReport([{ severity: 'critical', production: false }]);
    expect(getExitCodeForStrategy(report, 'production-critical')).toBe(0);
  });

  it('any: exits 1 for any vulnerability', () => {
    const report = makeReport([{ severity: 'low', production: false }]);
    expect(getExitCodeForStrategy(report, 'any')).toBe(1);
  });

  it('any: exits 0 for no vulnerabilities', () => {
    const report = makeReport([]);
    expect(getExitCodeForStrategy(report, 'any')).toBe(0);
  });

  it('always exits 2 for UNRELIABLE confidence', () => {
    const report = makeReport([{ severity: 'low', production: false }], 'UNRELIABLE');
    expect(getExitCodeForStrategy(report, 'any')).toBe(2);
  });
});
