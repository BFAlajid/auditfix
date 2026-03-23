import { describe, it, expect } from 'vitest';
import { aggregateFindings } from '../../../src/core/policy/findings.js';
import type { AuditReport } from '../../../src/types/report.js';

function makeReport(): AuditReport {
  return {
    vulnerabilities: [
      {
        match: {
          advisory: { id: 'GHSA-test', aliases: [], summary: 'Test', details: '', severity: [{ type: 'CVSS_V3', score: '9.8' }], affectedRange: '<2.0.0', fixVersion: '2.0.0', publishedAt: '', modifiedAt: '', references: [], source: 'osv-api' as const },
          package: 'lodash',
          installedVersion: '4.17.20',
          dependencyPath: ['lodash'],
          isProduction: true,
        },
        risk: {
          score: 85,
          label: 'critical',
          factors: { cvssScore: 9.8, cvssVector: '', productionReachable: true, directlyImported: true, exploitAvailable: false, epssScore: 0.7, inKev: true, fixAvailable: true, fixVersion: '4.17.21', depth: 1, directDependency: true },
        },
      },
      {
        match: {
          advisory: { id: 'GHSA-dev', aliases: [], summary: 'Dev vuln', details: '', severity: [{ type: 'CVSS_V3', score: '5.0' }], affectedRange: '<1.0.0', fixVersion: null, publishedAt: '', modifiedAt: '', references: [], source: 'osv-api' as const },
          package: 'devtool',
          installedVersion: '0.9.0',
          dependencyPath: ['a', 'b', 'devtool'],
          isProduction: false,
        },
        risk: {
          score: 30,
          label: 'medium',
          factors: { cvssScore: 5.0, cvssVector: '', productionReachable: false, directlyImported: false, exploitAvailable: false, epssScore: null, inKev: false, fixAvailable: false, fixVersion: null, depth: 3, directDependency: false },
        },
      },
    ],
    metadata: {
      totalPackages: 50, skippedPackages: 0, skippedReasons: [],
      advisorySource: 'OSV.dev API', advisoryCount: 100, confidence: 'HIGH', scanDurationMs: 500,
    },
    ignored: [],
  };
}

describe('Findings aggregator', () => {
  it('converts vulnerabilities to PolicyFindings', () => {
    const findings = aggregateFindings(makeReport());
    expect(findings).toHaveLength(2);
    expect(findings[0].findingType).toBe('vulnerability');
    expect(findings[1].findingType).toBe('vulnerability');
  });

  it('sets scope from isProduction', () => {
    const findings = aggregateFindings(makeReport());
    expect(findings[0].scope).toBe('production');
    expect(findings[1].scope).toBe('dev');
  });

  it('sets depth from dependencyPath length', () => {
    const findings = aggregateFindings(makeReport());
    expect(findings[0].depth).toBe(1);
    expect(findings[1].depth).toBe(3);
  });

  it('maps EPSS and KEV data', () => {
    const findings = aggregateFindings(makeReport());
    expect(findings[0].epss).toBe(0.7);
    expect(findings[0].kev).toBe(true);
    expect(findings[1].epss).toBeUndefined();
    expect(findings[1].kev).toBe(false);
  });

  it('maps fix availability', () => {
    const findings = aggregateFindings(makeReport());
    expect(findings[0].fixAvailable).toBe(true);
    expect(findings[1].fixAvailable).toBe(false);
  });
});
