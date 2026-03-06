import { describe, it, expect } from 'vitest';
import { getExitCode } from '../../src/cli/output/terminal.js';
import type { AuditReport, ScoredVulnerability, ConfidenceLevel } from '../../src/types/report.js';
import type { AdvisoryMatch, Advisory } from '../../src/types/advisory.js';

function makeAdvisory(overrides?: Partial<Advisory>): Advisory {
  return {
    id: 'GHSA-test-test-test',
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

function makeVuln(overrides: {
  isProduction: boolean;
  label: 'critical' | 'high' | 'medium' | 'low' | 'info';
}): ScoredVulnerability {
  const match: AdvisoryMatch = {
    advisory: makeAdvisory(),
    package: 'test-pkg',
    installedVersion: '1.0.0',
    dependencyPath: ['test-pkg'],
    isProduction: overrides.isProduction,
  };

  return {
    match,
    risk: {
      score: 50,
      label: overrides.label,
      factors: {
        cvssScore: 7.5,
        cvssVector: '',
        productionReachable: overrides.isProduction,
        exploitAvailable: false,
        fixAvailable: false,
        fixVersion: null,
        depth: 1,
        directDependency: true,
      },
    },
  };
}

function makeReport(overrides: {
  vulns?: ScoredVulnerability[];
  confidence?: ConfidenceLevel;
}): AuditReport {
  return {
    vulnerabilities: overrides.vulns ?? [],
    metadata: {
      totalPackages: 100,
      skippedPackages: 0,
      skippedReasons: [],
      advisorySource: 'OSV.dev API (real-time)',
      advisoryCount: 10,
      confidence: overrides.confidence ?? 'HIGH',
      scanDurationMs: 500,
    },
    ignored: [],
  };
}

describe('exit codes', () => {
  it('returns 0 when no vulnerabilities found', () => {
    const report = makeReport({ vulns: [] });
    expect(getExitCode(report)).toBe(0);
  });

  it('returns 0 when only dev vulnerabilities found', () => {
    const report = makeReport({
      vulns: [
        makeVuln({ isProduction: false, label: 'high' }),
        makeVuln({ isProduction: false, label: 'critical' }),
      ],
    });
    expect(getExitCode(report)).toBe(0);
  });

  it('returns 1 when production critical vulnerability found', () => {
    const report = makeReport({
      vulns: [makeVuln({ isProduction: true, label: 'critical' })],
    });
    expect(getExitCode(report)).toBe(1);
  });

  it('returns 1 when production high vulnerability found', () => {
    const report = makeReport({
      vulns: [makeVuln({ isProduction: true, label: 'high' })],
    });
    expect(getExitCode(report)).toBe(1);
  });

  it('returns 0 when production medium vulnerability found (not critical/high)', () => {
    const report = makeReport({
      vulns: [makeVuln({ isProduction: true, label: 'medium' })],
    });
    expect(getExitCode(report)).toBe(0);
  });

  it('returns 0 when production low vulnerability found', () => {
    const report = makeReport({
      vulns: [makeVuln({ isProduction: true, label: 'low' })],
    });
    expect(getExitCode(report)).toBe(0);
  });

  it('returns 2 when confidence is UNRELIABLE', () => {
    const report = makeReport({
      confidence: 'UNRELIABLE',
      vulns: [],
    });
    expect(getExitCode(report)).toBe(2);
  });

  it('returns 2 for UNRELIABLE even with no vulns (refuses to say safe)', () => {
    const report = makeReport({ confidence: 'UNRELIABLE' });
    expect(getExitCode(report)).toBe(2);
  });

  it('returns 2 for UNRELIABLE even with production vulns (tool error takes precedence)', () => {
    const report = makeReport({
      confidence: 'UNRELIABLE',
      vulns: [makeVuln({ isProduction: true, label: 'critical' })],
    });
    expect(getExitCode(report)).toBe(2);
  });

  it('returns 0 with HIGH confidence and only low/medium vulns', () => {
    const report = makeReport({
      confidence: 'HIGH',
      vulns: [
        makeVuln({ isProduction: true, label: 'medium' }),
        makeVuln({ isProduction: true, label: 'low' }),
      ],
    });
    expect(getExitCode(report)).toBe(0);
  });
});
