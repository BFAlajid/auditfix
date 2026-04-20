import { describe, it, expect } from 'vitest';
import { resolveFinalExitCode } from '../../src/core/exit-code.js';
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

function makeVuln(opts: {
  isProduction: boolean;
  label: 'critical' | 'high' | 'medium' | 'low' | 'info';
}): ScoredVulnerability {
  const match: AdvisoryMatch = {
    advisory: makeAdvisory(),
    package: 'test-pkg',
    installedVersion: '1.0.0',
    dependencyPath: ['test-pkg'],
    isProduction: opts.isProduction,
  };
  return {
    match,
    risk: {
      score: 50,
      label: opts.label,
      factors: {
        cvssScore: 7.5,
        cvssVector: '',
        productionReachable: opts.isProduction,
        directlyImported: false,
        exploitAvailable: false,
        epssScore: null,
        inKev: false,
        fixAvailable: false,
        fixVersion: null,
        depth: 1,
        directDependency: true,
      },
    },
  };
}

function makeReport(opts: {
  vulns?: ScoredVulnerability[];
  confidence?: ConfidenceLevel;
} = {}): AuditReport {
  return {
    vulnerabilities: opts.vulns ?? [],
    metadata: {
      totalPackages: 100,
      skippedPackages: 0,
      skippedReasons: [],
      advisorySource: 'OSV.dev API (real-time)',
      advisoryCount: 10,
      confidence: opts.confidence ?? 'HIGH',
      scanDurationMs: 500,
    },
    ignored: [],
  };
}

describe('resolveFinalExitCode — policy + fail-on combination matrix', () => {
  it('policy passes + no fail-on + no vulns -> 0', () => {
    expect(resolveFinalExitCode({ report: makeReport() })).toBe(0);
  });

  it('policy passes + no fail-on + prod high -> 1 (default production-high)', () => {
    const report = makeReport({ vulns: [makeVuln({ isProduction: true, label: 'high' })] });
    expect(resolveFinalExitCode({ report })).toBe(1);
  });

  it('policy FAILS + no fail-on + no vulns -> 1 (policy wins)', () => {
    expect(resolveFinalExitCode({ report: makeReport(), policyFailed: true })).toBe(1);
  });

  it('policy FAILS + --fail-on=high + no high vulns -> 1 (policy wins)', () => {
    // The failing case from the audit: strategy alone would say 0 (no prod high),
    // but policy gate must still fail the run.
    const report = makeReport({ vulns: [makeVuln({ isProduction: true, label: 'medium' })] });
    expect(resolveFinalExitCode({
      report,
      failOnStrategy: 'production-high',
      policyFailed: true,
    })).toBe(1);
  });

  it('policy passes + --fail-on=critical + has critical -> 1 (strategy wins)', () => {
    const report = makeReport({ vulns: [makeVuln({ isProduction: true, label: 'critical' })] });
    expect(resolveFinalExitCode({
      report,
      failOnStrategy: 'production-critical',
      policyFailed: false,
    })).toBe(1);
  });

  it('policy passes + --fail-on=critical + only prod high -> 0', () => {
    const report = makeReport({ vulns: [makeVuln({ isProduction: true, label: 'high' })] });
    expect(resolveFinalExitCode({
      report,
      failOnStrategy: 'production-critical',
      policyFailed: false,
    })).toBe(0);
  });

  it('policy FAILS + --fail-on=critical + has critical -> 1 (both agree)', () => {
    const report = makeReport({ vulns: [makeVuln({ isProduction: true, label: 'critical' })] });
    expect(resolveFinalExitCode({
      report,
      failOnStrategy: 'production-critical',
      policyFailed: true,
    })).toBe(1);
  });

  it('policy passes + --fail-on=any + no vulns -> 0', () => {
    expect(resolveFinalExitCode({
      report: makeReport(),
      failOnStrategy: 'any',
    })).toBe(0);
  });

  it('policy passes + --fail-on=any + low dev vuln -> 1', () => {
    const report = makeReport({ vulns: [makeVuln({ isProduction: false, label: 'low' })] });
    expect(resolveFinalExitCode({
      report,
      failOnStrategy: 'any',
    })).toBe(1);
  });

  it('UNRELIABLE always wins — overrides policy failure', () => {
    const report = makeReport({ confidence: 'UNRELIABLE' });
    expect(resolveFinalExitCode({ report, policyFailed: true })).toBe(2);
  });

  it('UNRELIABLE always wins — overrides strategy failure', () => {
    const report = makeReport({
      confidence: 'UNRELIABLE',
      vulns: [makeVuln({ isProduction: true, label: 'critical' })],
    });
    expect(resolveFinalExitCode({
      report,
      failOnStrategy: 'production-critical',
      policyFailed: false,
    })).toBe(2);
  });
});
