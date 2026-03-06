import { describe, it, expect } from 'vitest';
import { renderSarifReport } from '../../src/cli/output/sarif.js';
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
  advisoryId?: string;
  label: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cvssScore?: number;
  isProduction?: boolean;
  pkg?: string;
  fixVersion?: string | null;
}): ScoredVulnerability {
  const match: AdvisoryMatch = {
    advisory: makeAdvisory({
      id: overrides.advisoryId ?? 'GHSA-test-test-test',
      summary: `Vulnerability in ${overrides.pkg ?? 'test-pkg'}`,
    }),
    package: overrides.pkg ?? 'test-pkg',
    installedVersion: '1.0.0',
    dependencyPath: [overrides.pkg ?? 'test-pkg'],
    isProduction: overrides.isProduction ?? true,
  };

  return {
    match,
    risk: {
      score: 50,
      label: overrides.label,
      factors: {
        cvssScore: overrides.cvssScore ?? 7.5,
        cvssVector: '',
        productionReachable: overrides.isProduction ?? true,
        directlyImported: false,
        exploitAvailable: false,
        epssScore: null,
        inKev: false,
        fixAvailable: overrides.fixVersion != null,
        fixVersion: overrides.fixVersion ?? null,
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

describe('renderSarifReport', () => {
  it('generates valid SARIF structure with $schema and version 2.1.0', () => {
    const report = makeReport({ vulns: [makeVuln({ label: 'high' })] });
    const output = JSON.parse(renderSarifReport(report, '0.1.0'));

    expect(output.$schema).toBe(
      'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json',
    );
    expect(output.version).toBe('2.1.0');
    expect(output.runs).toHaveLength(1);
    expect(output.runs[0].tool.driver.name).toBe('auditfix');
    expect(output.runs[0].tool.driver.version).toBe('0.1.0');
  });

  it('rules array contains unique advisory IDs (no duplicates)', () => {
    const report = makeReport({
      vulns: [
        makeVuln({ advisoryId: 'GHSA-aaaa-bbbb-cccc', label: 'high', pkg: 'pkg-a' }),
        makeVuln({ advisoryId: 'GHSA-aaaa-bbbb-cccc', label: 'high', pkg: 'pkg-b' }),
        makeVuln({ advisoryId: 'GHSA-dddd-eeee-ffff', label: 'medium', pkg: 'pkg-c' }),
      ],
    });
    const output = JSON.parse(renderSarifReport(report, '0.1.0'));

    const rules = output.runs[0].tool.driver.rules;
    expect(rules).toHaveLength(2);

    const ruleIds = rules.map((r: { id: string }) => r.id);
    expect(ruleIds).toContain('GHSA-aaaa-bbbb-cccc');
    expect(ruleIds).toContain('GHSA-dddd-eeee-ffff');

    // Results still have 3 entries (one per vulnerability)
    expect(output.runs[0].results).toHaveLength(3);
  });

  it('results reference correct ruleIndex', () => {
    const report = makeReport({
      vulns: [
        makeVuln({ advisoryId: 'GHSA-aaaa-bbbb-cccc', label: 'high', pkg: 'pkg-a' }),
        makeVuln({ advisoryId: 'GHSA-dddd-eeee-ffff', label: 'medium', pkg: 'pkg-b' }),
        makeVuln({ advisoryId: 'GHSA-aaaa-bbbb-cccc', label: 'high', pkg: 'pkg-c' }),
      ],
    });
    const output = JSON.parse(renderSarifReport(report, '0.1.0'));

    const rules = output.runs[0].tool.driver.rules;
    const results = output.runs[0].results;

    // First result references first rule (GHSA-aaaa-bbbb-cccc at index 0)
    expect(results[0].ruleId).toBe('GHSA-aaaa-bbbb-cccc');
    expect(results[0].ruleIndex).toBe(0);
    expect(rules[results[0].ruleIndex].id).toBe('GHSA-aaaa-bbbb-cccc');

    // Second result references second rule (GHSA-dddd-eeee-ffff at index 1)
    expect(results[1].ruleId).toBe('GHSA-dddd-eeee-ffff');
    expect(results[1].ruleIndex).toBe(1);
    expect(rules[results[1].ruleIndex].id).toBe('GHSA-dddd-eeee-ffff');

    // Third result references first rule again
    expect(results[2].ruleId).toBe('GHSA-aaaa-bbbb-cccc');
    expect(results[2].ruleIndex).toBe(0);
  });

  it('maps severity levels correctly: critical->error, high->error, medium->warning, low->note, info->note', () => {
    const report = makeReport({
      vulns: [
        makeVuln({ advisoryId: 'GHSA-0001-0001-0001', label: 'critical', cvssScore: 9.8 }),
        makeVuln({ advisoryId: 'GHSA-0002-0002-0002', label: 'high', cvssScore: 7.5 }),
        makeVuln({ advisoryId: 'GHSA-0003-0003-0003', label: 'medium', cvssScore: 5.0 }),
        makeVuln({ advisoryId: 'GHSA-0004-0004-0004', label: 'low', cvssScore: 2.0 }),
        makeVuln({ advisoryId: 'GHSA-0005-0005-0005', label: 'info', cvssScore: 0.0 }),
      ],
    });
    const output = JSON.parse(renderSarifReport(report, '0.1.0'));
    const results = output.runs[0].results;

    expect(results[0].level).toBe('error');    // critical
    expect(results[1].level).toBe('error');    // high
    expect(results[2].level).toBe('warning');  // medium
    expect(results[3].level).toBe('note');     // low
    expect(results[4].level).toBe('note');     // info
  });

  it('security-severity is a float string matching CVSS score', () => {
    const report = makeReport({
      vulns: [
        makeVuln({ advisoryId: 'GHSA-0001-0001-0001', label: 'critical', cvssScore: 9.8 }),
        makeVuln({ advisoryId: 'GHSA-0002-0002-0002', label: 'high', cvssScore: 7.5 }),
        makeVuln({ advisoryId: 'GHSA-0003-0003-0003', label: 'low', cvssScore: 0.0 }),
      ],
    });
    const output = JSON.parse(renderSarifReport(report, '0.1.0'));
    const rules = output.runs[0].tool.driver.rules;

    expect(rules[0].properties['security-severity']).toBe('9.8');
    expect(rules[1].properties['security-severity']).toBe('7.5');
    expect(rules[2].properties['security-severity']).toBe('0.0');

    // Verify they are strings, not numbers
    for (const rule of rules) {
      expect(typeof rule.properties['security-severity']).toBe('string');
    }
  });

  it('empty report produces valid SARIF with empty results', () => {
    const report = makeReport({ vulns: [] });
    const output = JSON.parse(renderSarifReport(report, '0.1.0'));

    expect(output.$schema).toBeDefined();
    expect(output.version).toBe('2.1.0');
    expect(output.runs).toHaveLength(1);
    expect(output.runs[0].tool.driver.name).toBe('auditfix');
    expect(output.runs[0].tool.driver.rules).toEqual([]);
    expect(output.runs[0].results).toEqual([]);
  });

  it('locations point to lockfile URI', () => {
    const report = makeReport({
      vulns: [makeVuln({ label: 'high' })],
    });
    const output = JSON.parse(renderSarifReport(report, '0.1.0'));
    const result = output.runs[0].results[0];

    expect(result.locations).toHaveLength(1);
    expect(result.locations[0].physicalLocation.artifactLocation.uri).toBe('package-lock.json');
  });
});
