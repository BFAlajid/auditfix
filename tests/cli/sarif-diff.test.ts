import { describe, it, expect } from 'vitest';
import { renderSarifDiffReport } from '../../src/cli/output/sarif.js';
import type { AuditReport, ScoredVulnerability } from '../../src/types/report.js';
import type { Advisory } from '../../src/types/advisory.js';

function makeAdvisory(id: string): Advisory {
  return {
    id,
    aliases: [],
    summary: `Vulnerability ${id}`,
    details: '',
    severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
    affectedRange: '<2.0.0',
    fixVersion: '2.0.0',
    publishedAt: '2024-01-01',
    modifiedAt: '2024-01-01',
    references: [],
    source: 'osv-api',
  };
}

function makeVuln(id: string, pkg: string, version: string): ScoredVulnerability {
  return {
    match: {
      advisory: makeAdvisory(id),
      package: pkg,
      installedVersion: version,
      dependencyPath: [pkg],
      isProduction: true,
    },
    risk: {
      score: 70,
      label: 'high',
      factors: {
        cvssScore: 7.5,
        cvssVector: '',
        productionReachable: true,
        directlyImported: false,
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

function makeReport(vulns: ScoredVulnerability[]): AuditReport {
  return {
    vulnerabilities: vulns,
    metadata: {
      totalPackages: 50,
      skippedPackages: 0,
      skippedReasons: [],
      advisorySource: 'test',
      advisoryCount: vulns.length,
      confidence: 'HIGH',
      scanDurationMs: 100,
      lockfileType: 'npm-v3',
    },
    ignored: [],
  };
}

describe('SARIF diff mode', () => {
  it('excludes baseline vulns from output', () => {
    const shared = makeVuln('GHSA-0001', 'lodash', '4.17.20');
    const baseline = makeReport([shared]);
    const current = makeReport([shared, makeVuln('GHSA-0002', 'express', '4.17.1')]);

    const sarif = JSON.parse(renderSarifDiffReport(current, baseline, '2.0.0'));
    expect(sarif.runs[0].results).toHaveLength(1);
    expect(sarif.runs[0].results[0].ruleId).toBe('GHSA-0002');
  });

  it('includes all vulns when baseline is empty', () => {
    const baseline = makeReport([]);
    const current = makeReport([
      makeVuln('GHSA-0001', 'lodash', '4.17.20'),
      makeVuln('GHSA-0002', 'express', '4.17.1'),
    ]);

    const sarif = JSON.parse(renderSarifDiffReport(current, baseline, '2.0.0'));
    expect(sarif.runs[0].results).toHaveLength(2);
  });

  it('returns empty results when all vulns are in baseline', () => {
    const vulns = [makeVuln('GHSA-0001', 'lodash', '4.17.20')];
    const baseline = makeReport(vulns);
    const current = makeReport(vulns);

    const sarif = JSON.parse(renderSarifDiffReport(current, baseline, '2.0.0'));
    expect(sarif.runs[0].results).toHaveLength(0);
  });

  it('matches by advisory + package + version', () => {
    // Same advisory, different version = different vuln
    const baseline = makeReport([makeVuln('GHSA-0001', 'lodash', '4.17.20')]);
    const current = makeReport([makeVuln('GHSA-0001', 'lodash', '4.17.19')]);

    const sarif = JSON.parse(renderSarifDiffReport(current, baseline, '2.0.0'));
    expect(sarif.runs[0].results).toHaveLength(1);
  });

  it('generates valid SARIF structure', () => {
    const baseline = makeReport([]);
    const current = makeReport([makeVuln('GHSA-0001', 'lodash', '4.17.20')]);

    const sarif = JSON.parse(renderSarifDiffReport(current, baseline, '2.0.0'));
    expect(sarif.$schema).toContain('sarif');
    expect(sarif.version).toBe('2.1.0');
    expect(sarif.runs[0].tool.driver.name).toBe('auditfix');
  });
});
