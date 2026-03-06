import { describe, it, expect } from 'vitest';
import { diffReports } from '../../src/core/diff.js';

function makeReport(vulns: Array<{ id: string; pkg: string; ver: string; sev: string; score: number }>) {
  return {
    vulnerabilities: vulns.map(v => ({
      id: v.id,
      package: v.pkg,
      installedVersion: v.ver,
      severity: v.sev,
      score: v.score,
    })),
  };
}

describe('Scan diff', () => {
  it('detects new vulnerabilities', () => {
    const baseline = makeReport([
      { id: 'GHSA-1', pkg: 'lodash', ver: '4.17.20', sev: 'high', score: 70 },
    ]);
    const current = makeReport([
      { id: 'GHSA-1', pkg: 'lodash', ver: '4.17.20', sev: 'high', score: 70 },
      { id: 'GHSA-2', pkg: 'express', ver: '4.17.1', sev: 'medium', score: 50 },
    ]);

    const diff = diffReports(baseline, current);

    expect(diff.added).toHaveLength(1);
    expect(diff.added[0].id).toBe('GHSA-2');
    expect(diff.removed).toHaveLength(0);
    expect(diff.unchanged).toHaveLength(1);
    expect(diff.summary.improved).toBe(false);
  });

  it('detects fixed vulnerabilities', () => {
    const baseline = makeReport([
      { id: 'GHSA-1', pkg: 'lodash', ver: '4.17.20', sev: 'high', score: 70 },
      { id: 'GHSA-2', pkg: 'express', ver: '4.17.1', sev: 'medium', score: 50 },
    ]);
    const current = makeReport([
      { id: 'GHSA-1', pkg: 'lodash', ver: '4.17.20', sev: 'high', score: 70 },
    ]);

    const diff = diffReports(baseline, current);

    expect(diff.added).toHaveLength(0);
    expect(diff.removed).toHaveLength(1);
    expect(diff.removed[0].id).toBe('GHSA-2');
    expect(diff.summary.improved).toBe(true);
  });

  it('handles identical reports', () => {
    const report = makeReport([
      { id: 'GHSA-1', pkg: 'lodash', ver: '4.17.20', sev: 'high', score: 70 },
    ]);

    const diff = diffReports(report, report);

    expect(diff.added).toHaveLength(0);
    expect(diff.removed).toHaveLength(0);
    expect(diff.unchanged).toHaveLength(1);
    expect(diff.summary.improved).toBe(false);
  });

  it('handles empty baseline', () => {
    const baseline = makeReport([]);
    const current = makeReport([
      { id: 'GHSA-1', pkg: 'lodash', ver: '4.17.20', sev: 'high', score: 70 },
    ]);

    const diff = diffReports(baseline, current);

    expect(diff.added).toHaveLength(1);
    expect(diff.removed).toHaveLength(0);
  });

  it('handles empty current', () => {
    const baseline = makeReport([
      { id: 'GHSA-1', pkg: 'lodash', ver: '4.17.20', sev: 'high', score: 70 },
    ]);
    const current = makeReport([]);

    const diff = diffReports(baseline, current);

    expect(diff.added).toHaveLength(0);
    expect(diff.removed).toHaveLength(1);
    expect(diff.summary.improved).toBe(true);
  });
});
