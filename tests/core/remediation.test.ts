import { describe, it, expect } from 'vitest';
import { generateRemediationPlan } from '../../src/core/fixer/remediation.js';
import type { ScoredVulnerability } from '../../src/types/report.js';

function makeVuln(pkg: string, id: string, fixVersion: string | null, label: string = 'high'): ScoredVulnerability {
  return {
    match: {
      advisory: { id, aliases: [], summary: '', details: '', severity: [], affectedRange: '', fixVersion, publishedAt: '', modifiedAt: '', references: [], source: 'osv-api' },
      package: pkg,
      installedVersion: '1.0.0',
      isProduction: true,
      dependencyPath: [pkg],
    },
    risk: {
      score: 80,
      label: label as 'critical' | 'high' | 'medium' | 'low',
      factors: { cvssScore: 8, cvssVector: '', productionReachable: true, directlyImported: false, exploitAvailable: false, epssScore: null, inKev: false, fixAvailable: !!fixVersion, fixVersion, depth: 1, directDependency: true },
    },
  };
}

describe('Guided remediation', () => {
  it('groups vulns by package+fix and ranks by impact', () => {
    const vulns = [
      makeVuln('lodash', 'CVE-2021-1', '4.17.21', 'critical'),
      makeVuln('lodash', 'CVE-2021-2', '4.17.21', 'high'),
      makeVuln('express', 'CVE-2022-1', '4.18.0', 'medium'),
    ];

    const plan = generateRemediationPlan(vulns);

    expect(plan.steps).toHaveLength(2);
    expect(plan.fixableVulns).toBe(3);
    // lodash should be first (impact: 10+5=15 vs express 2)
    expect(plan.steps[0].packageName).toBe('lodash');
    expect(plan.steps[0].vulnsFixed).toHaveLength(2);
  });

  it('separates unfixable vulns', () => {
    const vulns = [
      makeVuln('lodash', 'CVE-2021-1', '4.17.21'),
      makeVuln('bad-pkg', 'CVE-2022-1', null),
    ];

    const plan = generateRemediationPlan(vulns);

    expect(plan.fixableVulns).toBe(1);
    expect(plan.unfixable).toEqual(['CVE-2022-1']);
  });

  it('marks breaking version bumps', () => {
    const vuln = makeVuln('pkg', 'CVE-1', '2.0.0');
    const plan = generateRemediationPlan([vuln]);

    expect(plan.steps[0].isBreaking).toBe(true);
  });
});
