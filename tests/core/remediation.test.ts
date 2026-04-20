import { describe, it, expect } from 'vitest';
import { generateRemediationPlan } from '../../src/core/fixer/remediation.js';
import type { ScoredVulnerability } from '../../src/types/report.js';

function makeVuln(
  pkg: string,
  id: string,
  fixVersion: string | null,
  label: string = 'high',
  installedVersion: string = '1.0.0',
  isDirect: boolean = true,
): ScoredVulnerability {
  return {
    match: {
      advisory: {
        id,
        aliases: [],
        summary: '',
        details: '',
        severity: [],
        affectedRange: '',
        fixVersion,
        publishedAt: '',
        modifiedAt: '',
        references: [],
        source: 'osv-api',
      },
      package: pkg,
      installedVersion,
      isProduction: true,
      dependencyPath: [pkg],
    },
    risk: {
      score: 80,
      label: label as 'critical' | 'high' | 'medium' | 'low',
      factors: {
        cvssScore: 8,
        cvssVector: '',
        productionReachable: true,
        directlyImported: false,
        exploitAvailable: false,
        epssScore: null,
        inKev: false,
        fixAvailable: !!fixVersion,
        fixVersion,
        depth: 1,
        directDependency: isDirect,
      },
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

  // -------------------------------------------------------------------------
  // Additional coverage
  // -------------------------------------------------------------------------

  it('returns empty steps when all vulns are unfixable', () => {
    const vulns = [
      makeVuln('a', 'CVE-1', null),
      makeVuln('b', 'CVE-2', null),
    ];
    const plan = generateRemediationPlan(vulns);
    expect(plan.steps).toHaveLength(0);
    expect(plan.fixableVulns).toBe(0);
    expect(plan.unfixable).toEqual(['CVE-1', 'CVE-2']);
  });

  it('returns empty plan for empty input', () => {
    const plan = generateRemediationPlan([]);
    expect(plan.steps).toHaveLength(0);
    expect(plan.totalVulns).toBe(0);
    expect(plan.fixableVulns).toBe(0);
    expect(plan.unfixable).toEqual([]);
  });

  it('keeps separate steps for same package with different fix versions', () => {
    // In the remediation (guidance) view, different fixVersions are legitimately
    // distinct steps — the user may choose between them.
    const vulns = [
      makeVuln('pkg', 'CVE-1', '1.2.0'),
      makeVuln('pkg', 'CVE-2', '2.0.0'),
    ];
    const plan = generateRemediationPlan(vulns);

    expect(plan.steps).toHaveLength(2);
    const fixVersions = plan.steps.map((s) => s.fixVersion).sort();
    expect(fixVersions).toEqual(['1.2.0', '2.0.0']);
  });

  it('sorts direct dependencies ahead of transitive when impact score ties', () => {
    const transitive = makeVuln('trans-pkg', 'CVE-1', '1.0.1', 'high', '1.0.0', false);
    const direct = makeVuln('direct-pkg', 'CVE-2', '2.0.1', 'high', '2.0.0', true);

    const plan = generateRemediationPlan([transitive, direct]);

    expect(plan.steps).toHaveLength(2);
    expect(plan.steps[0].packageName).toBe('direct-pkg');
    expect(plan.steps[0].isDirect).toBe(true);
  });

  it('flags same-major bump as non-breaking', () => {
    const vuln = makeVuln('pkg', 'CVE-1', '1.2.5', 'high', '1.2.0');
    const plan = generateRemediationPlan([vuln]);
    expect(plan.steps[0].isBreaking).toBe(false);
  });

  it('counts all advisory IDs that share a (pkg, fixVersion) group', () => {
    const vulns = [
      makeVuln('pkg', 'CVE-A', '1.0.1'),
      makeVuln('pkg', 'CVE-B', '1.0.1'),
      makeVuln('pkg', 'CVE-C', '1.0.1'),
    ];
    const plan = generateRemediationPlan(vulns);
    expect(plan.steps).toHaveLength(1);
    expect(plan.steps[0].vulnsFixed.sort()).toEqual(['CVE-A', 'CVE-B', 'CVE-C']);
  });

  it('preserves totalVulns count including unfixable entries', () => {
    const vulns = [
      makeVuln('a', 'CVE-1', '1.0.1'),
      makeVuln('b', 'CVE-2', null),
      makeVuln('c', 'CVE-3', null),
    ];
    const plan = generateRemediationPlan(vulns);
    expect(plan.totalVulns).toBe(3);
    expect(plan.fixableVulns).toBe(1);
    expect(plan.unfixable).toHaveLength(2);
  });
});
