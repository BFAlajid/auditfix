import { describe, it, expect } from 'vitest';
import { planFixes } from '../../src/core/fixer/safe-update.js';
import type { ScoredVulnerability } from '../../src/types/report.js';
import type { DependencyGraph, DependencyNode } from '../../src/types/package.js';
import type { Advisory, AdvisoryMatch } from '../../src/types/advisory.js';

// ---------------------------------------------------------------------------
// Helpers to build mock data
// ---------------------------------------------------------------------------

function makeAdvisory(overrides: Partial<Advisory> = {}): Advisory {
  return {
    id: 'GHSA-test-test-test',
    aliases: ['CVE-2024-0001'],
    summary: 'Test advisory',
    details: '',
    severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
    affectedRange: '>=1.0.0 <2.0.0',
    fixVersion: '2.0.0',
    publishedAt: '2024-01-01',
    modifiedAt: '2024-01-01',
    references: [],
    source: 'osv-api',
    ...overrides,
  };
}

function makeMatch(overrides: Partial<AdvisoryMatch> = {}): AdvisoryMatch {
  return {
    advisory: makeAdvisory(),
    package: 'vulnerable-pkg',
    installedVersion: '1.5.0',
    dependencyPath: ['vulnerable-pkg'],
    isProduction: true,
    ...overrides,
  };
}

function makeVuln(overrides: {
  packageName?: string;
  installedVersion?: string;
  fixVersion?: string | null;
  score?: number;
  label?: 'critical' | 'high' | 'medium' | 'low' | 'info';
  advisoryId?: string;
} = {}): ScoredVulnerability {
  const fixVersion = overrides.fixVersion !== undefined ? overrides.fixVersion : '1.5.1';
  return {
    match: makeMatch({
      package: overrides.packageName ?? 'vulnerable-pkg',
      installedVersion: overrides.installedVersion ?? '1.5.0',
      advisory: makeAdvisory({
        id: overrides.advisoryId ?? 'GHSA-test-test-test',
        fixVersion,
      }),
    }),
    risk: {
      score: overrides.score ?? 75,
      label: overrides.label ?? 'high',
      factors: {
        cvssScore: 9.8,
        cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
        productionReachable: true,
        directlyImported: false,
        exploitAvailable: false,
        epssScore: null,
        inKev: false,
        fixAvailable: fixVersion !== null,
        fixVersion,
        depth: 1,
        directDependency: true,
      },
    },
  };
}

function makeNode(overrides: Partial<DependencyNode> = {}): DependencyNode {
  return {
    name: 'vulnerable-pkg',
    version: '1.5.0',
    resolved: 'https://registry.npmjs.org/vulnerable-pkg/-/vulnerable-pkg-1.5.0.tgz',
    integrity: 'sha512-abc123',
    dependencies: [],
    isProduction: true,
    isDev: false,
    isOptional: false,
    depth: 1,
    dependencyPath: ['vulnerable-pkg'],
    ...overrides,
  };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('planFixes', () => {
  it('classifies vuln as safe when fix version is within direct dependency declared range', () => {
    const vuln = makeVuln({
      packageName: 'lodash',
      installedVersion: '4.17.15',
      fixVersion: '4.17.21',
    });
    const graph: DependencyGraph = new Map();
    const packageJsonDeps = { lodash: '^4.17.0' };

    const plan = planFixes([vuln], graph, packageJsonDeps);

    expect(plan.safe).toHaveLength(1);
    expect(plan.safe[0].packageName).toBe('lodash');
    expect(plan.safe[0].fixVersion).toBe('4.17.21');
    expect(plan.safe[0].reason).toBe('direct-dependency');
    expect(plan.breaking).toHaveLength(0);
    expect(plan.noFix).toHaveLength(0);
  });

  it('classifies vuln as breaking when fix version is outside direct dependency declared range', () => {
    const vuln = makeVuln({
      packageName: 'express',
      installedVersion: '3.21.2',
      fixVersion: '4.18.2',
    });
    const graph: DependencyGraph = new Map();
    const packageJsonDeps = { express: '~3.21.0' };

    const plan = planFixes([vuln], graph, packageJsonDeps);

    expect(plan.breaking).toHaveLength(1);
    expect(plan.breaking[0].packageName).toBe('express');
    expect(plan.breaking[0].fixVersion).toBe('4.18.2');
    expect(plan.breaking[0].reason).toContain('outside declared range');
    expect(plan.safe).toHaveLength(0);
    expect(plan.noFix).toHaveLength(0);
  });

  it('classifies vuln as noFix when no fix version is available', () => {
    const vuln = makeVuln({
      packageName: 'unfixable-pkg',
      installedVersion: '1.0.0',
      fixVersion: null,
    });
    const graph: DependencyGraph = new Map();
    const packageJsonDeps = {};

    const plan = planFixes([vuln], graph, packageJsonDeps);

    expect(plan.noFix).toHaveLength(1);
    expect(plan.noFix[0].packageName).toBe('unfixable-pkg');
    expect(plan.noFix[0].currentVersion).toBe('1.0.0');
    expect(plan.safe).toHaveLength(0);
    expect(plan.breaking).toHaveLength(0);
  });

  it('classifies transitive dep with same-major fix as safe', () => {
    const vuln = makeVuln({
      packageName: 'minimist',
      installedVersion: '1.2.5',
      fixVersion: '1.2.8',
    });
    const graph: DependencyGraph = new Map();
    graph.set('minimist@1.2.5', makeNode({
      name: 'minimist',
      version: '1.2.5',
      depth: 2,
      dependencyPath: ['mkdirp', 'minimist'],
    }));
    // Not in packageJsonDeps (transitive)
    const packageJsonDeps = {};

    const plan = planFixes([vuln], graph, packageJsonDeps);

    expect(plan.safe).toHaveLength(1);
    expect(plan.safe[0].packageName).toBe('minimist');
    expect(plan.safe[0].fixVersion).toBe('1.2.8');
    expect(plan.safe[0].reason).toBe('within-parent-range');
    expect(plan.breaking).toHaveLength(0);
  });

  it('classifies transitive dep with major version bump as breaking', () => {
    const vuln = makeVuln({
      packageName: 'glob-parent',
      installedVersion: '3.1.0',
      fixVersion: '5.1.2',
    });
    const graph: DependencyGraph = new Map();
    graph.set('glob-parent@3.1.0', makeNode({
      name: 'glob-parent',
      version: '3.1.0',
      depth: 3,
      dependencyPath: ['chokidar', 'glob-parent'],
    }));
    const packageJsonDeps = {};

    const plan = planFixes([vuln], graph, packageJsonDeps);

    expect(plan.breaking).toHaveLength(1);
    expect(plan.breaking[0].packageName).toBe('glob-parent');
    expect(plan.breaking[0].reason).toContain('major version bump');
    expect(plan.safe).toHaveLength(0);
  });

  it('deduplicates multiple vulns for same package (highest severity wins)', () => {
    const lowVuln = makeVuln({
      packageName: 'qs',
      installedVersion: '6.5.2',
      fixVersion: '6.5.3',
      score: 30,
      label: 'low',
      advisoryId: 'GHSA-aaaa-bbbb-cccc',
    });
    const highVuln = makeVuln({
      packageName: 'qs',
      installedVersion: '6.5.2',
      fixVersion: '6.5.3',
      score: 85,
      label: 'critical',
      advisoryId: 'GHSA-dddd-eeee-ffff',
    });
    const graph: DependencyGraph = new Map();
    const packageJsonDeps = { qs: '^6.5.0' };

    const plan = planFixes([lowVuln, highVuln], graph, packageJsonDeps);

    // Only one entry for 'qs', not two
    expect(plan.safe).toHaveLength(1);
    expect(plan.safe[0].packageName).toBe('qs');
    // The high-score vuln should be the one kept
    expect(plan.safe[0].vuln.risk.score).toBe(85);
  });

  it('returns empty plan for empty vulns array', () => {
    const graph: DependencyGraph = new Map();
    const packageJsonDeps = {};

    const plan = planFixes([], graph, packageJsonDeps);

    expect(plan.safe).toHaveLength(0);
    expect(plan.breaking).toHaveLength(0);
    expect(plan.noFix).toHaveLength(0);
  });
});
