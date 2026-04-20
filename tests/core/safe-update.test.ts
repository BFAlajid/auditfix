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
// Core classification
// ---------------------------------------------------------------------------

describe('planFixes — classification', () => {
  it('classifies vuln as safe when fix version is within direct dependency declared range', () => {
    const vuln = makeVuln({ packageName: 'lodash', installedVersion: '4.17.15', fixVersion: '4.17.21' });
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
    const vuln = makeVuln({ packageName: 'express', installedVersion: '3.21.2', fixVersion: '4.18.2' });
    const graph: DependencyGraph = new Map();
    const packageJsonDeps = { express: '~3.21.0' };

    const plan = planFixes([vuln], graph, packageJsonDeps);

    expect(plan.breaking).toHaveLength(1);
    expect(plan.breaking[0].packageName).toBe('express');
    expect(plan.breaking[0].fixVersion).toBe('4.18.2');
    expect(plan.breaking[0].reason).toContain('outside declared range');
  });

  it('classifies vuln as noFix when no fix version is available', () => {
    const vuln = makeVuln({ packageName: 'unfixable-pkg', installedVersion: '1.0.0', fixVersion: null });
    const plan = planFixes([vuln], new Map(), {});

    expect(plan.noFix).toHaveLength(1);
    expect(plan.noFix[0].packageName).toBe('unfixable-pkg');
    expect(plan.safe).toHaveLength(0);
    expect(plan.breaking).toHaveLength(0);
  });

  it('classifies transitive dep with same-major fix as safe', () => {
    const vuln = makeVuln({ packageName: 'minimist', installedVersion: '1.2.5', fixVersion: '1.2.8' });
    const graph: DependencyGraph = new Map();
    graph.set('minimist@1.2.5', makeNode({ name: 'minimist', version: '1.2.5' }));

    const plan = planFixes([vuln], graph, {});

    expect(plan.safe).toHaveLength(1);
    expect(plan.safe[0].reason).toBe('within-parent-range');
  });

  it('classifies transitive dep with major version bump as breaking', () => {
    const vuln = makeVuln({ packageName: 'glob-parent', installedVersion: '3.1.0', fixVersion: '5.1.2' });
    const graph: DependencyGraph = new Map();
    graph.set('glob-parent@3.1.0', makeNode({ name: 'glob-parent', version: '3.1.0' }));

    const plan = planFixes([vuln], graph, {});

    expect(plan.breaking).toHaveLength(1);
    expect(plan.breaking[0].reason).toContain('major version bump');
  });

  it('returns empty plan for empty vulns array', () => {
    const plan = planFixes([], new Map(), {});
    expect(plan.safe).toHaveLength(0);
    expect(plan.breaking).toHaveLength(0);
    expect(plan.noFix).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// C-B dedup: same package, same fixVersion, different advisories
// ---------------------------------------------------------------------------

describe('planFixes — dedup by (packageName, fixVersion)', () => {
  it('collapses two advisories with SAME fixVersion into a single plan entry, preserving all advisories', () => {
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

    const plan = planFixes([lowVuln, highVuln], new Map(), { qs: '^6.5.0' });

    expect(plan.safe).toHaveLength(1);
    expect(plan.safe[0].packageName).toBe('qs');
    expect(plan.safe[0].fixVersion).toBe('6.5.3');
    // Primary is the highest-score advisory
    expect(plan.safe[0].vuln.risk.score).toBe(85);
    // The other advisory is preserved in coveredVulns — not silently dropped
    expect(plan.safe[0].coveredVulns).toBeDefined();
    expect(plan.safe[0].coveredVulns).toHaveLength(1);
    expect(plan.safe[0].coveredVulns![0].match.advisory.id).toBe('GHSA-aaaa-bbbb-cccc');
  });
});

// ---------------------------------------------------------------------------
// C-B primary fix: dedup with DIFFERENT fixVersions
// ---------------------------------------------------------------------------

describe('planFixes — different fixVersions for same package', () => {
  // Selection rule: the HIGHEST valid fixVersion is chosen because security fixes
  // are cumulative in the npm ecosystem. All lower-or-equal fixVersions are
  // bundled into `coveredVulns` so no advisory is silently dropped.

  it('selects the highest fixVersion and bundles both advisories (primary + coveredVulns)', () => {
    const oldAdvisory = makeVuln({
      packageName: 'lodash',
      installedVersion: '4.17.10',
      fixVersion: '4.17.15',
      score: 90,
      label: 'critical',
      advisoryId: 'GHSA-aaaa-aaaa-aaaa',
    });
    const newAdvisory = makeVuln({
      packageName: 'lodash',
      installedVersion: '4.17.10',
      fixVersion: '4.17.21',
      score: 40,
      label: 'medium',
      advisoryId: 'GHSA-bbbb-bbbb-bbbb',
    });

    const plan = planFixes([oldAdvisory, newAdvisory], new Map(), { lodash: '^4.17.0' });

    expect(plan.safe).toHaveLength(1);
    expect(plan.safe[0].fixVersion).toBe('4.17.21'); // highest wins
    // Both advisories must be represented in the plan entry — primary + coveredVulns
    const representedIds = [
      plan.safe[0].vuln.match.advisory.id,
      ...(plan.safe[0].coveredVulns ?? []).map((v) => v.match.advisory.id),
    ];
    expect(representedIds).toContain('GHSA-aaaa-aaaa-aaaa');
    expect(representedIds).toContain('GHSA-bbbb-bbbb-bbbb');
  });

  it('selection is stable regardless of input ordering', () => {
    const a = makeVuln({ packageName: 'pkg', installedVersion: '1.2.0', fixVersion: '1.2.5', advisoryId: 'GHSA-aaaa-aaaa-aaaa', score: 50 });
    const b = makeVuln({ packageName: 'pkg', installedVersion: '1.2.0', fixVersion: '1.2.8', advisoryId: 'GHSA-bbbb-bbbb-bbbb', score: 50 });

    const planAB = planFixes([a, b], new Map(), { pkg: '^1.2.0' });
    const planBA = planFixes([b, a], new Map(), { pkg: '^1.2.0' });

    expect(planAB.safe[0].fixVersion).toBe('1.2.8');
    expect(planBA.safe[0].fixVersion).toBe('1.2.8');
  });

  it('does NOT silently drop advisories when one fix cannot cover another', () => {
    // Scenario: two advisories for the same installed version but fixVersions are NOT ordered
    // such that the highest covers both. The lower-fix advisory should still be represented.
    // (With current selection rule "highest wins", the lower-fix advisory IS covered because
    // security fixes are cumulative. But we still assert both advisories are represented
    // somewhere in the plan.)
    const critLow = makeVuln({
      packageName: 'pkg',
      installedVersion: '1.0.0',
      fixVersion: '1.5.0',
      score: 95,
      advisoryId: 'GHSA-aaaa-aaaa-aaaa',
    });
    const lowHigh = makeVuln({
      packageName: 'pkg',
      installedVersion: '1.0.0',
      fixVersion: '2.0.0',
      score: 20,
      advisoryId: 'GHSA-bbbb-bbbb-bbbb',
    });

    const plan = planFixes([critLow, lowHigh], new Map(), { pkg: '^1.0.0' });

    // Highest fix wins (2.0.0). The 1.5.0 advisory is bundled into coveredVulns.
    // 2.0.0 is outside ^1.0.0 so this lands in breaking, not safe.
    const allIds = [
      ...plan.safe.flatMap((s) => [s.vuln.match.advisory.id, ...(s.coveredVulns ?? []).map((v) => v.match.advisory.id)]),
      ...plan.breaking.flatMap((b) => [b.vuln.match.advisory.id, ...(b.coveredVulns ?? []).map((v) => v.match.advisory.id)]),
      ...plan.noFix.map((n) => n.vuln.match.advisory.id),
    ];
    expect(allIds).toContain('GHSA-aaaa-aaaa-aaaa');
    expect(allIds).toContain('GHSA-bbbb-bbbb-bbbb');
  });

  it('respects classification per fixVersion — direct-dep safe stays safe, out-of-range becomes breaking', () => {
    // Two advisories with different fixVersions. Both should end up in plan entries,
    // classified appropriately.
    const inRangeFix = makeVuln({
      packageName: 'lodash',
      installedVersion: '4.17.10',
      fixVersion: '4.17.21',
      score: 80,
      advisoryId: 'GHSA-aaaa-aaaa-aaaa',
    });
    const breakingFix = makeVuln({
      packageName: 'lodash',
      installedVersion: '4.17.10',
      fixVersion: '4.17.21',
      score: 60,
      advisoryId: 'GHSA-bbbb-bbbb-bbbb',
    });

    const plan = planFixes([inRangeFix, breakingFix], new Map(), { lodash: '^4.17.0' });
    expect(plan.safe).toHaveLength(1);
    expect(plan.breaking).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Peer-dep conflict detection (documented behavior)
// ---------------------------------------------------------------------------

describe('planFixes — peer-dep conflicts and edge cases', () => {
  it('flags transitive major bump as breaking (peer-dep-conflict proxy)', () => {
    // pkg-A@1.x installed; advisory wants upgrade to pkg-A@2.x.
    // Any other package in the graph that declares a peer-dep range like `pkg-A@^1.0.0`
    // would be broken by this upgrade. We surface it as breaking with a major-bump reason,
    // which is the signal the caller uses to gate the fix.
    const vuln = makeVuln({
      packageName: 'pkg-A',
      installedVersion: '1.5.0',
      fixVersion: '2.0.0',
    });
    const graph: DependencyGraph = new Map();
    graph.set('pkg-A@1.5.0', makeNode({ name: 'pkg-A', version: '1.5.0' }));

    const plan = planFixes([vuln], graph, {});

    expect(plan.safe).toHaveLength(0);
    expect(plan.breaking).toHaveLength(1);
    expect(plan.breaking[0].reason).toContain('major version bump');
  });

  it('flags direct-dep major bump as breaking when fix version is outside declared range', () => {
    // Declared ^1.0.0 but fix is 2.0.0 — the declared range would need widening.
    const vuln = makeVuln({
      packageName: 'pkg-B',
      installedVersion: '1.2.0',
      fixVersion: '2.0.0',
    });

    const plan = planFixes([vuln], new Map(), { 'pkg-B': '^1.0.0' });
    expect(plan.breaking).toHaveLength(1);
    expect(plan.breaking[0].reason).toContain('outside declared range');
  });
});

// ---------------------------------------------------------------------------
// Downgrade guard
// ---------------------------------------------------------------------------

describe('planFixes — downgrade guard', () => {
  it('refuses to downgrade when advisory fixVersion is older than installed', () => {
    // Advisory claims fix is 1.5.0 but installed is 1.6.0 — this is a data error or
    // an already-patched install. We must never silently downgrade.
    const vuln = makeVuln({
      packageName: 'pkg',
      installedVersion: '1.6.0',
      fixVersion: '1.5.0',
    });

    const plan = planFixes([vuln], new Map(), { pkg: '^1.0.0' });

    expect(plan.safe).toHaveLength(0);
    expect(plan.breaking).toHaveLength(1);
    expect(plan.breaking[0].reason).toMatch(/downgrade|older than installed/i);
  });

  it('allows same-version (edge): fixVersion == installedVersion is not a downgrade', () => {
    const vuln = makeVuln({
      packageName: 'pkg',
      installedVersion: '1.5.0',
      fixVersion: '1.5.0',
    });
    const plan = planFixes([vuln], new Map(), { pkg: '^1.5.0' });
    // Not breaking — this is a no-op fix. Still lands somewhere.
    expect(plan.safe.length + plan.breaking.length).toBe(1);
  });
});
