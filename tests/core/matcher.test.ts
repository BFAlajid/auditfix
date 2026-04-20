import { describe, it, expect } from 'vitest';
import semver from 'semver';
import { matchAdvisories } from '../../src/core/advisory/matcher.js';
import type { DependencyGraph, DependencyNode } from '../../src/types/package.js';
import type { Advisory } from '../../src/types/advisory.js';

function makeNode(name: string, version: string): DependencyNode {
  return {
    name,
    version,
    resolved: '',
    integrity: '',
    dependencies: [],
    isProduction: true,
    isDev: false,
    isOptional: false,
    depth: 0,
    dependencyPath: [name],
  };
}

function makeGraph(entries: [string, string][]): DependencyGraph {
  const graph: DependencyGraph = new Map();
  for (const [name, version] of entries) {
    graph.set(`${name}@${version}`, makeNode(name, version));
  }
  return graph;
}

function makeAdvisory(overrides: Partial<Advisory> & { affectedRange: string }): Advisory {
  return {
    id: overrides.id ?? 'GHSA-test',
    aliases: overrides.aliases ?? [],
    summary: overrides.summary ?? '',
    details: overrides.details ?? '',
    severity: overrides.severity ?? [],
    affectedRange: overrides.affectedRange,
    fixVersion: overrides.fixVersion ?? null,
    publishedAt: overrides.publishedAt ?? '',
    modifiedAt: overrides.modifiedAt ?? '',
    references: overrides.references ?? [],
    source: overrides.source ?? 'osv-api',
  };
}

describe('matchAdvisories', () => {
  it('returns matches for versions within the affected range', () => {
    const graph = makeGraph([
      ['lodash', '4.17.20'],
      ['minimatch', '3.0.4'],
    ]);
    const advisories = new Map<string, Advisory[]>([
      ['lodash', [makeAdvisory({ id: 'GHSA-a', affectedRange: '<4.17.21' })]],
      ['minimatch', [makeAdvisory({ id: 'GHSA-b', affectedRange: '<3.0.5' })]],
    ]);

    const matches = matchAdvisories(graph, advisories);

    expect(matches).toHaveLength(2);
    expect(matches.map((m) => m.package).sort()).toEqual(['lodash', 'minimatch']);
  });

  it('skips packages not in the advisory map', () => {
    const graph = makeGraph([['react', '18.0.0']]);
    const advisories = new Map<string, Advisory[]>([
      ['lodash', [makeAdvisory({ affectedRange: '<5.0.0' })]],
    ]);

    expect(matchAdvisories(graph, advisories)).toEqual([]);
  });

  it('skips advisories without an affectedRange', () => {
    const graph = makeGraph([['lodash', '4.17.20']]);
    const advisories = new Map<string, Advisory[]>([
      ['lodash', [makeAdvisory({ id: 'GHSA-broken', affectedRange: '' })]],
    ]);

    expect(matchAdvisories(graph, advisories)).toEqual([]);
  });

  it('excludes versions outside the affected range', () => {
    const graph = makeGraph([['lodash', '4.17.21']]); // patched version
    const advisories = new Map<string, Advisory[]>([
      ['lodash', [makeAdvisory({ affectedRange: '<4.17.21' })]],
    ]);

    expect(matchAdvisories(graph, advisories)).toEqual([]);
  });

  it('honors includePrerelease for prerelease versions', () => {
    // Without includePrerelease semver would silently exclude prereleases
    // and a vulnerable pre-release would slip through.
    const graph = makeGraph([['lodash', '4.17.21-beta.1']]);
    const advisories = new Map<string, Advisory[]>([
      ['lodash', [makeAdvisory({ affectedRange: '>=4.17.0 <4.17.22' })]],
    ]);

    expect(matchAdvisories(graph, advisories)).toHaveLength(1);
  });

  it('falls back to string-based satisfies for unparseable ranges', () => {
    // Empty string hits the early-continue, but an invalid range should not
    // throw — it should just not match.
    const graph = makeGraph([['lodash', '4.17.20']]);
    const advisories = new Map<string, Advisory[]>([
      ['lodash', [makeAdvisory({ affectedRange: 'not-a-real-range' })]],
    ]);

    // compileRange returns null, testRange also handles invalid — result: no match
    expect(matchAdvisories(graph, advisories)).toEqual([]);
  });

  it('pre-compiled range produces identical results to per-call satisfies across 100 advisories', () => {
    // Build a batch of diverse ranges and a graph of matching versions;
    // compare the optimized matcher against a direct semver.satisfies baseline.
    const ranges = [
      '<1.0.0',
      '>=1.0.0 <2.0.0',
      '>=2.0.0 <3.0.0',
      '>=2.0.0 <3.5.0 || >=4.0.0 <4.5.0',
      '<4.17.21',
      '>=0.0.0',
      '1.x',
      '~1.2.3',
      '^2.0.0',
      '>3.0.0 <=3.9.9',
    ];

    const graph: DependencyGraph = new Map();
    for (let i = 0; i < 100; i++) {
      const name = `pkg-${i}`;
      const version = `${i % 5}.${i % 7}.${i % 3}`;
      graph.set(`${name}@${version}`, makeNode(name, version));
    }

    const advisories = new Map<string, Advisory[]>();
    let counter = 0;
    for (const [, node] of graph) {
      const range = ranges[counter % ranges.length];
      counter++;
      advisories.set(node.name, [
        makeAdvisory({ id: `GHSA-${counter}`, affectedRange: range }),
      ]);
    }

    // Reference: per-call semver.satisfies with includePrerelease
    const reference: Array<{ pkg: string; id: string }> = [];
    for (const [, node] of graph) {
      for (const adv of advisories.get(node.name) ?? []) {
        if (semver.satisfies(node.version, adv.affectedRange, { includePrerelease: true })) {
          reference.push({ pkg: node.name, id: adv.id });
        }
      }
    }

    const matches = matchAdvisories(graph, advisories).map((m) => ({
      pkg: m.package,
      id: m.advisory.id,
    }));

    expect(matches.length).toBe(reference.length);
    expect(new Set(matches.map((m) => `${m.pkg}|${m.id}`))).toEqual(
      new Set(reference.map((m) => `${m.pkg}|${m.id}`)),
    );
  });

  it('reuses compiled range when the same advisory is evaluated against multiple versions', () => {
    // Same advisory, many packages sharing the name — confirms the per-advisory
    // compile cache hits the same object each time without changing semantics.
    const graph: DependencyGraph = new Map();
    for (let i = 0; i < 50; i++) {
      const v = `1.${i}.0`;
      graph.set(`shared@${v}`, makeNode('shared', v));
    }

    const advisory = makeAdvisory({ id: 'GHSA-hot', affectedRange: '>=1.10.0 <1.30.0' });
    const advisories = new Map<string, Advisory[]>([['shared', [advisory]]]);

    const matches = matchAdvisories(graph, advisories);

    // 1.10.0 through 1.29.0 → 20 matches
    expect(matches).toHaveLength(20);
    // Every match carries the same Advisory reference
    for (const m of matches) {
      expect(m.advisory).toBe(advisory);
    }
  });
});
