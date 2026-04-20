import { describe, it, expect } from 'vitest';
import { matchAdvisories } from '../../src/core/advisory/matcher.js';
import type { DependencyGraph, DependencyNode } from '../../src/types/package.js';
import type { Advisory } from '../../src/types/advisory.js';

function makeNode(overrides: Partial<DependencyNode> & { name: string; version: string }): DependencyNode {
  return {
    resolved: '',
    integrity: '',
    dependencies: [],
    isProduction: true,
    isDev: false,
    isOptional: false,
    depth: 1,
    dependencyPath: [overrides.name],
    ...overrides,
  };
}

function makeAdvisory(overrides?: Partial<Advisory>): Advisory {
  return {
    id: 'GHSA-test-0001-0001',
    aliases: [],
    summary: 'Test vulnerability',
    details: '',
    severity: [],
    affectedRange: '>=1.0.0 <2.0.0',
    fixVersion: '2.0.0',
    publishedAt: '2024-01-01',
    modifiedAt: '2024-01-01',
    references: [],
    source: 'osv-api',
    ...overrides,
  };
}

function buildGraph(nodes: DependencyNode[]): DependencyGraph {
  const graph: DependencyGraph = new Map();
  for (const node of nodes) {
    graph.set(`${node.name}@${node.version}`, node);
  }
  return graph;
}

describe('matchAdvisories', () => {
  describe('basic range matching', () => {
    it('matches when installed version is within the affected range', () => {
      const graph = buildGraph([
        makeNode({ name: 'lodash', version: '1.5.0' }),
      ]);
      const advisories = new Map([
        ['lodash', [makeAdvisory({ affectedRange: '>=1.0.0 <2.0.0' })]],
      ]);

      const matches = matchAdvisories(graph, advisories);

      expect(matches).toHaveLength(1);
      expect(matches[0].package).toBe('lodash');
      expect(matches[0].installedVersion).toBe('1.5.0');
    });

    it('does not match when installed version is outside the affected range', () => {
      const graph = buildGraph([
        makeNode({ name: 'lodash', version: '3.0.0' }),
      ]);
      const advisories = new Map([
        ['lodash', [makeAdvisory({ affectedRange: '>=1.0.0 <2.0.0' })]],
      ]);

      const matches = matchAdvisories(graph, advisories);

      expect(matches).toHaveLength(0);
    });

    it('does not match when package has no advisories', () => {
      const graph = buildGraph([
        makeNode({ name: 'express', version: '4.18.0' }),
      ]);
      const advisories = new Map([
        ['lodash', [makeAdvisory({ affectedRange: '>=1.0.0 <2.0.0' })]],
      ]);

      const matches = matchAdvisories(graph, advisories);

      expect(matches).toHaveLength(0);
    });

    it('returns empty array when graph is empty', () => {
      const graph: DependencyGraph = new Map();
      const advisories = new Map([
        ['lodash', [makeAdvisory()]],
      ]);

      const matches = matchAdvisories(graph, advisories);

      expect(matches).toEqual([]);
    });

    it('returns empty array when advisories map is empty', () => {
      const graph = buildGraph([
        makeNode({ name: 'lodash', version: '1.5.0' }),
      ]);
      const advisories = new Map<string, Advisory[]>();

      const matches = matchAdvisories(graph, advisories);

      expect(matches).toEqual([]);
    });
  });

  describe('prerelease version handling', () => {
    it('matches prerelease versions within the affected range', () => {
      const graph = buildGraph([
        makeNode({ name: 'pkg', version: '1.5.0-beta.1' }),
      ]);
      const advisories = new Map([
        ['pkg', [makeAdvisory({ affectedRange: '>=1.0.0 <2.0.0' })]],
      ]);

      const matches = matchAdvisories(graph, advisories);

      expect(matches).toHaveLength(1);
      expect(matches[0].installedVersion).toBe('1.5.0-beta.1');
    });

    it('matches prerelease versions with alpha tag', () => {
      const graph = buildGraph([
        makeNode({ name: 'pkg', version: '1.0.0-alpha.3' }),
      ]);
      const advisories = new Map([
        ['pkg', [makeAdvisory({ affectedRange: '>=1.0.0-alpha.0 <1.0.0' })]],
      ]);

      const matches = matchAdvisories(graph, advisories);

      expect(matches).toHaveLength(1);
    });

    it('matches prerelease versions that would be missed without includePrerelease', () => {
      const graph = buildGraph([
        makeNode({ name: 'pkg', version: '2.0.0-rc.1' }),
      ]);
      const advisories = new Map([
        ['pkg', [makeAdvisory({ affectedRange: '>=1.0.0 <3.0.0' })]],
      ]);

      const matches = matchAdvisories(graph, advisories);

      // With includePrerelease: true, 2.0.0-rc.1 is in >=1.0.0 <3.0.0
      expect(matches).toHaveLength(1);
    });
  });

  describe('empty/null advisory ranges', () => {
    it('skips advisories with empty affectedRange', () => {
      const graph = buildGraph([
        makeNode({ name: 'lodash', version: '1.5.0' }),
      ]);
      const advisories = new Map([
        ['lodash', [makeAdvisory({ affectedRange: '' })]],
      ]);

      const matches = matchAdvisories(graph, advisories);

      expect(matches).toHaveLength(0);
    });

    it('skips advisories with null-ish affectedRange', () => {
      const graph = buildGraph([
        makeNode({ name: 'lodash', version: '1.5.0' }),
      ]);
      const advisory = makeAdvisory();
      // Force affectedRange to be falsy (the code checks `if (!advisory.affectedRange)`)
      (advisory as { affectedRange: string }).affectedRange = '';

      const advisories = new Map([
        ['lodash', [advisory]],
      ]);

      const matches = matchAdvisories(graph, advisories);

      expect(matches).toHaveLength(0);
    });
  });

  describe('multiple advisories for same package', () => {
    it('matches multiple advisories against the same installed version', () => {
      const graph = buildGraph([
        makeNode({ name: 'lodash', version: '1.5.0' }),
      ]);
      const advisories = new Map([
        ['lodash', [
          makeAdvisory({ id: 'GHSA-0001', affectedRange: '>=1.0.0 <2.0.0' }),
          makeAdvisory({ id: 'GHSA-0002', affectedRange: '>=1.4.0 <1.6.0' }),
        ]],
      ]);

      const matches = matchAdvisories(graph, advisories);

      expect(matches).toHaveLength(2);
      expect(matches.map((m) => m.advisory.id)).toEqual(['GHSA-0001', 'GHSA-0002']);
    });

    it('matches only applicable advisories when version does not satisfy all', () => {
      const graph = buildGraph([
        makeNode({ name: 'lodash', version: '1.5.0' }),
      ]);
      const advisories = new Map([
        ['lodash', [
          makeAdvisory({ id: 'GHSA-0001', affectedRange: '>=1.0.0 <2.0.0' }),
          makeAdvisory({ id: 'GHSA-0002', affectedRange: '>=2.0.0 <3.0.0' }),
        ]],
      ]);

      const matches = matchAdvisories(graph, advisories);

      expect(matches).toHaveLength(1);
      expect(matches[0].advisory.id).toBe('GHSA-0001');
    });

    it('skips advisory with empty range among valid ones', () => {
      const graph = buildGraph([
        makeNode({ name: 'lodash', version: '1.5.0' }),
      ]);
      const advisories = new Map([
        ['lodash', [
          makeAdvisory({ id: 'GHSA-0001', affectedRange: '>=1.0.0 <2.0.0' }),
          makeAdvisory({ id: 'GHSA-0002', affectedRange: '' }),
        ]],
      ]);

      const matches = matchAdvisories(graph, advisories);

      expect(matches).toHaveLength(1);
      expect(matches[0].advisory.id).toBe('GHSA-0001');
    });
  });

  describe('edge cases', () => {
    it('matches exact version when range targets a single version', () => {
      const graph = buildGraph([
        makeNode({ name: 'pkg', version: '1.0.0' }),
      ]);
      const advisories = new Map([
        ['pkg', [makeAdvisory({ affectedRange: '1.0.0' })]],
      ]);

      const matches = matchAdvisories(graph, advisories);

      expect(matches).toHaveLength(1);
    });

    it('does not match version just above the upper boundary', () => {
      const graph = buildGraph([
        makeNode({ name: 'pkg', version: '2.0.0' }),
      ]);
      const advisories = new Map([
        ['pkg', [makeAdvisory({ affectedRange: '>=1.0.0 <2.0.0' })]],
      ]);

      const matches = matchAdvisories(graph, advisories);

      expect(matches).toHaveLength(0);
    });

    it('matches version at lower boundary (inclusive)', () => {
      const graph = buildGraph([
        makeNode({ name: 'pkg', version: '1.0.0' }),
      ]);
      const advisories = new Map([
        ['pkg', [makeAdvisory({ affectedRange: '>=1.0.0 <2.0.0' })]],
      ]);

      const matches = matchAdvisories(graph, advisories);

      expect(matches).toHaveLength(1);
    });

    it('propagates dependencyPath and isProduction from graph node', () => {
      const graph = buildGraph([
        makeNode({
          name: 'lodash',
          version: '1.5.0',
          dependencyPath: ['express', 'body-parser', 'lodash'],
          isProduction: false,
        }),
      ]);
      const advisories = new Map([
        ['lodash', [makeAdvisory({ affectedRange: '>=1.0.0 <2.0.0' })]],
      ]);

      const matches = matchAdvisories(graph, advisories);

      expect(matches).toHaveLength(1);
      expect(matches[0].dependencyPath).toEqual(['express', 'body-parser', 'lodash']);
      expect(matches[0].isProduction).toBe(false);
    });

    it('matches across multiple packages in the graph', () => {
      const graph = buildGraph([
        makeNode({ name: 'lodash', version: '1.5.0' }),
        makeNode({ name: 'express', version: '4.17.0' }),
        makeNode({ name: 'axios', version: '0.21.1' }),
      ]);
      const advisories = new Map([
        ['lodash', [makeAdvisory({ id: 'GHSA-lodash', affectedRange: '>=1.0.0 <2.0.0' })]],
        ['axios', [makeAdvisory({ id: 'GHSA-axios', affectedRange: '>=0.21.0 <0.21.2' })]],
      ]);

      const matches = matchAdvisories(graph, advisories);

      expect(matches).toHaveLength(2);
      const matchedPkgs = matches.map((m) => m.package).sort();
      expect(matchedPkgs).toEqual(['axios', 'lodash']);
    });
  });
});
