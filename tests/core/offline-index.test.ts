import { describe, it, expect } from 'vitest';
import { queryOfflineIndex, queryOfflineIndexBatch, getOfflineIndexSize } from '../../src/core/advisory/offline-index.js';
import type { DependencyGraph, DependencyNode } from '../../src/types/package.js';

function makeNode(name: string, version: string): DependencyNode {
  return {
    name, version, resolved: '', integrity: '',
    dependencies: [], isProduction: true, isDev: false,
    isOptional: false, depth: 1, dependencyPath: [],
  };
}

describe('Offline advisory index', () => {
  it('returns advisories for vulnerable lodash version', () => {
    const results = queryOfflineIndex('lodash', '4.17.20');
    expect(results.length).toBeGreaterThanOrEqual(1);
    expect(results[0].id).toBe('GHSA-35jh-r3h4-6jhm');
    expect(results[0].source).toBe('offline-index');
  });

  it('returns empty for patched lodash version', () => {
    const results = queryOfflineIndex('lodash', '4.17.21');
    expect(results).toHaveLength(0);
  });

  it('returns empty for unknown package', () => {
    const results = queryOfflineIndex('totally-unknown-pkg', '1.0.0');
    expect(results).toHaveLength(0);
  });

  it('batch queries all packages in a graph', async () => {
    const graph: DependencyGraph = new Map();
    graph.set('lodash@4.17.20', makeNode('lodash', '4.17.20'));
    graph.set('express@4.18.0', makeNode('express', '4.18.0'));
    graph.set('safe-pkg@1.0.0', makeNode('safe-pkg', '1.0.0'));

    const result = await queryOfflineIndexBatch(graph);
    expect(result.has('lodash')).toBe(true);
    expect(result.has('express')).toBe(true);
    expect(result.has('safe-pkg')).toBe(false);
  });

  it('reports correct index size', () => {
    expect(getOfflineIndexSize()).toBeGreaterThanOrEqual(20);
  });
});
