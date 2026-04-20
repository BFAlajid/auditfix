import { describe, it, expect } from 'vitest';
import { computeDependencyPaths, resolveDependencyPath } from '../../src/core/graph/reachability.js';
import type { DependencyGraph, DependencyNode } from '../../src/types/package.js';

function node(overrides: Partial<DependencyNode> & { name: string; depth: number }): DependencyNode {
  return {
    name: overrides.name,
    version: overrides.version ?? '1.0.0',
    resolved: '',
    integrity: '',
    dependencies: overrides.dependencies ?? [],
    isProduction: overrides.isProduction ?? true,
    isDev: overrides.isDev ?? false,
    isOptional: overrides.isOptional ?? false,
    depth: overrides.depth,
    dependencyPath: overrides.dependencyPath ?? [],
  };
}

function addEdge(graph: DependencyGraph, from: string, to: string): void {
  const n = graph.get(from);
  if (n && !n.dependencies.includes(to)) n.dependencies.push(to);
}

describe('computeDependencyPaths — lazy resolution', () => {
  it('records parent links without materializing full arrays', () => {
    const graph: DependencyGraph = new Map();
    graph.set('a@1.0.0', node({ name: 'a', depth: 1, dependencies: ['b@1.0.0'] }));
    graph.set('b@1.0.0', node({ name: 'b', depth: 2, dependencies: ['c@1.0.0'] }));
    graph.set('c@1.0.0', node({ name: 'c', depth: 3 }));

    computeDependencyPaths(graph);

    // Unmatched nodes should NOT pre-compute path arrays.
    for (const n of graph.values()) expect(n.dependencyPath).toEqual([]);

    // Resolver works on demand.
    expect(resolveDependencyPath(graph, 'c@1.0.0')).toEqual(['a', 'b', 'c']);
    expect(resolveDependencyPath(graph, 'b@1.0.0')).toEqual(['a', 'b']);
    expect(resolveDependencyPath(graph, 'a@1.0.0')).toEqual(['a']);
  });

  it('handles cycles without infinite loop (A→B→A)', () => {
    const graph: DependencyGraph = new Map();
    graph.set('a@1.0.0', node({ name: 'a', depth: 1, dependencies: ['b@1.0.0'] }));
    graph.set('b@1.0.0', node({ name: 'b', depth: 2, dependencies: ['a@1.0.0'] }));

    expect(() => computeDependencyPaths(graph)).not.toThrow();

    // Resolver must also tolerate the cycle.
    expect(resolveDependencyPath(graph, 'b@1.0.0')).toEqual(['a', 'b']);
  });

  it('handles edge to unresolved/missing dependency entry gracefully', () => {
    const graph: DependencyGraph = new Map();
    graph.set('a@1.0.0', node({ name: 'a', depth: 1, dependencies: ['ghost@9.9.9'] }));
    // No ghost node in the graph.

    expect(() => computeDependencyPaths(graph)).not.toThrow();
    expect(resolveDependencyPath(graph, 'ghost@9.9.9')).toEqual([]);
    expect(resolveDependencyPath(graph, 'a@1.0.0')).toEqual(['a']);
  });

  it('returns empty array when called before computeDependencyPaths', () => {
    const graph: DependencyGraph = new Map();
    graph.set('a@1.0.0', node({ name: 'a', depth: 1 }));
    expect(resolveDependencyPath(graph, 'a@1.0.0')).toEqual([]);
  });

  it('records shortest path when two roots reach the same node', () => {
    const graph: DependencyGraph = new Map();
    // Two direct roots share a transitive dep.
    graph.set('a@1.0.0', node({ name: 'a', depth: 1, dependencies: ['shared@1.0.0'] }));
    graph.set('b@1.0.0', node({ name: 'b', depth: 1, dependencies: ['mid@1.0.0'] }));
    graph.set('mid@1.0.0', node({ name: 'mid', depth: 2, dependencies: ['shared@1.0.0'] }));
    graph.set('shared@1.0.0', node({ name: 'shared', depth: 2 }));

    computeDependencyPaths(graph);
    // BFS should find shared via `a` (direct) before `b→mid`.
    expect(resolveDependencyPath(graph, 'shared@1.0.0')).toEqual(['a', 'shared']);
  });

  it('performance regression guard: 10k nodes complete under 500ms', () => {
    const graph: DependencyGraph = new Map();
    // 20 roots, branching=3 for 5 levels, chain=1 afterwards — ~10k, depth≈15.
    let idx = 0;
    const queue: string[] = [];
    for (let r = 0; r < 20; r++) {
      const key = `root${r}@1.0.0`;
      graph.set(key, node({ name: `root${r}`, depth: 1 }));
      queue.push(key);
      idx++;
    }
    let qi = 0;
    let levelEnd = queue.length;
    let level = 1;
    while (idx < 10_000 && qi < queue.length) {
      while (qi < levelEnd && idx < 10_000) {
        const parentKey = queue[qi++];
        const parent = graph.get(parentKey)!;
        const branching = level < 5 ? 3 : 1;
        for (let c = 0; c < branching && idx < 10_000 && parent.depth < 15; c++) {
          const key = `pkg${idx}@1.0.0`;
          graph.set(key, node({ name: `pkg${idx}`, depth: parent.depth + 1 }));
          addEdge(graph, parentKey, key);
          queue.push(key);
          idx++;
        }
      }
      levelEnd = queue.length;
      level++;
      if (level > 30) break;
    }
    expect(graph.size).toBeGreaterThanOrEqual(9_000);

    const t0 = performance.now();
    computeDependencyPaths(graph);
    const ms = performance.now() - t0;
    // Loose bound — catches accidental O(V²) regressions.
    expect(ms).toBeLessThan(500);
  });
});
