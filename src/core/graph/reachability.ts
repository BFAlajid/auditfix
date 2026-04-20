/**
 * Dependency graph traversal: shortest-path parent links + lazy path resolution.
 *
 * The original implementation eagerly materialized `dependencyPath: string[]`
 * on every node during BFS, duplicating ancestor names O(V*D) times — tens of
 * MB on deep monorepos even though only the tiny subset of nodes that match a
 * vulnerability actually need the path.
 *
 * New strategy: record a single `parentKey` link per node during BFS (O(V+E)
 * time, O(V) extra pointers) and expose `resolveDependencyPath` for callers
 * (matcher.ts) to walk the parent chain on demand for matched nodes only.
 *
 * Public API surface preserved:
 *   - computeDependencyPaths(graph) — unchanged signature; now populates
 *     parent links instead of full arrays. `node.dependencyPath` stays `[]`
 *     until a consumer calls the resolver.
 */
import type { DependencyGraph } from '../../types/package.js';

/** Internal parent-link store keyed by graph key. */
const parentLinks = new WeakMap<DependencyGraph, Map<string, string | null>>();

/**
 * BFS from depth-1 roots recording the first (shortest) parent that reaches
 * each node. Replaces the previous per-node array copy.
 */
export function computeDependencyPaths(graph: DependencyGraph): void {
  const parents = new Map<string, string | null>();
  const queue: string[] = [];

  // Seed: depth-1 nodes have no parent.
  for (const [key, node] of graph) {
    if (node.depth === 1) {
      parents.set(key, null);
      queue.push(key);
    }
  }

  // BFS — first visit wins (shortest path).
  for (let qi = 0; qi < queue.length; qi++) {
    const current = queue[qi];
    const node = graph.get(current);
    if (!node) continue;

    for (const depKey of node.dependencies) {
      if (parents.has(depKey)) continue;
      parents.set(depKey, current);
      queue.push(depKey);
    }
  }

  parentLinks.set(graph, parents);
}

/**
 * Resolve the root→node name path for a graph key on demand.
 * Safe on cycles (parent map can't form a cycle because BFS records only the
 * first parent to reach each node, which is an ancestor). Returns an empty
 * array if the key isn't in the graph.
 */
export function resolveDependencyPath(
  graph: DependencyGraph,
  key: string,
): string[] {
  const parents = parentLinks.get(graph);
  if (!parents) return [];

  const names: string[] = [];
  let cursor: string | null | undefined = key;
  // Guard against pathological inputs (self-loops, missing links).
  const seen = new Set<string>();
  while (cursor != null && !seen.has(cursor)) {
    seen.add(cursor);
    const node = graph.get(cursor);
    if (!node) break;
    names.push(node.name);
    cursor = parents.get(cursor) ?? null;
  }
  return names.reverse();
}
