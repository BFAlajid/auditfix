/**
 * Production reachability analysis.
 *
 * Strategy A (npm): Pre-computed flags already set during parsing. No-op.
 * Strategy B (yarn/pnpm): BFS from production roots with visited set. O(V+E).
 */
import type { DependencyGraph } from '../../types/package.js';

/**
 * BFS from production roots to mark all reachable nodes as isProduction.
 * Used for yarn/pnpm where lockfiles don't have pre-computed dev flags.
 *
 * @param graph - The dependency graph (mutated in place)
 * @param productionRoots - Package names from package.json `dependencies`
 */
export function markProductionReachable(
  graph: DependencyGraph,
  productionRoots: string[],
): void {
  // Find graph keys matching production root names
  const rootKeys: string[] = [];
  for (const rootName of productionRoots) {
    for (const [key, node] of graph) {
      if (node.name === rootName && node.depth === 1) {
        rootKeys.push(key);
      }
    }
  }

  // BFS with visited set (handles circular dependencies)
  const visited = new Set<string>();
  const queue = [...rootKeys];

  while (queue.length > 0) {
    const current = queue.shift()!;
    if (visited.has(current)) continue;
    visited.add(current);

    const node = graph.get(current);
    if (!node) continue;

    node.isProduction = true;
    node.isDev = false;

    for (const depKey of node.dependencies) {
      if (!visited.has(depKey)) {
        queue.push(depKey);
      }
    }
  }

  // Everything not visited is dev-only
  for (const [key, node] of graph) {
    if (!visited.has(key)) {
      node.isDev = true;
      node.isProduction = false;
    }
  }
}

/**
 * Compute dependency paths from root to each node (shortest path).
 * BFS from depth-1 nodes.
 */
export function computeDependencyPaths(graph: DependencyGraph): void {
  const visited = new Set<string>();

  // Start from depth-1 nodes (direct dependencies)
  const roots: string[] = [];
  for (const [key, node] of graph) {
    if (node.depth === 1) {
      node.dependencyPath = [node.name];
      roots.push(key);
    }
  }

  const queue = [...roots];
  for (const key of roots) visited.add(key);

  while (queue.length > 0) {
    const current = queue.shift()!;
    const node = graph.get(current)!;

    for (const depKey of node.dependencies) {
      if (visited.has(depKey)) continue;
      visited.add(depKey);

      const depNode = graph.get(depKey);
      if (!depNode) continue;

      depNode.dependencyPath = [...node.dependencyPath, depNode.name];
      queue.push(depKey);
    }
  }
}
