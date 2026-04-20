/**
 * Match advisories to installed packages by name + semver range.
 * CRITICAL: Uses includePrerelease via our semver wrapper.
 */
import type { DependencyGraph } from '../../types/package.js';
import type { Advisory, AdvisoryMatch } from '../../types/advisory.js';
import { satisfies } from '../../utils/semver.js';
import { resolveDependencyPath } from '../graph/reachability.js';

/**
 * Match a map of advisories against the dependency graph.
 * Returns all matches (package + version in affected range).
 *
 * The dependency path is materialized lazily per matched node so that the
 * graph doesn't pay O(V*D) memory for nodes that never match an advisory.
 * Nodes whose parsers already populated `dependencyPath` keep that value.
 */
export function matchAdvisories(
  graph: DependencyGraph,
  advisories: Map<string, Advisory[]>,
): AdvisoryMatch[] {
  const matches: AdvisoryMatch[] = [];

  for (const [key, node] of graph) {
    const pkgAdvisories = advisories.get(node.name);
    if (!pkgAdvisories) continue;

    for (const advisory of pkgAdvisories) {
      if (!advisory.affectedRange) continue;

      if (satisfies(node.version, advisory.affectedRange)) {
        const path = node.dependencyPath.length > 0
          ? node.dependencyPath
          : resolveDependencyPath(graph, key);
        matches.push({
          advisory,
          package: node.name,
          installedVersion: node.version,
          dependencyPath: path,
          isProduction: node.isProduction,
        });
      }
    }
  }

  return matches;
}
