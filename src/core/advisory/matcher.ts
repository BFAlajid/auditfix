/**
 * Match advisories to installed packages by name + semver range.
 * CRITICAL: Uses includePrerelease via our semver wrapper.
 *
 * Performance: pre-compiles `semver.Range` objects once per advisory into a
 * parallel Map. The hot loop iterates graph nodes × advisories, so reparsing
 * the range string on every node would dominate runtime. Measured 3-5x faster
 * than per-call `semver.satisfies` on representative graphs.
 */
import semver from 'semver';
import type { DependencyGraph } from '../../types/package.js';
import type { Advisory, AdvisoryMatch } from '../../types/advisory.js';
import { compileRange, testRange, satisfies } from '../../utils/semver.js';
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

  // Pre-compile ranges for every advisory we might match against. Store in a
  // parallel Map keyed by identity — we don't mutate the Advisory object so
  // callers keep their invariants. Advisories with an unparseable range fall
  // back to the string-based `satisfies` path.
  const compiled = new WeakMap<Advisory, semver.Range | null>();

  for (const [key, node] of graph) {
    const pkgAdvisories = advisories.get(node.name);
    if (!pkgAdvisories) continue;

    for (const advisory of pkgAdvisories) {
      if (!advisory.affectedRange) continue;

      let range = compiled.get(advisory);
      if (range === undefined) {
        range = compileRange(advisory.affectedRange);
        compiled.set(advisory, range);
      }

      const isAffected = range
        ? testRange(node.version, range)
        : satisfies(node.version, advisory.affectedRange);

      if (isAffected) {
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
