/**
 * Match advisories to installed packages by name + semver range.
 * CRITICAL: Uses includePrerelease via our semver wrapper.
 */
import type { DependencyGraph } from '../../types/package.js';
import type { Advisory, AdvisoryMatch } from '../../types/advisory.js';
import { satisfies } from '../../utils/semver.js';

/**
 * Match a map of advisories against the dependency graph.
 * Returns all matches (package + version in affected range).
 */
export function matchAdvisories(
  graph: DependencyGraph,
  advisories: Map<string, Advisory[]>,
): AdvisoryMatch[] {
  const matches: AdvisoryMatch[] = [];

  for (const [, node] of graph) {
    const pkgAdvisories = advisories.get(node.name);
    if (!pkgAdvisories) continue;

    for (const advisory of pkgAdvisories) {
      if (!advisory.affectedRange) continue;

      if (satisfies(node.version, advisory.affectedRange)) {
        matches.push({
          advisory,
          package: node.name,
          installedVersion: node.version,
          dependencyPath: node.dependencyPath,
          isProduction: node.isProduction,
        });
      }
    }
  }

  return matches;
}
