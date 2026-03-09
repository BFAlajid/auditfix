/**
 * Yarn Classic (v1) lockfile parser.
 * Uses @yarnpkg/lockfile for parsing the custom text format.
 * Requires package.json to classify production vs dev dependencies
 * since yarn.lock has no dev/prod flags.
 */
import type { DependencyGraph, DependencyNode, SkippedDependency } from '../../types/package.js';
import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
const { parse: parseYarnLock } = require('@yarnpkg/lockfile');
import { isValidVersion } from '../../utils/semver.js';
import * as logger from '../../utils/logger.js';

type YarnLockEntry = {
  version: string;
  resolved: string;
  integrity?: string;
  dependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
};

type PackageManifest = {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
};

export function parseYarnClassicLockfile(
  content: string,
  manifest: PackageManifest,
): {
  graph: DependencyGraph;
  skipped: SkippedDependency[];
} {
  const result = parseYarnLock(content);

  if (result.type !== 'success') {
    throw new Error('Failed to parse yarn.lock: invalid format or merge conflict markers present.');
  }

  const entries = result.object as Record<string, YarnLockEntry>;
  const graph: DependencyGraph = new Map();
  const skipped: SkippedDependency[] = [];

  // Build a version map: name -> resolved version(s) for edge resolution
  const versionMap = new Map<string, Set<string>>();

  // First pass: create nodes
  for (const [requestKey, entry] of Object.entries(entries)) {
    const name = extractNameFromRequestKey(requestKey);
    if (!name) {
      skipped.push({ key: requestKey, reason: 'unparseable' });
      continue;
    }

    const version = entry.version;
    if (!version || !isValidVersion(version)) {
      skipped.push({ key: requestKey, reason: 'unparseable' });
      continue;
    }

    const resolved = entry.resolved ?? '';

    // Skip git deps
    if (resolved.startsWith('git+') || resolved.startsWith('git://') || resolved.includes('#commit=')) {
      skipped.push({ key: requestKey, reason: 'git-dep' });
      continue;
    }

    // Skip file/link deps
    if (resolved.startsWith('file:') || resolved.startsWith('link:')) {
      skipped.push({ key: requestKey, reason: 'local-file' });
      continue;
    }

    const graphKey = `${name}@${version}`;

    // Track versions for edge resolution
    if (!versionMap.has(name)) {
      versionMap.set(name, new Set());
    }
    versionMap.get(name)!.add(version);

    // Skip if already in graph (multiple request keys resolve to same version)
    if (graph.has(graphKey)) continue;

    const node: DependencyNode = {
      name,
      version,
      resolved,
      integrity: entry.integrity ?? '',
      dependencies: [],
      isProduction: false, // set in reachability pass
      isDev: false,
      isOptional: false,
      depth: 0, // set in reachability pass
      dependencyPath: [],
    };

    graph.set(graphKey, node);
  }

  // Second pass: resolve dependency edges
  const processed = new Set<string>();
  for (const [requestKey, entry] of Object.entries(entries)) {
    const name = extractNameFromRequestKey(requestKey);
    if (!name || !entry.version) continue;

    const graphKey = `${name}@${entry.version}`;
    if (processed.has(graphKey)) continue;
    processed.add(graphKey);

    const node = graph.get(graphKey);
    if (!node) continue;

    const allDeps = {
      ...(entry.dependencies ?? {}),
      ...(entry.optionalDependencies ?? {}),
    };

    for (const [depName, _depRange] of Object.entries(allDeps)) {
      // Find this dep in the entries to get its resolved version
      const depKey = `${depName}@${_depRange}`;
      const depEntry = entries[depKey];
      if (depEntry?.version) {
        const depGraphKey = `${depName}@${depEntry.version}`;
        if (graph.has(depGraphKey) && !node.dependencies.includes(depGraphKey)) {
          node.dependencies.push(depGraphKey);
        }
      }
    }
  }

  // Reachability pass: classify prod/dev/optional via BFS from package.json roots
  classifyReachability(graph, entries, manifest);

  return { graph, skipped };
}

/**
 * Extract package name from a yarn.lock request key.
 * e.g. "lodash@^4.0.0" -> "lodash"
 *      "@scope/pkg@^1.0.0" -> "@scope/pkg"
 *      "lodash@^4.0.0, lodash@^4.17.0" -> "lodash" (first key)
 */
function extractNameFromRequestKey(requestKey: string): string | null {
  // Take first key if comma-separated
  const key = requestKey.split(',')[0].trim();

  // Handle scoped packages: @scope/name@range
  if (key.startsWith('@')) {
    const atIdx = key.indexOf('@', 1);
    if (atIdx === -1) return null;
    return key.slice(0, atIdx);
  }

  // Unscoped: name@range
  const atIdx = key.indexOf('@');
  if (atIdx === -1) return null;
  return key.slice(0, atIdx);
}

/**
 * BFS from package.json roots to classify production/dev/optional.
 */
function classifyReachability(
  graph: DependencyGraph,
  entries: Record<string, YarnLockEntry>,
  manifest: PackageManifest,
): void {
  const prodRoots = Object.entries(manifest.dependencies ?? {});
  const devRoots = Object.entries(manifest.devDependencies ?? {});
  const optionalRoots = Object.entries(manifest.optionalDependencies ?? {});

  // Resolve root dep names to graph keys
  function resolveRoot(name: string, range: string): string | null {
    const entryKey = `${name}@${range}`;
    const entry = entries[entryKey];
    if (entry?.version) {
      return `${name}@${entry.version}`;
    }
    // Fallback: search graph for name match
    for (const [key, node] of graph) {
      if (node.name === name) return key;
    }
    return null;
  }

  function bfs(roots: [string, string][], markFn: (node: DependencyNode) => void) {
    const visited = new Set<string>();
    const queue: { key: string; depth: number }[] = [];

    for (const [name, range] of roots) {
      const key = resolveRoot(name, range);
      if (key && !visited.has(key)) {
        visited.add(key);
        queue.push({ key, depth: 1 });
      }
    }

    let qi = 0;
    while (qi < queue.length) {
      const { key, depth } = queue[qi++];
      const node = graph.get(key);
      if (!node) continue;

      markFn(node);
      if (node.depth === 0 || depth < node.depth) {
        node.depth = depth;
      }

      for (const depKey of node.dependencies) {
        if (!visited.has(depKey)) {
          visited.add(depKey);
          queue.push({ key: depKey, depth: depth + 1 });
        }
      }
    }
  }

  // Mark production first (takes precedence)
  bfs(prodRoots, (node) => {
    node.isProduction = true;
  });

  // Mark optional
  bfs(optionalRoots, (node) => {
    node.isOptional = true;
    if (!node.isProduction) {
      node.isProduction = true; // optional deps are still production
    }
  });

  // Mark dev (only if not already production)
  bfs(devRoots, (node) => {
    if (!node.isProduction) {
      node.isDev = true;
    }
  });

  // Any node not reached by any BFS is dev by default
  for (const node of graph.values()) {
    if (!node.isProduction && !node.isDev && !node.isOptional) {
      node.isDev = true;
    }
  }

  logger.debug(`Yarn reachability: ${[...graph.values()].filter(n => n.isProduction).length} prod, ${[...graph.values()].filter(n => n.isDev).length} dev`);
}
