/**
 * Yarn Berry (v2/v3/v4) lockfile parser.
 * Berry uses YAML format with @npm: protocol prefixes.
 * Requires package.json for dev/prod classification (same as classic).
 */
import type { DependencyGraph, DependencyNode, SkippedDependency } from '../../types/package.js';
import { isValidVersion } from '../../utils/semver.js';
import { safeYamlParse } from '../../utils/sanitize.js';
import * as logger from '../../utils/logger.js';

type BerryEntry = {
  version: string;
  resolution: string;
  checksum?: string;
  dependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  peerDependenciesMeta?: Record<string, { optional?: boolean }>;
};

type PackageManifest = {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
};

export function parseYarnBerryLockfile(
  content: string,
  manifest: PackageManifest,
): {
  graph: DependencyGraph;
  skipped: SkippedDependency[];
} {
  const raw = safeYamlParse(content) as Record<string, BerryEntry> | null;

  if (!raw || typeof raw !== 'object') {
    throw new Error('Failed to parse yarn.lock: invalid YAML format.');
  }

  const graph: DependencyGraph = new Map();
  const skipped: SkippedDependency[] = [];

  // Map from "name@npm:range" request keys to resolved graphKey for edge resolution
  const requestToGraph = new Map<string, string>();

  // First pass: create nodes
  for (const [requestKey, entry] of Object.entries(raw)) {
    // Skip metadata keys like __metadata
    if (requestKey.startsWith('__')) continue;

    if (!entry || typeof entry !== 'object' || !entry.version) {
      skipped.push({ key: requestKey, reason: 'unparseable' });
      continue;
    }

    const name = extractNameFromBerryKey(requestKey, entry.resolution);
    if (!name) {
      skipped.push({ key: requestKey, reason: 'unparseable' });
      continue;
    }

    const version = entry.version;
    if (!isValidVersion(version)) {
      skipped.push({ key: requestKey, reason: 'unparseable' });
      continue;
    }

    const resolution = entry.resolution ?? '';

    // Skip workspace entries
    if (resolution.includes('@workspace:') || resolution.startsWith('workspace:')) {
      skipped.push({ key: requestKey, reason: 'workspace' });
      continue;
    }

    // Skip git deps
    if (resolution.includes('@git+') || resolution.includes('@git://')) {
      skipped.push({ key: requestKey, reason: 'git-dep' });
      continue;
    }

    // Skip file/link/portal deps
    if (resolution.includes('@file:') || resolution.includes('@link:') || resolution.includes('@portal:')) {
      skipped.push({ key: requestKey, reason: 'local-file' });
      continue;
    }

    const graphKey = `${name}@${version}`;

    // Map all request key variants to this graph key
    for (const rk of requestKey.split(',')) {
      requestToGraph.set(rk.trim(), graphKey);
    }

    if (graph.has(graphKey)) continue;

    const node: DependencyNode = {
      name,
      version,
      resolved: resolution,
      integrity: entry.checksum ?? '',
      dependencies: [],
      isProduction: false,
      isDev: false,
      isOptional: false,
      depth: 0,
      dependencyPath: [],
    };

    graph.set(graphKey, node);
  }

  // Second pass: resolve dependency edges
  const processed = new Set<string>();
  for (const [requestKey, entry] of Object.entries(raw)) {
    if (requestKey.startsWith('__') || !entry?.version) continue;

    const name = extractNameFromBerryKey(requestKey, entry.resolution);
    if (!name) continue;

    const graphKey = `${name}@${entry.version}`;
    if (processed.has(graphKey)) continue;
    processed.add(graphKey);

    const node = graph.get(graphKey);
    if (!node) continue;

    const deps = entry.dependencies ?? {};
    for (const [depName, depRange] of Object.entries(deps)) {
      // Berry stores ranges like "npm:^1.0.0" or just "^1.0.0"
      const cleanRange = depRange.startsWith('npm:') ? depRange.slice(4) : depRange;
      const lookupKey = `${depName}@npm:${cleanRange}`;

      // Try direct lookup first
      let depGraphKey = requestToGraph.get(lookupKey);

      // Fallback: search graph for name match
      if (!depGraphKey) {
        for (const [key, n] of graph) {
          if (n.name === depName) {
            depGraphKey = key;
            break;
          }
        }
      }

      if (depGraphKey && graph.has(depGraphKey) && !node.dependencies.includes(depGraphKey)) {
        node.dependencies.push(depGraphKey);
      }
    }
  }

  // Reachability pass
  classifyReachability(graph, requestToGraph, manifest);

  return { graph, skipped };
}

/**
 * Extract package name from a Berry request key.
 * Keys look like: "lodash@npm:^4.0.0" or "@scope/pkg@npm:^1.0.0"
 * Multiple keys: "lodash@npm:^4.0.0, lodash@npm:^4.17.0"
 * Also uses resolution field as fallback.
 */
function extractNameFromBerryKey(requestKey: string, resolution?: string): string | null {
  const key = requestKey.split(',')[0].trim();

  // Strip quotes
  const cleaned = key.replace(/^"|"$/g, '');

  // Find @npm: or @patch: etc.
  const protocols = ['@npm:', '@patch:', '@workspace:', '@git+', '@file:', '@link:', '@portal:'];
  for (const proto of protocols) {
    const idx = cleaned.indexOf(proto);
    if (idx !== -1) {
      const name = cleaned.slice(0, idx);
      return name || null;
    }
  }

  // Fallback: try resolution field (format: "name@npm:version")
  if (resolution) {
    const resMatch = resolution.match(/^(@?[^@]+)@/);
    if (resMatch) return resMatch[1];
  }

  return null;
}

/**
 * BFS from package.json roots to classify production/dev/optional.
 */
function classifyReachability(
  graph: DependencyGraph,
  requestToGraph: Map<string, string>,
  manifest: PackageManifest,
): void {
  function resolveRoot(name: string, range: string): string | null {
    // Try Berry-style lookup
    const lookupKey = `${name}@npm:${range}`;
    const key = requestToGraph.get(lookupKey);
    if (key) return key;

    // Fallback: search graph
    for (const [gk, node] of graph) {
      if (node.name === name) return gk;
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

    while (queue.length > 0) {
      const { key, depth } = queue.shift()!;
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

  const prodRoots = Object.entries(manifest.dependencies ?? {});
  const devRoots = Object.entries(manifest.devDependencies ?? {});
  const optionalRoots = Object.entries(manifest.optionalDependencies ?? {});

  bfs(prodRoots, (node) => { node.isProduction = true; });
  bfs(optionalRoots, (node) => {
    node.isOptional = true;
    if (!node.isProduction) node.isProduction = true;
  });
  bfs(devRoots, (node) => {
    if (!node.isProduction) node.isDev = true;
  });

  for (const node of graph.values()) {
    if (!node.isProduction && !node.isDev && !node.isOptional) {
      node.isDev = true;
    }
  }

  logger.debug(`Berry reachability: ${[...graph.values()].filter(n => n.isProduction).length} prod, ${[...graph.values()].filter(n => n.isDev).length} dev`);
}
