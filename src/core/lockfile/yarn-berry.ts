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

// M-S3: cap berry request-key length. 1KB is comfortably larger than real-world
// comma-joined request keys (scope + name + range * multiplicity).
const MAX_KEY_LENGTH = 1024;

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

    if (requestKey.length > MAX_KEY_LENGTH) {
      logger.warn(`yarn-berry: skipping oversized request key (${requestKey.length} bytes, max ${MAX_KEY_LENGTH})`);
      skipped.push({ key: requestKey.slice(0, 80) + '...', reason: 'unparseable' });
      continue;
    }

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

  // P1: build name-index once for O(1) fallback lookup (was O(N) per miss).
  const nameIndex = new Map<string, string[]>();
  for (const [graphKey, node] of graph) {
    const bucket = nameIndex.get(node.name);
    if (bucket) bucket.push(graphKey);
    else nameIndex.set(node.name, [graphKey]);
  }

  // Second pass: resolve dependency edges
  const processed = new Set<string>();
  for (const [requestKey, entry] of Object.entries(raw)) {
    if (requestKey.startsWith('__') || !entry?.version) continue;
    if (requestKey.length > MAX_KEY_LENGTH) continue;

    const name = extractNameFromBerryKey(requestKey, entry.resolution);
    if (!name) continue;

    const graphKey = `${name}@${entry.version}`;
    if (processed.has(graphKey)) continue;
    processed.add(graphKey);

    const node = graph.get(graphKey);
    if (!node) continue;

    // P7: iterate dependencies map directly, Set for dedup.
    const seen = new Set<string>(node.dependencies);

    if (entry.dependencies) {
      for (const [depName, depRange] of Object.entries(entry.dependencies)) {
        // Berry stores ranges like "npm:^1.0.0" or just "^1.0.0"
        const cleanRange = depRange.startsWith('npm:') ? depRange.slice(4) : depRange;
        const lookupKey = `${depName}@npm:${cleanRange}`;

        // Try direct lookup first
        let depGraphKey = requestToGraph.get(lookupKey);

        // Fallback via name-index (O(1))
        if (!depGraphKey) {
          const bucket = nameIndex.get(depName);
          if (bucket && bucket.length > 0) depGraphKey = bucket[0];
        }

        if (depGraphKey && graph.has(depGraphKey) && !seen.has(depGraphKey)) {
          seen.add(depGraphKey);
          node.dependencies.push(depGraphKey);
        }
      }
    }
  }

  // Reachability pass
  classifyReachability(graph, requestToGraph, manifest, nameIndex);

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
 *
 * Fix 6: resolveRoot returns null on exact-version miss — no longer falls
 * back to "first graph entry matching name" (which picked the wrong version).
 *
 * C-B4 (mirrored from yarn-classic): optional deps are NOT also marked as
 * production. They are their own classification.
 */
function classifyReachability(
  graph: DependencyGraph,
  requestToGraph: Map<string, string>,
  manifest: PackageManifest,
  _nameIndex: Map<string, string[]>,
): void {
  function resolveRoot(name: string, range: string): string | null {
    // Berry-style lookup: "name@npm:range"
    const lookupKey = `${name}@npm:${range}`;
    const key = requestToGraph.get(lookupKey);
    if (key && graph.has(key)) return key;

    // Also accept bare-range form (some berry variants / manifest shapes)
    const bareKey = `${name}@${range}`;
    const key2 = requestToGraph.get(bareKey);
    if (key2 && graph.has(key2)) return key2;

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

  const prodRoots = Object.entries(manifest.dependencies ?? {});
  const devRoots = Object.entries(manifest.devDependencies ?? {});
  const optionalRoots = Object.entries(manifest.optionalDependencies ?? {});

  bfs(prodRoots, (node) => { node.isProduction = true; });
  bfs(optionalRoots, (node) => {
    node.isOptional = true;
    // Intentionally do NOT set isProduction here (mirrors yarn-classic C-B4).
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
