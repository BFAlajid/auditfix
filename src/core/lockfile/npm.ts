/**
 * npm lockfile v2/v3 parser.
 * Reads the flat `packages` field via JSON.parse — no arborist needed.
 * Trusts pre-computed dev/optional/devOptional flags.
 */
import type { DependencyGraph, DependencyNode, LockfileType, SkippedDependency } from '../../types/package.js';
import { safeJsonParse } from '../../utils/sanitize.js';
import { isValidVersion } from '../../utils/semver.js';
import { isValidLockfilePath } from '../../utils/sanitize.js';
import semver from 'semver';

type NpmLockfileEntry = {
  version?: string;
  resolved?: string;
  integrity?: string;
  dev?: boolean;
  optional?: boolean;
  devOptional?: boolean;
  link?: boolean;
  name?: string; // present for aliased packages — differs from path key
  dependencies?: Record<string, string>;
};

type NpmLockfile = {
  lockfileVersion: number;
  packages: Record<string, NpmLockfileEntry>;
};

export function parseNpmLockfile(content: string): {
  type: LockfileType;
  graph: DependencyGraph;
  skipped: SkippedDependency[];
} {
  const lockfile = safeJsonParse<NpmLockfile>(content);

  if (!lockfile.lockfileVersion || lockfile.lockfileVersion < 2) {
    throw new Error(
      `Unsupported npm lockfile version ${lockfile.lockfileVersion}. auditfix requires lockfileVersion 2 or 3. Run \`npm install\` with npm 7+ to upgrade.`
    );
  }

  const type: LockfileType = lockfile.lockfileVersion >= 3 ? 'npm-v3' : 'npm-v2';
  const packages = lockfile.packages;

  if (!packages || typeof packages !== 'object') {
    throw new Error('Invalid lockfile: missing "packages" field.');
  }

  const graph: DependencyGraph = new Map();
  const skipped: SkippedDependency[] = [];

  // First pass: create all nodes
  for (const [pathKey, entry] of Object.entries(packages)) {
    // Skip root entry
    if (pathKey === '') continue;

    if (!isValidLockfilePath(pathKey)) {
      skipped.push({ key: pathKey, reason: 'unparseable' });
      continue;
    }

    // Skip linked/file/workspace dependencies
    if (entry.link) {
      skipped.push({ key: pathKey, reason: 'local-file' });
      continue;
    }

    const resolved = entry.resolved ?? '';

    // Skip git dependencies
    if (resolved.startsWith('git+') || resolved.startsWith('git://')) {
      skipped.push({ key: pathKey, reason: 'git-dep' });
      continue;
    }

    // Skip file/link protocol deps
    if (resolved.startsWith('file:')) {
      skipped.push({ key: pathKey, reason: 'local-file' });
      continue;
    }

    const version = entry.version;
    if (!version) {
      skipped.push({ key: pathKey, reason: 'unparseable' });
      continue;
    }

    // Use `name` field for aliased packages (P0 — wrong name = missed vuln)
    const name = entry.name ?? extractPackageName(pathKey);

    // S7: Validate package names from untrusted lockfile data
    if (name && (name.includes('..') || name.includes('\0') || name.includes('\\'))) {
      skipped.push({ key: pathKey, reason: 'invalid-name' });
      continue;
    }

    if (!isValidVersion(version)) {
      skipped.push({ key: pathKey, reason: 'unparseable' });
      continue;
    }

    const graphKey = `${name}@${version}`;

    // npm pre-computes these flags. No flag set = production.
    const isDev = entry.dev === true;
    const isOptional = entry.optional === true;
    const isDevOptional = entry.devOptional === true;
    const isProduction = !isDev && !isOptional && !isDevOptional;

    const node: DependencyNode = {
      name,
      version,
      resolved,
      integrity: entry.integrity ?? '',
      dependencies: [], // populated in second pass
      isProduction,
      isDev: isDev || isDevOptional,
      isOptional,
      depth: countDepth(pathKey),
      dependencyPath: [], // populated later if needed
    };

    // If same name@version already exists (deduplication), keep the production one
    const existing = graph.get(graphKey);
    if (existing) {
      if (isProduction && !existing.isProduction) {
        existing.isProduction = true;
        existing.isDev = false;
      }
    } else {
      graph.set(graphKey, node);
    }
  }

  // Build name-to-keys index for O(1) edge resolution (was O(N) per edge)
  const nameIndex = new Map<string, string[]>();
  for (const [graphKey, node] of graph) {
    const keys = nameIndex.get(node.name);
    if (keys) {
      keys.push(graphKey);
    } else {
      nameIndex.set(node.name, [graphKey]);
    }
  }

  // Second pass: resolve dependency edges
  for (const [pathKey, entry] of Object.entries(packages)) {
    if (pathKey === '' || !entry.version) continue;

    const name = entry.name ?? extractPackageName(pathKey);
    const graphKey = `${name}@${entry.version}`;
    const node = graph.get(graphKey);
    if (!node) continue;

    if (entry.dependencies) {
      for (const [depName, depRange] of Object.entries(entry.dependencies)) {
        const resolvedDep = findResolvedDep(graph, nameIndex, depName, depRange);
        if (resolvedDep) {
          node.dependencies.push(resolvedDep);
        }
      }
    }
  }

  return { type, graph, skipped };
}

/**
 * Extract package name from node_modules path key.
 * e.g. "node_modules/@scope/pkg" -> "@scope/pkg"
 *      "node_modules/foo/node_modules/bar" -> "bar"
 */
function extractPackageName(pathKey: string): string {
  const parts = pathKey.split('node_modules/');
  const last = parts[parts.length - 1];
  // Remove trailing slash if present
  return last.endsWith('/') ? last.slice(0, -1) : last;
}

/** Count depth by number of node_modules segments */
function countDepth(pathKey: string): number {
  return (pathKey.match(/node_modules\//g) || []).length;
}

/**
 * Find a resolved dependency in the graph by name + range match using name index.
 * C-B3 fix: when no candidate satisfies the range, use semver.maxSatisfying over
 * all candidate versions. If still no match, return null (do NOT return an
 * arbitrary first candidate, which previously pointed edges at the wrong version).
 */
function findResolvedDep(
  graph: DependencyGraph,
  nameIndex: Map<string, string[]>,
  name: string,
  range: string,
): string | null {
  const candidates = nameIndex.get(name);
  if (!candidates || candidates.length === 0) return null;

  // Fast path: first candidate satisfying the range.
  for (const key of candidates) {
    const node = graph.get(key);
    if (!node) continue;
    if (satisfiesRange(node.version, range)) {
      return key;
    }
  }

  // Slow path: use semver.maxSatisfying over all candidate versions.
  const versions = candidates
    .map((k) => graph.get(k)?.version)
    .filter((v): v is string => typeof v === 'string');

  let best: string | null = null;
  try {
    best = semver.maxSatisfying(versions, range, { includePrerelease: true });
  } catch {
    best = null;
  }
  if (!best) return null;

  for (const key of candidates) {
    const node = graph.get(key);
    if (node?.version === best) return key;
  }
  return null;
}

function satisfiesRange(version: string, range: string): boolean {
  try {
    return semver.satisfies(version, range, { includePrerelease: true });
  } catch {
    return false;
  }
}
