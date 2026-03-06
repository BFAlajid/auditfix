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

  // Second pass: resolve dependency edges
  for (const [pathKey, entry] of Object.entries(packages)) {
    if (pathKey === '' || !entry.version) continue;

    const name = entry.name ?? extractPackageName(pathKey);
    const graphKey = `${name}@${entry.version}`;
    const node = graph.get(graphKey);
    if (!node) continue;

    if (entry.dependencies) {
      for (const [depName, depRange] of Object.entries(entry.dependencies)) {
        // Find the resolved version of this dependency in the graph
        const resolvedDep = findResolvedDep(graph, depName, depRange);
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

/** Find a resolved dependency in the graph by name + range match */
function findResolvedDep(graph: DependencyGraph, name: string, range: string): string | null {
  let fallback: string | null = null;

  for (const [key, node] of graph) {
    if (node.name !== name) continue;

    // Try semver range match first
    if (satisfiesRange(node.version, range)) {
      return key;
    }

    // Keep first name match as fallback (handles non-semver ranges)
    if (!fallback) {
      fallback = key;
    }
  }

  return fallback;
}

function satisfiesRange(version: string, range: string): boolean {
  try {
    return semver.satisfies(version, range, { includePrerelease: true });
  } catch {
    return false;
  }
}
