/**
 * pnpm lockfile parser.
 * Parses pnpm-lock.yaml (v5/v6/v9) using js-yaml.
 * pnpm has explicit dev/prod classification in importers.
 */
import type { DependencyGraph, DependencyNode, LockfileType, SkippedDependency } from '../../types/package.js';
import { isValidVersion } from '../../utils/semver.js';
import { safeYamlParse } from '../../utils/sanitize.js';
import * as logger from '../../utils/logger.js';

type PnpmLockfile = {
  lockfileVersion: string | number;
  settings?: Record<string, unknown>;
  importers?: Record<string, PnpmImporter>;
  dependencies?: Record<string, PnpmDepRef>;
  devDependencies?: Record<string, PnpmDepRef>;
  optionalDependencies?: Record<string, PnpmDepRef>;
  packages?: Record<string, PnpmPackageEntry>;
};

type PnpmImporter = {
  dependencies?: Record<string, PnpmDepRef>;
  devDependencies?: Record<string, PnpmDepRef>;
  optionalDependencies?: Record<string, PnpmDepRef>;
};

type PnpmDepRef = {
  version: string;
  specifier?: string;
} | string;

type PnpmPackageEntry = {
  resolution?: { type?: string; tarball?: string; integrity?: string; directory?: string };
  name?: string;
  version?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  peerDependenciesMeta?: Record<string, { optional?: boolean }>;
  dev?: boolean;
  optional?: boolean;
  hasBin?: boolean;
};

export function parsePnpmLockfile(content: string): {
  type: LockfileType;
  graph: DependencyGraph;
  skipped: SkippedDependency[];
} {
  const lockfile = safeYamlParse(content) as PnpmLockfile | null;

  if (!lockfile || typeof lockfile !== 'object') {
    throw new Error('Failed to parse pnpm-lock.yaml: invalid YAML format.');
  }

  const rawVersion = lockfile.lockfileVersion;
  const version = typeof rawVersion === 'string' ? parseFloat(rawVersion) : (rawVersion ?? 0);

  let type: LockfileType;
  if (version >= 9) {
    type = 'pnpm-v9';
  } else if (version >= 6) {
    type = 'pnpm-v6';
  } else if (version >= 5) {
    type = 'pnpm-v5';
  } else {
    throw new Error(`Unsupported pnpm lockfile version ${rawVersion}. auditfix requires pnpm lockfileVersion 5+.`);
  }

  const packages = lockfile.packages;
  if (!packages || typeof packages !== 'object') {
    throw new Error('Invalid pnpm-lock.yaml: missing "packages" field.');
  }

  const graph: DependencyGraph = new Map();
  const skipped: SkippedDependency[] = [];

  // Determine root deps (from importers or top-level)
  const rootImporter = lockfile.importers?.['.'] ?? {
    dependencies: lockfile.dependencies,
    devDependencies: lockfile.devDependencies,
    optionalDependencies: lockfile.optionalDependencies,
  };

  // Build set of production/dev/optional root dep names
  const prodRootNames = new Set(Object.keys(rootImporter.dependencies ?? {}));
  const devRootNames = new Set(Object.keys(rootImporter.devDependencies ?? {}));
  const optionalRootNames = new Set(Object.keys(rootImporter.optionalDependencies ?? {}));

  // First pass: create nodes
  for (const [pkgKey, entry] of Object.entries(packages)) {
    const parsed = parsePnpmPackageKey(pkgKey, entry, version);
    if (!parsed) {
      skipped.push({ key: pkgKey, reason: 'unparseable' });
      continue;
    }

    const { name, pkgVersion } = parsed;

    // Skip workspace/directory deps
    if (entry.resolution?.type === 'directory' || entry.resolution?.directory) {
      skipped.push({ key: pkgKey, reason: 'workspace' });
      continue;
    }

    // Skip git deps
    const tarball = entry.resolution?.tarball ?? '';
    if (tarball.startsWith('git+') || tarball.startsWith('git://')) {
      skipped.push({ key: pkgKey, reason: 'git-dep' });
      continue;
    }

    // Skip file deps
    if (tarball.startsWith('file:')) {
      skipped.push({ key: pkgKey, reason: 'local-file' });
      continue;
    }

    if (!isValidVersion(pkgVersion)) {
      skipped.push({ key: pkgKey, reason: 'unparseable' });
      continue;
    }

    const graphKey = `${name}@${pkgVersion}`;

    // pnpm v5/v6 may have explicit dev flag
    const hasExplicitDev = entry.dev === true;
    const hasExplicitOptional = entry.optional === true;

    // Classify from root deps
    const isRootProd = prodRootNames.has(name);
    const isRootDev = devRootNames.has(name);
    const isRootOptional = optionalRootNames.has(name);

    const node: DependencyNode = {
      name,
      version: pkgVersion,
      resolved: tarball || entry.resolution?.integrity || '',
      integrity: entry.resolution?.integrity ?? '',
      dependencies: [],
      isProduction: isRootProd || (!hasExplicitDev && !isRootDev),
      isDev: hasExplicitDev || isRootDev,
      isOptional: hasExplicitOptional || isRootOptional,
      depth: isRootProd || isRootDev || isRootOptional ? 1 : 2,
      dependencyPath: [],
    };

    // Production takes precedence
    if (node.isProduction) {
      node.isDev = false;
    }

    const existing = graph.get(graphKey);
    if (existing) {
      if (node.isProduction && !existing.isProduction) {
        existing.isProduction = true;
        existing.isDev = false;
      }
    } else {
      graph.set(graphKey, node);
    }
  }

  // Second pass: resolve dependency edges
  for (const [pkgKey, entry] of Object.entries(packages)) {
    const parsed = parsePnpmPackageKey(pkgKey, entry, version);
    if (!parsed) continue;

    const graphKey = `${parsed.name}@${parsed.pkgVersion}`;
    const node = graph.get(graphKey);
    if (!node) continue;

    const allDeps = {
      ...(entry.dependencies ?? {}),
      ...(entry.optionalDependencies ?? {}),
    };

    for (const [depName, depVersion] of Object.entries(allDeps)) {
      const cleanVersion = cleanPnpmVersion(depVersion);
      if (!cleanVersion) continue;

      const depGraphKey = `${depName}@${cleanVersion}`;
      if (graph.has(depGraphKey) && !node.dependencies.includes(depGraphKey)) {
        node.dependencies.push(depGraphKey);
      } else {
        // Fallback: find by name
        for (const [key, n] of graph) {
          if (n.name === depName && !node.dependencies.includes(key)) {
            node.dependencies.push(key);
            break;
          }
        }
      }
    }
  }

  // Reachability pass: propagate prod/dev through dependency edges
  propagateReachability(graph);

  logger.debug(`pnpm: ${graph.size} packages, ${[...graph.values()].filter(n => n.isProduction).length} prod`);
  return { type, graph, skipped };
}

/**
 * Parse a pnpm package key into name + version.
 * v5/v6 format: "/name/version" or "/@scope/name/version"
 * v9 format: "name@version" or "@scope/name@version"
 */
function parsePnpmPackageKey(
  key: string,
  entry: PnpmPackageEntry,
  lockfileVersion: number,
): { name: string; pkgVersion: string } | null {
  // v9+ format: "name@version" or "@scope/name@version"
  if (lockfileVersion >= 9 || !key.startsWith('/')) {
    // Entry may have explicit name/version fields
    if (entry.name && entry.version) {
      return { name: entry.name, pkgVersion: entry.version };
    }

    // Parse from key: "@scope/name@version" or "name@version"
    let atIdx: number;
    if (key.startsWith('@')) {
      atIdx = key.indexOf('@', 1);
    } else {
      atIdx = key.indexOf('@');
    }

    if (atIdx === -1) return null;
    const name = key.slice(0, atIdx);
    const ver = key.slice(atIdx + 1);
    if (!name || !ver) return null;
    return { name, pkgVersion: ver };
  }

  // v5/v6 format: "/name/version" or "/@scope/name/version"
  const withoutSlash = key.slice(1); // remove leading /

  if (withoutSlash.startsWith('@')) {
    // Scoped: @scope/name/version
    const parts = withoutSlash.split('/');
    if (parts.length < 3) return null;
    const name = `${parts[0]}/${parts[1]}`;
    const ver = parts[2];
    return { name, pkgVersion: ver };
  }

  // Unscoped: name/version
  const slashIdx = withoutSlash.indexOf('/');
  if (slashIdx === -1) return null;
  const name = withoutSlash.slice(0, slashIdx);
  const ver = withoutSlash.slice(slashIdx + 1);
  // Version might have suffix like "_peer-dep@version" in v6
  const cleanVer = ver.split('_')[0];
  return { name, pkgVersion: cleanVer };
}

/**
 * Clean pnpm version references.
 * pnpm may store versions as "1.2.3" or "1.2.3_peer-dep@2.0.0"
 */
function cleanPnpmVersion(version: string): string | null {
  if (!version) return null;
  // Strip peer dep suffixes
  const clean = version.split('_')[0].split('(')[0];
  return clean || null;
}

/**
 * Propagate production flag through dependency edges.
 * If a production node depends on a dev node, promote it to production.
 */
function propagateReachability(graph: DependencyGraph): void {
  const visited = new Set<string>();
  const queue: string[] = [];

  // Start from production roots
  for (const [key, node] of graph) {
    if (node.isProduction) {
      queue.push(key);
      visited.add(key);
    }
  }

  // BFS: mark all reachable from production as production
  let qi = 0;
  while (qi < queue.length) {
    const key = queue[qi++];
    const node = graph.get(key);
    if (!node) continue;

    for (const depKey of node.dependencies) {
      if (visited.has(depKey)) continue;
      visited.add(depKey);

      const dep = graph.get(depKey);
      if (dep) {
        dep.isProduction = true;
        dep.isDev = false;
        queue.push(depKey);
      }
    }
  }
}
