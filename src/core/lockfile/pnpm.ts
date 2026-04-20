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

// M-S3: cap pnpm/berry package-key length to defend against 10MB key DOS.
// 1KB comfortably exceeds real pnpm keys (scope + name + version + peer-dep suffix).
const MAX_KEY_LENGTH = 1024;

// M-S5: whitelist known pnpm lockfileVersion values. parseFloat previously
// accepted "Infinity", "9abc", etc. which silently dispatched to the v9 path.
const SUPPORTED_LOCKFILE_VERSIONS = new Set<string>(['5', '5.0', '5.1', '5.2', '5.3', '5.4', '6', '6.0', '6.1', '9', '9.0']);

function parseLockfileVersion(rawVersion: unknown): number {
  if (typeof rawVersion === 'number') {
    if (!Number.isFinite(rawVersion)) return 0;
    if (rawVersion === 5 || rawVersion === 6 || rawVersion === 9) return rawVersion;
    return 0;
  }
  if (typeof rawVersion !== 'string') return 0;
  const trimmed = rawVersion.trim();
  if (!SUPPORTED_LOCKFILE_VERSIONS.has(trimmed)) return 0;
  // Safe now: whitelist guarantees the string is a clean numeric literal.
  const n = Number(trimmed);
  return Number.isFinite(n) ? n : 0;
}

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
  const version = parseLockfileVersion(rawVersion);

  let type: LockfileType;
  if (version === 9) {
    type = 'pnpm-v9';
  } else if (version === 6) {
    type = 'pnpm-v6';
  } else if (version === 5) {
    type = 'pnpm-v5';
  } else {
    throw new Error(
      `Unsupported pnpm lockfile version ${JSON.stringify(rawVersion)}. auditfix supports pnpm lockfileVersion 5, 6, or 9.`,
    );
  }

  const packages = lockfile.packages;
  if (!packages || typeof packages !== 'object') {
    throw new Error('Invalid pnpm-lock.yaml: missing "packages" field.');
  }

  const graph: DependencyGraph = new Map();
  const skipped: SkippedDependency[] = [];

  // Determine root deps from ALL importers (monorepo support).
  // For monorepos, pnpm has multiple importers (e.g. '.', 'packages/app', 'packages/utils').
  // We union dependencies across all importers. A package that is a production dep in ANY
  // importer is considered production (production takes precedence over dev).
  const importers: PnpmImporter[] = [];
  if (lockfile.importers && typeof lockfile.importers === 'object') {
    for (const importer of Object.values(lockfile.importers)) {
      if (importer && typeof importer === 'object') {
        importers.push(importer as PnpmImporter);
      }
    }
  }
  // Fallback: if no importers, use top-level fields (pnpm v5 compat)
  if (importers.length === 0) {
    importers.push({
      dependencies: lockfile.dependencies,
      devDependencies: lockfile.devDependencies,
      optionalDependencies: lockfile.optionalDependencies,
    });
  }

  const prodRootNames = new Set<string>();
  const devRootNames = new Set<string>();
  const optionalRootNames = new Set<string>();
  for (const importer of importers) {
    for (const name of Object.keys(importer.dependencies ?? {})) {
      prodRootNames.add(name);
    }
    for (const name of Object.keys(importer.devDependencies ?? {})) {
      devRootNames.add(name);
    }
    for (const name of Object.keys(importer.optionalDependencies ?? {})) {
      optionalRootNames.add(name);
    }
  }
  // Production takes precedence: if a package is a prod dep in any importer, remove from dev
  for (const name of prodRootNames) {
    devRootNames.delete(name);
  }

  // First pass: create nodes
  for (const [pkgKey, entry] of Object.entries(packages)) {
    // M-S3: reject absurdly long keys (DOS vector — repeated 10MB allocations).
    if (pkgKey.length > MAX_KEY_LENGTH) {
      logger.warn(`pnpm: skipping oversized package key (${pkgKey.length} bytes, max ${MAX_KEY_LENGTH})`);
      skipped.push({ key: pkgKey.slice(0, 80) + '...', reason: 'unparseable' });
      continue;
    }

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

    // C-B1: Respect explicit entry.dev / entry.optional flags from pnpm v5/v6
    // lockfiles. Fall back to BFS reachability only when flags are absent.
    const hasDevField = typeof entry.dev === 'boolean';
    const hasOptionalField = typeof entry.optional === 'boolean';
    const explicitDev = entry.dev === true;
    const explicitOptional = entry.optional === true;

    // Classify from root deps (monorepo union)
    const isRootProd = prodRootNames.has(name);
    const isRootDev = devRootNames.has(name);
    const isRootOptional = optionalRootNames.has(name);
    const isRootDep = isRootProd || isRootDev || isRootOptional;

    // Decide prod/dev. Explicit flags beat root-set inference.
    let isProduction: boolean;
    let isDev: boolean;
    if (hasDevField) {
      // Explicit flag present: trust it unconditionally for this node.
      // (propagateReachability may still promote transitive prod later.)
      isDev = explicitDev;
      isProduction = !explicitDev;
    } else if (isRootProd) {
      isProduction = true;
      isDev = false;
    } else if (isRootDev) {
      isProduction = false;
      isDev = true;
    } else {
      // Transitive with no flags: default to dev; reachability BFS promotes.
      isProduction = false;
      isDev = true;
    }

    const isOptional = hasOptionalField ? explicitOptional : isRootOptional;

    const node: DependencyNode = {
      name,
      version: pkgVersion,
      resolved: tarball || entry.resolution?.integrity || '',
      integrity: entry.resolution?.integrity ?? '',
      dependencies: [],
      isProduction,
      isDev,
      isOptional,
      depth: isRootDep ? 1 : 2,
      dependencyPath: [],
    };

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

  // P1: build name-index once for O(1) fallback lookup (was O(N) per miss).
  const nameIndex = new Map<string, string[]>();
  for (const [graphKey, node] of graph) {
    const bucket = nameIndex.get(node.name);
    if (bucket) bucket.push(graphKey);
    else nameIndex.set(node.name, [graphKey]);
  }

  // Second pass: resolve dependency edges
  for (const [pkgKey, entry] of Object.entries(packages)) {
    if (pkgKey.length > MAX_KEY_LENGTH) continue;

    const parsed = parsePnpmPackageKey(pkgKey, entry, version);
    if (!parsed) continue;

    const graphKey = `${parsed.name}@${parsed.pkgVersion}`;
    const node = graph.get(graphKey);
    if (!node) continue;

    // P7-analogue: iterate both maps directly, Set for dedup.
    const seen = new Set<string>(node.dependencies);

    const pushEdge = (depName: string, depVersion: string | undefined) => {
      if (!depVersion) return;
      const cleanVersion = cleanPnpmVersion(depVersion);
      if (!cleanVersion) return;

      const directKey = `${depName}@${cleanVersion}`;
      if (graph.has(directKey)) {
        if (!seen.has(directKey)) {
          seen.add(directKey);
          node.dependencies.push(directKey);
        }
        return;
      }

      // Fallback via name-index (O(1) lookup, O(k) scan where k = same-named versions).
      const bucket = nameIndex.get(depName);
      if (!bucket) return;
      for (const candidate of bucket) {
        if (!seen.has(candidate)) {
          seen.add(candidate);
          node.dependencies.push(candidate);
          return;
        }
      }
    };

    if (entry.dependencies) {
      for (const [depName, depVersion] of Object.entries(entry.dependencies)) {
        pushEdge(depName, depVersion);
      }
    }
    if (entry.optionalDependencies) {
      for (const [depName, depVersion] of Object.entries(entry.optionalDependencies)) {
        pushEdge(depName, depVersion);
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
