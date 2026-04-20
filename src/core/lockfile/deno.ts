/**
 * Deno lockfile parser for deno.lock (versions 3 and 4).
 *
 * auditfix scans npm supply chain, so we only extract the `packages.npm`
 * sub-tree. JSR, remote URLs, and Deno-specific modules are ignored — we
 * cannot advise on their security with an npm advisory corpus.
 *
 * Format reference:
 *   v3: https://docs.deno.com/runtime/fundamentals/modules/#integrity-checking-and-lock-files
 *   v4: adds `workspace.members` and restructures top-level keys, but the
 *       `packages.npm` sub-tree remains compatible for our purposes.
 */
import type {
  DependencyGraph,
  DependencyNode,
  LockfileType,
  SkippedDependency,
} from '../../types/package.js';
import { isValidVersion } from '../../utils/semver.js';
import { safeJsonParse } from '../../utils/sanitize.js';
import * as logger from '../../utils/logger.js';

const MAX_KEY_LENGTH = 1024;

type DenoNpmEntry = {
  integrity?: string;
  dependencies?: string[] | Record<string, string>;
  optionalDependencies?: string[] | Record<string, string>;
  optionalPeers?: Record<string, string>;
};

type DenoWorkspaceMember = {
  dependencies?: string[];
  packageJson?: {
    dependencies?: string[];
  };
};

type DenoLockfile = {
  version?: string | number;
  packages?: {
    specifiers?: Record<string, string>;
    npm?: Record<string, DenoNpmEntry>;
    jsr?: Record<string, unknown>;
  };
  // v3 sometimes places npm directly, sometimes inside `packages`.
  npm?: Record<string, DenoNpmEntry>;
  specifiers?: Record<string, string>;
  remote?: Record<string, string>;
  workspace?: {
    dependencies?: string[];
    packageJson?: {
      dependencies?: string[];
    };
    members?: Record<string, DenoWorkspaceMember>;
  };
};

export function parseDenoLockfile(content: string): {
  type: LockfileType;
  graph: DependencyGraph;
  skipped: SkippedDependency[];
} {
  let lockfile: DenoLockfile;
  try {
    lockfile = safeJsonParse<DenoLockfile>(content);
  } catch (err) {
    throw new Error(
      `Failed to parse deno.lock: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  if (!lockfile || typeof lockfile !== 'object') {
    throw new Error('Failed to parse deno.lock: expected a JSON object at the root.');
  }

  // v3 and v4 both use numeric version identifiers as a string.
  const versionRaw = lockfile.version;
  const versionNum =
    typeof versionRaw === 'string' ? parseFloat(versionRaw) : (versionRaw ?? 3);
  if (!Number.isFinite(versionNum) || versionNum < 3) {
    throw new Error(
      `Unsupported deno.lock version ${String(versionRaw)}. auditfix requires deno.lock version 3 or later.`,
    );
  }

  // npm packages may live at `packages.npm` (v3/v4 canonical) or `npm` (older v3 variants).
  const npmPackages = lockfile.packages?.npm ?? lockfile.npm ?? {};
  const specifiers = lockfile.packages?.specifiers ?? lockfile.specifiers ?? {};

  const graph: DependencyGraph = new Map();
  const skipped: SkippedDependency[] = [];

  // First pass: build nodes from packages.npm entries.
  for (const [pkgKey, entry] of Object.entries(npmPackages)) {
    if (pkgKey.length > MAX_KEY_LENGTH) {
      logger.warn(
        `deno: skipping oversized package key (${pkgKey.length} bytes, max ${MAX_KEY_LENGTH})`,
      );
      skipped.push({ key: pkgKey.slice(0, 80) + '...', reason: 'unparseable' });
      continue;
    }

    if (!entry || typeof entry !== 'object') {
      skipped.push({ key: pkgKey, reason: 'unparseable' });
      continue;
    }

    const parsed = parseDenoNpmKey(pkgKey);
    if (!parsed) {
      skipped.push({ key: pkgKey, reason: 'unparseable' });
      continue;
    }

    if (!isValidVersion(parsed.version)) {
      skipped.push({ key: pkgKey, reason: 'unparseable' });
      continue;
    }

    const graphKey = `${parsed.name}@${parsed.version}`;
    if (graph.has(graphKey)) continue;

    const node: DependencyNode = {
      name: parsed.name,
      version: parsed.version,
      resolved: `npm:${parsed.name}@${parsed.version}`,
      integrity: entry.integrity ?? '',
      dependencies: [],
      isProduction: false, // set via reachability
      isDev: false,
      isOptional: false,
      depth: 0,
      dependencyPath: [],
    };

    graph.set(graphKey, node);
  }

  // Name index for fallback name-only edge resolution.
  const nameIndex = new Map<string, string[]>();
  for (const [graphKey, node] of graph) {
    const bucket = nameIndex.get(node.name);
    if (bucket) bucket.push(graphKey);
    else nameIndex.set(node.name, [graphKey]);
  }

  // Second pass: resolve dependency edges. Entry `dependencies` is either an
  // array of "name@version_peer@version" strings, or a Record<string, string>
  // mapping name -> resolved-key in older variants.
  for (const [pkgKey, entry] of Object.entries(npmPackages)) {
    if (pkgKey.length > MAX_KEY_LENGTH) continue;

    const parsed = parseDenoNpmKey(pkgKey);
    if (!parsed || !isValidVersion(parsed.version)) continue;

    const graphKey = `${parsed.name}@${parsed.version}`;
    const node = graph.get(graphKey);
    if (!node) continue;

    const edges = collectEdges(entry);
    const seen = new Set<string>();
    for (const edge of edges) {
      const resolvedKey = resolveEdge(edge, graph, nameIndex);
      if (!resolvedKey) continue;
      if (seen.has(resolvedKey)) continue;
      seen.add(resolvedKey);
      node.dependencies.push(resolvedKey);
    }
  }

  // Root classification: follow workspace.dependencies + packageJson.dependencies
  // + top-level specifiers that come from npm:.
  const prodRootNames = collectRootNpmNames(lockfile, specifiers);

  classifyReachability(graph, nameIndex, prodRootNames);

  logger.debug(
    `deno: ${graph.size} npm packages, ${[...graph.values()].filter((n) => n.isProduction).length} prod`,
  );
  return { type: 'deno', graph, skipped };
}

/**
 * Parse a Deno npm key into name + version. Peer suffixes separated by '_'
 * are stripped: "lodash@4.17.21_other@2.0.0" -> { name: "lodash", version: "4.17.21" }.
 * Scoped packages keep the leading '@'.
 */
export function parseDenoNpmKey(
  key: string,
): { name: string; version: string } | null {
  if (!key) return null;
  // Peer-pinned keys: take the head before '_' (which itself splits "name@version").
  const head = key.split('_')[0];
  const nameStart = head.startsWith('@') ? 1 : 0;
  const atIdx = head.indexOf('@', nameStart);
  if (atIdx === -1 || atIdx === 0) return null;
  const name = head.slice(0, atIdx);
  const version = head.slice(atIdx + 1);
  if (!name || !version) return null;
  return { name, version };
}

function collectEdges(entry: DenoNpmEntry): string[] {
  const out: string[] = [];
  if (Array.isArray(entry.dependencies)) {
    out.push(...entry.dependencies);
  } else if (entry.dependencies && typeof entry.dependencies === 'object') {
    out.push(...Object.values(entry.dependencies));
  }
  if (Array.isArray(entry.optionalDependencies)) {
    out.push(...entry.optionalDependencies);
  } else if (entry.optionalDependencies && typeof entry.optionalDependencies === 'object') {
    out.push(...Object.values(entry.optionalDependencies));
  }
  return out;
}

/**
 * Resolve an edge reference against the graph.
 *
 * Edge reference shapes seen in deno.lock:
 *   "lodash@4.17.21"                -> exact key
 *   "lodash@4.17.21_peer@1.0.0"     -> peer-pinned; strip suffix, lookup name@version
 *   "lodash"                        -> name-only; resolve by nameIndex
 *   "name@npm:other@1.2.3"          -> aliased; treat as other@1.2.3
 */
function resolveEdge(
  ref: string,
  graph: DependencyGraph,
  nameIndex: Map<string, string[]>,
): string | null {
  if (!ref) return null;
  const trimmed = ref.trim();

  // name-only reference
  if (!trimmed.includes('@') || (trimmed.startsWith('@') && trimmed.indexOf('@', 1) === -1)) {
    const candidates = nameIndex.get(trimmed);
    if (candidates && candidates.length > 0) return candidates[0];
    return null;
  }

  const parsed = parseDenoNpmKey(trimmed);
  if (!parsed) return null;

  const exact = `${parsed.name}@${parsed.version}`;
  if (graph.has(exact)) return exact;

  // Fallback: first graph entry matching the name.
  const candidates = nameIndex.get(parsed.name);
  if (candidates && candidates.length > 0) return candidates[0];
  return null;
}

function collectRootNpmNames(
  lockfile: DenoLockfile,
  specifiers: Record<string, string>,
): Set<string> {
  const out = new Set<string>();

  // Top-level specifiers: map like "npm:lodash@^4" -> "npm:lodash@4.17.21".
  for (const specifier of Object.keys(specifiers)) {
    const name = npmNameFromSpecifier(specifier);
    if (name) out.add(name);
  }

  const ws = lockfile.workspace ?? {};

  function addFromDepList(deps?: string[]): void {
    if (!Array.isArray(deps)) return;
    for (const dep of deps) {
      const name = npmNameFromSpecifier(dep);
      if (name) out.add(name);
    }
  }

  addFromDepList(ws.dependencies);
  addFromDepList(ws.packageJson?.dependencies);

  const members = ws.members ?? {};
  for (const member of Object.values(members)) {
    addFromDepList(member?.dependencies);
    addFromDepList(member?.packageJson?.dependencies);
  }

  return out;
}

/**
 * Extract npm package name from a Deno specifier.
 *  "npm:lodash@^4.0.0"          -> "lodash"
 *  "npm:@scope/pkg@^1.0.0"      -> "@scope/pkg"
 *  "npm:lodash"                 -> "lodash"
 *  "jsr:@std/path"              -> null (not npm)
 */
function npmNameFromSpecifier(specifier: string): string | null {
  if (!specifier.startsWith('npm:')) return null;
  const tail = specifier.slice(4);
  const nameStart = tail.startsWith('@') ? 1 : 0;
  const atIdx = tail.indexOf('@', nameStart);
  if (atIdx === -1) return tail || null;
  return tail.slice(0, atIdx) || null;
}

function classifyReachability(
  graph: DependencyGraph,
  nameIndex: Map<string, string[]>,
  prodRootNames: Set<string>,
): void {
  const visited = new Set<string>();
  const queue: { key: string; depth: number }[] = [];

  for (const name of prodRootNames) {
    const candidates = nameIndex.get(name);
    if (!candidates) continue;
    for (const key of candidates) {
      if (visited.has(key)) continue;
      visited.add(key);
      queue.push({ key, depth: 1 });
    }
  }

  let qi = 0;
  while (qi < queue.length) {
    const { key, depth } = queue[qi++];
    const node = graph.get(key);
    if (!node) continue;

    node.isProduction = true;
    if (node.depth === 0 || depth < node.depth) {
      node.depth = depth;
    }

    for (const depKey of node.dependencies) {
      if (visited.has(depKey)) continue;
      visited.add(depKey);
      queue.push({ key: depKey, depth: depth + 1 });
    }
  }

  // Any node not reached from a prod root is classified as dev. Deno lockfiles
  // don't distinguish dev vs prod at the package level — only reachability.
  for (const node of graph.values()) {
    if (!node.isProduction) {
      node.isDev = true;
    }
  }
}
