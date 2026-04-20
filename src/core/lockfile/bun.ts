/**
 * Bun lockfile parser for bun.lock text format (Bun 1.2+).
 *
 * Format is JSONC-like: JSON with // and /* * / comments and trailing commas.
 * We strip comments + trailing commas inline, then hand off to safeJsonParse
 * (which keeps prototype-pollution protection).
 *
 * Binary bun.lockb is NOT supported. Bun has not published a stable spec for
 * the binary format, so we detect and skip-with-clear-reason. Callers should
 * instruct users to upgrade to Bun 1.2+ or run `bun install --save-text-lockfile`.
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

// Mirror pnpm/yarn-berry caps: 1KB key ceiling defends against
// oversized-key allocation DOS from malformed lockfiles.
const MAX_KEY_LENGTH = 1024;

type BunPackageMeta = {
  // bun stores per-package metadata as an object that may include dependencies,
  // devDependencies, peerDependencies, optionalDependencies, os, cpu, bin, etc.
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  os?: string | string[];
  cpu?: string | string[];
  bin?: unknown;
};

type BunWorkspace = {
  name?: string;
  version?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  optionalDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
};

type BunLockfile = {
  lockfileVersion?: number;
  workspaces?: Record<string, BunWorkspace>;
  packages?: Record<string, unknown[]>;
};

export function parseBunLockfile(content: string): {
  type: LockfileType;
  graph: DependencyGraph;
  skipped: SkippedDependency[];
} {
  if (isBinaryBunLockfile(content)) {
    logger.warn(
      'bun: detected binary bun.lockb. auditfix only supports the text bun.lock format (Bun 1.2+). Run `bun install --save-text-lockfile` to generate one.',
    );
    return {
      type: 'bun',
      graph: new Map(),
      skipped: [
        {
          key: 'bun.lockb',
          reason: 'unparseable',
        },
      ],
    };
  }

  const stripped = stripJsonc(content);

  let lockfile: BunLockfile;
  try {
    lockfile = safeJsonParse<BunLockfile>(stripped);
  } catch (err) {
    throw new Error(
      `Failed to parse bun.lock: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  if (!lockfile || typeof lockfile !== 'object') {
    throw new Error('Failed to parse bun.lock: expected a JSON object at the root.');
  }

  const packages = lockfile.packages ?? {};
  const workspaces = lockfile.workspaces ?? {};

  const graph: DependencyGraph = new Map();
  const skipped: SkippedDependency[] = [];

  // Collect the root workspace dep manifests for prod/dev classification.
  const rootWorkspace = workspaces[''] ?? null;
  const prodRootNames = new Set(Object.keys(rootWorkspace?.dependencies ?? {}));
  const devRootNames = new Set(Object.keys(rootWorkspace?.devDependencies ?? {}));
  const optionalRootNames = new Set(
    Object.keys(rootWorkspace?.optionalDependencies ?? {}),
  );
  // Include non-root workspaces' deps as prod roots (monorepo packages).
  for (const [wsKey, ws] of Object.entries(workspaces)) {
    if (wsKey === '') continue;
    for (const depName of Object.keys(ws?.dependencies ?? {})) {
      prodRootNames.add(depName);
    }
    for (const depName of Object.keys(ws?.devDependencies ?? {})) {
      devRootNames.add(depName);
    }
    for (const depName of Object.keys(ws?.optionalDependencies ?? {})) {
      optionalRootNames.add(depName);
    }
  }

  // First pass: build nodes.
  for (const [pkgKey, value] of Object.entries(packages)) {
    if (pkgKey.length > MAX_KEY_LENGTH) {
      logger.warn(
        `bun: skipping oversized package key (${pkgKey.length} bytes, max ${MAX_KEY_LENGTH})`,
      );
      skipped.push({ key: pkgKey.slice(0, 80) + '...', reason: 'unparseable' });
      continue;
    }

    // Entries for local workspaces look like "": [...] or "my-pkg": [...]
    // and do not resolve to an installable tarball. Skip them.
    if (pkgKey === '' || workspaces[pkgKey]) {
      skipped.push({ key: pkgKey || '<root>', reason: 'workspace' });
      continue;
    }

    if (!Array.isArray(value) || value.length === 0) {
      skipped.push({ key: pkgKey, reason: 'unparseable' });
      continue;
    }

    const spec = typeof value[0] === 'string' ? value[0] : null;
    if (!spec) {
      skipped.push({ key: pkgKey, reason: 'unparseable' });
      continue;
    }

    // Reject workspace/link/file/git protocol resolutions. Bun writes specs
    // like "pkg@git+https://..." or "pkg@file:../local" so we match on any
    // occurrence of the protocol marker in the spec, not just the prefix.
    if (
      spec.includes('@workspace:') ||
      spec.includes('workspace:') ||
      spec.includes('@link:') ||
      spec.startsWith('link:')
    ) {
      skipped.push({ key: pkgKey, reason: 'workspace' });
      continue;
    }
    if (
      spec.includes('git+') ||
      spec.includes('git://') ||
      spec.includes('#commit=') ||
      spec.includes('@github:')
    ) {
      skipped.push({ key: pkgKey, reason: 'git-dep' });
      continue;
    }
    if (spec.includes('@file:') || spec.startsWith('file:')) {
      skipped.push({ key: pkgKey, reason: 'local-file' });
      continue;
    }

    const parsed = parseBunSpec(spec);
    if (!parsed) {
      skipped.push({ key: pkgKey, reason: 'unparseable' });
      continue;
    }

    if (!isValidVersion(parsed.version)) {
      skipped.push({ key: pkgKey, reason: 'unparseable' });
      continue;
    }

    const integrity = typeof value[2] === 'string' ? value[2] : '';

    const graphKey = `${parsed.name}@${parsed.version}`;

    if (graph.has(graphKey)) continue;

    const isRootProd = prodRootNames.has(parsed.name);
    const isRootDev = devRootNames.has(parsed.name);
    const isRootOptional = optionalRootNames.has(parsed.name);

    const node: DependencyNode = {
      name: parsed.name,
      version: parsed.version,
      resolved: spec,
      integrity,
      dependencies: [],
      // Classification is refined in the reachability pass, but seed from roots.
      isProduction: isRootProd,
      isDev: isRootDev && !isRootProd,
      isOptional: isRootOptional,
      depth: isRootProd || isRootDev || isRootOptional ? 1 : 0,
      dependencyPath: [],
    };

    graph.set(graphKey, node);
  }

  // Name index for O(1) fallback edge lookup.
  const nameIndex = new Map<string, string[]>();
  for (const [graphKey, node] of graph) {
    const bucket = nameIndex.get(node.name);
    if (bucket) bucket.push(graphKey);
    else nameIndex.set(node.name, [graphKey]);
  }

  // Second pass: resolve dependency edges.
  for (const [pkgKey, value] of Object.entries(packages)) {
    if (pkgKey === '' || workspaces[pkgKey]) continue;
    if (pkgKey.length > MAX_KEY_LENGTH) continue;
    if (!Array.isArray(value) || typeof value[0] !== 'string') continue;

    const parsed = parseBunSpec(value[0]);
    if (!parsed || !isValidVersion(parsed.version)) continue;

    const graphKey = `${parsed.name}@${parsed.version}`;
    const node = graph.get(graphKey);
    if (!node) continue;

    const meta = (typeof value[1] === 'object' && value[1] !== null
      ? (value[1] as BunPackageMeta)
      : {}) as BunPackageMeta;

    const allDeps: Record<string, string> = {
      ...(meta.dependencies ?? {}),
      ...(meta.optionalDependencies ?? {}),
    };

    const seen = new Set<string>();
    for (const depName of Object.keys(allDeps)) {
      const candidates = nameIndex.get(depName);
      if (!candidates || candidates.length === 0) continue;
      // Bun lockfile stores resolved versions in the spec itself; we cannot
      // easily range-match here. Prefer the single candidate if only one
      // version exists; otherwise we pick the first (best-effort, mirrors
      // yarn-berry fallback behavior).
      const picked = candidates[0];
      if (seen.has(picked)) continue;
      seen.add(picked);
      node.dependencies.push(picked);
    }
  }

  // Reachability pass from workspace roots classifies transitive prod/dev/optional.
  classifyReachability(graph, nameIndex, {
    prod: [...prodRootNames],
    dev: [...devRootNames],
    optional: [...optionalRootNames],
  });

  logger.debug(
    `bun: ${graph.size} packages, ${[...graph.values()].filter((n) => n.isProduction).length} prod`,
  );
  return { type: 'bun', graph, skipped };
}

/**
 * Extract name + version from a Bun resolved spec.
 * Examples:
 *   "lodash@4.17.21"              -> { name: "lodash", version: "4.17.21" }
 *   "@scope/pkg@1.2.3"            -> { name: "@scope/pkg", version: "1.2.3" }
 *   "lodash@npm:4.17.21"          -> { name: "lodash", version: "4.17.21" }
 *   "pkg@github:user/repo#hash"   -> null (git, handled before this)
 */
export function parseBunSpec(spec: string): { name: string; version: string } | null {
  if (!spec) return null;
  const trimmed = spec.trim();

  // Locate the '@' that separates name from version-descriptor.
  // Scoped packages start with '@' so we start scanning from index 1.
  const nameStart = trimmed.startsWith('@') ? 1 : 0;
  const atIdx = trimmed.indexOf('@', nameStart);
  if (atIdx === -1 || atIdx === 0) return null;

  const name = trimmed.slice(0, atIdx);
  let version = trimmed.slice(atIdx + 1);

  // Strip npm: protocol prefix if present.
  if (version.startsWith('npm:')) {
    version = version.slice(4);
    // Nested name@version e.g. "lodash@npm:other-name@4.17.21" (aliased).
    // Strip alias prefix up to the last '@' if format looks like name@version.
    const aliasNameStart = version.startsWith('@') ? 1 : 0;
    const aliasAt = version.indexOf('@', aliasNameStart);
    if (aliasAt !== -1) {
      version = version.slice(aliasAt + 1);
    }
  }

  if (!name || !version) return null;
  return { name, version };
}

/**
 * Strip // line comments, /* block *\/ comments, and trailing commas from
 * a JSONC document. Skips content inside string literals (respects \" escapes).
 */
export function stripJsonc(input: string): string {
  const out: string[] = [];
  const n = input.length;
  let i = 0;
  let inString = false;
  let stringQuote: '"' | "'" | null = null;

  while (i < n) {
    const ch = input[i];
    const next = i + 1 < n ? input[i + 1] : '';

    if (inString) {
      out.push(ch);
      if (ch === '\\' && i + 1 < n) {
        // Keep the escape sequence intact.
        out.push(next);
        i += 2;
        continue;
      }
      if (ch === stringQuote) {
        inString = false;
        stringQuote = null;
      }
      i++;
      continue;
    }

    if (ch === '"' || ch === "'") {
      inString = true;
      stringQuote = ch as '"' | "'";
      out.push(ch);
      i++;
      continue;
    }

    if (ch === '/' && next === '/') {
      // Skip to end of line.
      i += 2;
      while (i < n && input[i] !== '\n') i++;
      continue;
    }

    if (ch === '/' && next === '*') {
      i += 2;
      while (i < n && !(input[i] === '*' && input[i + 1] === '/')) i++;
      i += 2;
      continue;
    }

    out.push(ch);
    i++;
  }

  // Strip trailing commas before } or ].
  return out.join('').replace(/,(\s*[}\]])/g, '$1');
}

/**
 * Detect whether the content is the binary bun.lockb format rather than
 * the text bun.lock format. Text lockfiles are JSON-shaped; binary ones
 * start with a magic byte sequence and are full of null bytes.
 */
function isBinaryBunLockfile(content: string): boolean {
  if (content.length === 0) return false;
  // Binary bun.lockb files start with a magic header and contain null bytes.
  if (content.includes('\0')) return true;
  const first = content.charCodeAt(0);
  // Text bun.lock starts with '{' (0x7b), possibly BOM (0xfeff), or whitespace.
  const isPlausibleText =
    first === 0x7b /* { */ ||
    first === 0xfeff /* BOM */ ||
    first === 0x20 /* space */ ||
    first === 0x09 /* tab */ ||
    first === 0x0a /* LF */ ||
    first === 0x0d /* CR */ ||
    first === 0x2f /* / — allow leading JSONC comment */;
  return !isPlausibleText;
}

function classifyReachability(
  graph: DependencyGraph,
  nameIndex: Map<string, string[]>,
  roots: { prod: string[]; dev: string[]; optional: string[] },
): void {
  function bfs(rootNames: string[], markFn: (node: DependencyNode) => void): void {
    const visited = new Set<string>();
    const queue: { key: string; depth: number }[] = [];

    for (const name of rootNames) {
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

      markFn(node);
      if (node.depth === 0 || depth < node.depth) {
        node.depth = depth;
      }

      for (const depKey of node.dependencies) {
        if (visited.has(depKey)) continue;
        visited.add(depKey);
        queue.push({ key: depKey, depth: depth + 1 });
      }
    }
  }

  bfs(roots.prod, (node) => {
    node.isProduction = true;
  });
  bfs(roots.optional, (node) => {
    node.isOptional = true;
    if (!node.isProduction) node.isProduction = true;
  });
  bfs(roots.dev, (node) => {
    if (!node.isProduction) node.isDev = true;
  });

  for (const node of graph.values()) {
    if (!node.isProduction && !node.isDev && !node.isOptional) {
      node.isDev = true;
    }
    if (node.isProduction) {
      node.isDev = false;
    }
  }
}
