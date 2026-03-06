/**
 * Workspace/monorepo detection.
 * Detects npm/yarn workspaces (package.json "workspaces" field)
 * and pnpm workspaces (pnpm-workspace.yaml).
 * Returns the list of workspace packages with their dependencies.
 */
import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { join, relative, resolve } from 'node:path';
import { safeJsonParse, safeYamlParse } from '../../utils/sanitize.js';
import * as logger from '../../utils/logger.js';

export type WorkspaceInfo = {
  name: string;
  path: string; // relative to project root
  dependencies: Record<string, string>;
  devDependencies: Record<string, string>;
};

export type WorkspaceConfig = {
  isMonorepo: boolean;
  workspaces: WorkspaceInfo[];
};

/**
 * Detect workspace configuration in a project directory.
 */
export function detectWorkspaces(projectDir: string): WorkspaceConfig {
  // Try pnpm-workspace.yaml first
  const pnpmWorkspacePath = join(projectDir, 'pnpm-workspace.yaml');
  if (existsSync(pnpmWorkspacePath)) {
    return detectPnpmWorkspaces(projectDir, pnpmWorkspacePath);
  }

  // Try package.json workspaces (npm/yarn)
  const packageJsonPath = join(projectDir, 'package.json');
  if (existsSync(packageJsonPath)) {
    try {
      const content = readFileSync(packageJsonPath, 'utf-8');
      const pkg = safeJsonParse<Record<string, unknown>>(content);
      const workspacesField = pkg.workspaces;

      if (workspacesField) {
        return detectNpmYarnWorkspaces(projectDir, workspacesField);
      }
    } catch {
      // Not a valid package.json — not a monorepo
    }
  }

  return { isMonorepo: false, workspaces: [] };
}

/**
 * Detect pnpm workspaces from pnpm-workspace.yaml.
 */
function detectPnpmWorkspaces(projectDir: string, configPath: string): WorkspaceConfig {
  try {
    const content = readFileSync(configPath, 'utf-8');
    const config = safeYamlParse(content) as { packages?: string[] } | null;

    if (!config?.packages || !Array.isArray(config.packages)) {
      return { isMonorepo: false, workspaces: [] };
    }

    const workspaces = resolveWorkspaceGlobs(projectDir, config.packages);
    logger.debug(`Detected pnpm monorepo with ${workspaces.length} workspaces`);
    return { isMonorepo: workspaces.length > 0, workspaces };
  } catch {
    return { isMonorepo: false, workspaces: [] };
  }
}

/**
 * Detect npm/yarn workspaces from package.json "workspaces" field.
 * Supports both array format and object format ({ packages: [...] }).
 */
function detectNpmYarnWorkspaces(projectDir: string, workspacesField: unknown): WorkspaceConfig {
  let patterns: string[];

  if (Array.isArray(workspacesField)) {
    patterns = workspacesField.filter((p): p is string => typeof p === 'string');
  } else if (
    typeof workspacesField === 'object' &&
    workspacesField !== null &&
    'packages' in workspacesField &&
    Array.isArray((workspacesField as { packages: unknown }).packages)
  ) {
    patterns = (workspacesField as { packages: string[] }).packages;
  } else {
    return { isMonorepo: false, workspaces: [] };
  }

  const workspaces = resolveWorkspaceGlobs(projectDir, patterns);
  logger.debug(`Detected npm/yarn monorepo with ${workspaces.length} workspaces`);
  return { isMonorepo: workspaces.length > 0, workspaces };
}

/**
 * Resolve workspace glob patterns to actual workspace directories.
 * Supports simple patterns like "packages/*" and "apps/*".
 */
function resolveWorkspaceGlobs(projectDir: string, patterns: string[]): WorkspaceInfo[] {
  const workspaces: WorkspaceInfo[] = [];
  const seen = new Set<string>();

  for (const pattern of patterns) {
    // Skip negated patterns
    if (pattern.startsWith('!')) continue;

    // Simple glob: "packages/*" or "apps/**"
    const cleanPattern = pattern.replace(/\/?\*\*?$/, '');

    const baseDir = join(projectDir, cleanPattern);
    if (!existsSync(baseDir) || !statSync(baseDir).isDirectory()) {
      // Try as a direct workspace path
      const directPkg = join(projectDir, pattern, 'package.json');
      if (existsSync(directPkg)) {
        const ws = readWorkspacePackage(projectDir, pattern);
        if (ws && !seen.has(ws.name)) {
          seen.add(ws.name);
          workspaces.push(ws);
        }
      }
      continue;
    }

    // Read subdirectories
    try {
      const entries = readdirSync(baseDir);
      for (const entry of entries) {
        const entryPath = join(baseDir, entry);
        const pkgJsonPath = join(entryPath, 'package.json');

        if (statSync(entryPath).isDirectory() && existsSync(pkgJsonPath)) {
          const relPath = relative(projectDir, entryPath).replace(/\\/g, '/');
          const ws = readWorkspacePackage(projectDir, relPath);
          if (ws && !seen.has(ws.name)) {
            seen.add(ws.name);
            workspaces.push(ws);
          }
        }
      }
    } catch {
      // Can't read directory — skip
    }
  }

  return workspaces;
}

/**
 * Read a workspace package.json and extract its dependencies.
 */
function readWorkspacePackage(projectDir: string, relPath: string): WorkspaceInfo | null {
  try {
    const pkgPath = join(projectDir, relPath, 'package.json');
    const content = readFileSync(pkgPath, 'utf-8');
    const pkg = safeJsonParse<Record<string, unknown>>(content);

    const name = (pkg.name as string) ?? relPath;

    return {
      name,
      path: relPath,
      dependencies: (pkg.dependencies as Record<string, string>) ?? {},
      devDependencies: (pkg.devDependencies as Record<string, string>) ?? {},
    };
  } catch {
    return null;
  }
}

/**
 * Map dependency graph nodes to the workspaces that depend on them.
 * Returns a map from graphKey (e.g. "lodash@4.17.21") to workspace names.
 */
export function mapDepsToWorkspaces(
  graph: import('../../types/package.js').DependencyGraph,
  workspaces: WorkspaceInfo[],
): Map<string, Set<string>> {
  if (workspaces.length === 0) return new Map();

  const depToWorkspaces = new Map<string, Set<string>>();

  // Build name-to-keys index for O(1) lookup (was O(N) per dep)
  const nameIndex = new Map<string, string[]>();
  for (const [graphKey, node] of graph) {
    const keys = nameIndex.get(node.name);
    if (keys) {
      keys.push(graphKey);
    } else {
      nameIndex.set(node.name, [graphKey]);
    }
  }

  // Memoize transitive dep sets per graph key
  const transitiveCache = new Map<string, Set<string>>();

  function getTransitiveDeps(graphKey: string): Set<string> {
    if (transitiveCache.has(graphKey)) return transitiveCache.get(graphKey)!;

    const result = new Set<string>();
    transitiveCache.set(graphKey, result); // set early to handle cycles

    const node = graph.get(graphKey);
    if (!node) return result;

    for (const depKey of node.dependencies) {
      result.add(depKey);
      for (const transKey of getTransitiveDeps(depKey)) {
        result.add(transKey);
      }
    }
    return result;
  }

  for (const ws of workspaces) {
    const allDeps = { ...ws.dependencies, ...ws.devDependencies };

    for (const depName of Object.keys(allDeps)) {
      const candidates = nameIndex.get(depName);
      if (!candidates) continue;

      for (const graphKey of candidates) {
        if (!depToWorkspaces.has(graphKey)) {
          depToWorkspaces.set(graphKey, new Set());
        }
        depToWorkspaces.get(graphKey)!.add(ws.name);

        // Map transitive deps using memoized set
        for (const transKey of getTransitiveDeps(graphKey)) {
          if (!depToWorkspaces.has(transKey)) {
            depToWorkspaces.set(transKey, new Set());
          }
          depToWorkspaces.get(transKey)!.add(ws.name);
        }
      }
    }
  }

  return depToWorkspaces;
}
