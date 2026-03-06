/**
 * Import chain reachability analysis.
 * Static analysis of require/import statements to determine if a vulnerable
 * package is actually imported (directly or transitively) by application code.
 *
 * This is a best-effort heuristic — it can prove reachability but cannot
 * definitively prove unreachability (dynamic requires, conditional imports).
 */
import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { join, extname, resolve, dirname } from 'node:path';
import * as logger from '../../utils/logger.js';

const JS_EXTENSIONS = new Set(['.js', '.mjs', '.cjs', '.ts', '.mts', '.cts', '.jsx', '.tsx']);

/**
 * Node.js built-in modules to exclude from import detection.
 * Covers the core set available in Node 18+.
 */
const NODE_BUILTINS = new Set([
  'assert', 'assert/strict', 'async_hooks', 'buffer', 'child_process',
  'cluster', 'console', 'constants', 'crypto', 'dgram', 'diagnostics_channel',
  'dns', 'dns/promises', 'domain', 'events', 'fs', 'fs/promises',
  'http', 'http2', 'https', 'inspector', 'module', 'net', 'os', 'path',
  'path/posix', 'path/win32', 'perf_hooks', 'process', 'punycode',
  'querystring', 'readline', 'readline/promises', 'repl', 'stream',
  'stream/consumers', 'stream/promises', 'stream/web', 'string_decoder',
  'sys', 'test', 'timers', 'timers/promises', 'tls', 'trace_events',
  'tty', 'url', 'util', 'util/types', 'v8', 'vm', 'wasi',
  'worker_threads', 'zlib',
]);

const IMPORT_PATTERNS = [
  // ES import: import x from 'pkg', import { x } from 'pkg', import 'pkg'
  /(?:import\s+(?:[\w{},*\s]+\s+from\s+)?['"])([^'"./][^'"]*)['"]/g,
  // require: require('pkg'), require("pkg")
  /require\s*\(\s*['"]([^'"./][^'"]*)['"]\s*\)/g,
  // dynamic import: import('pkg'), import("pkg"), import(`pkg`)
  /import\s*\(\s*['"`]([^'"`./][^'"`]*?)['"`]\s*\)/g,
  // re-export: export { foo } from 'pkg', export * from 'pkg'
  /export\s+(?:[\w{},*\s]+\s+from\s+)['"]([^'"./][^'"]*)['"]/g,
];

/**
 * Strip single-line (//) and multi-line comments from source code.
 * Respects string literals so that URLs or comment-like text inside strings
 * are preserved. Uses a character-by-character scan (lightweight AST approach).
 */
function stripComments(source: string): string {
  const result: string[] = [];
  let i = 0;
  const len = source.length;

  while (i < len) {
    const ch = source[i];
    const next = i + 1 < len ? source[i + 1] : '';

    // Single-line comment
    if (ch === '/' && next === '/') {
      // Skip until end of line
      i += 2;
      while (i < len && source[i] !== '\n') i++;
      // Keep the newline to preserve line structure
      continue;
    }

    // Multi-line comment
    if (ch === '/' && next === '*') {
      i += 2;
      while (i < len) {
        if (source[i] === '*' && i + 1 < len && source[i + 1] === '/') {
          i += 2;
          break;
        }
        i++;
      }
      // Replace with space to avoid merging tokens
      result.push(' ');
      continue;
    }

    // String literals — skip their contents to avoid stripping comment-like
    // sequences inside strings
    if (ch === '"' || ch === "'" || ch === '`') {
      const quote = ch;
      result.push(ch);
      i++;
      while (i < len) {
        const sc = source[i];
        if (sc === '\\') {
          // Escaped character — push both and skip
          result.push(sc);
          i++;
          if (i < len) {
            result.push(source[i]);
            i++;
          }
          continue;
        }
        result.push(sc);
        i++;
        if (sc === quote) break;
      }
      continue;
    }

    result.push(ch);
    i++;
  }

  return result.join('');
}

/**
 * Determine if a specifier refers to a Node.js built-in module.
 */
function isNodeBuiltin(specifier: string): boolean {
  if (specifier.startsWith('node:')) return true;
  // Check the base module name (e.g., 'fs' from 'fs/promises')
  return NODE_BUILTINS.has(specifier);
}

/**
 * Extract the package name from a bare specifier.
 * - `@scope/pkg/sub` -> `@scope/pkg`
 * - `lodash/merge` -> `lodash`
 */
function extractPackageName(specifier: string): string {
  if (specifier.startsWith('@')) {
    return specifier.split('/').slice(0, 2).join('/');
  }
  return specifier.split('/')[0];
}

/**
 * Extract package names imported by a source file.
 * Returns bare specifiers only (not relative paths, not Node builtins).
 *
 * Uses a two-pass approach for accuracy:
 * 1. Strip comments (// and /* ... * /) while respecting string literals
 * 2. Apply regex patterns on comment-free source
 */
function extractImports(content: string): Set<string> {
  const imports = new Set<string>();
  const cleaned = stripComments(content);

  for (const pattern of IMPORT_PATTERNS) {
    // Reset lastIndex for each file
    pattern.lastIndex = 0;
    let match;
    while ((match = pattern.exec(cleaned)) !== null) {
      const specifier = match[1];

      // Skip relative imports (should not match patterns, but defensive)
      if (specifier.startsWith('.')) continue;

      // Skip Node.js builtins
      if (isNodeBuiltin(specifier)) continue;

      const pkgName = extractPackageName(specifier);
      if (pkgName) {
        imports.add(pkgName);
      }
    }
  }

  return imports;
}

/**
 * Scan application source files to find which packages are actually imported.
 * Walks src/, lib/, app/ directories (configurable).
 */
export function scanImportChains(
  projectDir: string,
  entryDirs: string[] = ['src', 'lib', 'app', 'pages', 'routes'],
): Set<string> {
  const importedPackages = new Set<string>();
  const scannedFiles = new Set<string>();

  for (const dir of entryDirs) {
    const fullDir = join(projectDir, dir);
    if (existsSync(fullDir) && statSync(fullDir).isDirectory()) {
      walkDir(fullDir, scannedFiles, importedPackages);
    }
  }

  // Also scan root-level entry points
  for (const entry of ['index.js', 'index.ts', 'index.mjs', 'server.js', 'server.ts', 'main.js', 'main.ts']) {
    const entryPath = join(projectDir, entry);
    if (existsSync(entryPath)) {
      scanFile(entryPath, scannedFiles, importedPackages);
    }
  }

  logger.debug(`Import chain scan: ${scannedFiles.size} files scanned, ${importedPackages.size} packages imported`);
  return importedPackages;
}

function walkDir(dir: string, scanned: Set<string>, imports: Set<string>): void {
  try {
    const entries = readdirSync(dir);
    for (const entry of entries) {
      // Skip common non-source dirs
      if (entry === 'node_modules' || entry === '.git' || entry === 'dist' || entry === 'build' || entry === 'coverage') continue;

      const fullPath = join(dir, entry);
      try {
        const stat = statSync(fullPath);
        if (stat.isDirectory()) {
          walkDir(fullPath, scanned, imports);
        } else if (stat.isFile() && JS_EXTENSIONS.has(extname(entry))) {
          scanFile(fullPath, scanned, imports);
        }
      } catch {
        // Skip unreadable entries
      }
    }
  } catch {
    // Skip unreadable directories
  }
}

function scanFile(filePath: string, scanned: Set<string>, imports: Set<string>): void {
  const resolved = resolve(filePath);
  if (scanned.has(resolved)) return;
  scanned.add(resolved);

  try {
    const content = readFileSync(resolved, 'utf-8');
    for (const pkg of extractImports(content)) {
      imports.add(pkg);
    }
  } catch {
    // Skip unreadable files
  }
}

/**
 * Check if a package is directly imported by application source code.
 * This is a stronger signal than just being in the dependency graph.
 */
export function isDirectlyImported(
  packageName: string,
  importedPackages: Set<string>,
): boolean {
  return importedPackages.has(packageName);
}
