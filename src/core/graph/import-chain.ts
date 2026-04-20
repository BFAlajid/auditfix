/**
 * Import chain reachability analysis.
 * Static analysis of require/import statements to determine if a vulnerable
 * package is actually imported (directly or transitively) by application code.
 *
 * This is a best-effort heuristic — it can prove reachability but cannot
 * definitively prove unreachability (dynamic requires, conditional imports).
 */
import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { join, extname, resolve } from 'node:path';
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

/**
 * Single combined pattern for all bare-specifier import forms.
 * Alternation branches (ordered by expected frequency):
 *   1. `import … from 'pkg'` | `import 'pkg'`
 *   2. `export … from 'pkg'`
 *   3. `require('pkg')`
 *   4. dynamic `import('pkg')` | `import(\`pkg\`)`
 *
 * Bare specifiers only (first char is not `.` and not `/`).
 * The specifier is captured by whichever group fires; we scan all four.
 */
const IMPORT_PATTERN =
  /(?:import\s+(?:[\w{},*\s]+\s+from\s+)?['"]([^'"./][^'"]*)['"])|(?:export\s+(?:[\w{},*\s]+\s+from\s+)['"]([^'"./][^'"]*)['"])|(?:require\s*\(\s*['"]([^'"./][^'"]*)['"]\s*\))|(?:import\s*\(\s*['"`]([^'"`./][^'"`]*?)['"`]\s*\))/g;

/**
 * Strip single-line (//) and multi-line (/* ... *\/) comments from source.
 * String literals and template literals are preserved so that URLs or
 * comment-like text inside strings don't get stripped.
 *
 * Single-pass state machine over the source string using index-scanning
 * (avoids the per-character array-push + join from the previous version).
 */
function stripComments(source: string): string {
  const len = source.length;
  let out = '';
  let i = 0;
  let segStart = 0;

  while (i < len) {
    const ch = source.charCodeAt(i);

    // '/' — could start a comment
    if (ch === 47 /* / */ && i + 1 < len) {
      const next = source.charCodeAt(i + 1);
      if (next === 47 /* // */) {
        // Flush pre-comment text, then skip until newline.
        out += source.slice(segStart, i);
        i += 2;
        while (i < len && source.charCodeAt(i) !== 10 /* \n */) i++;
        segStart = i; // keep the newline
        continue;
      }
      if (next === 42 /* * */) {
        // Flush, then skip to */ and inject a single space.
        out += source.slice(segStart, i);
        i += 2;
        while (i + 1 < len) {
          if (source.charCodeAt(i) === 42 && source.charCodeAt(i + 1) === 47) {
            i += 2;
            break;
          }
          i++;
        }
        if (i + 1 >= len) i = len;
        out += ' ';
        segStart = i;
        continue;
      }
    }

    // String / template literal — skip to matching close, respecting escapes.
    if (ch === 34 /* " */ || ch === 39 /* ' */ || ch === 96 /* ` */) {
      const quote = ch;
      i++;
      while (i < len) {
        const sc = source.charCodeAt(i);
        if (sc === 92 /* \ */) { i += 2; continue; }
        if (sc === quote) { i++; break; }
        i++;
      }
      continue;
    }

    i++;
  }

  out += source.slice(segStart, len);
  return out;
}

/**
 * Determine if a specifier refers to a Node.js built-in module.
 */
function isNodeBuiltin(specifier: string): boolean {
  if (specifier.startsWith('node:')) return true;
  return NODE_BUILTINS.has(specifier);
}

/**
 * Extract the package name from a bare specifier.
 * - `@scope/pkg/sub` -> `@scope/pkg`
 * - `lodash/merge` -> `lodash`
 */
function extractPackageName(specifier: string): string {
  if (specifier.startsWith('@')) {
    const first = specifier.indexOf('/');
    if (first < 0) return specifier;
    const second = specifier.indexOf('/', first + 1);
    return second < 0 ? specifier : specifier.slice(0, second);
  }
  const slash = specifier.indexOf('/');
  return slash < 0 ? specifier : specifier.slice(0, slash);
}

/**
 * Extract package names imported by a source file.
 * Returns bare specifiers only (not relative paths, not Node builtins).
 */
function extractImports(content: string): Set<string> {
  const imports = new Set<string>();
  const cleaned = stripComments(content);

  IMPORT_PATTERN.lastIndex = 0;
  let m: RegExpExecArray | null;
  while ((m = IMPORT_PATTERN.exec(cleaned)) !== null) {
    const specifier = m[1] ?? m[2] ?? m[3] ?? m[4];
    if (!specifier) continue;
    if (specifier.charCodeAt(0) === 46 /* . */) continue;
    if (isNodeBuiltin(specifier)) continue;
    const pkgName = extractPackageName(specifier);
    if (pkgName) imports.add(pkgName);
  }

  return imports;
}

/**
 * mtime-keyed cache of per-file extracted package sets. Keeps repeated
 * scans (watch mode, multi-invocation test runs) from re-reading and
 * re-parsing unchanged files. The cache is process-scoped and cleared
 * on explicit request.
 */
const fileCache = new Map<string, { mtimeMs: number; packages: Set<string> }>();

/** Testing hook: clear memoization between test cases. */
export function clearImportChainCache(): void {
  fileCache.clear();
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
    if (existsSync(fullDir)) {
      // We check isDirectory via the withFileTypes walk, but need to guard
      // against `fullDir` itself being a file — readdirSync on a file throws.
      try {
        if (statSync(fullDir).isDirectory()) {
          walkDir(fullDir, scannedFiles, importedPackages);
        }
      } catch {
        // ignore unreadable
      }
    }
  }

  for (const entry of ['index.js', 'index.ts', 'index.mjs', 'server.js', 'server.ts', 'main.js', 'main.ts']) {
    const entryPath = join(projectDir, entry);
    if (existsSync(entryPath)) {
      scanFile(entryPath, scannedFiles, importedPackages);
    }
  }

  logger.debug(`Import chain scan: ${scannedFiles.size} files scanned, ${importedPackages.size} packages imported`);
  return importedPackages;
}

const MAX_SCAN_DEPTH = 15;
const MAX_SCAN_FILES = 10_000;
const SKIP_DIRS = new Set(['node_modules', '.git', 'dist', 'build', 'coverage']);

function walkDir(dir: string, scanned: Set<string>, imports: Set<string>, depth: number = 0): void {
  if (depth > MAX_SCAN_DEPTH || scanned.size > MAX_SCAN_FILES) return;
  let entries;
  try {
    // withFileTypes halves syscalls by returning Dirent (no per-entry stat).
    entries = readdirSync(dir, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const name = entry.name;
    if (SKIP_DIRS.has(name)) continue;
    const fullPath = join(dir, name);
    if (entry.isDirectory()) {
      walkDir(fullPath, scanned, imports, depth + 1);
    } else if (entry.isFile() && JS_EXTENSIONS.has(extname(name))) {
      scanFile(fullPath, scanned, imports);
    }
  }
}

function scanFile(filePath: string, scanned: Set<string>, imports: Set<string>): void {
  const resolved = resolve(filePath);
  if (scanned.has(resolved)) return;
  scanned.add(resolved);

  // mtime-keyed memoization — unchanged files skip read + parse.
  let mtimeMs: number | undefined;
  try {
    mtimeMs = statSync(resolved).mtimeMs;
  } catch {
    return;
  }

  const cached = fileCache.get(resolved);
  if (cached && cached.mtimeMs === mtimeMs) {
    for (const pkg of cached.packages) imports.add(pkg);
    return;
  }

  try {
    const content = readFileSync(resolved, 'utf-8');
    const pkgs = extractImports(content);
    fileCache.set(resolved, { mtimeMs, packages: pkgs });
    for (const pkg of pkgs) imports.add(pkg);
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
