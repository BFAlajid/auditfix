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

const IMPORT_PATTERNS = [
  // ES import: import x from 'pkg', import { x } from 'pkg', import 'pkg'
  /(?:import\s+(?:[\w{},*\s]+\s+from\s+)?['"])([^'"./][^'"]*)['"]/g,
  // require: require('pkg'), require("pkg")
  /require\s*\(\s*['"]([^'"./][^'"]*)['"]\s*\)/g,
  // dynamic import: import('pkg')
  /import\s*\(\s*['"]([^'"./][^'"]*)['"]\s*\)/g,
];

/**
 * Extract package names imported by a source file.
 * Returns bare specifiers only (not relative paths).
 */
function extractImports(content: string): Set<string> {
  const imports = new Set<string>();

  for (const pattern of IMPORT_PATTERNS) {
    // Reset lastIndex for each file
    pattern.lastIndex = 0;
    let match;
    while ((match = pattern.exec(content)) !== null) {
      const specifier = match[1];
      // Extract package name from specifier (handle scoped packages)
      const pkgName = specifier.startsWith('@')
        ? specifier.split('/').slice(0, 2).join('/')
        : specifier.split('/')[0];
      imports.add(pkgName);
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
