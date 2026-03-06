/**
 * Dependency license scanner.
 * Reads license fields from package.json in node_modules to detect
 * packages with incompatible or problematic licenses.
 */
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { safeJsonParse } from '../../utils/sanitize.js';
import type { DependencyGraph } from '../../types/package.js';

export type LicenseFinding = {
  package: string;
  version: string;
  license: string;
  category: 'copyleft' | 'network-copyleft' | 'unknown' | 'non-standard';
  isProduction: boolean;
};

/** Licenses that require derivative works to use the same license */
const COPYLEFT_LICENSES = new Set([
  'GPL-2.0', 'GPL-2.0-only', 'GPL-2.0-or-later',
  'GPL-3.0', 'GPL-3.0-only', 'GPL-3.0-or-later',
  'LGPL-2.0', 'LGPL-2.0-only', 'LGPL-2.0-or-later',
  'LGPL-2.1', 'LGPL-2.1-only', 'LGPL-2.1-or-later',
  'LGPL-3.0', 'LGPL-3.0-only', 'LGPL-3.0-or-later',
  'MPL-2.0',
  'EUPL-1.1', 'EUPL-1.2',
  'CDDL-1.0', 'CDDL-1.1',
  'EPL-1.0', 'EPL-2.0',
  'CECILL-2.1',
]);

/** Network copyleft — even stronger restriction (SaaS counts as distribution) */
const NETWORK_COPYLEFT = new Set([
  'AGPL-1.0', 'AGPL-3.0', 'AGPL-3.0-only', 'AGPL-3.0-or-later',
  'SSPL-1.0',
  'OSL-3.0',
]);

/** Well-known permissive licenses (not flagged) */
const PERMISSIVE_LICENSES = new Set([
  'MIT', 'ISC', 'BSD-2-Clause', 'BSD-3-Clause', 'Apache-2.0',
  '0BSD', 'Unlicense', 'CC0-1.0', 'CC-BY-3.0', 'CC-BY-4.0',
  'Zlib', 'BlueOak-1.0.0', 'Artistic-2.0', 'Python-2.0',
  'PSF-2.0', 'WTFPL',
]);

/**
 * Scan dependencies for license compatibility issues.
 */
export function scanLicenses(
  graph: DependencyGraph,
  projectDir: string,
): LicenseFinding[] {
  const findings: LicenseFinding[] = [];
  const checked = new Set<string>();

  for (const [, node] of graph) {
    const key = `${node.name}@${node.version}`;
    if (checked.has(key)) continue;
    checked.add(key);

    const license = readPackageLicense(node.name, projectDir);
    if (!license) continue;

    // Normalize: handle SPDX expressions like "(MIT OR Apache-2.0)"
    const normalized = normalizeLicense(license);

    const category = categorizeLicense(normalized);
    if (category) {
      findings.push({
        package: node.name,
        version: node.version,
        license: normalized,
        category,
        isProduction: node.isProduction,
      });
    }
  }

  return findings;
}

function readPackageLicense(packageName: string, projectDir: string): string | null {
  // Handle scoped packages: @scope/name -> node_modules/@scope/name
  const pkgJsonPath = join(projectDir, 'node_modules', packageName, 'package.json');
  if (!existsSync(pkgJsonPath)) return null;

  try {
    const content = readFileSync(pkgJsonPath, 'utf-8');
    const pkg = safeJsonParse<Record<string, unknown>>(content);
    if (typeof pkg.license === 'string') return pkg.license;
    // Some packages use { type, url } format
    if (pkg.license && typeof (pkg.license as Record<string, string>).type === 'string') {
      return (pkg.license as Record<string, string>).type;
    }
    // Legacy "licenses" array
    if (Array.isArray(pkg.licenses) && pkg.licenses.length > 0) {
      return (pkg.licenses as Array<Record<string, string>>).map(l => l.type).join(' OR ');
    }
    return null;
  } catch {
    return null;
  }
}

function normalizeLicense(raw: string): string {
  // Strip surrounding parens from SPDX expressions
  let license = raw.trim();
  if (license.startsWith('(') && license.endsWith(')')) {
    license = license.slice(1, -1);
  }
  return license;
}

function categorizeLicense(license: string): LicenseFinding['category'] | null {
  // SPDX expression: "(MIT OR GPL-3.0)" — if ANY option is permissive, it's fine
  if (license.includes(' OR ')) {
    const options = license.split(' OR ').map(s => s.trim());
    const hasPermissive = options.some(opt => PERMISSIVE_LICENSES.has(opt));
    if (hasPermissive) return null; // at least one permissive option
    // All options are problematic — categorize by worst
    for (const opt of options) {
      if (NETWORK_COPYLEFT.has(opt)) return 'network-copyleft';
    }
    for (const opt of options) {
      if (COPYLEFT_LICENSES.has(opt)) return 'copyleft';
    }
    return 'non-standard';
  }

  // AND expressions: all licenses must be acceptable
  if (license.includes(' AND ')) {
    const parts = license.split(' AND ').map(s => s.trim());
    for (const part of parts) {
      if (NETWORK_COPYLEFT.has(part)) return 'network-copyleft';
      if (COPYLEFT_LICENSES.has(part)) return 'copyleft';
      if (!PERMISSIVE_LICENSES.has(part)) return 'non-standard';
    }
    return null;
  }

  // Single license
  if (NETWORK_COPYLEFT.has(license)) return 'network-copyleft';
  if (COPYLEFT_LICENSES.has(license)) return 'copyleft';
  if (PERMISSIVE_LICENSES.has(license)) return null;
  if (license === 'UNLICENSED' || license === 'SEE LICENSE IN LICENSE') return 'unknown';

  return null; // Unknown but probably fine — don't flag everything
}
