/**
 * Pure conversion logic: OSV vulnerability -> OfflineEntry.
 * Extracted for testability — no I/O, no side effects.
 */
import type { OsvVulnerability, OsvAffected } from '../../types/advisory.js';
import type { OfflineEntry } from './offline-index.js';
import { affectedToSemverRange, affectedFixVersion } from './osv-ranges.js';

/**
 * Convert a single OSV vulnerability to zero or more OfflineEntry records.
 * One entry per affected npm package in the vulnerability.
 *
 * Skips entries that:
 * - Are not in the npm ecosystem
 * - Have no semver range (only GIT ranges or empty events)
 * - Have no fix version (not actionable for auditfix)
 */
export function osvToOfflineEntries(vuln: OsvVulnerability): OfflineEntry[] {
  if (!vuln.id || !vuln.affected || !Array.isArray(vuln.affected)) {
    return [];
  }

  const entries: OfflineEntry[] = [];

  for (const affected of vuln.affected) {
    if (!isNpmAffected(affected)) continue;

    const range = affectedToSemverRange(affected);
    if (!range) continue;

    const fix = affectedFixVersion(affected);
    if (fix === null) continue;

    const severity = extractBestSeverity(vuln);

    entries.push({
      id: vuln.id,
      pkg: affected.package.name,
      range,
      fix,
      severity,
      summary: vuln.summary ?? vuln.id,
    });
  }

  return entries;
}

/**
 * Check if the vulnerability was modified within the given cutoff period.
 */
export function isRecentlyModified(vuln: OsvVulnerability, cutoffDate: Date): boolean {
  if (!vuln.modified) return false;
  try {
    const modified = new Date(vuln.modified);
    return modified >= cutoffDate;
  } catch {
    return false;
  }
}

/**
 * Filter and convert a batch of OSV vulnerabilities to OfflineEntry records.
 * Applies the recency cutoff and deduplicates by id+pkg.
 */
export function convertOsvBatch(
  vulns: OsvVulnerability[],
  cutoffDate: Date,
): OfflineEntry[] {
  const seen = new Set<string>();
  const entries: OfflineEntry[] = [];

  for (const vuln of vulns) {
    if (!isRecentlyModified(vuln, cutoffDate)) continue;

    const converted = osvToOfflineEntries(vuln);
    for (const entry of converted) {
      const key = `${entry.id}:${entry.pkg}`;
      if (seen.has(key)) continue;
      seen.add(key);
      entries.push(entry);
    }
  }

  return entries;
}

function isNpmAffected(affected: OsvAffected): boolean {
  return (
    affected.package != null &&
    typeof affected.package.ecosystem === 'string' &&
    affected.package.ecosystem.toLowerCase() === 'npm' &&
    typeof affected.package.name === 'string' &&
    affected.package.name.length > 0
  );
}

function extractBestSeverity(vuln: OsvVulnerability): string {
  if (!vuln.severity || vuln.severity.length === 0) return '';

  // Prefer CVSS_V3, then CVSS_V4, then CVSS_V2
  const v3 = vuln.severity.find((s) => s.type === 'CVSS_V3');
  if (v3) return v3.score;

  const v4 = vuln.severity.find((s) => s.type === 'CVSS_V4');
  if (v4) return v4.score;

  return vuln.severity[0].score;
}
