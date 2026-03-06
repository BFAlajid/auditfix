/**
 * Dependency age checker.
 * Flags packages that haven't been updated in a long time,
 * which may indicate abandonment or maintenance risk.
 */
import type { DependencyGraph } from '../../types/package.js';
import * as logger from '../../utils/logger.js';

export type DepAgeFinding = {
  package: string;
  version: string;
  lastPublished: string; // ISO date
  ageMonths: number;
  isProduction: boolean;
};

const STALE_THRESHOLD_MONTHS = 24; // 2 years

/**
 * Check npm registry for last publish dates of packages.
 * Flags packages with no updates in 2+ years.
 */
export async function checkDepAge(
  graph: DependencyGraph,
  thresholdMonths: number = STALE_THRESHOLD_MONTHS,
): Promise<DepAgeFinding[]> {
  const findings: DepAgeFinding[] = [];
  const checked = new Set<string>();
  const now = Date.now();
  const thresholdMs = thresholdMonths * 30 * 24 * 60 * 60 * 1000;

  // Batch unique package names
  const packages = new Map<string, { version: string; isProduction: boolean }>();
  for (const [, node] of graph) {
    if (checked.has(node.name)) continue;
    checked.add(node.name);
    packages.set(node.name, { version: node.version, isProduction: node.isProduction });
  }

  // Check each package (limited concurrency)
  const entries = [...packages.entries()];
  const BATCH_SIZE = 10;

  for (let i = 0; i < entries.length; i += BATCH_SIZE) {
    const batch = entries.slice(i, i + BATCH_SIZE);
    const results = await Promise.allSettled(
      batch.map(async ([name, info]) => {
        const lastPublished = await fetchLastPublishDate(name);
        if (!lastPublished) return null;

        const ageMs = now - lastPublished.getTime();
        if (ageMs < thresholdMs) return null;

        const ageMonths = Math.floor(ageMs / (30 * 24 * 60 * 60 * 1000));
        return {
          package: name,
          version: info.version,
          lastPublished: lastPublished.toISOString().split('T')[0],
          ageMonths,
          isProduction: info.isProduction,
        };
      }),
    );

    for (const result of results) {
      if (result.status === 'fulfilled' && result.value) {
        findings.push(result.value);
      }
    }
  }

  // Sort by age descending
  findings.sort((a, b) => b.ageMonths - a.ageMonths);
  return findings;
}

async function fetchLastPublishDate(packageName: string): Promise<Date | null> {
  try {
    const encodedName = packageName.startsWith('@')
      ? `@${encodeURIComponent(packageName.slice(1))}`
      : encodeURIComponent(packageName);

    const response = await fetch(
      `https://registry.npmjs.org/${encodedName}`,
      {
        headers: { Accept: 'application/vnd.npm.install-v1+json' },
        signal: AbortSignal.timeout(5000),
      },
    );

    if (!response.ok) return null;

    const data = await response.json() as { modified?: string };
    if (data.modified) {
      return new Date(data.modified);
    }
    return null;
  } catch {
    logger.debug(`Failed to fetch publish date for ${packageName}`);
    return null;
  }
}
