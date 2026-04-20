/**
 * Advisory resolver with three-tier fallback chain.
 *
 * 1. OSV batch API (real-time, primary)
 * 2. Local cache (if OSV fails, fresh cache)
 * 3. npm bulk advisory endpoint (tertiary)
 * 4. Stale cache (last resort, any age)
 *
 * Never exits 0 when all sources fail.
 */
import type { DependencyGraph } from '../../types/package.js';
import type { Advisory, ResolverSourceId } from '../../types/advisory.js';
import type { ConfidenceLevel } from '../../types/report.js';
import { fetchOsvAdvisories } from './source-osv.js';
import { fetchNpmAdvisories } from './source-npm.js';
import {
  cacheAdvisoryBatch,
  getCachedPackageAdvisories,
  readCachedAdvisoriesForPackages,
} from './cache.js';
import { queryOfflineIndexBatch } from './offline-index.js';
import * as logger from '../../utils/logger.js';

export type { ResolverSourceId } from '../../types/advisory.js';

export type ResolverResult = {
  advisories: Map<string, Advisory[]>;
  /**
   * Human-readable source label (for display, logs, report metadata).
   * Derived from `sourceId`; consumers that branch programmatically should
   * read `sourceId` instead — the display string is not part of the API.
   */
  source: string;
  /**
   * Structured discriminator for programmatic branching / telemetry.
   * Kept distinct from `source` so the display string can evolve without
   * breaking consumers that pattern-match on origin.
   */
  sourceId: ResolverSourceId;
  confidence: ConfidenceLevel;
  errors: string[];
};

const SOURCE_LABELS: Record<ResolverSourceId, string> = {
  'osv': 'OSV.dev API (real-time)',
  'osv-partial': 'OSV.dev API (partial)',
  'cache': 'Local cache',
  'cache-stale': 'Local cache (stale)',
  'offline': 'Bundled offline index',
  'npm-bulk': 'npm bulk advisory endpoint',
};

function buildResult(
  advisories: Map<string, Advisory[]>,
  sourceId: ResolverSourceId,
  confidence: ConfidenceLevel,
  errors: string[],
): ResolverResult {
  return {
    advisories,
    source: SOURCE_LABELS[sourceId],
    sourceId,
    confidence,
    errors,
  };
}

/**
 * Resolve advisories using the three-tier fallback chain.
 */
export async function resolveAdvisories(graph: DependencyGraph): Promise<ResolverResult> {
  const errors: string[] = [];

  // Tier 1: OSV batch API
  logger.info('Fetching advisories from OSV.dev...');
  try {
    const osvResult = await fetchOsvAdvisories(graph);

    if (osvResult.errors.length === 0 && osvResult.advisories.size > 0) {
      // Cache results for future runs (background, don't block)
      cacheAdvisoryBatch(osvResult.advisories).catch((err) => {
        logger.debug(`Cache write failed: ${err}`);
      });

      return buildResult(osvResult.advisories, 'osv', 'HIGH', []);
    }

    // OSV had errors but returned some data — use it with reduced confidence
    if (osvResult.advisories.size > 0) {
      errors.push(...osvResult.errors);
      cacheAdvisoryBatch(osvResult.advisories).catch(() => {});

      return buildResult(
        osvResult.advisories,
        'osv-partial',
        'MEDIUM',
        errors,
      );
    }

    errors.push(...osvResult.errors);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    errors.push(`OSV API failed: ${msg}`);
    logger.warn(`OSV API failed: ${msg}`);
  }

  // Tier 2: Local cache
  logger.info('OSV unavailable, checking local cache...');
  const cachedAdvisories = getCachedAdvisoriesForGraph(graph);
  if (cachedAdvisories.size > 0) {
    logger.info(`Using ${cachedAdvisories.size} cached advisory entries`);
    return buildResult(cachedAdvisories, 'cache', 'MEDIUM', errors);
  }

  // Tier 3: Bundled offline index
  logger.info('Checking bundled offline advisory index...');
  const offlineAdvisories = await queryOfflineIndexBatch(graph);
  if (offlineAdvisories.size > 0) {
    logger.info(`Using ${offlineAdvisories.size} entries from offline index`);
    return buildResult(offlineAdvisories, 'offline', 'LOW', errors);
  }

  // Tier 4: npm bulk advisory endpoint
  logger.info('Offline index empty, trying npm bulk advisory endpoint...');
  try {
    const npmResult = await fetchNpmAdvisories(graph);

    if (npmResult.errors.length === 0 || npmResult.advisories.size > 0) {
      // Cache npm results too
      cacheAdvisoryBatch(npmResult.advisories).catch(() => {});

      errors.push(...npmResult.errors);
      return buildResult(
        npmResult.advisories,
        'npm-bulk',
        npmResult.errors.length > 0 ? 'LOW' : 'MEDIUM',
        errors,
      );
    }

    errors.push(...npmResult.errors);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    errors.push(`npm bulk endpoint failed: ${msg}`);
    logger.warn(`npm bulk endpoint failed: ${msg}`);
  }

  // All sources failed
  errors.push('All advisory sources failed. Cannot produce reliable results.');
  throw new AdvisoryResolutionError(
    'All advisory sources failed (OSV API, local cache, npm bulk endpoint). ' +
    'Check network connectivity or update the auditfix package for a fresh bundled index.',
    errors,
  );
}

export class AdvisoryResolutionError extends Error {
  public readonly errors: string[];
  constructor(message: string, errors: string[]) {
    super(message);
    this.name = 'AdvisoryResolutionError';
    this.errors = errors;
  }
}

/**
 * Cache-first advisory resolution. Checks per-package cache before hitting the network.
 * - Fresh (<1h): return immediately, zero network calls
 * - Stale (1-4h): return immediately, trigger background refresh
 * - Cold/missing: fall back to resolveAdvisories() (full network flow)
 */
export async function resolveAdvisoriesWithCache(
  graph: DependencyGraph,
  options?: { noCache?: boolean },
): Promise<ResolverResult> {
  if (options?.noCache) {
    return resolveAdvisories(graph);
  }

  // Collect unique package names
  const packageNames: string[] = [];
  const seen = new Set<string>();
  for (const [, node] of graph) {
    if (!seen.has(node.name)) {
      seen.add(node.name);
      packageNames.push(node.name);
    }
  }

  // Try reading all from cache
  const cached = readCachedAdvisoriesForPackages(packageNames);
  if (cached) {
    if (cached.freshness === 'fresh') {
      logger.info(`All ${packageNames.length} packages served from fresh cache (<1h)`);
      return {
        advisories: cached.advisories,
        sourceId: 'cache',
        source: 'Local cache (fresh)',
        confidence: 'HIGH',
        errors: [],
      };
    }

    if (cached.freshness === 'stale') {
      logger.info(`All ${packageNames.length} packages served from stale cache (1-4h), refreshing in background`);
      // Trigger background refresh (don't await)
      resolveAdvisories(graph).catch((err) => {
        logger.debug(`Background cache refresh failed: ${err}`);
      });
      return {
        advisories: cached.advisories,
        sourceId: 'cache-stale',
        source: 'Local cache (stale, refreshing)',
        confidence: 'HIGH',
        errors: [],
      };
    }
  }

  // Cold or missing — full network resolution
  return resolveAdvisories(graph);
}

/**
 * Check cache for all packages in the graph.
 * Returns cached advisories keyed by package name.
 */
function getCachedAdvisoriesForGraph(graph: DependencyGraph): Map<string, Advisory[]> {
  const result = new Map<string, Advisory[]>();
  const checkedNames = new Set<string>();

  for (const [, node] of graph) {
    if (checkedNames.has(node.name)) continue;
    checkedNames.add(node.name);

    const cached = getCachedPackageAdvisories(node.name);
    if (cached && cached.length > 0) {
      result.set(node.name, cached);
    }
  }

  return result;
}
