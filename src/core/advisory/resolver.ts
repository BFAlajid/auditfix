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
import { fetchGhsaAdvisories } from './source-ghsa.js';
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

export type ResolveAdvisoriesOptions = {
  /**
   * Optional GitHub token. When present, GHSA GraphQL is called as an
   * enrichment step to merge CWE + CVSS fields into existing advisories.
   * Falls back silently to GITHUB_TOKEN / GH_TOKEN env vars.
   */
  ghsaToken?: string;
};

/** Resolve the GHSA token from options or common env-var fallbacks. */
function resolveGhsaToken(options: ResolveAdvisoriesOptions): string {
  if (options.ghsaToken && options.ghsaToken.length > 0) {
    return options.ghsaToken;
  }
  return process.env.GITHUB_TOKEN ?? process.env.GH_TOKEN ?? '';
}

/**
 * Overlay GHSA enrichment data onto existing advisories. Matches by GHSA id
 * in advisory id or aliases; copies cwes, cvss, and an upgraded CVSS vector
 * when available. Never removes or replaces primary advisories.
 */
async function enrichWithGhsa(
  result: ResolverResult,
  token: string
): Promise<void> {
  if (!token || result.advisories.size === 0) return;

  const packageNames = Array.from(result.advisories.keys());
  let ghsaMap: Map<string, Advisory[]>;
  try {
    ghsaMap = await fetchGhsaAdvisories({ token, packages: packageNames });
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    logger.warn(`GHSA enrichment skipped (non-fatal): ${msg}`);
    return;
  }
  if (ghsaMap.size === 0) return;

  let enrichedCount = 0;

  for (const [pkg, existingList] of result.advisories) {
    const ghsaForPkg = ghsaMap.get(pkg);
    if (!ghsaForPkg || ghsaForPkg.length === 0) continue;

    // Build a fast lookup by GHSA id.
    const byId = new Map<string, Advisory>();
    for (const g of ghsaForPkg) {
      byId.set(g.id, g);
    }

    for (const advisory of existingList) {
      const match = findGhsaMatch(advisory, byId);
      if (!match) continue;

      if (match.cwes && match.cwes.length > 0) {
        advisory.cwes = match.cwes;
      }
      if (match.cvss) {
        advisory.cvss = match.cvss;
        // Prefer GHSA's CVSS vector if the advisory lacks one.
        if (advisory.severity.length === 0 && match.cvss.vectorString) {
          advisory.severity = [
            { type: 'CVSS_V3', score: match.cvss.vectorString },
          ];
        }
      }
      enrichedCount++;
    }
  }

  if (enrichedCount > 0) {
    logger.info(`GHSA enrichment added metadata to ${enrichedCount} advisories`);
  }
}

/** Find a GHSA advisory matching `advisory` by id or alias. */
function findGhsaMatch(
  advisory: Advisory,
  byId: Map<string, Advisory>
): Advisory | null {
  if (byId.has(advisory.id)) return byId.get(advisory.id) ?? null;
  for (const alias of advisory.aliases) {
    if (byId.has(alias)) return byId.get(alias) ?? null;
  }
  return null;
}

/**
 * Resolve advisories using the three-tier fallback chain.
 *
 * When `options.ghsaToken` (or GITHUB_TOKEN / GH_TOKEN env vars) is present,
 * GHSA GraphQL is called after the primary source to enrich advisories with
 * CWE classifications and CVSS metadata. GHSA failures never degrade the
 * scan — enrichment only.
 */
export async function resolveAdvisories(
  graph: DependencyGraph,
  options: ResolveAdvisoriesOptions = {}
): Promise<ResolverResult> {
  const errors: string[] = [];
  const ghsaToken = resolveGhsaToken(options);

  // Tier 1: OSV batch API
  logger.info('Fetching advisories from OSV.dev...');
  try {
    const osvResult = await fetchOsvAdvisories(graph);

    if (osvResult.errors.length === 0 && osvResult.advisories.size > 0) {
      // Cache results for future runs (background, don't block)
      cacheAdvisoryBatch(osvResult.advisories).catch((err) => {
        logger.debug(`Cache write failed: ${err}`);
      });

      const result: ResolverResult = {
        advisories: osvResult.advisories,
        source: 'OSV.dev API (real-time)',
        confidence: 'HIGH',
        errors: [],
      };
      await enrichWithGhsa(result, ghsaToken);
      return result;
    }

    // OSV had errors but returned some data — use it with reduced confidence
    if (osvResult.advisories.size > 0) {
      errors.push(...osvResult.errors);
      cacheAdvisoryBatch(osvResult.advisories).catch(() => {});

      const result: ResolverResult = {
        advisories: osvResult.advisories,
        source: 'OSV.dev API (partial)',
        confidence: 'MEDIUM',
        errors,
      };
      await enrichWithGhsa(result, ghsaToken);
      return result;
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
    const result: ResolverResult = {
      advisories: cachedAdvisories,
      source: 'Local cache',
      confidence: 'MEDIUM',
      errors,
    };
    await enrichWithGhsa(result, ghsaToken);
    return result;
  }

  // Tier 3: Bundled offline index
  logger.info('Checking bundled offline advisory index...');
  const offlineAdvisories = await queryOfflineIndexBatch(graph);
  if (offlineAdvisories.size > 0) {
    logger.info(`Using ${offlineAdvisories.size} entries from offline index`);
    const result: ResolverResult = {
      advisories: offlineAdvisories,
      source: 'Bundled offline index',
      confidence: 'LOW',
      errors,
    };
    await enrichWithGhsa(result, ghsaToken);
    return result;
  }

  // Tier 4: npm bulk advisory endpoint
  logger.info('Offline index empty, trying npm bulk advisory endpoint...');
  try {
    const npmResult = await fetchNpmAdvisories(graph);

    if (npmResult.errors.length === 0 || npmResult.advisories.size > 0) {
      // Cache npm results too
      cacheAdvisoryBatch(npmResult.advisories).catch(() => {});

      errors.push(...npmResult.errors);
      const result: ResolverResult = {
        advisories: npmResult.advisories,
        source: 'npm bulk advisory endpoint',
        confidence: npmResult.errors.length > 0 ? 'LOW' : 'MEDIUM',
        errors,
      };
      await enrichWithGhsa(result, ghsaToken);
      return result;
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
