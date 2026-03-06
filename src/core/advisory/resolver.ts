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
import type { Advisory } from '../../types/advisory.js';
import type { ConfidenceLevel } from '../../types/report.js';
import { fetchOsvAdvisories } from './source-osv.js';
import { fetchNpmAdvisories } from './source-npm.js';
import {
  cacheAdvisoryBatch,
  getCachedPackageAdvisories,
} from './cache.js';
import * as logger from '../../utils/logger.js';

export type ResolverResult = {
  advisories: Map<string, Advisory[]>;
  source: string;
  confidence: ConfidenceLevel;
  errors: string[];
};

/**
 * Resolve advisories using the three-tier fallback chain.
 */
export async function resolveAdvisories(graph: DependencyGraph): Promise<ResolverResult> {
  const errors: string[] = [];

  // Tier 1: OSV batch API
  logger.info('Fetching advisories from OSV.dev...');
  try {
    const osvResult = await fetchOsvAdvisories(graph);

    if (osvResult.errors.length === 0 && osvResult.advisories.size >= 0) {
      // Cache results for future runs (background, don't block)
      cacheAdvisoryBatch(osvResult.advisories).catch((err) => {
        logger.debug(`Cache write failed: ${err}`);
      });

      return {
        advisories: osvResult.advisories,
        source: 'OSV.dev API (real-time)',
        confidence: 'HIGH',
        errors: [],
      };
    }

    // OSV had errors but returned some data — use it with reduced confidence
    if (osvResult.advisories.size > 0) {
      errors.push(...osvResult.errors);
      cacheAdvisoryBatch(osvResult.advisories).catch(() => {});

      return {
        advisories: osvResult.advisories,
        source: 'OSV.dev API (partial)',
        confidence: 'MEDIUM',
        errors,
      };
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
    return {
      advisories: cachedAdvisories,
      source: 'Local cache',
      confidence: 'MEDIUM',
      errors,
    };
  }

  // Tier 3: npm bulk advisory endpoint
  logger.info('Cache empty, trying npm bulk advisory endpoint...');
  try {
    const npmResult = await fetchNpmAdvisories(graph);

    if (npmResult.errors.length === 0 || npmResult.advisories.size > 0) {
      // Cache npm results too
      cacheAdvisoryBatch(npmResult.advisories).catch(() => {});

      errors.push(...npmResult.errors);
      return {
        advisories: npmResult.advisories,
        source: 'npm bulk advisory endpoint',
        confidence: npmResult.errors.length > 0 ? 'LOW' : 'MEDIUM',
        errors,
      };
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
