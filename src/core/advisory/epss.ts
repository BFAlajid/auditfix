/**
 * EPSS (Exploit Prediction Scoring System) integration.
 * Queries FIRST.org API for exploit probability scores.
 * Also checks CISA KEV (Known Exploited Vulnerabilities) catalog.
 */
import * as logger from '../../utils/logger.js';
import { fetchJsonWithValidation, FetchValidationError } from '../../utils/fetch.js';

export type EpssScore = {
  cve: string;
  epss: number;       // 0-1 probability of exploitation in next 30 days
  percentile: number;  // 0-1 percentile rank
};

export type KevEntry = {
  cveID: string;
  vendorProject: string;
  product: string;
  dateAdded: string;
  knownRansomwareCampaignUse: string;
};

const EPSS_MAX_BYTES = 10 * 1024 * 1024;   // 10MB — worst-case batch of 50 CVEs is ~20KB
const KEV_MAX_BYTES = 20 * 1024 * 1024;    // 20MB — catalog is ~2MB today
const EPSS_TIMEOUT_MS = 30_000;
const KEV_TIMEOUT_MS = 30_000;
const EPSS_BATCH_SIZE = 50;
const EPSS_BATCH_CONCURRENCY = 5;

// Resettable KEV cache — mutable container so tests / long-running analyze()
// callers can reset freshness without module state leaking across invocations.
export type KevCacheState = {
  cache: Set<string> | null;
  cachedAt: number;
  ttlMs: number;
  reset(): void;
};

function makeKevCache(ttlMs: number): KevCacheState {
  const state: KevCacheState = {
    cache: null,
    cachedAt: 0,
    ttlMs,
    reset() {
      state.cache = null;
      state.cachedAt = 0;
    },
  };
  return state;
}

const kevState: KevCacheState = makeKevCache(4 * 60 * 60 * 1000); // 4 hours

/** Reset the in-memory KEV cache. Intended for tests and per-analyze-call freshness. */
export function resetKevCache(): void {
  kevState.reset();
}

/**
 * Bounded-concurrency map — runs at most `concurrency` tasks in parallel.
 * Preserves input order in the returned array.
 */
async function pMap<T, R>(
  items: readonly T[],
  fn: (item: T, index: number) => Promise<R>,
  concurrency: number,
): Promise<R[]> {
  const results: R[] = new Array(items.length);
  let cursor = 0;
  const workerCount = Math.max(1, Math.min(concurrency, items.length));

  async function worker(): Promise<void> {
    while (true) {
      const index = cursor++;
      if (index >= items.length) return;
      results[index] = await fn(items[index], index);
    }
  }

  await Promise.all(Array.from({ length: workerCount }, () => worker()));
  return results;
}

type EpssApiResponse = {
  data?: Array<{ cve: string; epss: string; percentile: string }>;
};

async function fetchEpssBatch(batch: string[]): Promise<EpssApiResponse['data']> {
  const param = batch.join(',');
  const url = `https://api.first.org/data/v1/epss?cve=${param}`;
  try {
    const data = await fetchJsonWithValidation<EpssApiResponse>(url, {
      maxBytes: EPSS_MAX_BYTES,
      timeoutMs: EPSS_TIMEOUT_MS,
      contentType: 'application/json',
    });
    return data.data ?? [];
  } catch (err) {
    if (err instanceof FetchValidationError) {
      logger.debug(`EPSS batch query failed (${err.kind}): ${err.message}`);
    } else {
      logger.debug(`EPSS batch query failed: ${err instanceof Error ? err.message : err}`);
    }
    return [];
  }
}

/**
 * Batch-fetch EPSS scores for a list of CVE IDs.
 * Batches run with bounded parallelism (concurrency = 5).
 */
export async function fetchEpssScores(cveIds: string[]): Promise<Map<string, EpssScore>> {
  const results = new Map<string, EpssScore>();
  if (cveIds.length === 0) return results;

  const batches: string[][] = [];
  for (let i = 0; i < cveIds.length; i += EPSS_BATCH_SIZE) {
    batches.push(cveIds.slice(i, i + EPSS_BATCH_SIZE));
  }

  const batchResults = await pMap(batches, fetchEpssBatch, EPSS_BATCH_CONCURRENCY);

  for (const data of batchResults) {
    for (const entry of data ?? []) {
      results.set(entry.cve, {
        cve: entry.cve,
        epss: parseFloat(entry.epss),
        percentile: parseFloat(entry.percentile),
      });
    }
  }

  return results;
}

/**
 * Fetch the CISA KEV catalog and return a set of CVE IDs.
 * Cached for 4 hours. Call `resetKevCache()` to force a refresh.
 */
export async function fetchKevCatalog(): Promise<Set<string>> {
  if (kevState.cache && Date.now() - kevState.cachedAt < kevState.ttlMs) {
    return kevState.cache;
  }

  try {
    const data = await fetchJsonWithValidation<{ vulnerabilities?: Array<{ cveID: string }> }>(
      'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
      {
        maxBytes: KEV_MAX_BYTES,
        timeoutMs: KEV_TIMEOUT_MS,
        contentType: 'application/json',
      },
    );

    const next = new Set((data.vulnerabilities ?? []).map((v) => v.cveID));
    kevState.cache = next;
    kevState.cachedAt = Date.now();
    logger.debug(`CISA KEV loaded: ${next.size} entries`);
    return next;
  } catch (err) {
    if (err instanceof FetchValidationError) {
      logger.debug(`CISA KEV fetch failed (${err.kind}): ${err.message}`);
    } else {
      logger.debug(`CISA KEV fetch failed: ${err instanceof Error ? err.message : err}`);
    }
    return kevState.cache ?? new Set();
  }
}

/**
 * Check if a CVE is in the CISA KEV catalog.
 */
export function isInKev(cveId: string, kevSet: Set<string>): boolean {
  return kevSet.has(cveId);
}

/**
 * Extract CVE IDs from advisory aliases.
 */
export function extractCveIds(aliases: string[]): string[] {
  return aliases.filter(a => a.startsWith('CVE-'));
}

/**
 * Compute an exploit score from EPSS + KEV data.
 * Returns a graduated score (0-20) replacing the old binary 15-point bonus.
 */
export function computeExploitScore(
  cveIds: string[],
  epssScores: Map<string, EpssScore>,
  kevSet: Set<string>,
): { score: number; inKev: boolean; epssMax: number | null } {
  // CISA KEV is the highest signal — actively exploited
  const inKev = cveIds.some(id => kevSet.has(id));
  if (inKev) {
    return { score: 20, inKev: true, epssMax: 1.0 };
  }

  // Find highest EPSS score among all CVE aliases
  let epssMax: number | null = null;
  for (const cve of cveIds) {
    const entry = epssScores.get(cve);
    if (entry && (epssMax === null || entry.epss > epssMax)) {
      epssMax = entry.epss;
    }
  }

  if (epssMax === null) {
    return { score: 0, inKev: false, epssMax: null };
  }

  // Graduated EPSS scoring
  let score = 0;
  if (epssMax >= 0.5) score = 20;       // top ~2% — actively exploited
  else if (epssMax >= 0.1) score = 15;   // top ~10% — high likelihood
  else if (epssMax >= 0.01) score = 8;   // top ~30% — moderate likelihood
  else score = 2;                         // low likelihood but data exists

  return { score, inKev: false, epssMax };
}
