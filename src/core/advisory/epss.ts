/**
 * EPSS (Exploit Prediction Scoring System) integration.
 * Queries FIRST.org API for exploit probability scores.
 * Also checks CISA KEV (Known Exploited Vulnerabilities) catalog.
 */
import * as logger from '../../utils/logger.js';

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

let kevCache: Set<string> | null = null;
let kevCacheTime = 0;
const KEV_CACHE_TTL = 4 * 60 * 60 * 1000; // 4 hours

/**
 * Batch-fetch EPSS scores for a list of CVE IDs.
 */
export async function fetchEpssScores(cveIds: string[]): Promise<Map<string, EpssScore>> {
  const results = new Map<string, EpssScore>();
  if (cveIds.length === 0) return results;

  // EPSS API supports comma-separated CVEs, batch in groups of 50
  const BATCH_SIZE = 50;
  for (let i = 0; i < cveIds.length; i += BATCH_SIZE) {
    const batch = cveIds.slice(i, i + BATCH_SIZE);
    try {
      const param = batch.join(',');
      const response = await fetch(
        `https://api.first.org/data/v1/epss?cve=${param}`,
        { signal: AbortSignal.timeout(10_000) },
      );
      if (!response.ok) continue;

      const data = await response.json() as {
        data: Array<{ cve: string; epss: string; percentile: string }>;
      };

      for (const entry of data.data ?? []) {
        results.set(entry.cve, {
          cve: entry.cve,
          epss: parseFloat(entry.epss),
          percentile: parseFloat(entry.percentile),
        });
      }
    } catch (err) {
      logger.debug(`EPSS batch query failed: ${err instanceof Error ? err.message : err}`);
    }
  }

  return results;
}

/**
 * Fetch the CISA KEV catalog and return a set of CVE IDs.
 * Cached for 4 hours.
 */
export async function fetchKevCatalog(): Promise<Set<string>> {
  if (kevCache && Date.now() - kevCacheTime < KEV_CACHE_TTL) {
    return kevCache;
  }

  try {
    const response = await fetch(
      'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
      { signal: AbortSignal.timeout(15_000) },
    );
    if (!response.ok) {
      logger.debug(`CISA KEV fetch failed: HTTP ${response.status}`);
      return kevCache ?? new Set();
    }

    const data = await response.json() as {
      vulnerabilities: Array<{ cveID: string }>;
    };

    kevCache = new Set(data.vulnerabilities.map(v => v.cveID));
    kevCacheTime = Date.now();
    logger.debug(`CISA KEV loaded: ${kevCache.size} entries`);
    return kevCache;
  } catch (err) {
    logger.debug(`CISA KEV fetch failed: ${err instanceof Error ? err.message : err}`);
    return kevCache ?? new Set();
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
