/**
 * OSV.dev batch API integration.
 * Primary advisory source — real-time, no auth required.
 *
 * Flow:
 * 1. POST /v1/querybatch with all packages (up to 1000 per batch)
 * 2. Batch returns abbreviated results (id + modified only)
 * 3. Follow up with GET /v1/vulns/{id} for full details (bounded concurrency)
 */
import type { DependencyGraph } from '../../types/package.js';
import type {
  OsvBatchQuery,
  OsvBatchResponse,
  OsvVulnerability,
  Advisory,
} from '../../types/advisory.js';
import { affectedToSemverRange, affectedFixVersion } from './osv-ranges.js';
import { safeJsonParse } from '../../utils/sanitize.js';
import * as logger from '../../utils/logger.js';

const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';
const OSV_VULN_URL = 'https://api.osv.dev/v1/vulns';
const MAX_BATCH_SIZE = 1000;
const MAX_CONCURRENT_FETCHES = 10; // applies to individual vuln-detail GETs
const MAX_CONCURRENT_BATCHES = 5; // applies to POST /querybatch — heavier server-side, keep lower
const MAX_RESPONSE_SIZE = 50 * 1024 * 1024; // 50MB
const MAX_INDIVIDUAL_SIZE = 1 * 1024 * 1024; // 1MB

export type OsvFetchResult = {
  advisories: Map<string, Advisory[]>; // keyed by package name
  fetchedIds: string[];
  errors: string[];
};

/**
 * Fetch advisories for all packages in the dependency graph via OSV batch API.
 */
export async function fetchOsvAdvisories(graph: DependencyGraph): Promise<OsvFetchResult> {
  const errors: string[] = [];

  // Build unique package list (deduplicate by name@version)
  const uniquePackages = new Map<string, { name: string; version: string }>();
  for (const [, node] of graph) {
    const key = `${node.name}@${node.version}`;
    if (!uniquePackages.has(key)) {
      uniquePackages.set(key, { name: node.name, version: node.version });
    }
  }

  // Split into batches of MAX_BATCH_SIZE
  const packages = Array.from(uniquePackages.values());
  const batches: typeof packages[] = [];
  for (let i = 0; i < packages.length; i += MAX_BATCH_SIZE) {
    batches.push(packages.slice(i, i + MAX_BATCH_SIZE));
  }

  // Execute batch queries with bounded parallelism.
  // Sequential awaits here previously made 50k-package scans 50 serial round trips.
  // Failures are isolated per-batch via Promise.allSettled — one bad batch does not abort the rest.
  const allVulnIds = new Set<string>();

  const runBatch = async (batch: typeof packages): Promise<OsvBatchResponse> => {
    const query: OsvBatchQuery = {
      queries: batch.map((pkg) => ({
        version: pkg.version,
        package: {
          name: pkg.name,
          ecosystem: 'npm',
        },
      })),
    };
    const response = await fetchWithValidation(OSV_BATCH_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(query),
    }, MAX_RESPONSE_SIZE);
    return response as OsvBatchResponse;
  };

  for (let i = 0; i < batches.length; i += MAX_CONCURRENT_BATCHES) {
    const chunk = batches.slice(i, i + MAX_CONCURRENT_BATCHES);
    const results = await Promise.allSettled(chunk.map((batch) => runBatch(batch)));

    for (const result of results) {
      if (result.status === 'fulfilled') {
        const batchResponse = result.value;
        if (batchResponse.results) {
          for (const r of batchResponse.results) {
            if (r.vulns) {
              for (const vuln of r.vulns) {
                allVulnIds.add(vuln.id);
              }
            }
          }
        }
      } else {
        const msg = result.reason instanceof Error ? result.reason.message : String(result.reason);
        errors.push(`OSV batch query failed: ${msg}`);
        logger.warn(`OSV batch query failed: ${msg}`);
      }
    }
  }

  if (allVulnIds.size === 0) {
    return { advisories: new Map(), fetchedIds: [], errors };
  }

  logger.debug(`OSV batch found ${allVulnIds.size} vulnerability IDs, fetching details...`);

  // Fetch full details with bounded concurrency
  const vulnIds = Array.from(allVulnIds);
  const fullVulns: OsvVulnerability[] = [];

  for (let i = 0; i < vulnIds.length; i += MAX_CONCURRENT_FETCHES) {
    const chunk = vulnIds.slice(i, i + MAX_CONCURRENT_FETCHES);
    const results = await Promise.allSettled(
      chunk.map((id) => fetchVulnDetail(id))
    );

    for (const result of results) {
      if (result.status === 'fulfilled' && result.value) {
        fullVulns.push(result.value);
      } else if (result.status === 'rejected') {
        errors.push(`Failed to fetch vuln detail: ${result.reason}`);
      }
    }
  }

  // Convert to Advisory map keyed by package name.
  // Each advisory is parsed in a try/catch so a single malformed `affected` entry
  // does not drop the other advisories in the response.
  const advisories = new Map<string, Advisory[]>();

  for (const vuln of fullVulns) {
    if (!vuln || !Array.isArray(vuln.affected)) continue;
    for (const affected of vuln.affected) {
      try {
        if (!affected?.package?.ecosystem || !affected.package.name) continue;
        if (affected.package.ecosystem.toLowerCase() !== 'npm') continue;
        if (!Array.isArray(affected.ranges)) continue;

        const pkgName = affected.package.name;
        const advisory: Advisory = {
          id: vuln.id,
          aliases: vuln.aliases ?? [],
          summary: vuln.summary ?? '',
          details: vuln.details ?? '',
          severity: vuln.severity ?? [],
          affectedRange: affectedToSemverRange(affected),
          fixVersion: affectedFixVersion(affected),
          publishedAt: vuln.published ?? vuln.modified,
          modifiedAt: vuln.modified,
          references: vuln.references ?? [],
          source: 'osv-api',
        };

        const existing = advisories.get(pkgName) ?? [];
        existing.push(advisory);
        advisories.set(pkgName, existing);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        logger.warn(`Skipping malformed OSV affected entry in ${vuln.id}: ${msg}`);
      }
    }
  }

  return {
    advisories,
    fetchedIds: vulnIds,
    errors,
  };
}

async function fetchVulnDetail(id: string): Promise<OsvVulnerability | null> {
  try {
    return await fetchWithValidation(
      `${OSV_VULN_URL}/${encodeURIComponent(id)}`,
      { method: 'GET' },
      MAX_INDIVIDUAL_SIZE,
    ) as OsvVulnerability;
  } catch (err) {
    logger.warn(`Failed to fetch OSV vuln ${id}: ${err instanceof Error ? err.message : err}`);
    return null;
  }
}

async function fetchWithValidation(url: string, init: RequestInit, maxSize: number): Promise<unknown> {
  const response = await fetch(url, {
    ...init,
    signal: AbortSignal.timeout(30_000),
  });

  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${response.statusText}`);
  }

  const contentType = response.headers.get('content-type') ?? '';
  if (!contentType.includes('application/json')) {
    throw new Error(`Unexpected Content-Type: ${contentType}. Expected application/json.`);
  }

  const contentLength = response.headers.get('content-length');
  if (contentLength && parseInt(contentLength, 10) > maxSize) {
    throw new Error(`Response too large: ${contentLength} bytes (max ${maxSize})`);
  }

  const text = await response.text();
  if (text.length > maxSize) {
    throw new Error(`Response body too large: ${text.length} chars (max ${maxSize})`);
  }

  return safeJsonParse(text);
}
