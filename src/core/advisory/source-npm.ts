/**
 * npm bulk advisory endpoint integration.
 * Tertiary fallback source — no auth required.
 *
 * Endpoint: POST https://registry.npmjs.org/-/npm/v1/security/advisories/bulk
 * Body: { "package-name": ["version1", "version2"] }
 * Returns advisory objects with severity, CWE, fix info.
 */
import type { DependencyGraph } from '../../types/package.js';
import type { Advisory } from '../../types/advisory.js';
import { safeJsonParse } from '../../utils/sanitize.js';
import { getPooledDispatcher } from '../../utils/fetch.js';
import * as logger from '../../utils/logger.js';
import {
  defaultNpmrcConfig,
  registryForPackage,
  tokenForRegistry,
  type NpmrcConfig,
} from '../../utils/npmrc.js';

const DEFAULT_REGISTRY = 'https://registry.npmjs.org/';
const NPM_BULK_PATH = '-/npm/v1/security/advisories/bulk';
const NPM_BULK_URL = `${DEFAULT_REGISTRY}${NPM_BULK_PATH}`;
const MAX_RESPONSE_SIZE = 50 * 1024 * 1024; // 50MB

export type NpmFetchResult = {
  advisories: Map<string, Advisory[]>;
  errors: string[];
};

/**
 * Shape of a single advisory object returned by the npm bulk endpoint.
 */
type NpmAdvisoryResponse = {
  id: number;
  title?: string;
  overview?: string;
  severity?: string;
  url?: string;
  vulnerable_versions?: string;
  patched_versions?: string;
  cves?: string[];
  cwe?: string[];
  created?: string;
  updated?: string;
  module_name?: string;
  findings?: { version: string; paths: string[] }[];
};

/**
 * The bulk endpoint returns a map of advisory ID -> advisory object.
 * Each advisory contains a `module_name` field identifying the package.
 */
type NpmBulkResponse = Record<string, NpmAdvisoryResponse>;

const SEVERITY_MAP: Record<string, number> = {
  critical: 9.5,
  high: 8.0,
  medium: 5.5,
  low: 3.0,
  info: 0.0,
};

/**
 * Convert an npm severity string to an approximate CVSS severity entry
 * compatible with our Advisory type.
 */
function npmSeverityToOsv(severity: string | undefined): Advisory['severity'] {
  if (!severity) return [];
  const normalized = severity.toLowerCase();
  const score = SEVERITY_MAP[normalized];
  if (score === undefined) return [];

  // Approximate CVSS vector from severity label for compatibility
  return [
    {
      type: 'CVSS_V3',
      score: approximateCvssVector(normalized),
    },
  ];
}

/**
 * Return a representative CVSS:3.1 vector string for an npm severity label.
 * These are rough approximations used to maintain consistency with the
 * OSV source which provides real CVSS vectors.
 */
function approximateCvssVector(severity: string): string {
  switch (severity) {
    case 'critical':
      return 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H';
    case 'high':
      return 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N';
    case 'medium':
      return 'CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N';
    case 'low':
      return 'CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:U/C:L/I:N/A:N';
    default:
      return 'CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N';
  }
}

/**
 * Normalize patched_versions into a fixVersion string or null.
 * npm returns strings like ">=4.2.1" or "<0.0.0" (meaning no fix).
 */
function extractFixVersion(patchedVersions: string | undefined): string | null {
  if (!patchedVersions) return null;
  const trimmed = patchedVersions.trim();
  // "<0.0.0" means no fix available
  if (trimmed === '<0.0.0' || trimmed === '') return null;
  // Extract the version from patterns like ">=4.2.1"
  const match = trimmed.match(/(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.]+)?)/);
  return match ? match[1] : trimmed;
}

/**
 * Build the npm bulk request body from a dependency graph.
 * Deduplicates packages, producing { "package-name": ["v1", "v2"] }.
 */
function buildRequestBody(
  graph: DependencyGraph
): Record<string, string[]> | null {
  const packageVersions = new Map<string, Set<string>>();

  for (const [, node] of graph) {
    if (!node.name || !node.version) continue;
    const versions = packageVersions.get(node.name) ?? new Set<string>();
    versions.add(node.version);
    packageVersions.set(node.name, versions);
  }

  if (packageVersions.size === 0) return null;

  const body: Record<string, string[]> = {};
  for (const [name, versions] of packageVersions) {
    body[name] = Array.from(versions);
  }
  return body;
}

/**
 * Partition a bulk-request body into per-registry sub-bodies based on
 * scope-to-registry routing from the supplied npmrc config.
 *
 * Packages with no scope override go to the default registry.
 */
function partitionByRegistry(
  body: Record<string, string[]>,
  config: NpmrcConfig
): Map<string, Record<string, string[]>> {
  const byRegistry = new Map<string, Record<string, string[]>>();

  for (const [name, versions] of Object.entries(body)) {
    const registry = registryForPackage(name, config);
    const bucket = byRegistry.get(registry) ?? {};
    bucket[name] = versions;
    byRegistry.set(registry, bucket);
  }
  return byRegistry;
}

/** Join a registry base URL with the bulk advisories path. */
function bulkUrlFor(registry: string): string {
  const base = registry.endsWith('/') ? registry : `${registry}/`;
  return `${base}${NPM_BULK_PATH}`;
}

export type FetchNpmOptions = {
  /** Pre-loaded .npmrc config. Default: public registry, no auth. */
  npmrc?: NpmrcConfig;
};

/**
 * Fetch advisories for all packages in the dependency graph via the npm
 * bulk advisory endpoint.
 *
 * When `options.npmrc` is provided, packages are partitioned by their
 * configured registry and each registry gets its own request with the
 * matching auth token.
 */
export async function fetchNpmAdvisories(
  graph: DependencyGraph,
  options: FetchNpmOptions = {}
): Promise<NpmFetchResult> {
  const errors: string[] = [];
  const advisories = new Map<string, Advisory[]>();

  if (graph.size === 0) {
    return { advisories, errors };
  }

  const body = buildRequestBody(graph);
  if (!body) {
    return { advisories, errors };
  }

  const npmrc = options.npmrc ?? defaultNpmrcConfig();
  const buckets = partitionByRegistry(body, npmrc);

  // Preserve legacy URL for the public registry so the default path
  // continues to look identical in tests and traces.
  for (const [registry, subBody] of buckets) {
    const url =
      registry === DEFAULT_REGISTRY ? NPM_BULK_URL : bulkUrlFor(registry);
    const token = tokenForRegistry(registry, npmrc);
    const fetched = await fetchOneBulk(url, subBody, token, errors);
    for (const [pkg, list] of fetched) {
      const existing = advisories.get(pkg) ?? [];
      existing.push(...list);
      advisories.set(pkg, existing);
    }
  }

  logger.debug(
    `npm bulk returned ${advisories.size} affected packages with advisories`
  );

  return { advisories, errors };
}

/**
 * Perform a single bulk-advisory request against one registry. Push errors
 * onto the caller's array so partial failures don't abort other registries.
 */
async function fetchOneBulk(
  url: string,
  body: Record<string, string[]>,
  token: string | null,
  errors: string[]
): Promise<Map<string, Advisory[]>> {
  const advisories = new Map<string, Advisory[]>();
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  let response: Response;
  try {
    const dispatcher = await getPooledDispatcher();
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const init: any = {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(30_000),
    };
    if (dispatcher) init.dispatcher = dispatcher;
    response = await fetch(url, init);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    errors.push(`npm bulk request failed: ${msg}`);
    logger.warn(`npm bulk request failed: ${msg}`);
    return advisories;
  }

  if (!response.ok) {
    errors.push(`npm bulk HTTP ${response.status}: ${response.statusText}`);
    logger.warn(`npm bulk HTTP ${response.status}: ${response.statusText}`);
    return advisories;
  }

  // Validate Content-Type before parsing (S5: npm outages return HTML)
  const contentType = response.headers.get('content-type') ?? '';
  if (!contentType.includes('application/json')) {
    errors.push(
      `npm bulk unexpected Content-Type: ${contentType}. Expected application/json.`
    );
    logger.warn(
      `npm bulk unexpected Content-Type: ${contentType}. Expected application/json.`
    );
    return advisories;
  }

  const contentLength = response.headers.get('content-length');
  if (contentLength && parseInt(contentLength, 10) > MAX_RESPONSE_SIZE) {
    errors.push(
      `npm bulk response too large: ${contentLength} bytes (max ${MAX_RESPONSE_SIZE})`
    );
    logger.warn(`npm bulk response too large: ${contentLength} bytes`);
    return advisories;
  }

  let text: string;
  try {
    text = await response.text();
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    errors.push(`npm bulk failed to read response body: ${msg}`);
    logger.warn(`npm bulk failed to read body: ${msg}`);
    return advisories;
  }

  if (text.length > MAX_RESPONSE_SIZE) {
    errors.push(
      `npm bulk response body too large: ${text.length} chars (max ${MAX_RESPONSE_SIZE})`
    );
    logger.warn(`npm bulk response body too large: ${text.length} chars`);
    return advisories;
  }

  let parsed: NpmBulkResponse;
  try {
    parsed = safeJsonParse<NpmBulkResponse>(text);
  } catch {
    const preview = text.slice(0, 200);
    errors.push(
      `npm bulk response is not valid JSON (possible outage). Preview: ${preview}`
    );
    logger.warn(`npm bulk response is not valid JSON. Preview: ${preview}`);
    return advisories;
  }

  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    errors.push('npm bulk response is not an object');
    return advisories;
  }

  for (const [, npmAdvisory] of Object.entries(parsed)) {
    if (!npmAdvisory || typeof npmAdvisory !== 'object') continue;

    const pkgName = npmAdvisory.module_name;
    if (!pkgName) continue;

    // Include module_name in the key — the numeric `id` field is only unique
    // within a package, so two different packages can share the same id and
    // collide downstream if we keyed solely on it.
    const advisory: Advisory = {
      id:
        npmAdvisory.id != null
          ? `npm-${pkgName}-${npmAdvisory.id}`
          : `npm-${pkgName}-unknown`,
      aliases: npmAdvisory.cves ?? [],
      summary: npmAdvisory.title ?? '',
      details: npmAdvisory.overview ?? '',
      severity: npmSeverityToOsv(npmAdvisory.severity),
      affectedRange: npmAdvisory.vulnerable_versions ?? '*',
      fixVersion: extractFixVersion(npmAdvisory.patched_versions),
      publishedAt: npmAdvisory.created ?? '',
      modifiedAt: npmAdvisory.updated ?? npmAdvisory.created ?? '',
      references: npmAdvisory.url
        ? [{ type: 'WEB', url: npmAdvisory.url }]
        : [],
      source: 'npm-bulk',
    };

    const existing = advisories.get(pkgName) ?? [];
    existing.push(advisory);
    advisories.set(pkgName, existing);
  }

  return advisories;
}
