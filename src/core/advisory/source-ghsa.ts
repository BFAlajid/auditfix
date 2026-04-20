/**
 * GitHub Security Advisories (GHSA) GraphQL enrichment source.
 *
 * GHSA provides richer metadata than OSV for the same advisories:
 *   - CWE classifications
 *   - CVSS score + vector
 *   - Canonical GHSA id
 *   - Severity labels, references
 *
 * Used as an ENRICHMENT step — never replaces the primary advisory source.
 * Missing token returns an empty map (logs a single warning); errors never
 * degrade the scan.
 *
 * Reference:
 *   https://docs.github.com/en/graphql/reference/queries#securityvulnerabilities
 */
import type { Advisory, CweRef, CvssDetails } from '../../types/advisory.js';
import { safeJsonParse } from '../../utils/sanitize.js';
import * as logger from '../../utils/logger.js';

const GITHUB_GRAPHQL_URL = 'https://api.github.com/graphql';
const MAX_RESPONSE_SIZE = 50 * 1024 * 1024; // 50MB
const REQUEST_TIMEOUT_MS = 30_000;
const MAX_PAGES = 1000;
const PAGE_SIZE = 100;

const GRAPHQL_QUERY = `
query($ecosystem: SecurityAdvisoryEcosystem!, $first: Int!, $after: String) {
  securityVulnerabilities(ecosystem: $ecosystem, first: $first, after: $after) {
    pageInfo { hasNextPage endCursor }
    nodes {
      advisory {
        ghsaId
        summary
        severity
        cwes(first: 10) { nodes { cweId name } }
        cvss { score vectorString }
        references { url }
        publishedAt
        updatedAt
      }
      package { name ecosystem }
      vulnerableVersionRange
      firstPatchedVersion { identifier }
    }
  }
}`;

export type GhsaOptions = {
  /** GitHub API token (required; empty string is treated as missing). */
  token: string;
  /** Filter to these package names (npm). If omitted, all packages returned. */
  packages?: string[];
  /** Optional cancellation signal. */
  signal?: AbortSignal;
};

type GhsaAdvisoryNode = {
  advisory: {
    ghsaId: string;
    summary?: string;
    severity?: string;
    cwes?: { nodes?: Array<{ cweId: string; name: string }> };
    cvss?: { score?: number | null; vectorString?: string | null } | null;
    references?: Array<{ url: string }>;
    publishedAt?: string;
    updatedAt?: string;
  };
  package: { name: string; ecosystem: string };
  vulnerableVersionRange?: string;
  firstPatchedVersion?: { identifier: string } | null;
};

type GhsaGraphqlResponse = {
  data?: {
    securityVulnerabilities?: {
      pageInfo: { hasNextPage: boolean; endCursor: string | null };
      nodes: GhsaAdvisoryNode[];
    };
  };
  errors?: Array<{ message: string }>;
};

/**
 * Fetch GHSA advisories for the npm ecosystem, paginating until exhausted or
 * MAX_PAGES reached. Returns a map keyed by package name.
 *
 * When `packages` is provided, the result is filtered post-fetch (GitHub's
 * GraphQL API does not support server-side package filtering).
 */
export async function fetchGhsaAdvisories(
  options: GhsaOptions
): Promise<Map<string, Advisory[]>> {
  const { token, packages, signal } = options;

  if (!token) {
    logger.warn(
      'GHSA enrichment skipped: no GitHub token provided (set GITHUB_TOKEN or GH_TOKEN).'
    );
    return new Map();
  }

  const packageFilter = packages && packages.length > 0
    ? new Set(packages)
    : null;

  const byPackage = new Map<string, Advisory[]>();
  let after: string | null = null;

  for (let page = 0; page < MAX_PAGES; page++) {
    let response: GhsaGraphqlResponse;
    try {
      response = await graphqlRequest(token, after, signal);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      logger.warn(`GHSA enrichment failed at page ${page}: ${msg}`);
      break;
    }

    if (response.errors && response.errors.length > 0) {
      logger.warn(
        `GHSA GraphQL returned errors: ${response.errors.map((e) => e.message).join('; ')}`
      );
      break;
    }

    const conn = response.data?.securityVulnerabilities;
    if (!conn) break;

    for (const node of conn.nodes ?? []) {
      const pkgName = node.package?.name;
      if (!pkgName) continue;
      if (packageFilter && !packageFilter.has(pkgName)) continue;

      const advisory = toAdvisory(node);
      if (!advisory) continue;

      const list = byPackage.get(pkgName) ?? [];
      list.push(advisory);
      byPackage.set(pkgName, list);
    }

    if (!conn.pageInfo?.hasNextPage || !conn.pageInfo.endCursor) break;
    after = conn.pageInfo.endCursor;
  }

  return byPackage;
}

/**
 * Send a single GraphQL page request. Honors rate limits via retry-after.
 * Throws on non-retryable errors; returns parsed response on success.
 */
async function graphqlRequest(
  token: string,
  after: string | null,
  signal?: AbortSignal
): Promise<GhsaGraphqlResponse> {
  const body = JSON.stringify({
    query: GRAPHQL_QUERY,
    variables: {
      ecosystem: 'NPM',
      first: PAGE_SIZE,
      after,
    },
  });

  // Single retry when rate-limited; honors retry-after or resets after a
  // minimal wait so we never block the scan for long.
  for (let attempt = 0; attempt < 2; attempt++) {
    const composedSignal = composeSignals(
      signal,
      AbortSignal.timeout(REQUEST_TIMEOUT_MS)
    );

    const response = await fetch(GITHUB_GRAPHQL_URL, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
        'User-Agent': 'auditfix',
        Accept: 'application/vnd.github+json',
      },
      body,
      signal: composedSignal,
    });

    const remaining = response.headers.get('x-ratelimit-remaining');
    if (response.status === 429 || remaining === '0') {
      if (attempt === 0) {
        const delay = computeRetryDelayMs(response.headers);
        logger.warn(
          `GHSA rate limited; retrying in ${Math.round(delay / 1000)}s`
        );
        await sleep(delay, signal);
        continue;
      }
      throw new Error('GHSA rate limited (retries exhausted)');
    }

    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }

    const contentType = response.headers.get('content-type') ?? '';
    if (!contentType.includes('application/json')) {
      throw new Error(`Unexpected Content-Type: ${contentType}`);
    }

    const contentLength = response.headers.get('content-length');
    if (contentLength && parseInt(contentLength, 10) > MAX_RESPONSE_SIZE) {
      throw new Error(`Response too large: ${contentLength} bytes`);
    }

    const text = await response.text();
    if (text.length > MAX_RESPONSE_SIZE) {
      throw new Error(`Response body too large: ${text.length} chars`);
    }

    return safeJsonParse<GhsaGraphqlResponse>(text);
  }

  // Unreachable — loop either returns or throws.
  throw new Error('GHSA request loop exited unexpectedly');
}

/** Compute retry delay from GitHub rate-limit headers, clamped to a sane range. */
function computeRetryDelayMs(headers: Headers): number {
  const retryAfter = headers.get('retry-after');
  if (retryAfter) {
    const seconds = parseInt(retryAfter, 10);
    if (Number.isFinite(seconds) && seconds > 0) {
      return Math.min(seconds, 60) * 1000;
    }
  }
  const reset = headers.get('x-ratelimit-reset');
  if (reset) {
    const resetSec = parseInt(reset, 10);
    if (Number.isFinite(resetSec)) {
      const deltaMs = resetSec * 1000 - Date.now();
      if (deltaMs > 0) return Math.min(deltaMs, 60_000);
    }
  }
  return 2000;
}

/** Abort-aware sleep. */
function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolvePromise, rejectPromise) => {
    const timer = setTimeout(resolvePromise, ms);
    if (signal) {
      if (signal.aborted) {
        clearTimeout(timer);
        rejectPromise(new Error('aborted'));
        return;
      }
      signal.addEventListener(
        'abort',
        () => {
          clearTimeout(timer);
          rejectPromise(new Error('aborted'));
        },
        { once: true }
      );
    }
  });
}

/** Compose optional caller signal with an internal timeout signal. */
function composeSignals(
  a: AbortSignal | undefined,
  b: AbortSignal
): AbortSignal {
  if (!a) return b;
  const controller = new AbortController();
  const abort = () => controller.abort();
  if (a.aborted || b.aborted) controller.abort();
  a.addEventListener('abort', abort, { once: true });
  b.addEventListener('abort', abort, { once: true });
  return controller.signal;
}

/** Convert a GHSA node into our Advisory shape. Returns null if unusable. */
function toAdvisory(node: GhsaAdvisoryNode): Advisory | null {
  const ghsaId = node.advisory?.ghsaId;
  if (!ghsaId) return null;

  const cwes: CweRef[] =
    node.advisory.cwes?.nodes?.map((c) => ({ id: c.cweId, name: c.name })) ??
    [];

  const cvss: CvssDetails | undefined =
    node.advisory.cvss && typeof node.advisory.cvss.score === 'number'
      ? {
          score: node.advisory.cvss.score,
          vectorString: node.advisory.cvss.vectorString ?? '',
        }
      : undefined;

  const severity = cvss?.vectorString
    ? [{ type: 'CVSS_V3' as const, score: cvss.vectorString }]
    : [];

  return {
    id: ghsaId,
    aliases: [],
    summary: node.advisory.summary ?? '',
    details: '',
    severity,
    affectedRange: node.vulnerableVersionRange ?? '*',
    fixVersion: node.firstPatchedVersion?.identifier ?? null,
    publishedAt: node.advisory.publishedAt ?? '',
    modifiedAt: node.advisory.updatedAt ?? node.advisory.publishedAt ?? '',
    references: (node.advisory.references ?? []).map((r) => ({
      type: 'WEB',
      url: r.url,
    })),
    source: 'ghsa',
    cwes: cwes.length > 0 ? cwes : undefined,
    cvss,
  };
}
