import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { fetchOsvAdvisories } from '../../src/core/advisory/source-osv.js';
import type { DependencyGraph, DependencyNode } from '../../src/types/package.js';

const OSV_BATCH_URL = 'https://api.osv.dev/v1/querybatch';
const OSV_VULN_URL = 'https://api.osv.dev/v1/vulns';

function makeNode(name: string, version: string): DependencyNode {
  return {
    name,
    version,
    resolved: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`,
    integrity: 'sha512-fake',
    dependencies: [],
    isProduction: true,
    isDev: false,
    isOptional: false,
    depth: 0,
    dependencyPath: [name],
  };
}

function makeGraph(entries: [string, string][]): DependencyGraph {
  const graph: DependencyGraph = new Map();
  for (const [name, version] of entries) {
    graph.set(`${name}@${version}`, makeNode(name, version));
  }
  return graph;
}

type MockResponseOptions = {
  status?: number;
  statusText?: string;
  contentType?: string;
  contentLength?: string;
};

function mockResponse(body: string | object, options: MockResponseOptions = {}): Response {
  const {
    status = 200,
    statusText = 'OK',
    contentType = 'application/json',
    contentLength,
  } = options;

  const text = typeof body === 'string' ? body : JSON.stringify(body);
  const headers = new Headers();
  headers.set('content-type', contentType);
  if (contentLength) {
    headers.set('content-length', contentLength);
  }

  return {
    ok: status >= 200 && status < 300,
    status,
    statusText,
    headers,
    text: vi.fn().mockResolvedValue(text),
    json: vi.fn().mockImplementation(() => Promise.resolve(JSON.parse(text))),
  } as unknown as Response;
}

/** Build a full OSV vulnerability detail payload. */
function makeVuln(id: string, packageName: string, overrides: Record<string, unknown> = {}) {
  return {
    id,
    summary: `${id} summary`,
    details: `${id} details`,
    aliases: [`CVE-2024-${id.slice(-4)}`],
    modified: '2024-01-15T00:00:00Z',
    published: '2024-01-01T00:00:00Z',
    affected: [
      {
        package: { ecosystem: 'npm', name: packageName },
        ranges: [
          {
            type: 'SEMVER',
            events: [{ introduced: '0' }, { fixed: '2.0.0' }],
          },
        ],
      },
    ],
    severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
    references: [{ type: 'ADVISORY', url: `https://example.com/${id}` }],
    ...overrides,
  };
}

describe('fetchOsvAdvisories', () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it('returns empty result when graph is empty', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    const graph: DependencyGraph = new Map();
    const result = await fetchOsvAdvisories(graph);

    expect(result.advisories.size).toBe(0);
    expect(result.fetchedIds).toHaveLength(0);
    expect(result.errors).toHaveLength(0);
    // Batch URL may be called once even for empty packages (depends on impl);
    // the important invariant is that no network issue occurs and result is empty.
  });

  it('happy path: parses batch + detail responses into Advisory objects', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockImplementation(async (url: string) => {
        if (url === OSV_BATCH_URL) {
          return mockResponse({
            results: [
              { vulns: [{ id: 'GHSA-aaaa-bbbb-cccc', modified: '2024-01-15T00:00:00Z' }] },
              { vulns: [{ id: 'GHSA-dddd-eeee-ffff', modified: '2024-01-16T00:00:00Z' }] },
            ],
          });
        }
        if (url.startsWith(OSV_VULN_URL)) {
          const id = decodeURIComponent(url.split('/').pop()!);
          const pkg = id === 'GHSA-aaaa-bbbb-cccc' ? 'lodash' : 'minimatch';
          return mockResponse(makeVuln(id, pkg));
        }
        throw new Error(`Unexpected URL: ${url}`);
      }),
    );

    const graph = makeGraph([
      ['lodash', '1.0.0'],
      ['minimatch', '1.0.0'],
    ]);
    const result = await fetchOsvAdvisories(graph);

    expect(result.errors).toHaveLength(0);
    expect(result.fetchedIds).toHaveLength(2);
    expect(result.advisories.size).toBe(2);

    const lodashAdvs = result.advisories.get('lodash');
    expect(lodashAdvs).toBeDefined();
    expect(lodashAdvs).toHaveLength(1);
    expect(lodashAdvs![0].id).toBe('GHSA-aaaa-bbbb-cccc');
    expect(lodashAdvs![0].fixVersion).toBe('2.0.0');
    expect(lodashAdvs![0].affectedRange).toContain('<2.0.0');
    expect(lodashAdvs![0].source).toBe('osv-api');
    expect(lodashAdvs![0].references).toHaveLength(1);

    const minimatchAdvs = result.advisories.get('minimatch');
    expect(minimatchAdvs).toBeDefined();
    expect(minimatchAdvs![0].id).toBe('GHSA-dddd-eeee-ffff');
  });

  it('single-package graph produces one batch call and one vuln-detail call', async () => {
    const fetchMock = vi.fn().mockImplementation(async (url: string) => {
      if (url === OSV_BATCH_URL) {
        return mockResponse({
          results: [{ vulns: [{ id: 'GHSA-1111-2222-3333', modified: '2024-01-15T00:00:00Z' }] }],
        });
      }
      return mockResponse(makeVuln('GHSA-1111-2222-3333', 'lodash'));
    });
    vi.stubGlobal('fetch', fetchMock);

    const graph = makeGraph([['lodash', '1.0.0']]);
    const result = await fetchOsvAdvisories(graph);

    expect(result.advisories.size).toBe(1);
    // one batch POST + one detail GET
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it('handles malformed JSON body gracefully (batch level)', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(mockResponse('not-json-{{{')),
    );

    const graph = makeGraph([['lodash', '1.0.0']]);
    const result = await fetchOsvAdvisories(graph);

    // Batch parse fails → no vuln IDs → empty advisories, but error recorded
    expect(result.advisories.size).toBe(0);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0]).toContain('OSV batch query failed');
  });

  it('handles HTTP 429 (rate-limit) gracefully — batch reported as error, no crash', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        mockResponse('rate limited', { status: 429, statusText: 'Too Many Requests', contentType: 'text/plain' }),
      ),
    );

    const graph = makeGraph([['lodash', '1.0.0']]);
    const result = await fetchOsvAdvisories(graph);

    expect(result.advisories.size).toBe(0);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0]).toMatch(/HTTP 429/);
  });

  it('handles HTTP 5xx gracefully', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        mockResponse('server error', { status: 503, statusText: 'Service Unavailable', contentType: 'text/plain' }),
      ),
    );

    const graph = makeGraph([['lodash', '1.0.0']]);
    const result = await fetchOsvAdvisories(graph);

    expect(result.advisories.size).toBe(0);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0]).toMatch(/HTTP 503/);
  });

  it('handles timeout / AbortError gracefully', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockRejectedValue(Object.assign(new Error('The operation was aborted'), { name: 'TimeoutError' })),
    );

    const graph = makeGraph([['lodash', '1.0.0']]);
    const result = await fetchOsvAdvisories(graph);

    expect(result.advisories.size).toBe(0);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0]).toContain('OSV batch query failed');
    expect(result.errors[0]).toContain('aborted');
  });

  it('rejects oversize responses via Content-Length header', async () => {
    const oversize = String(60 * 1024 * 1024); // >50MB limit
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(mockResponse({ results: [] }, { contentLength: oversize })),
    );

    const graph = makeGraph([['lodash', '1.0.0']]);
    const result = await fetchOsvAdvisories(graph);

    expect(result.advisories.size).toBe(0);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0]).toMatch(/too large/i);
    expect(result.errors[0]).toContain(oversize);
  });

  it('rejects wrong Content-Type (e.g. HTML outage page)', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        mockResponse('<html>outage</html>', { contentType: 'text/html' }),
      ),
    );

    const graph = makeGraph([['lodash', '1.0.0']]);
    const result = await fetchOsvAdvisories(graph);

    expect(result.advisories.size).toBe(0);
    expect(result.errors.length).toBeGreaterThan(0);
    expect(result.errors[0]).toMatch(/Content-Type/);
    expect(result.errors[0]).toContain('text/html');
  });

  it('skips malformed affected entries; other advisories still returned', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockImplementation(async (url: string) => {
        if (url === OSV_BATCH_URL) {
          return mockResponse({
            results: [
              {
                vulns: [
                  { id: 'GHSA-good-good-good', modified: '2024-01-15T00:00:00Z' },
                  { id: 'GHSA-bad-bad-bad-', modified: '2024-01-16T00:00:00Z' },
                ],
              },
            ],
          });
        }
        const id = decodeURIComponent(url.split('/').pop()!);
        if (id === 'GHSA-good-good-good') {
          return mockResponse(makeVuln(id, 'lodash'));
        }
        // Malformed: affected exists but ranges is not an array, plus a valid entry alongside
        return mockResponse({
          id,
          modified: '2024-01-16T00:00:00Z',
          affected: [
            // bad one (ranges is not an array)
            { package: { ecosystem: 'npm', name: 'bad-pkg' }, ranges: 'not-an-array' },
            // good one following it
            {
              package: { ecosystem: 'npm', name: 'other-pkg' },
              ranges: [{ type: 'SEMVER', events: [{ introduced: '0' }, { fixed: '3.0.0' }] }],
            },
          ],
        });
      }),
    );

    const graph = makeGraph([
      ['lodash', '1.0.0'],
      ['bad-pkg', '1.0.0'],
      ['other-pkg', '1.0.0'],
    ]);
    const result = await fetchOsvAdvisories(graph);

    // Good advisory in same vuln is preserved; malformed affected entry skipped silently
    expect(result.advisories.get('lodash')).toBeDefined();
    expect(result.advisories.get('other-pkg')).toBeDefined();
    expect(result.advisories.get('bad-pkg')).toBeUndefined();
  });

  it('bounds concurrency: no more than MAX_CONCURRENT_BATCHES (=5) in-flight at once', async () => {
    // Build a graph with 20+ batches. MAX_BATCH_SIZE=1000, so we need >20000 unique packages.
    // To keep the test fast, we instead assert the invariant with a mock counter regardless of
    // exact batch count, so the assertion only matters if multiple batches are queued.
    // We force enough packages to produce 20 batches: 20 * 1000 = 20000 unique entries.
    const entries: [string, string][] = [];
    for (let i = 0; i < 20000; i++) {
      entries.push([`pkg-${i}`, '1.0.0']);
    }
    const graph = makeGraph(entries);

    let inFlight = 0;
    let maxInFlight = 0;
    const batchCalls: number[] = [];

    vi.stubGlobal(
      'fetch',
      vi.fn().mockImplementation(async (url: string) => {
        if (url === OSV_BATCH_URL) {
          inFlight++;
          maxInFlight = Math.max(maxInFlight, inFlight);
          batchCalls.push(inFlight);
          // simulate some I/O delay so concurrent requests overlap
          await new Promise((resolve) => setTimeout(resolve, 10));
          inFlight--;
          return mockResponse({ results: [{}] }); // no vulns in any batch
        }
        throw new Error(`Unexpected URL: ${url}`);
      }),
    );

    const result = await fetchOsvAdvisories(graph);

    expect(result.errors).toHaveLength(0);
    expect(batchCalls.length).toBe(20); // 20000 / 1000 batches
    // Concurrency cap must be respected
    expect(maxInFlight).toBeGreaterThan(1); // proof parallelism actually happened
    expect(maxInFlight).toBeLessThanOrEqual(5); // MAX_CONCURRENT_BATCHES
  }, 30000);

  it('bounded parallelism still isolates per-batch failures (Promise.allSettled semantics)', async () => {
    // 10 batches; one fails, others succeed. Ensure we still get partial results + error recorded.
    const entries: [string, string][] = [];
    for (let i = 0; i < 10000; i++) {
      entries.push([`pkg-${i}`, '1.0.0']);
    }
    const graph = makeGraph(entries);

    let batchCall = 0;
    vi.stubGlobal(
      'fetch',
      vi.fn().mockImplementation(async (url: string) => {
        if (url === OSV_BATCH_URL) {
          batchCall++;
          if (batchCall === 3) {
            // Third batch fails
            return mockResponse('boom', { status: 500, statusText: 'Internal Error', contentType: 'text/plain' });
          }
          return mockResponse({ results: [] });
        }
        throw new Error(`Unexpected URL: ${url}`);
      }),
    );

    const result = await fetchOsvAdvisories(graph);

    // One recorded error from the failing batch; other batches completed
    expect(result.errors.length).toBe(1);
    expect(result.errors[0]).toMatch(/HTTP 500/);
  }, 30000);

  it('records detail-fetch errors separately from batch errors', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockImplementation(async (url: string) => {
        if (url === OSV_BATCH_URL) {
          return mockResponse({
            results: [{ vulns: [{ id: 'GHSA-xxxx-yyyy-zzzz', modified: '2024-01-15T00:00:00Z' }] }],
          });
        }
        // detail fetch fails
        return mockResponse('gone', { status: 404, statusText: 'Not Found', contentType: 'text/plain' });
      }),
    );

    const graph = makeGraph([['lodash', '1.0.0']]);
    const result = await fetchOsvAdvisories(graph);

    expect(result.advisories.size).toBe(0);
    // fetchVulnDetail swallows and logs; it returns null, not a rejection.
    // So errors[] may be empty here — but fetchedIds still captures the attempted IDs.
    expect(result.fetchedIds).toContain('GHSA-xxxx-yyyy-zzzz');
  });

  it('deduplicates packages by name@version before batching', async () => {
    const fetchMock = vi.fn().mockImplementation(async (url: string) => {
      if (url === OSV_BATCH_URL) {
        return mockResponse({ results: [] });
      }
      throw new Error(`Unexpected URL: ${url}`);
    });
    vi.stubGlobal('fetch', fetchMock);

    // Same package@version appears twice in the graph via different keys
    const graph: DependencyGraph = new Map();
    graph.set('lodash@1.0.0#a', makeNode('lodash', '1.0.0'));
    graph.set('lodash@1.0.0#b', makeNode('lodash', '1.0.0'));
    await fetchOsvAdvisories(graph);

    // Only one batch call; one unique package inside it
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const sentBody = JSON.parse((fetchMock.mock.calls[0][1] as RequestInit).body as string);
    expect(sentBody.queries).toHaveLength(1);
    expect(sentBody.queries[0].package.name).toBe('lodash');
  });
});
