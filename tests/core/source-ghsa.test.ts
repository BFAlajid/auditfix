import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { fetchGhsaAdvisories } from '../../src/core/advisory/source-ghsa.js';

type Page = {
  hasNextPage: boolean;
  endCursor: string | null;
  nodes: Array<Record<string, unknown>>;
};

function makeNode(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    advisory: {
      ghsaId: 'GHSA-aaaa-bbbb-cccc',
      summary: 'Example advisory',
      severity: 'HIGH',
      cwes: {
        nodes: [
          { cweId: 'CWE-79', name: 'Cross-site Scripting' },
          { cweId: 'CWE-400', name: 'Uncontrolled Resource Consumption' },
        ],
      },
      cvss: {
        score: 8.1,
        vectorString: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      },
      references: [{ url: 'https://github.com/advisories/GHSA-aaaa-bbbb-cccc' }],
      publishedAt: '2024-01-01T00:00:00Z',
      updatedAt: '2024-01-02T00:00:00Z',
    },
    package: { name: 'lodash', ecosystem: 'NPM' },
    vulnerableVersionRange: '<4.17.21',
    firstPatchedVersion: { identifier: '4.17.21' },
    ...overrides,
  };
}

function mockGraphqlResponse(
  page: Page,
  options: { status?: number; headers?: Record<string, string> } = {}
): Response {
  const status = options.status ?? 200;
  const body = JSON.stringify({
    data: {
      securityVulnerabilities: {
        pageInfo: {
          hasNextPage: page.hasNextPage,
          endCursor: page.endCursor,
        },
        nodes: page.nodes,
      },
    },
  });
  const headers = new Headers({ 'content-type': 'application/json' });
  for (const [k, v] of Object.entries(options.headers ?? {})) {
    headers.set(k, v);
  }
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: 'OK',
    headers,
    text: vi.fn().mockResolvedValue(body),
  } as unknown as Response;
}

describe('fetchGhsaAdvisories', () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it('returns empty map when token is missing (no fetch called)', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    const result = await fetchGhsaAdvisories({ token: '' });

    expect(result.size).toBe(0);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('transforms a GHSA node into an Advisory with cwes and cvss', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        mockGraphqlResponse({
          hasNextPage: false,
          endCursor: null,
          nodes: [makeNode()],
        })
      )
    );

    const result = await fetchGhsaAdvisories({ token: 'tok' });

    expect(result.size).toBe(1);
    const lodash = result.get('lodash');
    expect(lodash).toBeDefined();
    expect(lodash).toHaveLength(1);
    const adv = lodash![0];
    expect(adv.id).toBe('GHSA-aaaa-bbbb-cccc');
    expect(adv.affectedRange).toBe('<4.17.21');
    expect(adv.fixVersion).toBe('4.17.21');
    expect(adv.source).toBe('ghsa');
    expect(adv.cwes).toEqual([
      { id: 'CWE-79', name: 'Cross-site Scripting' },
      { id: 'CWE-400', name: 'Uncontrolled Resource Consumption' },
    ]);
    expect(adv.cvss?.score).toBe(8.1);
    expect(adv.cvss?.vectorString).toContain('CVSS:3.1/');
    expect(adv.severity[0]?.type).toBe('CVSS_V3');
  });

  it('paginates until hasNextPage is false', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        mockGraphqlResponse({
          hasNextPage: true,
          endCursor: 'cursor1',
          nodes: [makeNode({ package: { name: 'pkg-a', ecosystem: 'NPM' } })],
        })
      )
      .mockResolvedValueOnce(
        mockGraphqlResponse({
          hasNextPage: false,
          endCursor: null,
          nodes: [makeNode({ package: { name: 'pkg-b', ecosystem: 'NPM' } })],
        })
      );
    vi.stubGlobal('fetch', fetchMock);

    const result = await fetchGhsaAdvisories({ token: 'tok' });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(result.has('pkg-a')).toBe(true);
    expect(result.has('pkg-b')).toBe(true);

    // Verify the second call passed the cursor.
    const secondCall = fetchMock.mock.calls[1];
    const body = JSON.parse((secondCall[1] as RequestInit).body as string);
    expect(body.variables.after).toBe('cursor1');
  });

  it('filters results by packages option', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        mockGraphqlResponse({
          hasNextPage: false,
          endCursor: null,
          nodes: [
            makeNode({ package: { name: 'pkg-a', ecosystem: 'NPM' } }),
            makeNode({ package: { name: 'pkg-b', ecosystem: 'NPM' } }),
          ],
        })
      )
    );

    const result = await fetchGhsaAdvisories({
      token: 'tok',
      packages: ['pkg-a'],
    });

    expect(result.has('pkg-a')).toBe(true);
    expect(result.has('pkg-b')).toBe(false);
  });

  it('retries once when rate-limited (x-ratelimit-remaining=0)', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        mockGraphqlResponse(
          { hasNextPage: false, endCursor: null, nodes: [] },
          { status: 200, headers: { 'x-ratelimit-remaining': '0', 'retry-after': '1' } }
        )
      )
      .mockResolvedValueOnce(
        mockGraphqlResponse({
          hasNextPage: false,
          endCursor: null,
          nodes: [makeNode()],
        })
      );
    vi.stubGlobal('fetch', fetchMock);

    const result = await fetchGhsaAdvisories({ token: 'tok' });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(result.get('lodash')).toHaveLength(1);
  });

  it('returns empty map when fetch throws network error', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockRejectedValue(new Error('ECONNREFUSED'))
    );
    const result = await fetchGhsaAdvisories({ token: 'tok' });
    expect(result.size).toBe(0);
  });

  it('sends Authorization bearer header', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      mockGraphqlResponse({
        hasNextPage: false,
        endCursor: null,
        nodes: [],
      })
    );
    vi.stubGlobal('fetch', fetchMock);

    await fetchGhsaAdvisories({ token: 'my-token-xyz' });

    const [, init] = fetchMock.mock.calls[0];
    const headers = (init as RequestInit).headers as Record<string, string>;
    expect(headers.Authorization).toBe('Bearer my-token-xyz');
    expect(headers['Content-Type']).toBe('application/json');
  });

  it('skips nodes without a ghsaId', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        mockGraphqlResponse({
          hasNextPage: false,
          endCursor: null,
          nodes: [
            {
              advisory: { ghsaId: '' },
              package: { name: 'bad', ecosystem: 'NPM' },
              vulnerableVersionRange: '*',
              firstPatchedVersion: null,
            },
          ],
        })
      )
    );

    const result = await fetchGhsaAdvisories({ token: 'tok' });
    expect(result.has('bad')).toBe(false);
  });
});
