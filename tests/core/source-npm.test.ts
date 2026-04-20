import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { fetchNpmAdvisories } from '../../src/core/advisory/source-npm.js';
import { defaultNpmrcConfig } from '../../src/utils/npmrc.js';
import type { DependencyGraph, DependencyNode } from '../../src/types/package.js';

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

function mockResponse(
  body: string | object,
  options: {
    status?: number;
    statusText?: string;
    contentType?: string;
    contentLength?: string;
  } = {}
): Response {
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

const sampleNpmResponse = {
  '1234': {
    id: 1234,
    title: 'Prototype Pollution',
    overview: 'lodash allows prototype pollution via merge functions',
    severity: 'high',
    url: 'https://npmjs.com/advisories/1234',
    vulnerable_versions: '<4.17.21',
    patched_versions: '>=4.17.21',
    cves: ['CVE-2021-23337'],
    cwe: ['CWE-1321'],
    created: '2021-02-15T00:00:00.000Z',
    updated: '2021-06-01T00:00:00.000Z',
    module_name: 'lodash',
    findings: [{ version: '4.17.20', paths: ['lodash'] }],
  },
  '5678': {
    id: 5678,
    title: 'Regular Expression Denial of Service',
    overview: 'minimatch ReDoS vulnerability',
    severity: 'critical',
    url: 'https://npmjs.com/advisories/5678',
    vulnerable_versions: '<3.0.5',
    patched_versions: '>=3.0.5',
    cves: ['CVE-2022-3517'],
    cwe: ['CWE-1333'],
    created: '2022-10-01T00:00:00.000Z',
    updated: '2022-10-15T00:00:00.000Z',
    module_name: 'minimatch',
    findings: [{ version: '3.0.4', paths: ['minimatch'] }],
  },
};

describe('fetchNpmAdvisories', () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it('parses a successful npm response into Advisory objects', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
      mockResponse(sampleNpmResponse)
    ));

    const graph = makeGraph([
      ['lodash', '4.17.20'],
      ['minimatch', '3.0.4'],
    ]);

    const result = await fetchNpmAdvisories(graph);

    expect(result.errors).toHaveLength(0);
    expect(result.advisories.size).toBe(2);

    // Check lodash advisory
    const lodashAdvisories = result.advisories.get('lodash');
    expect(lodashAdvisories).toBeDefined();
    expect(lodashAdvisories).toHaveLength(1);
    const lodash = lodashAdvisories![0];
    expect(lodash.id).toBe('npm-1234');
    expect(lodash.summary).toBe('Prototype Pollution');
    expect(lodash.details).toBe('lodash allows prototype pollution via merge functions');
    expect(lodash.affectedRange).toBe('<4.17.21');
    expect(lodash.fixVersion).toBe('4.17.21');
    expect(lodash.aliases).toEqual(['CVE-2021-23337']);
    expect(lodash.source).toBe('npm-bulk');
    expect(lodash.severity).toHaveLength(1);
    expect(lodash.severity[0].type).toBe('CVSS_V3');
    expect(lodash.references).toEqual([
      { type: 'WEB', url: 'https://npmjs.com/advisories/1234' },
    ]);

    // Check minimatch advisory
    const minimatchAdvisories = result.advisories.get('minimatch');
    expect(minimatchAdvisories).toBeDefined();
    expect(minimatchAdvisories).toHaveLength(1);
    expect(minimatchAdvisories![0].id).toBe('npm-5678');
    expect(minimatchAdvisories![0].fixVersion).toBe('3.0.5');
    expect(minimatchAdvisories![0].source).toBe('npm-bulk');

    // Verify fetch was called with correct parameters
    const fetchMock = vi.mocked(globalThis.fetch);
    expect(fetchMock).toHaveBeenCalledOnce();
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe('https://registry.npmjs.org/-/npm/v1/security/advisories/bulk');
    expect(init?.method).toBe('POST');
    const sentBody = JSON.parse(init?.body as string);
    expect(sentBody['lodash']).toEqual(['4.17.20']);
    expect(sentBody['minimatch']).toEqual(['3.0.4']);
  });

  it('handles HTML response (npm outage) gracefully', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
      mockResponse(
        '<html><body>Service Unavailable</body></html>',
        { contentType: 'text/html' }
      )
    ));

    const graph = makeGraph([['lodash', '4.17.20']]);
    const result = await fetchNpmAdvisories(graph);

    expect(result.advisories.size).toBe(0);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]).toContain('Content-Type');
    expect(result.errors[0]).toContain('text/html');
  });

  it('aborts oversized responses via Content-Length', async () => {
    const oversizeLength = String(60 * 1024 * 1024); // 60MB
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
      mockResponse(
        { some: 'data' },
        { contentLength: oversizeLength }
      )
    ));

    const graph = makeGraph([['lodash', '4.17.20']]);
    const result = await fetchNpmAdvisories(graph);

    expect(result.advisories.size).toBe(0);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]).toContain('too large');
    expect(result.errors[0]).toContain(oversizeLength);
  });

  it('handles wrong Content-Type gracefully', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(
      mockResponse(
        'plain text response',
        { contentType: 'text/plain' }
      )
    ));

    const graph = makeGraph([['lodash', '4.17.20']]);
    const result = await fetchNpmAdvisories(graph);

    expect(result.advisories.size).toBe(0);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]).toContain('Content-Type');
    expect(result.errors[0]).toContain('text/plain');
  });

  it('returns empty result with no fetch call for empty graph', async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal('fetch', fetchMock);

    const graph: DependencyGraph = new Map();
    const result = await fetchNpmAdvisories(graph);

    expect(result.advisories.size).toBe(0);
    expect(result.errors).toHaveLength(0);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('does NOT send Authorization when no npmrc config is provided', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(mockResponse(sampleNpmResponse));
    vi.stubGlobal('fetch', fetchMock);

    const graph = makeGraph([['lodash', '4.17.20']]);
    await fetchNpmAdvisories(graph);

    const [, init] = fetchMock.mock.calls[0];
    const headers = (init as RequestInit).headers as Record<string, string>;
    expect(headers.Authorization).toBeUndefined();
  });

  it('sends Authorization header when npmrc token matches default registry', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(mockResponse(sampleNpmResponse));
    vi.stubGlobal('fetch', fetchMock);

    const npmrc = defaultNpmrcConfig();
    npmrc.authTokens['//registry.npmjs.org/'] = 'PUBLIC_TOKEN';

    const graph = makeGraph([['lodash', '4.17.20']]);
    await fetchNpmAdvisories(graph, { npmrc });

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe(
      'https://registry.npmjs.org/-/npm/v1/security/advisories/bulk'
    );
    const headers = (init as RequestInit).headers as Record<string, string>;
    expect(headers.Authorization).toBe('Bearer PUBLIC_TOKEN');
  });

  it('routes a scoped package to its scope registry with its own auth', async () => {
    // Two sequential calls — one per registry bucket.
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(mockResponse(sampleNpmResponse))
      .mockResolvedValueOnce(mockResponse({}));
    vi.stubGlobal('fetch', fetchMock);

    const npmrc = defaultNpmrcConfig();
    npmrc.scopeRegistries['@acme'] = 'https://acme.example.com/';
    npmrc.authTokens['//acme.example.com/'] = 'ACME_TOKEN';

    const graph = makeGraph([
      ['lodash', '4.17.20'],
      ['@acme/widget', '1.0.0'],
    ]);
    await fetchNpmAdvisories(graph, { npmrc });

    expect(fetchMock).toHaveBeenCalledTimes(2);

    // Find the call to the acme registry.
    const acmeCall = fetchMock.mock.calls.find(([url]) =>
      String(url).startsWith('https://acme.example.com/')
    );
    expect(acmeCall).toBeDefined();
    const acmeHeaders = (acmeCall![1] as RequestInit).headers as Record<
      string,
      string
    >;
    expect(acmeHeaders.Authorization).toBe('Bearer ACME_TOKEN');

    // The public registry call should have no Authorization header.
    const publicCall = fetchMock.mock.calls.find(([url]) =>
      String(url).startsWith('https://registry.npmjs.org/')
    );
    expect(publicCall).toBeDefined();
    const publicHeaders = (publicCall![1] as RequestInit).headers as Record<
      string,
      string
    >;
    expect(publicHeaders.Authorization).toBeUndefined();
  });

  it('omits Authorization when no token matches the registry', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(mockResponse(sampleNpmResponse));
    vi.stubGlobal('fetch', fetchMock);

    // Config with auth for a different registry.
    const npmrc = defaultNpmrcConfig();
    npmrc.authTokens['//other.example.com/'] = 'OTHER_TOKEN';

    const graph = makeGraph([['lodash', '4.17.20']]);
    await fetchNpmAdvisories(graph, { npmrc });

    const [, init] = fetchMock.mock.calls[0];
    const headers = (init as RequestInit).headers as Record<string, string>;
    expect(headers.Authorization).toBeUndefined();
  });
});
