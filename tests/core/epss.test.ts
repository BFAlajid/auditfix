import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest';
import {
  extractCveIds,
  computeExploitScore,
  fetchEpssScores,
  fetchKevCatalog,
  resetKevCache,
} from '../../src/core/advisory/epss.js';
import type { EpssScore } from '../../src/core/advisory/epss.js';
import { FetchValidationError } from '../../src/utils/fetch.js';

describe('extractCveIds', () => {
  it('filters CVE-prefixed aliases', () => {
    const result = extractCveIds(['CVE-2024-1234', 'GHSA-xxxx', 'CVE-2023-5678']);
    expect(result).toEqual(['CVE-2024-1234', 'CVE-2023-5678']);
  });

  it('returns empty for no CVEs', () => {
    expect(extractCveIds(['GHSA-xxxx'])).toEqual([]);
    expect(extractCveIds([])).toEqual([]);
  });
});

describe('computeExploitScore', () => {
  it('returns 20 for CVE in KEV catalog', () => {
    const kevSet = new Set(['CVE-2024-1234']);
    const result = computeExploitScore(['CVE-2024-1234'], new Map(), kevSet);
    expect(result.score).toBe(20);
    expect(result.inKev).toBe(true);
  });

  it('returns 20 for very high EPSS (>=0.5)', () => {
    const epss = new Map<string, EpssScore>([
      ['CVE-2024-1234', { cve: 'CVE-2024-1234', epss: 0.6, percentile: 0.98 }],
    ]);
    const result = computeExploitScore(['CVE-2024-1234'], epss, new Set());
    expect(result.score).toBe(20);
    expect(result.inKev).toBe(false);
    expect(result.epssMax).toBe(0.6);
  });

  it('returns 15 for high EPSS (>=0.1)', () => {
    const epss = new Map<string, EpssScore>([
      ['CVE-2024-1234', { cve: 'CVE-2024-1234', epss: 0.15, percentile: 0.9 }],
    ]);
    const result = computeExploitScore(['CVE-2024-1234'], epss, new Set());
    expect(result.score).toBe(15);
  });

  it('returns 8 for moderate EPSS (>=0.01)', () => {
    const epss = new Map<string, EpssScore>([
      ['CVE-2024-1234', { cve: 'CVE-2024-1234', epss: 0.05, percentile: 0.7 }],
    ]);
    const result = computeExploitScore(['CVE-2024-1234'], epss, new Set());
    expect(result.score).toBe(8);
  });

  it('returns 2 for low EPSS (<0.01)', () => {
    const epss = new Map<string, EpssScore>([
      ['CVE-2024-1234', { cve: 'CVE-2024-1234', epss: 0.005, percentile: 0.3 }],
    ]);
    const result = computeExploitScore(['CVE-2024-1234'], epss, new Set());
    expect(result.score).toBe(2);
  });

  it('returns 0 when no data available', () => {
    const result = computeExploitScore(['CVE-2024-1234'], new Map(), new Set());
    expect(result.score).toBe(0);
    expect(result.epssMax).toBeNull();
  });

  it('picks highest EPSS across multiple CVEs', () => {
    const epss = new Map<string, EpssScore>([
      ['CVE-2024-1', { cve: 'CVE-2024-1', epss: 0.02, percentile: 0.5 }],
      ['CVE-2024-2', { cve: 'CVE-2024-2', epss: 0.2, percentile: 0.92 }],
    ]);
    const result = computeExploitScore(['CVE-2024-1', 'CVE-2024-2'], epss, new Set());
    expect(result.epssMax).toBe(0.2);
    expect(result.score).toBe(15);
  });
});

// -----------------------------------------------------------------------------
// Remote-fetch hardening — tests for EPSS + KEV responses going through
// fetchWithValidation.
// -----------------------------------------------------------------------------

type FetchInit = { signal?: AbortSignal } & Record<string, unknown>;
type FetchArgs = [string | URL, FetchInit?];

function jsonResponse(body: string, headers: Record<string, string> = {}): Response {
  const encoder = new TextEncoder();
  const bytes = encoder.encode(body);
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(bytes);
      controller.close();
    },
  });
  return new Response(stream, {
    status: 200,
    statusText: 'OK',
    headers: {
      'content-type': 'application/json',
      ...headers,
    },
  });
}

/** Emits a stream that advertises JSON but produces many chunks summing past `totalBytes`. */
function hugeStreamResponse(totalBytes: number): Response {
  const chunkSize = 64 * 1024;
  const chunk = new Uint8Array(chunkSize);
  chunk.fill(0x20); // spaces
  let sent = 0;
  const stream = new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (sent >= totalBytes) {
        controller.close();
        return;
      }
      const remaining = totalBytes - sent;
      const out = remaining >= chunkSize ? chunk : chunk.slice(0, remaining);
      controller.enqueue(out);
      sent += out.byteLength;
    },
  });
  return new Response(stream, {
    status: 200,
    statusText: 'OK',
    headers: { 'content-type': 'application/json' },
  });
}

describe('fetchKevCatalog — fetch hardening', () => {
  const realFetch = globalThis.fetch;

  beforeEach(() => {
    resetKevCache();
  });

  afterEach(() => {
    globalThis.fetch = realFetch;
    resetKevCache();
    vi.restoreAllMocks();
  });

  it('rejects oversized KEV bodies (stream exceeds maxBytes)', async () => {
    // 21MB payload vs 20MB cap — should be cut off mid-stream.
    let caught: unknown = null;
    globalThis.fetch = vi.fn(async () => hugeStreamResponse(21 * 1024 * 1024)) as unknown as typeof fetch;

    // fetchKevCatalog swallows errors and returns an empty set; to assert
    // the FetchValidationError we also exercise fetchWithValidation directly.
    const { fetchWithValidation } = await import('../../src/utils/fetch.js');
    try {
      await fetchWithValidation('https://example.test/feed.json', {
        maxBytes: 20 * 1024 * 1024,
        contentType: 'application/json',
      });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(FetchValidationError);
    expect((caught as FetchValidationError).kind).toBe('oversize');

    // fetchKevCatalog itself resolves to an empty set and does not throw.
    const result = await fetchKevCatalog();
    expect(result).toBeInstanceOf(Set);
  });

  it('rejects wrong content-type (HTML served as JSON endpoint)', async () => {
    globalThis.fetch = vi.fn(async () => {
      return new Response('<!DOCTYPE html><html><body>portal</body></html>', {
        status: 200,
        headers: { 'content-type': 'text/html; charset=utf-8' },
      });
    }) as unknown as typeof fetch;

    resetKevCache();
    const result = await fetchKevCatalog();
    // fetchKevCatalog logs + returns empty set on validation error.
    expect(result.size).toBe(0);

    // Direct call should throw.
    const { fetchWithValidation } = await import('../../src/utils/fetch.js');
    await expect(
      fetchWithValidation('https://example.test/feed.json', {
        maxBytes: 1024,
        contentType: 'application/json',
      }),
    ).rejects.toMatchObject({
      name: 'FetchValidationError',
      kind: 'content-type',
    });
  });

  it('rejects Content-Length over cap before reading body', async () => {
    globalThis.fetch = vi.fn(async () =>
      new Response('{}', {
        status: 200,
        headers: {
          'content-type': 'application/json',
          'content-length': String(50 * 1024 * 1024),
        },
      }),
    ) as unknown as typeof fetch;

    const { fetchWithValidation } = await import('../../src/utils/fetch.js');
    await expect(
      fetchWithValidation('https://example.test/feed.json', {
        maxBytes: 20 * 1024 * 1024,
        contentType: 'application/json',
      }),
    ).rejects.toMatchObject({ kind: 'oversize' });
  });

  it('rejects HTML body returned with JSON content-type', async () => {
    globalThis.fetch = vi.fn(async () =>
      jsonResponse('<!DOCTYPE html><html><body>oops</body></html>'),
    ) as unknown as typeof fetch;

    const { fetchWithValidation } = await import('../../src/utils/fetch.js');
    await expect(
      fetchWithValidation('https://example.test/feed.json', {
        maxBytes: 1024,
        contentType: 'application/json',
      }),
    ).rejects.toMatchObject({ kind: 'html-body' });
  });

  it('accepts a well-formed JSON KEV response and caches it', async () => {
    const payload = JSON.stringify({
      vulnerabilities: [
        { cveID: 'CVE-2024-0001' },
        { cveID: 'CVE-2024-0002' },
      ],
    });
    const fetchSpy = vi.fn(async () => jsonResponse(payload));
    globalThis.fetch = fetchSpy as unknown as typeof fetch;

    resetKevCache();
    const first = await fetchKevCatalog();
    expect(first.size).toBe(2);
    expect(first.has('CVE-2024-0001')).toBe(true);

    // Second call should hit the cache (no extra fetch).
    const second = await fetchKevCatalog();
    expect(second.size).toBe(2);
    expect(fetchSpy).toHaveBeenCalledTimes(1);
  });

  it('resetKevCache forces a refetch', async () => {
    const payload = JSON.stringify({ vulnerabilities: [{ cveID: 'CVE-A' }] });
    const fetchSpy = vi.fn(async () => jsonResponse(payload));
    globalThis.fetch = fetchSpy as unknown as typeof fetch;

    resetKevCache();
    await fetchKevCatalog();
    resetKevCache();
    await fetchKevCatalog();
    expect(fetchSpy).toHaveBeenCalledTimes(2);
  });
});

describe('fetchEpssScores — parallel batches', () => {
  const realFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = realFetch;
    vi.restoreAllMocks();
  });

  it('runs batches with bounded concurrency (5) — observed inflight count never exceeds cap', async () => {
    // 250 CVEs → 5 batches of 50. With concurrency=5 they all start roughly together.
    const cveIds = Array.from({ length: 250 }, (_, i) => `CVE-2024-${String(i).padStart(5, '0')}`);

    let inflight = 0;
    let maxInflight = 0;
    const calls: FetchArgs[] = [];

    globalThis.fetch = vi.fn(async (...args: FetchArgs) => {
      calls.push(args);
      inflight += 1;
      maxInflight = Math.max(maxInflight, inflight);
      // Simulate network latency so concurrency is observable.
      await new Promise((r) => setTimeout(r, 30));
      inflight -= 1;

      // Build a valid EPSS payload containing each CVE in the requested batch.
      const url = String(args[0]);
      const match = /cve=([^&]+)/.exec(url);
      const batchCves = match ? decodeURIComponent(match[1]).split(',') : [];
      const data = batchCves.map((cve) => ({ cve, epss: '0.01', percentile: '0.5' }));
      return jsonResponse(JSON.stringify({ data }));
    }) as unknown as typeof fetch;

    const result = await fetchEpssScores(cveIds);

    expect(calls.length).toBe(5); // 250 / 50 = 5 batches
    expect(maxInflight).toBeGreaterThanOrEqual(2); // parallel, not serial
    expect(maxInflight).toBeLessThanOrEqual(5);    // capped at 5
    expect(result.size).toBe(250);
  });

  it('tolerates one batch failing without losing the others', async () => {
    const cveIds = Array.from({ length: 100 }, (_, i) => `CVE-2024-${String(i).padStart(5, '0')}`);

    let call = 0;
    globalThis.fetch = vi.fn(async (..._args: FetchArgs) => {
      call += 1;
      const url = String(_args[0]);
      const match = /cve=([^&]+)/.exec(url);
      const batchCves = match ? decodeURIComponent(match[1]).split(',') : [];

      // Fail the second batch.
      if (call === 2) {
        return new Response('server error', { status: 500 });
      }
      const data = batchCves.map((cve) => ({ cve, epss: '0.02', percentile: '0.6' }));
      return jsonResponse(JSON.stringify({ data }));
    }) as unknown as typeof fetch;

    const result = await fetchEpssScores(cveIds);
    // First batch (50 CVEs) succeeded; second failed → ~50 results total.
    expect(result.size).toBe(50);
  });

  it('rejects oversized EPSS body (stream cap)', async () => {
    // Force a single batch that serves > 10MB body.
    globalThis.fetch = vi.fn(async () => hugeStreamResponse(11 * 1024 * 1024)) as unknown as typeof fetch;

    const result = await fetchEpssScores(['CVE-2024-0001']);
    // Validation rejects → empty map (error swallowed to keep scan alive).
    expect(result.size).toBe(0);
  });

  it('handles empty input without fetching', async () => {
    const spy = vi.fn();
    globalThis.fetch = spy as unknown as typeof fetch;
    const result = await fetchEpssScores([]);
    expect(result.size).toBe(0);
    expect(spy).not.toHaveBeenCalled();
  });
});
