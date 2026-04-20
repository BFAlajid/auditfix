/**
 * Tests for the pooled-fetch layer in src/utils/fetch.ts.
 *
 * Strategy:
 *   - Dynamically import('undici') once to detect availability. If not
 *     resolvable (older Node, missing dep), tests that rely on it use it.skip.
 *   - Mock Agent via vi.mock so we can observe construction + close without
 *     opening real sockets.
 *   - Reset the module-level dispatcher cache between tests so each test
 *     exercises the lazy-init path cleanly.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

/**
 * Availability detection:
 *   In practice undici is a hard dep on Node >=18 (ships built in) and is
 *   listed in package.json, so it's always present in our CI. Older Node
 *   versions without the package would throw at `require.resolve`, in which
 *   case we fall through to a skipped block with a clear reason.
 *
 *   We use `require.resolve`-style detection rather than `await import` so
 *   the decision is made synchronously and doesn't race with vi.mock hoisting.
 */
import { createRequire } from 'node:module';
const requireFromHere = createRequire(import.meta.url);
let undiciAvailable = false;
try {
  requireFromHere.resolve('undici');
  undiciAvailable = true;
} catch {
  undiciAvailable = false;
}

const describeIfUndici = undiciAvailable
  ? describe
  : (describe.skip as typeof describe);
if (!undiciAvailable) {
  // eslint-disable-next-line no-console
  console.warn('[fetch-pool.test] undici not resolvable — pooled tests skipped');
}

// ---------- Shared mock Agent ---------------------------------------------

type MockAgentInstance = {
  opts: Record<string, unknown>;
  close: ReturnType<typeof vi.fn>;
  destroy: ReturnType<typeof vi.fn>;
};

const agentInstances: MockAgentInstance[] = [];

class MockAgent {
  opts: Record<string, unknown>;
  close = vi.fn(async () => {});
  destroy = vi.fn(async () => {});
  constructor(opts: Record<string, unknown>) {
    this.opts = opts;
    agentInstances.push(this as unknown as MockAgentInstance);
  }
}

vi.mock('undici', () => ({
  Agent: MockAgent,
}));

describeIfUndici('fetch pool (undici Agent)', () => {
  beforeEach(async () => {
    agentInstances.length = 0;
    // Reset the module cache so pooledDispatcher is re-initialized per test.
    const mod = await import('../../src/utils/fetch.js');
    mod.resetFetchPoolForTests();
  });

  afterEach(async () => {
    const mod = await import('../../src/utils/fetch.js');
    await mod.closeFetchPool();
    vi.restoreAllMocks();
  });

  it('creates a dispatcher once and reuses it across calls', async () => {
    const { getPooledDispatcher } = await import('../../src/utils/fetch.js');

    const first = await getPooledDispatcher();
    const second = await getPooledDispatcher();
    const third = await getPooledDispatcher();

    expect(first).not.toBeNull();
    expect(second).toBe(first);
    expect(third).toBe(first);
    // Only one Agent instance was constructed.
    expect(agentInstances).toHaveLength(1);
  });

  it('configures the Agent with keep-alive options', async () => {
    const { getPooledDispatcher } = await import('../../src/utils/fetch.js');
    await getPooledDispatcher();

    expect(agentInstances).toHaveLength(1);
    const opts = agentInstances[0].opts;
    expect(opts.keepAliveTimeout).toBeTypeOf('number');
    expect(opts.keepAliveMaxTimeout).toBeTypeOf('number');
    expect(opts.connections).toBeTypeOf('number');
    // Sanity: keep-alive max must not undershoot keep-alive base.
    expect(opts.keepAliveMaxTimeout as number).toBeGreaterThanOrEqual(
      opts.keepAliveTimeout as number,
    );
  });

  it('closeFetchPool tears down the dispatcher and a new one is created next', async () => {
    const { getPooledDispatcher, closeFetchPool } = await import(
      '../../src/utils/fetch.js'
    );

    const first = await getPooledDispatcher();
    expect(first).not.toBeNull();
    expect(agentInstances).toHaveLength(1);

    await closeFetchPool();
    expect(agentInstances[0].close).toHaveBeenCalledTimes(1);

    const second = await getPooledDispatcher();
    expect(second).not.toBeNull();
    // After teardown a new Agent should be constructed.
    expect(agentInstances).toHaveLength(2);
    expect(second).not.toBe(first);
  });

  it('fetchJsonWithValidation wires dispatcher when pool:true', async () => {
    const { fetchJsonWithValidation } = await import('../../src/utils/fetch.js');

    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    );
    vi.stubGlobal('fetch', fetchMock);

    const result = await fetchJsonWithValidation<{ ok: boolean }>(
      'https://example.test/ok',
      { method: 'GET' },
      { pool: true },
    );

    expect(result).toEqual({ ok: true });
    expect(fetchMock).toHaveBeenCalledOnce();
    const [, init] = fetchMock.mock.calls[0];
    // Dispatcher was injected from our mock Agent.
    expect(init.dispatcher).toBeDefined();
    expect(init.dispatcher).toBe(agentInstances[0]);
  });

  it('fetchJsonWithValidation omits dispatcher when pool:false (default)', async () => {
    const { fetchJsonWithValidation } = await import('../../src/utils/fetch.js');

    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    );
    vi.stubGlobal('fetch', fetchMock);

    await fetchJsonWithValidation('https://example.test/ok', { method: 'GET' });

    expect(fetchMock).toHaveBeenCalledOnce();
    const [, init] = fetchMock.mock.calls[0];
    expect(init.dispatcher).toBeUndefined();
    // No Agent was constructed because pool was not requested.
    expect(agentInstances).toHaveLength(0);
  });

  it('reuses the same dispatcher across multiple pooled fetches', async () => {
    const { fetchJsonWithValidation } = await import('../../src/utils/fetch.js');

    // Fresh Response per call — a Response body can only be consumed once.
    const fetchMock = vi.fn().mockImplementation(() =>
      Promise.resolve(
        new Response(JSON.stringify({ ok: true }), {
          status: 200,
          headers: { 'content-type': 'application/json' },
        }),
      ),
    );
    vi.stubGlobal('fetch', fetchMock);

    for (let i = 0; i < 5; i++) {
      await fetchJsonWithValidation(
        `https://example.test/${i}`,
        { method: 'GET' },
        { pool: true },
      );
    }

    expect(fetchMock).toHaveBeenCalledTimes(5);
    // One Agent, referenced by all five calls.
    expect(agentInstances).toHaveLength(1);
    const dispatchers = fetchMock.mock.calls.map(([, init]) => init.dispatcher);
    for (const d of dispatchers) {
      expect(d).toBe(agentInstances[0]);
    }
  });

  it('enforces content-type validation on pooled requests', async () => {
    const { fetchJsonWithValidation } = await import('../../src/utils/fetch.js');

    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response('<html>outage</html>', {
          status: 200,
          headers: { 'content-type': 'text/html' },
        }),
      ),
    );

    await expect(
      fetchJsonWithValidation(
        'https://example.test/outage',
        { method: 'GET' },
        { pool: true },
      ),
    ).rejects.toThrow(/Content-Type/);
  });

  it('enforces content-length cap on pooled requests', async () => {
    const { fetchJsonWithValidation } = await import('../../src/utils/fetch.js');

    const oversize = String(100 * 1024 * 1024);
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({}), {
          status: 200,
          headers: {
            'content-type': 'application/json',
            'content-length': oversize,
          },
        }),
      ),
    );

    await expect(
      fetchJsonWithValidation(
        'https://example.test/huge',
        { method: 'GET' },
        { pool: true, maxSize: 50 * 1024 * 1024 },
      ),
    ).rejects.toThrow(/too large/);
  });
});

// This block runs regardless of undici availability to ensure the fallback
// path works and callers don't blow up.
describe('fetch pool fallback (no pooling)', () => {
  beforeEach(async () => {
    const mod = await import('../../src/utils/fetch.js');
    mod.resetFetchPoolForTests();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('works without pool option (global fetch path)', async () => {
    const { fetchJsonWithValidation } = await import('../../src/utils/fetch.js');

    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ v: 1 }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      }),
    );
    vi.stubGlobal('fetch', fetchMock);

    const result = await fetchJsonWithValidation<{ v: number }>(
      'https://example.test/plain',
    );
    expect(result).toEqual({ v: 1 });
    expect(fetchMock).toHaveBeenCalledOnce();
  });
});
