import { describe, it, expect, beforeEach, vi } from 'vitest';
import {
  queryOfflineIndex,
  queryOfflineIndexBatch,
  getOfflineIndexSize,
} from '../../src/core/advisory/offline-index.js';
import type { DependencyGraph, DependencyNode } from '../../src/types/package.js';

function makeNode(name: string, version: string): DependencyNode {
  return {
    name, version, resolved: '', integrity: '',
    dependencies: [], isProduction: true, isDev: false,
    isOptional: false, depth: 1, dependencyPath: [],
  };
}

describe('Offline advisory index', () => {
  it('returns advisories for vulnerable lodash version', () => {
    const results = queryOfflineIndex('lodash', '4.17.20');
    expect(results.length).toBeGreaterThanOrEqual(1);
    expect(results[0].id).toBe('GHSA-35jh-r3h4-6jhm');
    expect(results[0].source).toBe('offline-index');
  });

  it('returns empty for patched lodash version', () => {
    const results = queryOfflineIndex('lodash', '4.17.21');
    expect(results).toHaveLength(0);
  });

  it('returns empty for unknown package', () => {
    const results = queryOfflineIndex('totally-unknown-pkg', '1.0.0');
    expect(results).toHaveLength(0);
  });

  it('batch queries all packages in a graph', async () => {
    const graph: DependencyGraph = new Map();
    graph.set('lodash@4.17.20', makeNode('lodash', '4.17.20'));
    graph.set('express@4.18.0', makeNode('express', '4.18.0'));
    graph.set('safe-pkg@1.0.0', makeNode('safe-pkg', '1.0.0'));

    const result = await queryOfflineIndexBatch(graph);
    expect(result.has('lodash')).toBe(true);
    expect(result.has('express')).toBe(true);
    expect(result.has('safe-pkg')).toBe(false);
  });

  it('reports correct index size', () => {
    expect(getOfflineIndexSize()).toBeGreaterThanOrEqual(20);
  });
});

// -----------------------------------------------------------------------------
// Retry-on-transient-failure for the generated index loader.
//
// If the first attempt to load ./offline-index.generated.js throws for a
// reason other than MODULE_NOT_FOUND (e.g. an FS race while unpacking), the
// next call should retry — not stay permanently degraded.
//
// These tests exercise the internal retry machinery directly via the
// `__testable` export rather than hijacking dynamic `import()` resolution,
// which is brittle when the target module does not exist on disk.
// -----------------------------------------------------------------------------
describe('ensureIndex retry-on-failure', () => {
  beforeEach(() => {
    vi.resetModules();
  });

  it('retries loading the generated index on transient failure', async () => {
    const mod = await import('../../src/core/advisory/offline-index.js');
    mod.resetOfflineIndexState();

    let attempts = 0;
    const loader = vi.fn(async () => {
      attempts += 1;
      if (attempts === 1) {
        const err = new Error('simulated FS flake') as Error & { code?: string };
        err.code = 'EACCES';
        throw err;
      }
      return [
        {
          id: 'GHSA-TEST-0001',
          pkg: 'retry-me',
          range: '<2.0.0',
          fix: '2.0.0',
          severity: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
          summary: 'test retry advisory',
        },
      ];
    });
    mod.__testable.setLoader(loader);

    const graph: DependencyGraph = new Map();
    graph.set('retry-me@1.5.0', makeNode('retry-me', '1.5.0'));

    // First call — loader throws, no generated advisory available yet.
    const first = await mod.queryOfflineIndexBatch(graph);
    expect(attempts).toBe(1);
    expect(first.has('retry-me')).toBe(false);

    // Second call — loader succeeds this time. Advisory now discoverable.
    const second = await mod.queryOfflineIndexBatch(graph);
    expect(attempts).toBe(2);
    expect(second.has('retry-me')).toBe(true);

    mod.__testable.resetLoader();
  });

  it('stops retrying after MAX_INDEX_LOAD_FAILURES consecutive failures', async () => {
    const mod = await import('../../src/core/advisory/offline-index.js');
    mod.resetOfflineIndexState();

    let attempts = 0;
    const loader = vi.fn(async () => {
      attempts += 1;
      const err = new Error('persistent FS error') as Error & { code?: string };
      err.code = 'EACCES';
      throw err;
    });
    mod.__testable.setLoader(loader);

    const graph: DependencyGraph = new Map();
    graph.set('lodash@4.17.20', makeNode('lodash', '4.17.20'));

    for (let i = 0; i < 5; i++) {
      const result = await mod.queryOfflineIndexBatch(graph);
      // Scans still produce results from the hardcoded fallback.
      expect(result.has('lodash')).toBe(true);
    }
    // Plateau at the failure ceiling.
    expect(attempts).toBe(3);

    mod.__testable.resetLoader();
  });

  it('does not retry when the generated module is absent (MODULE_NOT_FOUND)', async () => {
    const mod = await import('../../src/core/advisory/offline-index.js');
    mod.resetOfflineIndexState();

    let attempts = 0;
    const loader = vi.fn(async () => {
      attempts += 1;
      const err = new Error("Cannot find module './offline-index.generated.js'") as Error & {
        code?: string;
      };
      err.code = 'ERR_MODULE_NOT_FOUND';
      throw err;
    });
    mod.__testable.setLoader(loader);

    const graph: DependencyGraph = new Map();
    graph.set('lodash@4.17.20', makeNode('lodash', '4.17.20'));

    await mod.queryOfflineIndexBatch(graph);
    await mod.queryOfflineIndexBatch(graph);
    await mod.queryOfflineIndexBatch(graph);

    // MODULE_NOT_FOUND is the expected fresh-install path — attempt only once.
    expect(attempts).toBe(1);

    mod.__testable.resetLoader();
  });
});
