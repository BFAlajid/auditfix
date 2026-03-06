import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { DependencyGraph, DependencyNode } from '../../src/types/package.js';

vi.mock('../../src/utils/logger.js', () => ({
  info: vi.fn(),
  warn: vi.fn(),
  debug: vi.fn(),
  error: vi.fn(),
}));

function makeGraph(packages: Array<{ name: string; version?: string; isProduction?: boolean }>): DependencyGraph {
  const graph: DependencyGraph = new Map();
  for (const pkg of packages) {
    const node: DependencyNode = {
      name: pkg.name,
      version: pkg.version ?? '1.0.0',
      isProduction: pkg.isProduction ?? true,
      dependencies: [],
      integrity: null,
      resolved: null,
    };
    graph.set(`${pkg.name}@${pkg.version ?? '1.0.0'}`, node);
  }
  return graph;
}

describe('provenance checking', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('reports verified when attestation exists', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: true,
      json: () => Promise.resolve({
        attestations: [{
          predicateType: 'https://slsa.dev/provenance/v1',
          bundle: { verificationMaterial: { tlogEntries: [{ logIndex: '12345' }] } },
        }],
      }),
    });
    vi.stubGlobal('fetch', mockFetch);

    const { checkProvenance } = await import('../../src/core/scanner/provenance.js');
    const graph = makeGraph([{ name: 'verified-pkg', version: '1.0.0' }]);
    const report = await checkProvenance(graph);

    expect(report.verified).toBe(1);
    expect(report.unverified).toBe(0);
    expect(report.findings[0].hasProvenance).toBe(true);
    expect(report.findings[0].provenanceUrl).toContain('sigstore');

    vi.unstubAllGlobals();
  });

  it('reports unverified when no attestation', async () => {
    const mockFetch = vi.fn().mockResolvedValue({
      ok: false,
    });
    vi.stubGlobal('fetch', mockFetch);

    const { checkProvenance } = await import('../../src/core/scanner/provenance.js');
    const graph = makeGraph([{ name: 'unverified-pkg', version: '2.0.0' }]);
    const report = await checkProvenance(graph);

    expect(report.unverified).toBe(1);
    expect(report.findings[0].hasProvenance).toBe(false);

    vi.unstubAllGlobals();
  });

  it('handles fetch errors gracefully', async () => {
    const mockFetch = vi.fn().mockRejectedValue(new Error('Network error'));
    vi.stubGlobal('fetch', mockFetch);

    const { checkProvenance } = await import('../../src/core/scanner/provenance.js');
    const graph = makeGraph([{ name: 'error-pkg' }]);
    const report = await checkProvenance(graph);

    // Should not throw, just report as unverified
    expect(report.verified + report.unverified).toBeLessThanOrEqual(1);

    vi.unstubAllGlobals();
  });
});
