import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { DependencyGraph, DependencyNode } from '../../src/types/package.js';

vi.mock('../../src/core/advisory/source-osv.js', () => ({
  fetchOsvAdvisories: vi.fn(),
}));

vi.mock('../../src/core/advisory/source-npm.js', () => ({
  fetchNpmAdvisories: vi.fn(),
}));

vi.mock('../../src/core/advisory/cache.js', () => ({
  cacheAdvisoryBatch: vi.fn().mockResolvedValue(undefined),
  getCachedPackageAdvisories: vi.fn().mockReturnValue(null),
}));

vi.mock('../../src/core/advisory/offline-index.js', () => ({
  queryOfflineIndexBatch: vi.fn().mockResolvedValue(new Map()),
}));

vi.mock('../../src/utils/logger.js', () => ({
  info: vi.fn(),
  warn: vi.fn(),
  debug: vi.fn(),
  error: vi.fn(),
}));

import { resolveAdvisories, AdvisoryResolutionError } from '../../src/core/advisory/resolver.js';
import { fetchOsvAdvisories } from '../../src/core/advisory/source-osv.js';
import { fetchNpmAdvisories } from '../../src/core/advisory/source-npm.js';

function makeGraph(): DependencyGraph {
  const node: DependencyNode = {
    name: 'lodash',
    version: '4.17.20',
    resolved: '',
    integrity: '',
    dependencies: [],
    isProduction: true,
    isDev: false,
    isOptional: false,
    depth: 1,
    dependencyPath: ['lodash'],
  };
  const graph: DependencyGraph = new Map();
  graph.set('lodash@4.17.20', node);
  return graph;
}

function makeAdvisory(id: string) {
  return {
    id,
    aliases: [],
    summary: 'Test',
    details: '',
    severity: [],
    affectedRange: '>=1.0.0',
    fixVersion: '5.0.0',
    publishedAt: '',
    modifiedAt: '',
    references: [],
    source: 'osv-api' as const,
  };
}

describe('resolveAdvisories', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('returns OSV results with HIGH confidence when successful', async () => {
    const advisories = new Map([['lodash', [makeAdvisory('GHSA-1234-5678-abcd')]]]);
    vi.mocked(fetchOsvAdvisories).mockResolvedValue({
      advisories,
      fetchedIds: ['GHSA-1234-5678-abcd'],
      errors: [],
    });

    const result = await resolveAdvisories(makeGraph());

    expect(result.confidence).toBe('HIGH');
    expect(result.source).toContain('OSV');
    expect(result.sourceId).toBe('osv');
    expect(result.advisories.size).toBe(1);
  });

  it('returns MEDIUM confidence when OSV has partial errors', async () => {
    const advisories = new Map([['lodash', [makeAdvisory('GHSA-1234-5678-abcd')]]]);
    vi.mocked(fetchOsvAdvisories).mockResolvedValue({
      advisories,
      fetchedIds: ['GHSA-1234-5678-abcd'],
      errors: ['Some batch failed'],
    });

    const result = await resolveAdvisories(makeGraph());

    expect(result.confidence).toBe('MEDIUM');
    expect(result.source).toContain('partial');
    expect(result.sourceId).toBe('osv-partial');
  });

  it('does NOT use OSV when it returns zero advisories with no errors (C1 fix)', async () => {
    vi.mocked(fetchOsvAdvisories).mockResolvedValue({
      advisories: new Map(),
      fetchedIds: [],
      errors: [],
    });
    vi.mocked(fetchNpmAdvisories).mockResolvedValue({
      advisories: new Map([['lodash', [makeAdvisory('npm-lodash-123')]]]),
      errors: [],
    });

    const result = await resolveAdvisories(makeGraph());

    // Should fall through to npm since OSV had 0 advisories
    expect(result.source).toContain('npm');
    expect(result.sourceId).toBe('npm-bulk');
  });

  it('throws AdvisoryResolutionError when all sources fail', async () => {
    vi.mocked(fetchOsvAdvisories).mockRejectedValue(new Error('network'));
    vi.mocked(fetchNpmAdvisories).mockRejectedValue(new Error('network'));

    await expect(resolveAdvisories(makeGraph())).rejects.toThrow(AdvisoryResolutionError);
  });

  it('assigns sourceId=cache when falling back to local cache', async () => {
    const { getCachedPackageAdvisories } = await import(
      '../../src/core/advisory/cache.js'
    );
    vi.mocked(fetchOsvAdvisories).mockRejectedValue(new Error('offline'));
    vi.mocked(getCachedPackageAdvisories).mockReturnValue([
      makeAdvisory('GHSA-cache-entry'),
    ]);

    const result = await resolveAdvisories(makeGraph());

    expect(result.sourceId).toBe('cache');
    expect(result.source).toBe('Local cache');
    expect(result.confidence).toBe('MEDIUM');
  });

  it('assigns sourceId=offline when falling back to offline index', async () => {
    const { getCachedPackageAdvisories } = await import(
      '../../src/core/advisory/cache.js'
    );
    const { queryOfflineIndexBatch } = await import(
      '../../src/core/advisory/offline-index.js'
    );
    vi.mocked(fetchOsvAdvisories).mockRejectedValue(new Error('offline'));
    vi.mocked(getCachedPackageAdvisories).mockReturnValue(null);
    vi.mocked(queryOfflineIndexBatch).mockResolvedValue(
      new Map([['lodash', [makeAdvisory('GHSA-offline-entry')]]]),
    );

    const result = await resolveAdvisories(makeGraph());

    expect(result.sourceId).toBe('offline');
    expect(result.source).toBe('Bundled offline index');
    expect(result.confidence).toBe('LOW');
  });

  it('source string remains derivable from sourceId for every fallback tier', async () => {
    // Guards against drift between the discriminator and the display label
    const expected: Record<string, string> = {
      osv: 'OSV.dev API (real-time)',
      'osv-partial': 'OSV.dev API (partial)',
      cache: 'Local cache',
      offline: 'Bundled offline index',
      'npm-bulk': 'npm bulk advisory endpoint',
    };

    // osv (HIGH)
    vi.mocked(fetchOsvAdvisories).mockResolvedValueOnce({
      advisories: new Map([['lodash', [makeAdvisory('GHSA-a')]]]),
      fetchedIds: ['GHSA-a'],
      errors: [],
    });
    let r = await resolveAdvisories(makeGraph());
    expect(r.source).toBe(expected[r.sourceId]);

    // osv-partial
    vi.mocked(fetchOsvAdvisories).mockResolvedValueOnce({
      advisories: new Map([['lodash', [makeAdvisory('GHSA-b')]]]),
      fetchedIds: ['GHSA-b'],
      errors: ['partial'],
    });
    r = await resolveAdvisories(makeGraph());
    expect(r.source).toBe(expected[r.sourceId]);

    // npm-bulk
    vi.mocked(fetchOsvAdvisories).mockResolvedValueOnce({
      advisories: new Map(),
      fetchedIds: [],
      errors: [],
    });
    vi.mocked(fetchNpmAdvisories).mockResolvedValueOnce({
      advisories: new Map([['lodash', [makeAdvisory('npm-lodash-9')]]]),
      errors: [],
    });
    r = await resolveAdvisories(makeGraph());
    expect(r.source).toBe(expected[r.sourceId]);
  });
});
