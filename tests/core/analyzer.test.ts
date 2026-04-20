/**
 * Analyzer tests covering the merged annotation pass (workspaces +
 * isDirectlyImported). Uses the existing vulnerable-project fixture so we
 * exercise the real pipeline end-to-end.
 */
import { describe, it, expect, vi } from 'vitest';
import * as path from 'node:path';

// Mock network sources so tests work offline
vi.mock('../../src/core/advisory/source-osv.js', () => ({
  fetchOsvAdvisories: vi.fn().mockRejectedValue(new Error('offline')),
}));

vi.mock('../../src/core/advisory/source-npm.js', () => ({
  fetchNpmAdvisories: vi.fn().mockRejectedValue(new Error('offline')),
}));

vi.mock('../../src/core/advisory/cache.js', () => ({
  cacheAdvisoryBatch: vi.fn().mockResolvedValue(undefined),
  getCachedPackageAdvisories: vi.fn().mockReturnValue(null),
  readCachedAdvisoriesForPackages: vi.fn().mockReturnValue(null),
}));

vi.mock('../../src/utils/logger.js', () => ({
  info: vi.fn(),
  warn: vi.fn(),
  debug: vi.fn(),
  error: vi.fn(),
}));

import { analyze } from '../../src/core/analyzer.js';

const FIXTURE_DIR = path.resolve(__dirname, '../fixtures/vulnerable-project');

describe('analyzer — merged annotation pass', () => {
  it('annotates every match with isDirectlyImported (property present on all matches)', async () => {
    const report = await analyze({
      projectDir: FIXTURE_DIR,
      productionOnly: false,
    });

    expect(report.vulnerabilities.length).toBeGreaterThan(0);
    for (const v of report.vulnerabilities) {
      // Merged loop must still set the property for every match; prior
      // implementation ran a separate pass to populate this.
      expect(typeof v.match.isDirectlyImported).toBe('boolean');
    }
  });

  it('still produces a deterministic report shape', async () => {
    const report = await analyze({
      projectDir: FIXTURE_DIR,
      productionOnly: false,
    });

    expect(report).toHaveProperty('vulnerabilities');
    expect(report).toHaveProperty('metadata');
    expect(report).toHaveProperty('ignored');
    expect(report.metadata).toMatchObject({
      totalPackages: expect.any(Number),
      advisorySource: expect.any(String),
      advisoryCount: expect.any(Number),
      confidence: expect.any(String),
    });
  });

  it('running the analyzer twice yields identical vulnerabilities (determinism)', async () => {
    const a = await analyze({ projectDir: FIXTURE_DIR, productionOnly: false });
    const b = await analyze({ projectDir: FIXTURE_DIR, productionOnly: false });

    const project = (r: typeof a) => r.vulnerabilities.map(v => ({
      id: v.match.advisory.id,
      pkg: v.match.package,
      version: v.match.installedVersion,
      prod: v.match.isProduction,
      directlyImported: v.match.isDirectlyImported,
    })).sort((x, y) => (x.id + x.pkg).localeCompare(y.id + y.pkg));

    expect(project(a)).toEqual(project(b));
  });
});
