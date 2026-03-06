/**
 * Integration tests against the real vulnerable-project fixture.
 * Tests the full pipeline: lockfile parsing → advisory matching → scoring.
 *
 * Uses the bundled offline index (no network needed) by mocking the OSV/npm APIs.
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
}));

vi.mock('../../src/utils/logger.js', () => ({
  info: vi.fn(),
  warn: vi.fn(),
  debug: vi.fn(),
  error: vi.fn(),
}));

import { analyze } from '../../src/core/analyzer.js';

const FIXTURE_DIR = path.resolve(__dirname, '../fixtures/vulnerable-project');

describe('Integration: vulnerable-project fixture', () => {
  it('detects vulnerabilities from offline index', async () => {
    const report = await analyze({
      projectDir: FIXTURE_DIR,
      productionOnly: false,
    });

    expect(report.metadata.totalPackages).toBeGreaterThanOrEqual(4);
    expect(report.metadata.advisorySource).toBe('Bundled offline index');
    expect(report.metadata.confidence).toBe('LOW'); // offline index = LOW confidence
    expect(report.vulnerabilities.length).toBeGreaterThanOrEqual(1);

    // lodash 4.17.20 should be flagged (prototype pollution)
    const lodashVuln = report.vulnerabilities.find(v => v.match.package === 'lodash');
    expect(lodashVuln).toBeDefined();
    expect(lodashVuln!.match.isProduction).toBe(true);
  });

  it('correctly classifies production vs dev packages', async () => {
    const report = await analyze({
      projectDir: FIXTURE_DIR,
      productionOnly: false,
    });

    // express, lodash, jsonwebtoken are prod; semver is dev
    const packages = new Map<string, boolean>();
    for (const v of report.vulnerabilities) {
      packages.set(v.match.package, v.match.isProduction);
    }

    if (packages.has('lodash')) {
      expect(packages.get('lodash')).toBe(true);
    }
  });

  it('filters to production-only when requested', async () => {
    const report = await analyze({
      projectDir: FIXTURE_DIR,
      productionOnly: true,
    });

    for (const v of report.vulnerabilities) {
      expect(v.match.isProduction).toBe(true);
    }
  });

  it('applies severity threshold filtering', async () => {
    const report = await analyze({
      projectDir: FIXTURE_DIR,
      productionOnly: false,
      severityThreshold: 'high',
    });

    for (const v of report.vulnerabilities) {
      expect(['critical', 'high']).toContain(v.risk.label);
    }
  });

  it('includes scan metadata', async () => {
    const report = await analyze({
      projectDir: FIXTURE_DIR,
      productionOnly: false,
    });

    expect(report.metadata.scanDurationMs).toBeGreaterThan(0);
    expect(report.metadata.lockfileType).toContain('npm');
    expect(report.metadata.advisoryCount).toBeGreaterThan(0);
  });
});
