import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import type { Advisory } from '../../src/types/advisory.js';
import {
  cacheAdvisoryBatch,
  getCachedPackageAdvisories,
} from '../../src/core/advisory/cache.js';

/**
 * Re-derive the package cache file path exactly as cache.ts does.
 * Kept in sync with `buildPackagePath` there.
 */
function packageCachePath(packageName: string, cacheDir: string): string {
  const hash = crypto
    .createHash('sha256')
    .update(packageName)
    .digest('hex')
    .slice(0, 16);
  return path.join(cacheDir, `pkg-${hash}.json`);
}

function makeTempCacheDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'auditfix-cache-batch-test-'));
  const cacheDir = path.join(dir, 'cache');
  fs.mkdirSync(cacheDir, { recursive: true });
  return cacheDir;
}

function cleanupDir(cacheDir: string): void {
  try {
    fs.rmSync(path.dirname(cacheDir), { recursive: true, force: true });
  } catch {
    // best effort
  }
}

function makeAdvisory(id: string): Advisory {
  return {
    id,
    aliases: [],
    summary: `Test advisory ${id}`,
    details: '',
    severity: [],
    affectedRange: '>=1.0.0 <2.0.0',
    fixVersion: '2.0.0',
    publishedAt: '2025-01-01T00:00:00Z',
    modifiedAt: '2025-06-01T00:00:00Z',
    references: [],
    source: 'osv-api',
  };
}

describe('cacheAdvisoryBatch error isolation', () => {
  let cacheDir: string;

  beforeEach(() => {
    cacheDir = makeTempCacheDir();
  });

  afterEach(() => {
    cleanupDir(cacheDir);
  });

  it('continues with remaining entries when one write throws', async () => {
    // Force a single entry to fail by pre-creating a directory at its target
    // path. `atomicWrite` does writeFileSync(tmp) then renameSync(tmp, target);
    // renaming a file over an existing directory fails on both POSIX and
    // Windows, so this produces a real IO error without mocking `fs`.
    const failingPkg = 'will-fail';
    fs.mkdirSync(packageCachePath(failingPkg, cacheDir), { recursive: true });

    const batch = new Map<string, Advisory[]>([
      ['alpha', [makeAdvisory('GHSA-alpha')]],
      [failingPkg, [makeAdvisory('GHSA-fail')]],
      ['beta', [makeAdvisory('GHSA-beta')]],
    ]);

    // Top-level must not throw even though one inner write fails
    await expect(cacheAdvisoryBatch(batch, cacheDir)).resolves.toBeUndefined();

    // Succeeded entries are present
    expect(getCachedPackageAdvisories('alpha', cacheDir)).not.toBeNull();
    expect(getCachedPackageAdvisories('beta', cacheDir)).not.toBeNull();

    // Failed entry was skipped — target path is still the directory we created,
    // so getCachedPackageAdvisories returns null (can't parse a dir as a file).
    expect(getCachedPackageAdvisories(failingPkg, cacheDir)).toBeNull();
  });

  it('continues past multiple failing entries', async () => {
    // Force two entries (b, d) to fail by pre-creating directories at their
    // target paths. a and c should still write cleanly.
    fs.mkdirSync(packageCachePath('b', cacheDir), { recursive: true });
    fs.mkdirSync(packageCachePath('d', cacheDir), { recursive: true });

    const batch = new Map<string, Advisory[]>([
      ['a', [makeAdvisory('GHSA-a')]],
      ['b', [makeAdvisory('GHSA-b')]],
      ['c', [makeAdvisory('GHSA-c')]],
      ['d', [makeAdvisory('GHSA-d')]],
    ]);

    await expect(cacheAdvisoryBatch(batch, cacheDir)).resolves.toBeUndefined();

    // a and c should have written successfully, b and d should not
    expect(getCachedPackageAdvisories('a', cacheDir)).not.toBeNull();
    expect(getCachedPackageAdvisories('b', cacheDir)).toBeNull();
    expect(getCachedPackageAdvisories('c', cacheDir)).not.toBeNull();
    expect(getCachedPackageAdvisories('d', cacheDir)).toBeNull();
  });

  it('writes all entries when no errors occur', async () => {
    const batch = new Map<string, Advisory[]>([
      ['alpha', [makeAdvisory('GHSA-alpha')]],
      ['beta', [makeAdvisory('GHSA-beta')]],
    ]);

    await cacheAdvisoryBatch(batch, cacheDir);

    expect(getCachedPackageAdvisories('alpha', cacheDir)).not.toBeNull();
    expect(getCachedPackageAdvisories('beta', cacheDir)).not.toBeNull();
  });

  it('does not throw on an empty batch', async () => {
    await expect(
      cacheAdvisoryBatch(new Map(), cacheDir),
    ).resolves.toBeUndefined();
  });

  it('skips entries with empty advisory arrays (no negative caching)', async () => {
    const batch = new Map<string, Advisory[]>([
      ['empty-pkg', []],
      ['real-pkg', [makeAdvisory('GHSA-real')]],
    ]);

    await cacheAdvisoryBatch(batch, cacheDir);

    expect(getCachedPackageAdvisories('empty-pkg', cacheDir)).toBeNull();
    expect(getCachedPackageAdvisories('real-pkg', cacheDir)).not.toBeNull();
  });
});
