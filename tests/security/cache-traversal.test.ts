import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import * as fs from 'node:fs';
import * as path from 'node:path';
import * as os from 'node:os';
import * as crypto from 'node:crypto';
import type { Advisory } from '../../src/types/advisory.js';
import {
  cacheAdvisory,
  getCachedAdvisory,
  cacheAdvisoryBatch,
  getCachedPackageAdvisories,
  getCacheStats,
} from '../../src/core/advisory/cache.js';

// --- Test helpers ---

function makeTempCacheDir(): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'auditfix-cache-test-'));
  const cacheDir = path.join(dir, 'cache');
  fs.mkdirSync(cacheDir, { recursive: true });
  return cacheDir;
}

function cleanupDir(dir: string): void {
  try {
    fs.rmSync(path.dirname(dir), { recursive: true, force: true });
  } catch {
    // best effort
  }
}

function makeAdvisory(id: string): Advisory {
  return {
    id,
    aliases: [],
    summary: `Test advisory ${id}`,
    details: 'Test details',
    severity: [{ type: 'CVSS_V3', score: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H' }],
    affectedRange: '>=1.0.0 <2.0.0',
    fixVersion: '2.0.0',
    publishedAt: '2025-01-01T00:00:00Z',
    modifiedAt: '2025-06-01T00:00:00Z',
    references: [{ type: 'ADVISORY', url: 'https://example.com' }],
    source: 'osv-api',
  };
}

// --- Tests ---

describe('Advisory cache — round trip', () => {
  let cacheDir: string;

  beforeEach(() => {
    cacheDir = makeTempCacheDir();
  });

  afterEach(() => {
    cleanupDir(cacheDir);
  });

  it('writes a cached advisory and reads it back with matching data', async () => {
    const id = 'GHSA-abcd-efgh-ijkl';
    const advisory = makeAdvisory(id);

    await cacheAdvisory(id, advisory, cacheDir);
    const result = getCachedAdvisory(id, cacheDir);

    expect(result).not.toBeNull();
    expect(result!.id).toBe(id);
    expect(result!.summary).toBe(advisory.summary);
    expect(result!.affectedRange).toBe(advisory.affectedRange);
    expect(result!.fixVersion).toBe(advisory.fixVersion);
    expect(result!.source).toBe(advisory.source);
  });

  it('reads back CVE-format IDs correctly', async () => {
    const id = 'CVE-2024-12345';
    const advisory = makeAdvisory(id);

    await cacheAdvisory(id, advisory, cacheDir);
    const result = getCachedAdvisory(id, cacheDir);

    expect(result).not.toBeNull();
    expect(result!.id).toBe(id);
  });
});

describe('Advisory cache — TTL expiration', () => {
  let cacheDir: string;

  beforeEach(() => {
    cacheDir = makeTempCacheDir();
  });

  afterEach(() => {
    cleanupDir(cacheDir);
  });

  it('returns null for expired cache entries (TTL exceeded)', async () => {
    const id = 'GHSA-aaaa-bbbb-cccc';
    const advisory = makeAdvisory(id);

    await cacheAdvisory(id, advisory, cacheDir);

    // Manually tamper with the timestamp to simulate expiration
    // Find the cache file and rewrite it with old timestamp and correct HMAC
    const filePath = path.join(cacheDir, `advisory-${id}.json`);
    const keyPath = path.join(path.dirname(cacheDir), 'cache-key');
    const hmacKey = fs.readFileSync(keyPath);

    const oldTimestamp = Date.now() - (5 * 60 * 60 * 1000); // 5 hours ago
    const payload = JSON.stringify(advisory) + '|' + String(oldTimestamp);
    const hmac = crypto.createHmac('sha256', hmacKey).update(payload).digest('hex');

    const entry = { data: advisory, timestamp: oldTimestamp, hmac };
    fs.writeFileSync(filePath, JSON.stringify(entry));

    const result = getCachedAdvisory(id, cacheDir);
    expect(result).toBeNull();
  });
});

describe('Advisory cache — HMAC integrity', () => {
  let cacheDir: string;

  beforeEach(() => {
    cacheDir = makeTempCacheDir();
  });

  afterEach(() => {
    cleanupDir(cacheDir);
  });

  it('returns null when cache file HMAC is tampered with', async () => {
    const id = 'GHSA-xxxx-yyyy-zzzz';
    const advisory = makeAdvisory(id);

    await cacheAdvisory(id, advisory, cacheDir);

    // Tamper with the HMAC in the cache file
    const filePath = path.join(cacheDir, `advisory-${id}.json`);
    const raw = fs.readFileSync(filePath, 'utf-8');
    const entry = JSON.parse(raw);
    entry.hmac = 'deadbeef'.repeat(8); // 64 hex chars for sha256
    fs.writeFileSync(filePath, JSON.stringify(entry));

    const result = getCachedAdvisory(id, cacheDir);
    expect(result).toBeNull();
  });

  it('returns null when cache data is modified but HMAC is not updated', async () => {
    const id = 'GHSA-mmmm-nnnn-oooo';
    const advisory = makeAdvisory(id);

    await cacheAdvisory(id, advisory, cacheDir);

    // Modify the data but keep the old HMAC
    const filePath = path.join(cacheDir, `advisory-${id}.json`);
    const raw = fs.readFileSync(filePath, 'utf-8');
    const entry = JSON.parse(raw);
    entry.data.summary = 'INJECTED MALICIOUS DATA';
    fs.writeFileSync(filePath, JSON.stringify(entry));

    const result = getCachedAdvisory(id, cacheDir);
    expect(result).toBeNull();
  });
});

describe('Advisory cache — path traversal rejection', () => {
  let cacheDir: string;

  beforeEach(() => {
    cacheDir = makeTempCacheDir();
  });

  afterEach(() => {
    cleanupDir(cacheDir);
  });

  it('rejects advisory ID containing ../ (path traversal)', async () => {
    const maliciousId = '../../../etc/passwd';
    const advisory = makeAdvisory('GHSA-aaaa-bbbb-cccc');

    await cacheAdvisory(maliciousId, advisory, cacheDir);
    const result = getCachedAdvisory(maliciousId, cacheDir);

    expect(result).toBeNull();

    // Verify nothing was written outside the cache dir
    const parentFiles = fs.readdirSync(path.dirname(cacheDir));
    const leakedFiles = parentFiles.filter(f => f.includes('passwd'));
    expect(leakedFiles).toHaveLength(0);
  });

  it('rejects advisory ID containing .. without slash', async () => {
    const maliciousId = 'GHSA-..test-abcd-efgh';
    const advisory = makeAdvisory('GHSA-aaaa-bbbb-cccc');

    await cacheAdvisory(maliciousId, advisory, cacheDir);
    const result = getCachedAdvisory(maliciousId, cacheDir);
    expect(result).toBeNull();
  });
});

describe('Advisory cache — null byte rejection', () => {
  let cacheDir: string;

  beforeEach(() => {
    cacheDir = makeTempCacheDir();
  });

  afterEach(() => {
    cleanupDir(cacheDir);
  });

  it('rejects advisory ID containing null byte', async () => {
    const maliciousId = 'GHSA-abcd-efgh-ijkl\0.evil';
    const advisory = makeAdvisory('GHSA-aaaa-bbbb-cccc');

    await cacheAdvisory(maliciousId, advisory, cacheDir);
    const result = getCachedAdvisory(maliciousId, cacheDir);
    expect(result).toBeNull();
  });

  it('rejects advisory ID with embedded null byte', async () => {
    const maliciousId = 'GHSA-abcd\0efgh-ijkl';
    const advisory = makeAdvisory('GHSA-aaaa-bbbb-cccc');

    await cacheAdvisory(maliciousId, advisory, cacheDir);
    const result = getCachedAdvisory(maliciousId, cacheDir);
    expect(result).toBeNull();
  });
});

describe('Advisory cache — backslash rejection', () => {
  let cacheDir: string;

  beforeEach(() => {
    cacheDir = makeTempCacheDir();
  });

  afterEach(() => {
    cleanupDir(cacheDir);
  });

  it('rejects advisory ID containing backslash', async () => {
    const maliciousId = 'GHSA-abcd\\efgh-ijkl';
    const advisory = makeAdvisory('GHSA-aaaa-bbbb-cccc');

    await cacheAdvisory(maliciousId, advisory, cacheDir);
    const result = getCachedAdvisory(maliciousId, cacheDir);
    expect(result).toBeNull();
  });

  it('rejects advisory ID with backslash path traversal', async () => {
    const maliciousId = '..\\..\\etc\\passwd';
    const advisory = makeAdvisory('GHSA-aaaa-bbbb-cccc');

    await cacheAdvisory(maliciousId, advisory, cacheDir);
    const result = getCachedAdvisory(maliciousId, cacheDir);
    expect(result).toBeNull();
  });
});

describe('Advisory cache — Windows reserved names', () => {
  let cacheDir: string;

  beforeEach(() => {
    cacheDir = makeTempCacheDir();
  });

  afterEach(() => {
    cleanupDir(cacheDir);
  });

  it('rejects CON as advisory ID', async () => {
    const advisory = makeAdvisory('GHSA-aaaa-bbbb-cccc');

    await cacheAdvisory('CON', advisory, cacheDir);
    const result = getCachedAdvisory('CON', cacheDir);
    expect(result).toBeNull();
  });

  it('rejects NUL as advisory ID', async () => {
    const advisory = makeAdvisory('GHSA-aaaa-bbbb-cccc');

    await cacheAdvisory('NUL', advisory, cacheDir);
    const result = getCachedAdvisory('NUL', cacheDir);
    expect(result).toBeNull();
  });

  it('rejects PRN as advisory ID', async () => {
    const advisory = makeAdvisory('GHSA-aaaa-bbbb-cccc');

    await cacheAdvisory('PRN', advisory, cacheDir);
    const result = getCachedAdvisory('PRN', cacheDir);
    expect(result).toBeNull();
  });

  it('rejects COM1 as advisory ID (case insensitive)', async () => {
    const advisory = makeAdvisory('GHSA-aaaa-bbbb-cccc');

    await cacheAdvisory('com1', advisory, cacheDir);
    const result = getCachedAdvisory('com1', cacheDir);
    expect(result).toBeNull();
  });

  it('rejects LPT1 as advisory ID', async () => {
    const advisory = makeAdvisory('GHSA-aaaa-bbbb-cccc');

    await cacheAdvisory('LPT1', advisory, cacheDir);
    const result = getCachedAdvisory('LPT1', cacheDir);
    expect(result).toBeNull();
  });
});

describe('Advisory cache — negative result rejection', () => {
  let cacheDir: string;

  beforeEach(() => {
    cacheDir = makeTempCacheDir();
  });

  afterEach(() => {
    cleanupDir(cacheDir);
  });

  it('does not cache empty advisory arrays (negative results)', async () => {
    const advisories = new Map<string, Advisory[]>();
    advisories.set('lodash', []);

    await cacheAdvisoryBatch(advisories, cacheDir);

    const result = getCachedPackageAdvisories('lodash', cacheDir);
    expect(result).toBeNull();

    // Verify nothing was written
    const stats = getCacheStats(cacheDir);
    expect(stats.entries).toBe(0);
  });

  it('caches non-empty advisory arrays', async () => {
    const advisory = makeAdvisory('GHSA-abcd-efgh-ijkl');
    const advisories = new Map<string, Advisory[]>();
    advisories.set('lodash', [advisory]);

    await cacheAdvisoryBatch(advisories, cacheDir);

    const result = getCachedPackageAdvisories('lodash', cacheDir);
    expect(result).not.toBeNull();
    expect(result).toHaveLength(1);
    expect(result![0].id).toBe('GHSA-abcd-efgh-ijkl');
  });

  it('skips empty arrays while caching non-empty ones in a batch', async () => {
    const advisory = makeAdvisory('CVE-2024-99999');
    const advisories = new Map<string, Advisory[]>();
    advisories.set('safe-pkg', []);
    advisories.set('vuln-pkg', [advisory]);

    await cacheAdvisoryBatch(advisories, cacheDir);

    expect(getCachedPackageAdvisories('safe-pkg', cacheDir)).toBeNull();
    const result = getCachedPackageAdvisories('vuln-pkg', cacheDir);
    expect(result).not.toBeNull();
    expect(result).toHaveLength(1);
  });
});

describe('Advisory cache — symlink rejection', () => {
  let cacheDir: string;

  beforeEach(() => {
    cacheDir = makeTempCacheDir();
  });

  afterEach(() => {
    cleanupDir(cacheDir);
  });

  // Symlink creation on Windows requires admin privileges.
  // This test creates a symlink if possible, otherwise skips.
  it('rejects writing to a symlink target', async () => {
    const id = 'GHSA-abcd-efgh-ijkl';
    const advisory = makeAdvisory(id);

    // Create a file that the symlink will point to
    const realFile = path.join(path.dirname(cacheDir), 'real-target.json');
    fs.writeFileSync(realFile, '{}');

    const symlinkPath = path.join(cacheDir, `advisory-${id}.json`);

    try {
      fs.symlinkSync(realFile, symlinkPath);
    } catch {
      // On Windows without admin, symlink creation fails — skip the test
      return;
    }

    // Attempt to cache — should refuse to write because target is a symlink
    await expect(cacheAdvisory(id, advisory, cacheDir)).rejects.toThrow('symlink');

    // The symlink target should not have been overwritten with advisory data
    const targetContent = fs.readFileSync(realFile, 'utf-8');
    expect(targetContent).toBe('{}');
  });
});

describe('Advisory cache — getCacheStats', () => {
  let cacheDir: string;

  beforeEach(() => {
    cacheDir = makeTempCacheDir();
  });

  afterEach(() => {
    cleanupDir(cacheDir);
  });

  it('returns zero stats for empty cache', () => {
    const stats = getCacheStats(cacheDir);
    expect(stats.entries).toBe(0);
    expect(stats.totalSize).toBe(0);
    expect(stats.oldestEntry).toBeNull();
  });

  it('returns correct stats after caching entries', async () => {
    await cacheAdvisory('GHSA-aaaa-bbbb-cccc', makeAdvisory('GHSA-aaaa-bbbb-cccc'), cacheDir);
    await cacheAdvisory('CVE-2024-12345', makeAdvisory('CVE-2024-12345'), cacheDir);

    const stats = getCacheStats(cacheDir);
    expect(stats.entries).toBe(2);
    expect(stats.totalSize).toBeGreaterThan(0);
    expect(stats.oldestEntry).toBeInstanceOf(Date);
  });
});
