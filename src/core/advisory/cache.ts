/**
 * Local advisory cache with security hardening.
 *
 * Security features:
 * - HMAC integrity verification (sha256) per cache file
 * - Path traversal prevention (resolve + startsWith check)
 * - Symlink rejection (lstatSync before write)
 * - Null byte, backslash, ".." segment rejection in IDs
 * - Windows reserved name rejection
 * - Atomic writes (temp file + renameSync)
 * - Directory permissions 0o700, file permissions 0o600
 * - TTL expiration (4 hours)
 * - Never caches negative results
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import * as os from 'node:os';
import type { Advisory } from '../../types/advisory.js';
import { isValidAdvisoryId, safeJsonParse } from '../../utils/sanitize.js';

const CACHE_TTL_MS = 4 * 60 * 60 * 1000; // 4 hours
const CACHE_FRESH_MS = 1 * 60 * 60 * 1000; // 1 hour — serve without refresh
const CACHE_STALE_MS = 4 * 60 * 60 * 1000; // 4 hours — serve but trigger background refresh
const CACHE_EXPIRED_MS = 24 * 60 * 60 * 1000; // 24 hours — fallback only

export type CacheFreshness = 'fresh' | 'stale' | 'expired' | 'missing';
const HMAC_ALGORITHM = 'sha256';
const WINDOWS_RESERVED_RE = /^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$/i;

// --- Path and ID validation ---

/**
 * Reject advisory IDs containing dangerous characters or patterns.
 * This runs BEFORE isValidAdvisoryId regex check as an additional layer.
 */
function containsDangerousChars(id: string): boolean {
  if (id.includes('\0')) return true;
  if (id.includes('\\')) return true;
  if (id.includes('..')) return true;
  if (id.includes('/')) return true;
  return false;
}

/**
 * Reject Windows reserved device names (CON, NUL, PRN, AUX, COM1-9, LPT1-9).
 * These are checked case-insensitively.
 */
function isWindowsReservedName(name: string): boolean {
  // Strip extension if present — "CON.json" is also reserved on Windows
  const baseName = name.replace(/\.[^.]*$/, '');
  return WINDOWS_RESERVED_RE.test(baseName);
}

/**
 * Validate that the resolved file path stays within the cache directory.
 * Prevents path traversal attacks.
 */
function isPathWithinCache(filePath: string, cacheDir: string): boolean {
  const resolvedPath = path.resolve(filePath);
  const resolvedCacheDir = path.resolve(cacheDir);
  return resolvedPath.startsWith(resolvedCacheDir + path.sep);
}

/**
 * Check if a path is a symlink. Returns true if symlink detected.
 */
function isSymlink(filePath: string): boolean {
  try {
    const stats = fs.lstatSync(filePath);
    return stats.isSymbolicLink();
  } catch {
    // File does not exist — not a symlink
    return false;
  }
}

/**
 * Validate an advisory ID for use as a cache key / filename component.
 * Returns false if the ID is invalid or contains dangerous characters.
 */
function validateCacheId(id: string): boolean {
  if (typeof id !== 'string' || id.length === 0) return false;
  if (containsDangerousChars(id)) return false;
  if (isWindowsReservedName(id)) return false;
  if (!isValidAdvisoryId(id)) return false;
  return true;
}

/**
 * Validate a package name for use as a cache key.
 * Package names are hashed, but we still reject dangerous input.
 */
function validatePackageName(name: string): boolean {
  if (typeof name !== 'string' || name.length === 0) return false;
  if (name.includes('\0')) return false;
  return true;
}

// --- Cache directory and HMAC key management ---

function getDefaultCacheDir(): string {
  return path.join(os.homedir(), '.auditfix', 'cache');
}

function getCacheKeyPath(cacheDir: string): string {
  // Store the HMAC key file one level up from the cache directory
  return path.join(path.dirname(cacheDir), 'cache-key');
}

/**
 * Ensure the cache directory exists with secure permissions.
 */
function ensureCacheDir(cacheDir: string): void {
  fs.mkdirSync(cacheDir, { recursive: true, mode: 0o700 });
  // Ensure parent dir for cache-key also exists
  const parentDir = path.dirname(cacheDir);
  fs.mkdirSync(parentDir, { recursive: true, mode: 0o700 });
}

/**
 * Get or create the per-installation HMAC key.
 * Stored at ~/.auditfix/cache-key with mode 0600.
 */
function getHmacKey(cacheDir: string): Buffer {
  const keyPath = getCacheKeyPath(cacheDir);
  try {
    return fs.readFileSync(keyPath);
  } catch {
    // Generate a new random key
    const key = crypto.randomBytes(32);
    ensureCacheDir(cacheDir);
    fs.writeFileSync(keyPath, key, { mode: 0o600 });
    return key;
  }
}

/**
 * Compute HMAC for cache data.
 */
function computeHmac(data: string, key: Buffer): string {
  return crypto.createHmac(HMAC_ALGORITHM, key).update(data).digest('hex');
}

// --- Cache entry format ---

interface CacheEntry {
  data: Advisory | Advisory[];
  timestamp: number;
  hmac: string;
}

/**
 * Build the full file path for an advisory cache entry.
 * Returns null if the path would escape the cache directory.
 */
function buildAdvisoryPath(id: string, cacheDir: string): string | null {
  const filePath = path.join(cacheDir, `advisory-${id}.json`);
  if (!isPathWithinCache(filePath, cacheDir)) return null;
  return filePath;
}

/**
 * Build the full file path for a package advisory batch cache entry.
 * Package names are hashed to avoid filesystem issues with scoped names.
 */
function buildPackagePath(packageName: string, cacheDir: string): string | null {
  const hash = crypto.createHash('sha256').update(packageName).digest('hex').slice(0, 16);
  const filePath = path.join(cacheDir, `pkg-${hash}.json`);
  if (!isPathWithinCache(filePath, cacheDir)) return null;
  return filePath;
}

// --- Atomic write ---

/**
 * Write data atomically: write to temp file, then rename.
 * Rejects symlink targets. Sets file permissions to 0600.
 */
function atomicWrite(filePath: string, content: string): void {
  // Check that the target is not a symlink
  if (isSymlink(filePath)) {
    throw new Error(`Refusing to write to symlink: ${filePath}`);
  }

  const tempPath = filePath + `.tmp.${crypto.randomBytes(4).toString('hex')}`;

  // Check temp path is not a symlink either
  if (isSymlink(tempPath)) {
    throw new Error(`Refusing to write to symlink: ${tempPath}`);
  }

  fs.writeFileSync(tempPath, content, { mode: 0o600 });
  fs.renameSync(tempPath, filePath);
}

// --- Read with HMAC verification ---

/**
 * Read and verify a cache entry. Returns null if missing, expired, or tampered.
 */
function readVerifiedEntry(filePath: string, hmacKey: Buffer): CacheEntry | null {
  try {
    if (isSymlink(filePath)) return null;

    const raw = fs.readFileSync(filePath, 'utf-8');
    const entry = safeJsonParse<CacheEntry>(raw);

    // Verify required fields exist
    if (
      typeof entry.timestamp !== 'number' ||
      typeof entry.hmac !== 'string' ||
      entry.data === undefined ||
      entry.data === null
    ) {
      return null;
    }

    // Verify HMAC — compute over serialized data + timestamp
    const payload = JSON.stringify(entry.data) + '|' + String(entry.timestamp);
    const expectedHmac = computeHmac(payload, hmacKey);
    if (!crypto.timingSafeEqual(Buffer.from(entry.hmac, 'hex'), Buffer.from(expectedHmac, 'hex'))) {
      return null;
    }

    // Check TTL
    if (Date.now() - entry.timestamp > CACHE_TTL_MS) {
      return null;
    }

    return entry;
  } catch {
    return null;
  }
}

// --- Public API ---

/**
 * Cache advisory data by ID.
 * Only caches actual Advisory objects — never negative results.
 */
export async function cacheAdvisory(
  id: string,
  data: Advisory,
  cacheDir: string = getDefaultCacheDir(),
): Promise<void> {
  if (!validateCacheId(id)) return;
  if (!data || typeof data !== 'object') return;

  ensureCacheDir(cacheDir);
  const filePath = buildAdvisoryPath(id, cacheDir);
  if (!filePath) return;

  const hmacKey = getHmacKey(cacheDir);
  const timestamp = Date.now();
  const payload = JSON.stringify(data) + '|' + String(timestamp);
  const hmac = computeHmac(payload, hmacKey);

  const entry: CacheEntry = { data, timestamp, hmac };
  atomicWrite(filePath, JSON.stringify(entry));
}

/**
 * Get cached advisory by ID.
 * Returns null if expired, missing, or tampered.
 */
export function getCachedAdvisory(
  id: string,
  cacheDir: string = getDefaultCacheDir(),
): Advisory | null {
  if (!validateCacheId(id)) return null;

  const filePath = buildAdvisoryPath(id, cacheDir);
  if (!filePath) return null;

  const hmacKey = getHmacKey(cacheDir);
  const entry = readVerifiedEntry(filePath, hmacKey);
  if (!entry) return null;

  return entry.data as Advisory;
}

/**
 * Cache a batch of advisories keyed by package name.
 * Skips packages with empty advisory arrays (never cache negative results).
 */
export async function cacheAdvisoryBatch(
  advisories: Map<string, Advisory[]>,
  cacheDir: string = getDefaultCacheDir(),
): Promise<void> {
  ensureCacheDir(cacheDir);
  const hmacKey = getHmacKey(cacheDir);

  for (const [packageName, advisoryList] of advisories) {
    if (!validatePackageName(packageName)) continue;

    // NEVER cache negative results — skip empty arrays
    if (!Array.isArray(advisoryList) || advisoryList.length === 0) continue;

    const filePath = buildPackagePath(packageName, cacheDir);
    if (!filePath) continue;

    const timestamp = Date.now();
    const payload = JSON.stringify(advisoryList) + '|' + String(timestamp);
    const hmac = computeHmac(payload, hmacKey);

    const entry: CacheEntry = { data: advisoryList, timestamp, hmac };
    atomicWrite(filePath, JSON.stringify(entry));
  }
}

/**
 * Get cached advisories for a package name.
 * Returns null if expired, missing, or tampered.
 */
export function getCachedPackageAdvisories(
  packageName: string,
  cacheDir: string = getDefaultCacheDir(),
): Advisory[] | null {
  if (!validatePackageName(packageName)) return null;

  const filePath = buildPackagePath(packageName, cacheDir);
  if (!filePath) return null;

  const hmacKey = getHmacKey(cacheDir);
  const entry = readVerifiedEntry(filePath, hmacKey);
  if (!entry) return null;

  return entry.data as Advisory[];
}

/**
 * Get cache statistics: entry count, total size, oldest entry timestamp.
 */
export function getCacheStats(
  cacheDir: string = getDefaultCacheDir(),
): { entries: number; totalSize: number; oldestEntry: Date | null } {
  try {
    const files = fs.readdirSync(cacheDir);
    let entries = 0;
    let totalSize = 0;
    let oldestTimestamp = Infinity;

    for (const file of files) {
      if (!file.endsWith('.json')) continue;

      const filePath = path.join(cacheDir, file);
      if (!isPathWithinCache(filePath, cacheDir)) continue;
      if (isSymlink(filePath)) continue;

      try {
        const stat = fs.statSync(filePath);
        entries++;
        totalSize += stat.size;
        if (stat.mtimeMs < oldestTimestamp) {
          oldestTimestamp = stat.mtimeMs;
        }
      } catch {
        // Skip files we can't stat
      }
    }

    return {
      entries,
      totalSize,
      oldestEntry: entries > 0 ? new Date(oldestTimestamp) : null,
    };
  } catch {
    return { entries: 0, totalSize: 0, oldestEntry: null };
  }
}

// --- Cache-first resolution helpers ---

/**
 * Read a verified cache entry with extended tolerance for stale-while-revalidate.
 * Returns the entry even if it's past TTL but within CACHE_EXPIRED_MS (24h).
 * The caller determines freshness via getCacheFreshness().
 */
function readVerifiedEntryWithStaleTolerance(filePath: string, hmacKey: Buffer): CacheEntry | null {
  try {
    if (isSymlink(filePath)) return null;
    const raw = fs.readFileSync(filePath, 'utf-8');
    const entry = safeJsonParse<CacheEntry>(raw);
    if (
      typeof entry.timestamp !== 'number' ||
      typeof entry.hmac !== 'string' ||
      entry.data === undefined ||
      entry.data === null
    ) {
      return null;
    }
    const payload = JSON.stringify(entry.data) + '|' + String(entry.timestamp);
    const expectedHmac = computeHmac(payload, hmacKey);
    if (!crypto.timingSafeEqual(Buffer.from(entry.hmac, 'hex'), Buffer.from(expectedHmac, 'hex'))) {
      return null;
    }
    // Accept up to 24h (expired) — caller checks freshness
    if (Date.now() - entry.timestamp > CACHE_EXPIRED_MS) {
      return null;
    }
    return entry;
  } catch {
    return null;
  }
}

/**
 * Determine cache freshness tier.
 */
export function getCacheFreshness(timestamp: number): CacheFreshness {
  const age = Date.now() - timestamp;
  if (age < CACHE_FRESH_MS) return 'fresh';
  if (age < CACHE_STALE_MS) return 'stale';
  if (age < CACHE_EXPIRED_MS) return 'expired';
  return 'missing';
}

/**
 * Attempt to read cached advisories for a set of package names.
 * Returns a Map of results and the overall freshness tier.
 * If ANY package is missing from cache, returns null.
 */
export function readCachedAdvisoriesForPackages(
  packageNames: string[],
  cacheDir: string = getDefaultCacheDir(),
): { advisories: Map<string, Advisory[]>; freshness: CacheFreshness } | null {
  const hmacKey = getHmacKey(cacheDir);
  const results = new Map<string, Advisory[]>();
  let worstFreshness: CacheFreshness = 'fresh';
  const freshnessOrder: CacheFreshness[] = ['fresh', 'stale', 'expired', 'missing'];

  for (const name of packageNames) {
    if (!validatePackageName(name)) return null;
    const filePath = buildPackagePath(name, cacheDir);
    if (!filePath) return null;

    const entry = readVerifiedEntryWithStaleTolerance(filePath, hmacKey);
    if (!entry) return null; // Missing or invalid

    const freshness = getCacheFreshness(entry.timestamp);
    if (freshnessOrder.indexOf(freshness) > freshnessOrder.indexOf(worstFreshness)) {
      worstFreshness = freshness;
    }

    results.set(name, entry.data as Advisory[]);
  }

  return { advisories: results, freshness: worstFreshness };
}
