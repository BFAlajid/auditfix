/**
 * Shared constants for auditfix.
 * Centralizes magic numbers and configuration values.
 */

/** Batch sizes for concurrent API requests */
export const BATCH_SIZES = {
  EPSS: 50,
  OSV: 1000,
  OSV_CONCURRENT: 10,
  DEP_AGE: 10,
  PROVENANCE: 10,
} as const;

/** Timeouts for external API calls (ms) */
export const API_TIMEOUTS = {
  EPSS: 10_000,
  KEV: 15_000,
  OSV: 30_000,
  NPM: 15_000,
  WEBHOOK: 10_000,
  INSTALL: 120_000,
  SARIF_UPLOAD: 30_000,
} as const;

/** Scanner limits */
export const SCANNER_LIMITS = {
  MAX_FILE_SIZE: 500_000,
  MAX_FILES_PER_PACKAGE: 50,
  MAX_SCAN_DEPTH: 15,
  MAX_SCAN_FILES: 10_000,
  STALE_DEP_MONTHS: 24,
  TYPOSQUAT_MAX_DISTANCE: 2,
  MINIFIED_LINE_THRESHOLD: 5000,
} as const;

/** Cache settings */
export const CACHE_SETTINGS = {
  KEV_TTL: 4 * 60 * 60 * 1000,  // 4 hours
  FRESH_TTL: 60 * 60 * 1000,     // 1 hour
  STALE_TTL: 4 * 60 * 60 * 1000, // 4 hours
} as const;

/** Lockfile names in detection priority order */
export const LOCKFILE_NAMES = [
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
] as const;

/** Directories to skip during source scanning */
export const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'coverage',
  '.next', '.nuxt', '.cache', 'out', 'tmp',
]);

/** OSV API limits */
export const OSV_LIMITS = {
  MAX_RESPONSE_SIZE: 50 * 1024 * 1024, // 50MB
  MAX_INDIVIDUAL_SIZE: 1 * 1024 * 1024, // 1MB
} as const;
