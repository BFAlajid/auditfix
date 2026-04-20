/**
 * Semver helpers wrapping node-semver.
 * CRITICAL: Always pass { includePrerelease: true } for advisory matching.
 * Without it, pre-release versions silently evade vulnerability detection.
 */
import semver from 'semver';

const MAX_VERSION_LENGTH = 256;

const PRERELEASE_OPTS = { includePrerelease: true } as const;

/** Check if a version is valid and within length limits */
export function isValidVersion(version: string): boolean {
  if (version.length > MAX_VERSION_LENGTH) return false;
  return semver.valid(version) !== null;
}

/** Check if a version satisfies a range — always with includePrerelease */
export function satisfies(version: string, range: string): boolean {
  if (!isValidVersion(version)) return false;
  try {
    return semver.satisfies(version, range, PRERELEASE_OPTS);
  } catch {
    return false;
  }
}

/**
 * Pre-compile a semver range string into a reusable `semver.Range` instance.
 * Use this when the same range is tested against many versions in a hot loop:
 * calling `satisfies` re-parses the range string on every invocation, while
 * a compiled Range amortizes that cost. Returns null on an invalid range.
 */
export function compileRange(range: string): semver.Range | null {
  try {
    return new semver.Range(range, PRERELEASE_OPTS);
  } catch {
    return null;
  }
}

/** Test a version against a pre-compiled range. Honors includePrerelease. */
export function testRange(version: string, range: semver.Range): boolean {
  if (!isValidVersion(version)) return false;
  try {
    return range.test(version);
  } catch {
    return false;
  }
}

/** Clean a version string — returns null if invalid */
export function cleanVersion(version: string): string | null {
  if (version.length > MAX_VERSION_LENGTH) return null;
  return semver.clean(version);
}

/** Compare two versions */
export function compareVersions(a: string, b: string): -1 | 0 | 1 {
  return semver.compare(a, b);
}

/** Find the max version satisfying a range */
export function maxSatisfying(versions: string[], range: string): string | null {
  return semver.maxSatisfying(versions, range, PRERELEASE_OPTS);
}

/** Check if a fix version is within a parent's declared range (safe update check) */
export function isSafeUpdate(fixVersion: string, parentRange: string): boolean {
  return semver.satisfies(fixVersion, parentRange, PRERELEASE_OPTS);
}
