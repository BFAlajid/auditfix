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
