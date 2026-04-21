/**
 * Convert OSV events[] arrays to node-semver range strings.
 * ~20 lines, no library needed.
 *
 * OSV spec: events processed in order.
 * - "introduced" opens a range
 * - "fixed" / "last_affected" closes it
 * - "introduced":"0" is a sentinel meaning all versions from the beginning
 * - Unpaired "introduced" = no fix exists (open-ended range)
 */
import type { OsvEvent, OsvRange, OsvAffected } from '../../types/advisory.js';

export function eventsToSemverRange(events: OsvEvent[]): string {
  const ranges: string[] = [];
  let currentIntroduced: string | null = null;

  for (const event of events) {
    if (event.introduced !== undefined) {
      currentIntroduced = event.introduced === '0' ? '0.0.0' : event.introduced;
    }
    if (event.fixed !== undefined && currentIntroduced) {
      ranges.push(`>=${currentIntroduced} <${event.fixed}`);
      currentIntroduced = null;
    }
    if (event.last_affected !== undefined && currentIntroduced) {
      ranges.push(`>=${currentIntroduced} <=${event.last_affected}`);
      currentIntroduced = null;
    }
  }

  // No fix exists — open-ended
  if (currentIntroduced !== null) {
    ranges.push(`>=${currentIntroduced}`);
  }

  return ranges.join(' || ');
}

/**
 * Extract the fix version from an OSV range's events.
 * Returns the first "fixed" version found, or null.
 */
export function extractFixVersion(events: OsvEvent[]): string | null {
  for (const event of events) {
    if (event.fixed !== undefined) {
      return event.fixed;
    }
  }
  return null;
}

/**
 * Convert all ranges from an OSV affected entry to a single semver range string.
 * Only processes SEMVER and ECOSYSTEM range types (identical for npm).
 */
export function affectedToSemverRange(affected: OsvAffected): string {
  const allRanges: string[] = [];

  if (!Array.isArray(affected.ranges)) return '';

  for (const range of affected.ranges) {
    if (!range || typeof range !== 'object') continue;
    if (range.type === 'GIT') continue; // skip git ranges
    if (!Array.isArray(range.events)) continue;
    const converted = eventsToSemverRange(range.events);
    if (converted) {
      allRanges.push(converted);
    }
  }

  return allRanges.join(' || ');
}

/**
 * Extract the best fix version from all ranges of an affected entry.
 */
export function affectedFixVersion(affected: OsvAffected): string | null {
  for (const range of affected.ranges) {
    if (range.type === 'GIT') continue;
    const fix = extractFixVersion(range.events);
    if (fix) return fix;
  }
  return null;
}
